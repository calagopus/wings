use super::{
    format::GoodbyeItem,
    {Entry, EntryKind, Metadata, Stat, StatxTimestamp, Symlink},
};
use std::{
    ffi::OsStr,
    ops::Range,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::FileExt,
    },
    path::{Component, Path, PathBuf},
};

pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize>;
}

pub struct Accessor<T> {
    input: T,
    size: u64,
}

impl<T: ReadAt + Clone> Accessor<T> {
    pub fn new(input: T, size: u64) -> std::io::Result<Self> {
        if size < super::format::GOODBYE_ITEM_SIZE {
            return Err(std::io::Error::other("pxar: archive too small"));
        }
        Ok(Self { input, size })
    }

    pub fn open_root(&self) -> std::io::Result<Directory<T>> {
        Directory::open_at_end(self.input.clone(), self.size, PathBuf::from("/"))
    }
}

pub struct Directory<T> {
    input: T,
    goodbye_ofs: u64,
    table: Vec<GoodbyeItem>,
    path: PathBuf,
}

impl<T: ReadAt + Clone> Directory<T> {
    fn open_at_end(input: T, end_offset: u64, path: PathBuf) -> std::io::Result<Self> {
        let tail_at = end_offset
            .checked_sub(super::format::GOODBYE_ITEM_SIZE)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye tail does not fit"))?;
        let tail = super::format::GoodbyeItem::from_le_bytes(&read_array::<24>(&input, tail_at)?)?;
        if tail.hash != super::format::PXAR_GOODBYE_TAIL_MARKER {
            return Err(std::io::Error::other("pxar: missing goodbye tail marker"));
        }

        let goodbye_ofs = end_offset
            .checked_sub(tail.size)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye size out of range"))?;

        let table_bytes = end_offset
            .checked_sub(goodbye_ofs)
            .and_then(|v| v.checked_sub(super::format::HEADER_SIZE))
            .ok_or_else(|| std::io::Error::other("pxar: goodbye table out of range"))?;
        if table_bytes % super::format::GOODBYE_ITEM_SIZE != 0 || table_bytes == 0 {
            return Err(std::io::Error::other("pxar: invalid goodbye table size"));
        }

        let count = (table_bytes / super::format::GOODBYE_ITEM_SIZE) as usize - 1;
        let table_ofs = goodbye_ofs + super::format::HEADER_SIZE;
        let raw = read_data(
            &input,
            table_ofs,
            count as u64 * super::format::GOODBYE_ITEM_SIZE,
        )?;

        let mut table = Vec::with_capacity(count);
        for chunk in raw.chunks_exact(super::format::GOODBYE_ITEM_SIZE as usize) {
            table.push(super::format::GoodbyeItem::from_le_bytes(chunk)?);
        }

        Ok(Self {
            input,
            goodbye_ofs,
            table,
            path,
        })
    }

    pub fn lookup(&self, path: &Path) -> std::io::Result<Option<FileEntry<T>>> {
        let names: Vec<&OsStr> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(Ok(name)),
                Component::RootDir | Component::CurDir => None,
                _ => Some(Err(())),
            })
            .collect::<Result<Vec<_>, ()>>()
            .map_err(|_| std::io::Error::other("pxar: unsupported path component in lookup"))?;

        let mut descended: Option<Directory<T>> = None;
        let mut result: Option<FileEntry<T>> = None;

        for (index, name) in names.iter().enumerate() {
            let dir = descended.as_ref().unwrap_or(self);
            let entry = match dir.lookup_component(name)? {
                Some(entry) => entry,
                None => return Ok(None),
            };

            if index + 1 == names.len() {
                result = Some(entry);
            } else {
                descended = Some(entry.enter_directory()?);
            }
        }

        Ok(result)
    }

    fn lookup_component(&self, name: &OsStr) -> std::io::Result<Option<FileEntry<T>>> {
        let hash = super::format::hash_filename(name.as_bytes());
        let first =
            match super::format::bst_search_by(&self.table, 0, 0, |item| hash.cmp(&item.hash)) {
                Some(index) => index,
                None => return Ok(None),
            };

        let mut dup = 0;
        loop {
            let index = match super::format::bst_search_by(&self.table, first, dup, |item| {
                hash.cmp(&item.hash)
            }) {
                Some(index) => index,
                None => return Ok(None),
            };

            let cursor = self.cursor(index)?;
            if cursor.file_name == *name {
                return self.decode_cursor(&cursor).map(Some);
            }
            dup += 1;
        }
    }

    fn cursor(&self, index: usize) -> std::io::Result<Cursor> {
        let item = self
            .table
            .get(index)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye index out of range"))?;

        let file_ofs = self
            .goodbye_ofs
            .checked_sub(item.offset)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye item offset out of range"))?;

        let (file_name, entry_ofs) = self.read_filename(file_ofs)?;
        let entry_end = file_ofs
            .checked_add(item.size)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye item size out of range"))?;

        Ok(Cursor {
            file_name,
            entry_range: entry_ofs..entry_end,
        })
    }

    fn read_filename(&self, file_ofs: u64) -> std::io::Result<(std::ffi::OsString, u64)> {
        let header = read_header(&self.input, file_ofs)?;
        if header.htype != super::format::PXAR_FILENAME {
            return Err(std::io::Error::other("pxar: expected a filename header"));
        }
        let content = header.content_size()?;
        let mut name = read_data(&self.input, file_ofs + super::format::HEADER_SIZE, content)?;
        if name.pop() != Some(0) {
            return Err(std::io::Error::other(
                "pxar: file name missing terminating zero",
            ));
        }
        super::format::validate_filename(&name)?;

        Ok((
            std::ffi::OsString::from_vec(name),
            file_ofs + header.full_size,
        ))
    }

    fn decode_cursor(&self, cursor: &Cursor) -> std::io::Result<FileEntry<T>> {
        let (metadata, kind) = decode_entry(
            &self.input,
            cursor.entry_range.start,
            cursor.entry_range.end,
        )?;

        Ok(FileEntry {
            input: self.input.clone(),
            entry: Entry {
                path: self.path.join(&cursor.file_name),
                metadata,
                kind,
            },
            entry_end: cursor.entry_range.end,
        })
    }
}

struct Cursor {
    file_name: std::ffi::OsString,
    entry_range: Range<u64>,
}

pub struct FileEntry<T> {
    input: T,
    entry: Entry,
    entry_end: u64,
}

impl<T: ReadAt + Clone> FileEntry<T> {
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    fn is_dir(&self) -> bool {
        matches!(self.entry.kind, EntryKind::Directory)
    }

    pub fn enter_directory(&self) -> std::io::Result<Directory<T>> {
        if !self.is_dir() {
            return Err(std::io::Error::other("pxar: entry is not a directory"));
        }
        Directory::open_at_end(self.input.clone(), self.entry_end, self.entry.path.clone())
    }

    pub fn contents(&self) -> std::io::Result<FileContents<T>> {
        match self.entry.kind {
            EntryKind::File {
                size,
                offset: Some(offset),
            } => Ok(FileContents {
                input: self.input.clone(),
                start: offset,
                size,
                at: 0,
            }),
            EntryKind::File { offset: None, .. } => Err(std::io::Error::other(
                "pxar: file entry has no content offset",
            )),
            _ => Err(std::io::Error::other("pxar: entry is not a regular file")),
        }
    }
}

pub struct FileContents<T> {
    input: T,
    start: u64,
    size: u64,
    at: u64,
}

impl<T: ReadAt> FileContents<T> {
    fn read_window(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let remaining = self.size - offset;
        let want = remaining.min(buf.len() as u64) as usize;
        let slice = buf
            .get_mut(..want)
            .ok_or_else(|| std::io::Error::other("pxar: read buffer too small"))?;
        self.input.read_at(slice, self.start + offset)
    }
}

impl<T: ReadAt> std::io::Read for FileContents<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let got = self.read_window(buf, self.at)?;
        self.at += got as u64;
        Ok(got)
    }
}

impl<T: ReadAt> FileExt for FileContents<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.read_window(buf, offset)
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "pxar: archive contents are read-only",
        ))
    }
}

fn decode_entry<T: ReadAt>(
    input: &T,
    start: u64,
    end: u64,
) -> std::io::Result<(Metadata, EntryKind)> {
    let header = read_header(input, start)?;
    if header.htype != super::format::PXAR_ENTRY {
        return Err(std::io::Error::other("pxar: expected an entry header"));
    }
    let metadata = read_metadata(input, start + super::format::HEADER_SIZE, header)?;

    let at = start + header.full_size;
    if at >= end {
        return Ok((metadata, EntryKind::Directory));
    }

    let item = read_header(input, at)?;
    match item.htype {
        super::format::PXAR_PAYLOAD => Ok((
            metadata,
            EntryKind::File {
                size: item.content_size()?,
                offset: Some(at + super::format::HEADER_SIZE),
            },
        )),
        super::format::PXAR_SYMLINK => {
            let data = read_data(input, at + super::format::HEADER_SIZE, item.content_size()?)?;
            Ok((metadata, EntryKind::Symlink(Symlink { data })))
        }
        super::format::PXAR_FILENAME | super::format::PXAR_GOODBYE => {
            Ok((metadata, EntryKind::Directory))
        }
        _ => Err(std::io::Error::other("pxar: unsupported entry item")),
    }
}

fn read_metadata<T: ReadAt>(
    input: &T,
    offset: u64,
    header: super::format::Header,
) -> std::io::Result<Metadata> {
    if header.content_size()? != super::format::STAT_SIZE {
        return Err(std::io::Error::other(
            "pxar: entry has an unexpected stat size",
        ));
    }
    let buf = read_array::<40>(input, offset)?;

    Ok(Metadata {
        stat: Stat {
            mode: u64_at(&buf, 0)?,
            flags: u64_at(&buf, 8)?,
            uid: u32_at(&buf, 16)?,
            gid: u32_at(&buf, 20)?,
            mtime: StatxTimestamp {
                secs: u64_at(&buf, 24)? as i64,
                nanos: u32_at(&buf, 32)?,
            },
        },
    })
}

fn read_header<T: ReadAt>(input: &T, offset: u64) -> std::io::Result<super::format::Header> {
    let buf = read_array::<16>(input, offset)?;
    let header = super::format::Header {
        htype: u64_at(&buf, 0)?,
        full_size: u64_at(&buf, 8)?,
    };
    header.content_size()?;

    Ok(header)
}

fn read_array<const N: usize>(input: &impl ReadAt, offset: u64) -> std::io::Result<[u8; N]> {
    let mut buf = [0; N];
    read_exact_at(input, &mut buf, offset)?;
    Ok(buf)
}

fn read_data(input: &impl ReadAt, offset: u64, size: u64) -> std::io::Result<Vec<u8>> {
    let size = usize::try_from(size).map_err(std::io::Error::other)?;
    let mut buf = vec![0; size];
    read_exact_at(input, &mut buf, offset)?;
    Ok(buf)
}

fn read_exact_at(input: &impl ReadAt, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        match input.read_at(buf, offset)? {
            0 => return Err(std::io::Error::other("pxar: unexpected EOF")),
            got => {
                let rest = std::mem::take(&mut buf);
                buf = rest
                    .get_mut(got..)
                    .ok_or_else(|| std::io::Error::other("pxar: read past buffer"))?;
                offset += got as u64;
            }
        }
    }
    Ok(())
}

fn u64_at(buf: &[u8], at: usize) -> std::io::Result<u64> {
    let array: [u8; 8] = buf
        .get(at..at + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| std::io::Error::other("pxar: truncated u64 field"))?;
    Ok(u64::from_le_bytes(array))
}

fn u32_at(buf: &[u8], at: usize) -> std::io::Result<u32> {
    let array: [u8; 4] = buf
        .get(at..at + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| std::io::Error::other("pxar: truncated u32 field"))?;
    Ok(u32::from_le_bytes(array))
}
