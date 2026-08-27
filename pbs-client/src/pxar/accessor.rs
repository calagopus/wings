use super::{
    format::GoodbyeItem,
    {Entry, EntryKind, Metadata, Stat, StatxTimestamp, Symlink},
};
use crate::osstr::{os_str_as_bytes, os_string_from_bytes};
use std::{
    ffi::OsStr,
    future::Future,
    ops::Range,
    path::{Component, Path, PathBuf},
};

pub trait ReadAt: Send + Sync {
    fn read_at(
        &self,
        offset: u64,
        buf: &mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send;
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

    pub async fn open_root(&self) -> std::io::Result<Directory<T>> {
        Directory::open_at_end(self.input.clone(), self.size, PathBuf::from("/")).await
    }
}

pub struct Directory<T> {
    input: T,
    goodbye_ofs: u64,
    table: Vec<GoodbyeItem>,
    path: PathBuf,
}

impl<T: ReadAt + Clone> Directory<T> {
    async fn open_at_end(input: T, end_offset: u64, path: PathBuf) -> std::io::Result<Self> {
        let tail_at = end_offset
            .checked_sub(super::format::GOODBYE_ITEM_SIZE)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye tail does not fit"))?;
        let tail = super::format::GoodbyeItem::from_le_bytes(
            &read_array::<24, _>(&input, tail_at).await?,
        )?;
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
        if table_bytes > super::format::MAX_GOODBYE_TABLE_LEN {
            return Err(std::io::Error::other(
                "pxar: goodbye table exceeds maximum length",
            ));
        }

        let count = (table_bytes / super::format::GOODBYE_ITEM_SIZE) as usize - 1;
        let table_ofs = goodbye_ofs + super::format::HEADER_SIZE;
        let raw = read_data(
            &input,
            table_ofs,
            count as u64 * super::format::GOODBYE_ITEM_SIZE,
        )
        .await?;

        let mut table = Vec::with_capacity(count);
        for chunk in raw
            .as_chunks::<{ super::format::GOODBYE_ITEM_SIZE as usize }>()
            .0
        {
            table.push(super::format::GoodbyeItem::from_le_bytes(chunk)?);
        }

        Ok(Self {
            input,
            goodbye_ofs,
            table,
            path,
        })
    }

    pub async fn lookup(&self, path: &Path) -> std::io::Result<Option<FileEntry<T>>> {
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
            let entry = match dir.lookup_component(name).await? {
                Some(entry) => entry,
                None => return Ok(None),
            };

            if index + 1 == names.len() {
                result = Some(entry);
            } else {
                descended = Some(entry.enter_directory().await?);
            }
        }

        Ok(result)
    }

    async fn lookup_component(&self, name: &OsStr) -> std::io::Result<Option<FileEntry<T>>> {
        let hash = super::format::hash_filename(&os_str_as_bytes(name));
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

            let cursor = self.cursor(index).await?;
            if cursor.file_name == *name {
                return self.decode_cursor(&cursor).await.map(Some);
            }
            dup += 1;
        }
    }

    async fn cursor(&self, index: usize) -> std::io::Result<Cursor> {
        let item = self
            .table
            .get(index)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye index out of range"))?;

        let file_ofs = self
            .goodbye_ofs
            .checked_sub(item.offset)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye item offset out of range"))?;

        let (file_name, entry_ofs) = self.read_filename(file_ofs).await?;
        let entry_end = file_ofs
            .checked_add(item.size)
            .ok_or_else(|| std::io::Error::other("pxar: goodbye item size out of range"))?;

        Ok(Cursor {
            file_name,
            entry_range: entry_ofs..entry_end,
        })
    }

    async fn read_filename(&self, file_ofs: u64) -> std::io::Result<(std::ffi::OsString, u64)> {
        let header = read_header(&self.input, file_ofs).await?;
        if header.htype != super::format::PXAR_FILENAME {
            return Err(std::io::Error::other("pxar: expected a filename header"));
        }
        let content = header.content_size()?;
        if content > super::format::MAX_FILENAME_LEN {
            return Err(std::io::Error::other(
                "pxar: filename exceeds maximum length",
            ));
        }

        let mut name =
            read_data(&self.input, file_ofs + super::format::HEADER_SIZE, content).await?;
        if name.pop() != Some(0) {
            return Err(std::io::Error::other(
                "pxar: file name missing terminating zero",
            ));
        }
        super::format::validate_filename(&name)?;

        Ok((os_string_from_bytes(name), file_ofs + header.full_size))
    }

    async fn decode_cursor(&self, cursor: &Cursor) -> std::io::Result<FileEntry<T>> {
        let (metadata, kind) = decode_entry(
            &self.input,
            cursor.entry_range.start,
            cursor.entry_range.end,
        )
        .await?;

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

    pub async fn enter_directory(&self) -> std::io::Result<Directory<T>> {
        if !self.is_dir() {
            return Err(std::io::Error::other("pxar: entry is not a directory"));
        }
        Directory::open_at_end(self.input.clone(), self.entry_end, self.entry.path.clone()).await
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
}

impl<T: ReadAt> FileContents<T> {
    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub async fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let remaining = self.size - offset;
        let want = remaining.min(buf.len() as u64) as usize;
        let slice = buf
            .get_mut(..want)
            .ok_or_else(|| std::io::Error::other("pxar: read buffer too small"))?;

        self.input.read_at(self.start + offset, slice).await
    }
}

async fn decode_entry<T: ReadAt>(
    input: &T,
    start: u64,
    end: u64,
) -> std::io::Result<(Metadata, EntryKind)> {
    let header = read_header(input, start).await?;
    if header.htype != super::format::PXAR_ENTRY {
        return Err(std::io::Error::other("pxar: expected an entry header"));
    }
    let metadata = read_metadata(input, start + super::format::HEADER_SIZE, header).await?;

    let at = start + header.full_size;
    if at >= end {
        return Ok((metadata, EntryKind::Directory));
    }

    let item = read_header(input, at).await?;
    match item.htype {
        super::format::PXAR_PAYLOAD => Ok((
            metadata,
            EntryKind::File {
                size: item.content_size()?,
                offset: Some(at + super::format::HEADER_SIZE),
            },
        )),
        super::format::PXAR_SYMLINK => {
            let symlink_size = item.content_size()?;
            if symlink_size > super::format::MAX_SYMLINK_LEN {
                return Err(std::io::Error::other(
                    "pxar: symlink exceeds maximum length",
                ));
            }

            let data = read_data(input, at + super::format::HEADER_SIZE, symlink_size).await?;
            Ok((metadata, EntryKind::Symlink(Symlink { data })))
        }
        super::format::PXAR_FILENAME | super::format::PXAR_GOODBYE => {
            Ok((metadata, EntryKind::Directory))
        }
        _ => Err(std::io::Error::other("pxar: unsupported entry item")),
    }
}

async fn read_metadata<T: ReadAt>(
    input: &T,
    offset: u64,
    header: super::format::Header,
) -> std::io::Result<Metadata> {
    if header.content_size()? != super::format::STAT_SIZE {
        return Err(std::io::Error::other(
            "pxar: entry has an unexpected stat size",
        ));
    }
    let buf = read_array::<40, _>(input, offset).await?;

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

async fn read_header<T: ReadAt>(input: &T, offset: u64) -> std::io::Result<super::format::Header> {
    let buf = read_array::<16, _>(input, offset).await?;
    let header = super::format::Header {
        htype: u64_at(&buf, 0)?,
        full_size: u64_at(&buf, 8)?,
    };
    header.content_size()?;

    Ok(header)
}

async fn read_array<const N: usize, T: ReadAt>(input: &T, offset: u64) -> std::io::Result<[u8; N]> {
    let mut buf = [0; N];
    read_exact_at(input, &mut buf, offset).await?;
    Ok(buf)
}

async fn read_data<T: ReadAt>(input: &T, offset: u64, size: u64) -> std::io::Result<Vec<u8>> {
    if size > super::format::MAX_GOODBYE_TABLE_LEN {
        return Err(std::io::Error::other(
            "pxar: data section exceeds maximum length",
        ));
    }

    let size = usize::try_from(size).map_err(std::io::Error::other)?;
    let mut buf = vec![0; size];
    read_exact_at(input, &mut buf, offset).await?;
    Ok(buf)
}

async fn read_exact_at<T: ReadAt>(
    input: &T,
    mut buf: &mut [u8],
    mut offset: u64,
) -> std::io::Result<()> {
    while !buf.is_empty() {
        match input.read_at(offset, buf).await? {
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
