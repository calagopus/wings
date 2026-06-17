use super::{
    accessor::{ArchiveEntry, ArchiveEntryKind},
    error::PbsError,
};
use std::{
    ffi::OsStr,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

pub const CATALOG_MAGIC: [u8; 8] = [145, 253, 96, 249, 196, 103, 88, 213];
pub const CATALOG_NAME: &str = "catalog.pcat1.didx";

const ENTRY_DIRECTORY: u8 = b'd';
const ENTRY_FILE: u8 = b'f';
const ENTRY_SYMLINK: u8 = b'l';
const ENTRY_HARDLINK: u8 = b'h';
const ENTRY_BLOCKDEV: u8 = b'b';
const ENTRY_CHARDEV: u8 = b'c';
const ENTRY_FIFO: u8 = b'p';
const ENTRY_SOCKET: u8 = b's';

pub fn encode_u64(out: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            out.push(value as u8);
            break;
        }
        out.push(0x80 | (value & 0x7f) as u8);
        value >>= 7;
    }
}

pub fn encode_i64(out: &mut Vec<u8>, value: i64) {
    let negative = value < 0;
    let mut magnitude = if negative {
        (-(value + 1)) as u64
    } else {
        value as u64
    };

    loop {
        if magnitude < 0x40 {
            let sign = if negative { 0x40 } else { 0 };
            out.push(sign | magnitude as u8);
            break;
        }
        out.push(0x80 | (magnitude & 0x7f) as u8);
        magnitude >>= 7;
    }
}

enum Attribute {
    Directory { start: u64 },
    File { size: u64, mtime: i64 },
    Symlink,
    Hardlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

struct CatalogEntry {
    name: Vec<u8>,
    attribute: Attribute,
}

struct DirectoryInfo {
    name: Vec<u8>,
    entries: Vec<CatalogEntry>,
}

impl DirectoryInfo {
    fn new(name: Vec<u8>) -> Self {
        Self {
            name,
            entries: Vec::new(),
        }
    }

    fn encode(&self, start: u64) -> Vec<u8> {
        let mut table = Vec::new();
        encode_u64(&mut table, self.entries.len() as u64);
        for entry in &self.entries {
            encode_entry(&mut table, entry, start);
        }

        let mut data = Vec::new();
        encode_u64(&mut data, table.len() as u64);
        data.extend_from_slice(&table);
        data
    }
}

fn encode_entry(table: &mut Vec<u8>, entry: &CatalogEntry, start: u64) {
    let type_byte = match entry.attribute {
        Attribute::Directory { .. } => ENTRY_DIRECTORY,
        Attribute::File { .. } => ENTRY_FILE,
        Attribute::Symlink => ENTRY_SYMLINK,
        Attribute::Hardlink => ENTRY_HARDLINK,
        Attribute::BlockDevice => ENTRY_BLOCKDEV,
        Attribute::CharDevice => ENTRY_CHARDEV,
        Attribute::Fifo => ENTRY_FIFO,
        Attribute::Socket => ENTRY_SOCKET,
    };

    table.push(type_byte);
    encode_u64(table, entry.name.len() as u64);
    table.extend_from_slice(&entry.name);

    match entry.attribute {
        Attribute::Directory { start: child_start } => {
            encode_u64(table, start - child_start);
        }
        Attribute::File { size, mtime } => {
            encode_u64(table, size);
            encode_i64(table, mtime);
        }
        _ => {}
    }
}
pub struct CatalogWriter<W> {
    writer: W,
    stack: Vec<DirectoryInfo>,
    pos: u64,
}

impl<W: Write> CatalogWriter<W> {
    pub fn new(mut writer: W) -> io::Result<Self> {
        writer.write_all(&CATALOG_MAGIC)?;
        Ok(Self {
            writer,
            stack: vec![DirectoryInfo::new(Vec::new())],
            pos: CATALOG_MAGIC.len() as u64,
        })
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.pos += data.len() as u64;
        Ok(())
    }

    fn current(&mut self) -> io::Result<&mut DirectoryInfo> {
        self.stack
            .last_mut()
            .ok_or_else(|| io::Error::other("catalog directory stack underflow"))
    }

    pub fn start_directory(&mut self, name: &[u8]) {
        self.stack.push(DirectoryInfo::new(name.to_vec()));
    }

    pub fn end_directory(&mut self) -> io::Result<()> {
        let dir = self
            .stack
            .pop()
            .ok_or_else(|| io::Error::other("catalog directory stack underflow"))?;
        if self.stack.is_empty() {
            return Err(io::Error::other("cannot end the catalog root directory"));
        }

        let start = self.pos;
        let data = dir.encode(start);
        self.write_all(&data)?;

        self.current()?.entries.push(CatalogEntry {
            name: dir.name,
            attribute: Attribute::Directory { start },
        });
        Ok(())
    }

    fn add(&mut self, name: &[u8], attribute: Attribute) -> io::Result<()> {
        self.current()?.entries.push(CatalogEntry {
            name: name.to_vec(),
            attribute,
        });
        Ok(())
    }

    pub fn add_file(&mut self, name: &[u8], size: u64, mtime: i64) -> io::Result<()> {
        self.add(name, Attribute::File { size, mtime })
    }

    pub fn add_symlink(&mut self, name: &[u8]) -> io::Result<()> {
        self.add(name, Attribute::Symlink)
    }

    pub fn add_hardlink(&mut self, name: &[u8]) -> io::Result<()> {
        self.add(name, Attribute::Hardlink)
    }

    pub fn add_block_device(&mut self, name: &[u8]) -> io::Result<()> {
        self.add(name, Attribute::BlockDevice)
    }

    pub fn add_char_device(&mut self, name: &[u8]) -> io::Result<()> {
        self.add(name, Attribute::CharDevice)
    }

    pub fn add_fifo(&mut self, name: &[u8]) -> io::Result<()> {
        self.add(name, Attribute::Fifo)
    }

    pub fn add_socket(&mut self, name: &[u8]) -> io::Result<()> {
        self.add(name, Attribute::Socket)
    }

    pub fn finish(mut self) -> io::Result<W> {
        if self.stack.len() != 1 {
            return Err(io::Error::other("unbalanced catalog directories at finish"));
        }
        let root = self
            .stack
            .pop()
            .ok_or_else(|| io::Error::other("catalog directory stack underflow"))?;

        let start = self.pos;
        let data = root.encode(start);
        self.write_all(&data)?;
        self.write_all(&start.to_le_bytes())?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}

const MAX_CATALOG_DEPTH: usize = 1024;

fn decode_error(msg: &'static str) -> PbsError {
    PbsError::Decode(msg.into())
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn byte(&mut self) -> Result<u8, PbsError> {
        let value = *self
            .data
            .get(self.pos)
            .ok_or_else(|| decode_error("catalog: unexpected end of data"))?;
        self.pos += 1;

        Ok(value)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PbsError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| decode_error("catalog: length overflow"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| decode_error("catalog: slice out of range"))?;
        self.pos = end;

        Ok(slice)
    }

    fn u64(&mut self) -> Result<u64, PbsError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.byte()?;
            if shift >= 64 {
                return Err(decode_error("catalog: varint too long"));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn i64(&mut self) -> Result<i64, PbsError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.byte()?;
            if shift >= 64 {
                return Err(decode_error("catalog: varint too long"));
            }
            if byte & 0x80 != 0 {
                value |= u64::from(byte & 0x7f) << shift;
                shift += 7;
            } else {
                value |= u64::from(byte & 0x3f) << shift;
                return Ok(if byte & 0x40 != 0 {
                    -(value as i64) - 1
                } else {
                    value as i64
                });
            }
        }
    }
}

enum RawKind {
    Directory { child: usize },
    File { size: u64, mtime: i64 },
    Symlink,
    Hardlink,
    Other,
}

struct RawEntry {
    name: Vec<u8>,
    kind: RawKind,
}

fn read_table(data: &[u8], block_pos: usize) -> Result<Vec<RawEntry>, PbsError> {
    let mut block = Cursor::new(data, block_pos);
    let table_len = usize::try_from(block.u64()?)
        .map_err(|_| decode_error("catalog: table length overflow"))?;
    let table = block.take(table_len)?;

    let mut cursor = Cursor::new(table, 0);
    let count = cursor.u64()?;

    let mut entries = Vec::new();
    for _ in 0..count {
        let type_byte = cursor.byte()?;
        let name_len = usize::try_from(cursor.u64()?)
            .map_err(|_| decode_error("catalog: name length overflow"))?;
        let name = cursor.take(name_len)?.to_vec();

        let kind = match type_byte {
            ENTRY_DIRECTORY => {
                let delta = usize::try_from(cursor.u64()?)
                    .map_err(|_| decode_error("catalog: directory offset overflow"))?;
                let child = block_pos
                    .checked_sub(delta)
                    .ok_or_else(|| decode_error("catalog: directory offset underflow"))?;
                RawKind::Directory { child }
            }
            ENTRY_FILE => {
                let size = cursor.u64()?;
                let mtime = cursor.i64()?;
                RawKind::File { size, mtime }
            }
            ENTRY_SYMLINK => RawKind::Symlink,
            ENTRY_HARDLINK => RawKind::Hardlink,
            ENTRY_BLOCKDEV | ENTRY_CHARDEV | ENTRY_FIFO | ENTRY_SOCKET => RawKind::Other,
            _ => return Err(decode_error("catalog: unknown entry type")),
        };

        entries.push(RawEntry { name, kind });
    }

    Ok(entries)
}

fn push_walk(
    data: &[u8],
    block_pos: usize,
    base: &Path,
    out: &mut Vec<ArchiveEntry>,
    depth: usize,
) -> Result<(), PbsError> {
    if depth > MAX_CATALOG_DEPTH {
        return Err(decode_error("catalog: directory nesting too deep"));
    }

    for entry in read_table(data, block_pos)? {
        let path = base.join(OsStr::from_bytes(&entry.name));
        match entry.kind {
            RawKind::Directory { child } => {
                out.push(ArchiveEntry {
                    path: path.clone(),
                    kind: ArchiveEntryKind::Directory,
                    size: 0,
                    mode: 0o755,
                    mtime: 0,
                    symlink: None,
                });
                push_walk(data, child, &path, out, depth + 1)?;
            }
            RawKind::File { size, mtime } => out.push(ArchiveEntry {
                path,
                kind: ArchiveEntryKind::File,
                size,
                mode: 0o644,
                mtime,
                symlink: None,
            }),
            RawKind::Hardlink => out.push(ArchiveEntry {
                path,
                kind: ArchiveEntryKind::File,
                size: 0,
                mode: 0o644,
                mtime: 0,
                symlink: None,
            }),
            RawKind::Symlink => out.push(ArchiveEntry {
                path,
                kind: ArchiveEntryKind::Symlink,
                size: 0,
                mode: 0o777,
                mtime: 0,
                symlink: None,
            }),
            RawKind::Other => {}
        }
    }

    Ok(())
}

pub fn parse_catalog(data: &[u8]) -> Result<Vec<ArchiveEntry>, PbsError> {
    if data.get(..CATALOG_MAGIC.len()) != Some(&CATALOG_MAGIC[..]) {
        return Err(decode_error("catalog: invalid magic"));
    }

    let trailer_start = data
        .len()
        .checked_sub(8)
        .ok_or_else(|| decode_error("catalog: missing trailer"))?;
    let trailer = data
        .get(trailer_start..)
        .ok_or_else(|| decode_error("catalog: missing trailer"))?;
    let root_offset = usize::try_from(u64::from_le_bytes(
        trailer
            .try_into()
            .map_err(|_| decode_error("catalog: bad trailer"))?,
    ))
    .map_err(|_| decode_error("catalog: root offset overflow"))?;

    let mut out = Vec::new();
    for entry in read_table(data, root_offset)? {
        let path = PathBuf::from(OsStr::from_bytes(&entry.name));
        match entry.kind {
            RawKind::Directory { child } => push_walk(data, child, Path::new(""), &mut out, 0)?,
            RawKind::File { size, mtime } => out.push(ArchiveEntry {
                path,
                kind: ArchiveEntryKind::File,
                size,
                mode: 0o644,
                mtime,
                symlink: None,
            }),
            _ => {}
        }
    }

    Ok(out)
}
