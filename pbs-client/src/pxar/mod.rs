use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};

pub mod accessor;
pub mod decoder;
pub mod encoder;
pub mod format;

#[derive(Clone, Copy, Debug, Default)]
pub struct StatxTimestamp {
    pub secs: i64,
    pub nanos: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub mode: u64,
    pub flags: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime: StatxTimestamp,
}

impl Stat {
    pub fn file_type(&self) -> u64 {
        self.mode & format::mode::IFMT
    }

    pub fn is_dir(&self) -> bool {
        self.file_type() == format::mode::IFDIR
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Metadata {
    pub stat: Stat,
}

impl Metadata {
    pub fn builder(mode: u64) -> MetadataBuilder {
        MetadataBuilder {
            inner: Metadata {
                stat: Stat {
                    mode,
                    ..Stat::default()
                },
            },
        }
    }

    pub fn dir_builder(mode: u64) -> MetadataBuilder {
        Self::builder(format::mode::IFDIR | (mode & !format::mode::IFMT))
    }

    pub fn file_builder(mode: u64) -> MetadataBuilder {
        Self::builder(format::mode::IFREG | (mode & !format::mode::IFMT))
    }

    pub fn is_dir(&self) -> bool {
        self.stat.is_dir()
    }
}

pub struct MetadataBuilder {
    inner: Metadata,
}

impl MetadataBuilder {
    pub fn mtime_unix(mut self, mtime: Duration) -> Self {
        self.inner.stat.mtime = StatxTimestamp {
            secs: mtime.as_secs() as i64,
            nanos: mtime.subsec_nanos(),
        };
        self
    }

    pub fn build(self) -> Metadata {
        self.inner
    }
}

#[derive(Clone, Debug)]
pub struct Symlink {
    pub data: Vec<u8>,
}

impl Symlink {
    pub fn as_os_str(&self) -> &OsStr {
        let len = self.data.len().saturating_sub(1);
        OsStr::from_bytes(self.data.get(..len).unwrap_or(&[]))
    }
}

#[derive(Clone, Debug)]
pub enum EntryKind {
    Directory,
    File { size: u64, offset: Option<u64> },
    Symlink(Symlink),
}

#[derive(Clone, Debug)]
pub struct Entry {
    path: PathBuf,
    metadata: Metadata,
    kind: EntryKind,
}

impl Entry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn kind(&self) -> &EntryKind {
        &self.kind
    }
}
