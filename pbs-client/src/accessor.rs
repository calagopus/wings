use super::{
    config::PbsConfig,
    datablob,
    error::PbsError,
    h2::H2Transport,
    pxar::{
        EntryKind,
        accessor::{Accessor, ReadAt},
    },
    reader::parse_dynamic_index_entries,
    writer::ARCHIVE_NAME,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const CHUNK_CACHE_CAPACITY: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArchiveEntryKind {
    Directory,
    File,
    Symlink,
}

#[derive(Clone, Debug)]
pub struct ArchiveEntry {
    pub path: PathBuf,
    pub kind: ArchiveEntryKind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub symlink: Option<PathBuf>,
}

fn decode_err(err: io::Error) -> PbsError {
    PbsError::Decode(err.to_string().into())
}

struct ChunkCache {
    map: HashMap<usize, Arc<Vec<u8>>>,
    order: VecDeque<usize>,
    capacity: usize,
}

impl ChunkCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn get(&mut self, idx: usize) -> Option<Arc<Vec<u8>>> {
        let value = self.map.get(&idx)?.clone();
        if let Some(pos) = self.order.iter().position(|&i| i == idx) {
            self.order.remove(pos);
        }
        self.order.push_back(idx);
        Some(value)
    }

    fn insert(&mut self, idx: usize, value: Arc<Vec<u8>>) {
        if self.map.contains_key(&idx) {
            return;
        }
        while self.order.len() >= self.capacity
            && let Some(evict) = self.order.pop_front()
        {
            self.map.remove(&evict);
        }
        self.order.push_back(idx);
        self.map.insert(idx, value);
    }
}

struct ChunkReaderInner {
    transport: H2Transport,
    handle: tokio::runtime::Handle,
    ends: Vec<u64>,
    digests: Vec<[u8; 32]>,
    size: u64,
    cache: Mutex<ChunkCache>,
}

impl ChunkReaderInner {
    async fn fetch_chunk(&self, idx: usize) -> io::Result<Arc<Vec<u8>>> {
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(idx)
        {
            return Ok(cached);
        }

        let digest = self
            .digests
            .get(idx)
            .ok_or_else(|| io::Error::other("chunk index out of range"))?;
        let encoded = self
            .transport
            .download("chunk", &[("digest", hex::encode(digest))])
            .await
            .map_err(io::Error::other)?;
        let plaintext = datablob::decode_blob(&encoded).map_err(io::Error::other)?;
        let plaintext = Arc::new(plaintext);

        self.cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(idx, Arc::clone(&plaintext));

        Ok(plaintext)
    }

    async fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() || offset >= self.size {
            return Ok(0);
        }

        let idx = self.ends.partition_point(|&end| end <= offset);
        let chunk_start = match idx.checked_sub(1) {
            Some(prev) => *self.ends.get(prev).unwrap_or(&0),
            None => 0,
        };

        let chunk = self.fetch_chunk(idx).await?;
        let within = (offset - chunk_start) as usize;
        let available = chunk.len().saturating_sub(within);
        let len = available.min(buf.len());

        let src = chunk
            .get(within..within + len)
            .ok_or_else(|| io::Error::other("chunk shorter than its index entry"))?;
        let dst = buf
            .get_mut(..len)
            .ok_or_else(|| io::Error::other("read buffer too small"))?;
        dst.copy_from_slice(src);

        Ok(len)
    }
}

#[derive(Clone)]
pub struct ChunkReader {
    inner: Arc<ChunkReaderInner>,
}

impl ReadAt for ChunkReader {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let inner = &self.inner;
        inner.handle.clone().block_on(inner.read_into(buf, offset))
    }
}

pub struct PbsArchive {
    reader: ChunkReader,
    size: u64,
}

impl PbsArchive {
    pub async fn connect(
        config: &PbsConfig,
        backup_id: &str,
        backup_time: i64,
    ) -> Result<Self, PbsError> {
        let transport = H2Transport::connect(
            config,
            "proxmox-backup-reader-protocol-v1",
            "reader",
            &super::h2::snapshot_query(config, backup_id, backup_time),
        )
        .await?;

        let index = transport
            .download("download", &[("file-name", ARCHIVE_NAME.to_string())])
            .await?;
        let entries = parse_dynamic_index_entries(&index)?;

        let size = entries.last().map(|(end, _)| *end).unwrap_or(0);
        let mut ends = Vec::with_capacity(entries.len());
        let mut digests = Vec::with_capacity(entries.len());
        for (end, digest) in entries {
            ends.push(end);
            digests.push(digest);
        }

        Ok(Self {
            reader: ChunkReader {
                inner: Arc::new(ChunkReaderInner {
                    transport,
                    handle: tokio::runtime::Handle::current(),
                    ends,
                    digests,
                    size,
                    cache: Mutex::new(ChunkCache::new(CHUNK_CACHE_CAPACITY)),
                }),
            },
            size,
        })
    }

    fn accessor(&self) -> Result<Accessor<ChunkReader>, PbsError> {
        Accessor::new(self.reader.clone(), self.size).map_err(decode_err)
    }

    pub async fn close(&self) {
        self.reader.inner.transport.close().await;
    }

    pub async fn read_catalog(&self) -> Result<Vec<u8>, PbsError> {
        let transport = &self.reader.inner.transport;

        let index = transport
            .download(
                "download",
                &[("file-name", super::catalog::CATALOG_NAME.to_string())],
            )
            .await?;
        let chunks = parse_dynamic_index_entries(&index)?;

        let mut catalog = Vec::new();
        for (_, digest) in chunks {
            let encoded = transport
                .download("chunk", &[("digest", hex::encode(digest))])
                .await?;
            catalog.extend_from_slice(&datablob::decode_blob(&encoded)?);
        }

        Ok(catalog)
    }

    pub fn read_link(&self, path: &Path) -> Result<PathBuf, PbsError> {
        let accessor = self.accessor()?;
        let root = accessor.open_root().map_err(decode_err)?;

        let entry = root
            .lookup(path)
            .map_err(decode_err)?
            .ok_or_else(|| PbsError::Decode("symlink not found in archive".into()))?;

        match entry.entry().kind() {
            EntryKind::Symlink(target) => Ok(PathBuf::from(target.as_os_str())),
            _ => Err(PbsError::Decode("archive entry is not a symlink".into())),
        }
    }

    pub fn open_reader(
        &self,
        path: &Path,
        range: Option<(u64, u64)>,
    ) -> Result<Box<dyn io::Read + Send + Sync>, PbsError> {
        let accessor = self.accessor()?;
        let root = accessor.open_root().map_err(decode_err)?;

        let entry = root
            .lookup(path)
            .map_err(decode_err)?
            .ok_or_else(|| PbsError::Decode("file not found in archive".into()))?;

        if !matches!(entry.entry().kind(), EntryKind::File { .. }) {
            return Err(PbsError::Decode(
                "archive entry is not a regular file".into(),
            ));
        }

        let contents = entry.contents().map_err(decode_err)?;
        match range {
            Some((start, len)) => Ok(Box::new(RangedReader::new(contents, start, len))),
            None => Ok(Box::new(contents)),
        }
    }
}

struct RangedReader<R> {
    inner: R,
    offset: u64,
    remaining: u64,
}

impl<R: FileExt> RangedReader<R> {
    fn new(inner: R, start: u64, len: u64) -> Self {
        Self {
            inner,
            offset: start,
            remaining: len,
        }
    }
}

impl<R: FileExt> io::Read for RangedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }

        let want = self.remaining.min(buf.len() as u64) as usize;
        let slice = buf
            .get_mut(..want)
            .ok_or_else(|| io::Error::other("read buffer too small"))?;
        let read = self.inner.read_at(slice, self.offset)?;
        self.offset += read as u64;
        self.remaining -= read as u64;

        Ok(read)
    }
}
