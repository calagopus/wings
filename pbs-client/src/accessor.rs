use super::{
    config::PbsConfig,
    datablob,
    error::PbsError,
    h2::H2Transport,
    pxar::{
        EntryKind,
        accessor::{Accessor, FileContents, ReadAt},
    },
    reader::parse_dynamic_index_entries,
    writer::ARCHIVE_NAME,
};
use compact_str::ToCompactString;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    runtime::Handle,
};

const CHUNK_CACHE_CAPACITY: usize = 32;
const MAX_CATALOG_SIZE: usize = 256 * 1024 * 1024;

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

fn decode_err(err: std::io::Error) -> PbsError {
    PbsError::Decode(err.to_compact_string())
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
    ends: Vec<u64>,
    digests: Vec<[u8; 32]>,
    size: u64,
    cache: Mutex<ChunkCache>,
}

impl ChunkReaderInner {
    async fn fetch_chunk(&self, idx: usize) -> std::io::Result<Arc<Vec<u8>>> {
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
            .ok_or_else(|| std::io::Error::other("chunk index out of range"))?;
        let encoded = self
            .transport
            .download("chunk", &[("digest", hex::encode(digest))])
            .await
            .map_err(std::io::Error::other)?;
        let plaintext = tokio::task::spawn_blocking(move || datablob::decode_blob(&encoded))
            .await
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)?;
        let plaintext = Arc::new(plaintext);

        self.cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(idx, Arc::clone(&plaintext));

        Ok(plaintext)
    }

    async fn read_into(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
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
            .ok_or_else(|| std::io::Error::other("chunk shorter than its index entry"))?;
        let dst = buf
            .get_mut(..len)
            .ok_or_else(|| std::io::Error::other("read buffer too small"))?;
        dst.copy_from_slice(src);

        Ok(len)
    }
}

#[derive(Clone)]
pub struct ChunkReader {
    inner: Arc<ChunkReaderInner>,
}

impl ReadAt for ChunkReader {
    fn read_at(
        &self,
        offset: u64,
        buf: &mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send {
        self.inner.read_into(buf, offset)
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send + Sync>>;

pub struct PbsFileReader {
    contents: Arc<FileContents<ChunkReader>>,
    offset: u64,
    remaining: u64,
    pending: Option<ReadFuture>,
}

impl PbsFileReader {
    fn new(contents: FileContents<ChunkReader>, offset: u64, remaining: u64) -> Self {
        Self {
            contents: Arc::new(contents),
            offset,
            remaining,
            pending: None,
        }
    }
}

impl AsyncRead for PbsFileReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            if let Some(future) = this.pending.as_mut() {
                let data = ready!(future.as_mut().poll(cx))?;
                this.pending = None;
                this.offset += data.len() as u64;
                this.remaining -= data.len() as u64;
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }

            if this.remaining == 0 || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let want = (buf.remaining() as u64).min(this.remaining);
            let contents = Arc::clone(&this.contents);
            let offset = this.offset;
            this.pending = Some(Box::pin(async move {
                let mut chunk = vec![0; want as usize];
                let read = contents.read_at(offset, &mut chunk).await?;
                chunk.truncate(read);
                Ok(chunk)
            }));
        }
    }
}

pub struct SyncPbsFileReader {
    reader: PbsFileReader,
    handle: Handle,
}

impl Read for SyncPbsFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;

        self.handle.block_on(self.reader.read(buf))
    }
}

pub struct PbsArchive {
    reader: ChunkReader,
    size: u64,
    handle: Handle,
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
                    ends,
                    digests,
                    size,
                    cache: Mutex::new(ChunkCache::new(CHUNK_CACHE_CAPACITY)),
                }),
            },
            size,
            handle: Handle::current(),
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
            let plaintext = tokio::task::spawn_blocking(move || datablob::decode_blob(&encoded))
                .await
                .map_err(|err| PbsError::Transport(err.to_string().into()))??;

            if catalog.len().saturating_add(plaintext.len()) > MAX_CATALOG_SIZE {
                return Err(PbsError::Decode("catalog: size exceeds limit".into()));
            }

            catalog.extend_from_slice(&plaintext);
        }

        Ok(catalog)
    }

    pub async fn read_link(&self, path: &Path) -> Result<PathBuf, PbsError> {
        let accessor = self.accessor()?;
        let root = accessor.open_root().await.map_err(decode_err)?;

        let entry = root
            .lookup(path)
            .await
            .map_err(decode_err)?
            .ok_or_else(|| PbsError::Decode("symlink not found in archive".into()))?;

        match entry.entry().kind() {
            EntryKind::Symlink(target) => Ok(PathBuf::from(target.as_os_str())),
            _ => Err(PbsError::Decode("archive entry is not a symlink".into())),
        }
    }

    pub fn read_link_blocking(&self, path: &Path) -> Result<PathBuf, PbsError> {
        self.handle.block_on(self.read_link(path))
    }

    pub async fn open_reader(
        &self,
        path: &Path,
        range: Option<(u64, u64)>,
    ) -> Result<PbsFileReader, PbsError> {
        let accessor = self.accessor()?;
        let root = accessor.open_root().await.map_err(decode_err)?;

        let entry = root
            .lookup(path)
            .await
            .map_err(decode_err)?
            .ok_or_else(|| PbsError::Decode("file not found in archive".into()))?;

        if !matches!(entry.entry().kind(), EntryKind::File { .. }) {
            return Err(PbsError::Decode(
                "archive entry is not a regular file".into(),
            ));
        }

        let contents = entry.contents().map_err(decode_err)?;
        let (offset, remaining) = match range {
            Some((start, len)) => (start, len),
            None => (0, contents.len()),
        };

        Ok(PbsFileReader::new(contents, offset, remaining))
    }

    pub fn open_reader_blocking(
        &self,
        path: &Path,
        range: Option<(u64, u64)>,
    ) -> Result<SyncPbsFileReader, PbsError> {
        let reader = self.handle.block_on(self.open_reader(path, range))?;

        Ok(SyncPbsFileReader {
            reader,
            handle: self.handle.clone(),
        })
    }
}
