#![allow(dead_code)]

use crate::{
    io::{
        compression::CompressionLevel,
        range_reader::{AsyncRangeReader, RangeReader},
    },
    models::DirectoryEntry,
    server::filesystem::{archive::StreamableArchiveFormat, cap::FileType},
    utils::PortablePermissions,
};
use axum::http::{HeaderMap, HeaderValue};
pub use functions::{
    AsyncDirectoryStreamWalkFn, AsyncDirectoryWalkFn, DirectoryWalkFn, IsIgnoredFn,
};
use parking_lot::RwLock;
use std::{
    ops::Bound,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Semaphore,
};

pub mod archive;
pub mod cap;
pub mod functions;
pub mod mount;

#[derive(Clone, Copy)]
pub struct ByteRange(Bound<u64>, Bound<u64>);

impl ByteRange {
    pub fn new(start: Bound<u64>, end: Bound<u64>) -> Self {
        Self(start, end)
    }

    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let range_header = headers.get(axum::http::header::RANGE)?;

        let range_str = range_header.to_str().ok()?;
        let range_values = range_str.strip_prefix("bytes=")?;

        let mut range_split = range_values.split('-');
        let (Some(start_str), Some(end_str)) = (range_split.next(), range_split.next()) else {
            return None;
        };
        if range_split.next().is_some() {
            return None;
        }

        let start = if start_str.is_empty() {
            Bound::Unbounded
        } else {
            match start_str.parse::<u64>() {
                Ok(val) => Bound::Included(val),
                Err(_) => return None,
            }
        };

        let end = if end_str.is_empty() {
            Bound::Unbounded
        } else {
            match end_str.parse::<u64>() {
                Ok(val) => Bound::Included(val),
                Err(_) => return None,
            }
        };

        Some(Self::new(start, end))
    }

    pub fn get_start(&self) -> Option<u64> {
        match &self.0 {
            Bound::Included(s) => Some(*s),
            Bound::Excluded(s) => Some(s + 1),
            Bound::Unbounded => None,
        }
    }

    pub fn get_end(&self) -> Option<u64> {
        match &self.1 {
            Bound::Included(e) => Some(*e),
            Bound::Excluded(e) => Some(e - 1),
            Bound::Unbounded => None,
        }
    }

    pub fn is_full(&self) -> bool {
        matches!((&self.0, &self.1), (Bound::Unbounded, Bound::Unbounded))
    }

    pub fn get_header_value(&self, total: u64) -> HeaderValue {
        let range_header_value = match (&self.0, &self.1) {
            (Bound::Included(s), Bound::Included(e)) => format!("bytes {}-{}/{}", s, e, total),
            (Bound::Included(s), Bound::Excluded(e)) => format!("bytes {}-{}/{}", s, e - 1, total),
            (Bound::Included(s), Bound::Unbounded) => {
                format!("bytes {}-{}/{}", s, total - 1, total)
            }
            (Bound::Excluded(s), Bound::Included(e)) => format!("bytes {}-{}/{}", s + 1, e, total),
            (Bound::Excluded(s), Bound::Excluded(e)) => {
                format!("bytes {}-{}/{}", s + 1, e - 1, total)
            }
            (Bound::Excluded(s), Bound::Unbounded) => {
                format!("bytes {}-{}/{}", s + 1, total - 1, total)
            }
            (Bound::Unbounded, Bound::Included(e)) => format!("bytes 0-{}/{}", e, total),
            (Bound::Unbounded, Bound::Excluded(e)) => format!("bytes 0-{}/{}", e - 1, total),
            (Bound::Unbounded, Bound::Unbounded) => format!("bytes 0-{}/{}", total - 1, total),
        };

        unsafe { HeaderValue::from_str(&range_header_value).unwrap_unchecked() }
    }
}

impl From<ByteRange> for (Bound<u64>, Bound<u64>) {
    fn from(range: ByteRange) -> Self {
        (range.0, range.1)
    }
}

pub type ReadableFileStream = Box<dyn std::io::Read + Send + Sync>;
pub type AsyncReadableFileStream = Box<dyn AsyncRead + Unpin + Send + Sync>;

pub type WritableFileStream = Box<dyn std::io::Write + Send + Sync>;
pub type AsyncWritableFileStream = Box<dyn AsyncWrite + Unpin + Send>;
pub type WritableSeekableFileStream = Box<dyn crate::io::WriteSeek + Send + Sync>;
pub type AsyncWritableSeekableFileStream = Box<dyn crate::io::AsyncWriteSeek + Send>;
pub type ReadableWritableSeekableFileStream = Box<dyn crate::io::ReadWriteSeek + Send>;
pub type AsyncReadableWritableSeekableFileStream = Box<dyn crate::io::AsyncReadWriteSeek + Send>;

pub struct DirectoryListing {
    pub total_entries: usize,
    pub entries: Vec<DirectoryEntry>,
}

pub struct FileRead {
    pub size: u64,
    pub total_size: u64,
    pub reader_range: Option<ByteRange>,
    pub reader: ReadableFileStream,
}

impl FileRead {
    pub fn from_file(
        file: std::fs::File,
        reader_range: Option<ByteRange>,
    ) -> Result<Self, std::io::Error> {
        let metadata = file.metadata()?;

        if let Some(range) = reader_range {
            let reader = RangeReader::new(file, range, metadata.len())?;

            Ok(Self {
                size: reader.len(),
                total_size: metadata.len(),
                reader_range: Some(range),
                reader: Box::new(reader),
            })
        } else {
            Ok(Self {
                size: metadata.len(),
                total_size: metadata.len(),
                reader_range: None,
                reader: Box::new(file),
            })
        }
    }
}

pub struct AsyncFileRead {
    pub size: u64,
    pub total_size: u64,
    pub reader_range: Option<ByteRange>,
    pub reader: AsyncReadableFileStream,
}

impl AsyncFileRead {
    pub async fn from_file(
        file: tokio::fs::File,
        reader_range: Option<ByteRange>,
    ) -> Result<Self, std::io::Error> {
        let metadata = file.metadata().await?;

        if let Some(range) = reader_range {
            let reader = AsyncRangeReader::new(file, range, metadata.len()).await?;

            Ok(Self {
                size: reader.len(),
                total_size: metadata.len(),
                reader_range: Some(range),
                reader: Box::new(reader),
            })
        } else {
            Ok(Self {
                size: metadata.len(),
                total_size: metadata.len(),
                reader_range: None,
                reader: Box::new(file),
            })
        }
    }

    pub fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        headers.insert(axum::http::header::CONTENT_LENGTH, self.size.into());

        if let Some(reader_range) = &self.reader_range {
            headers.insert(
                axum::http::header::ACCEPT_RANGES,
                HeaderValue::from_static("bytes"),
            );
            headers.insert(
                axum::http::header::CONTENT_RANGE,
                reader_range.get_header_value(self.total_size),
            );
        }

        headers
    }
}

pub struct FileMetadata {
    pub file_type: FileType,
    pub permissions: PortablePermissions,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
    pub created: Option<std::time::SystemTime>,
}

impl From<cap_std::fs::Metadata> for FileMetadata {
    fn from(metadata: cap_std::fs::Metadata) -> Self {
        Self {
            file_type: match metadata.file_type() {
                ft if ft.is_dir() => FileType::Dir,
                ft if ft.is_file() => FileType::File,
                ft if ft.is_symlink() => FileType::Symlink,
                _ => FileType::Unknown,
            },
            permissions: PortablePermissions::from(metadata.permissions()),
            size: metadata.len(),
            modified: metadata.modified().ok().map(|t| t.into_std()),
            created: metadata.created().ok().map(|t| t.into_std()),
        }
    }
}

impl From<std::fs::Metadata> for FileMetadata {
    fn from(metadata: std::fs::Metadata) -> Self {
        Self {
            file_type: match metadata.file_type() {
                ft if ft.is_dir() => FileType::Dir,
                ft if ft.is_file() => FileType::File,
                ft if ft.is_symlink() => FileType::Symlink,
                _ => FileType::Unknown,
            },
            permissions: PortablePermissions::from(metadata.permissions()),
            size: metadata.len(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
        }
    }
}

pub trait DirectoryWalk {
    fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>>;

    fn run_multithreaded(
        &mut self,
        threads: usize,
        func: DirectoryWalkFn,
    ) -> Result<(), anyhow::Error> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()?;
        let error = Arc::new(RwLock::new(None));

        pool.in_place_scope(|scope| {
            while let Some(entry) = self.next_entry() {
                match entry {
                    Ok((file_type, path)) => {
                        if crate::unlikely(error.read().is_some()) {
                            break;
                        }

                        let error = Arc::clone(&error);
                        let func = func.clone();

                        scope.spawn(move |_| {
                            if crate::unlikely(error.read().is_some()) {
                                return;
                            }

                            if let Err(err) = func(file_type, path) {
                                *error.write() = Some(err);
                            }
                        });
                    }
                    Err(err) => {
                        *error.write() = Some(err);
                        break;
                    }
                }
            }
        });

        if let Some(err) = error.write().take() {
            return Err(err);
        }

        Ok(())
    }
}

#[async_trait::async_trait]
pub trait AsyncDirectoryWalk {
    async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>>;

    async fn run_multithreaded(
        &mut self,
        threads: usize,
        func: AsyncDirectoryWalkFn,
    ) -> Result<(), anyhow::Error> {
        let semaphore = Arc::new(Semaphore::new(threads));
        let error = Arc::new(RwLock::new(None));

        while let Some(entry) = self.next_entry().await {
            match entry {
                Ok((file_type, path)) => {
                    if crate::unlikely(error.read().is_some()) {
                        break;
                    }

                    let semaphore = Arc::clone(&semaphore);
                    let error = Arc::clone(&error);
                    let func = func.clone();

                    let permit = match semaphore.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
                        match func(file_type, path).await {
                            Ok(_) => {}
                            Err(err) => {
                                *error.write() = Some(err);
                            }
                        }
                    });
                }
                Err(err) => return Err(err),
            }
        }

        semaphore.acquire_many(threads as u32).await.ok();

        if let Some(err) = error.write().take() {
            return Err(err);
        }

        Ok(())
    }
}

#[async_trait::async_trait]
pub trait AsyncDirectoryStreamWalk {
    #[inline]
    fn supports_multithreading(&self) -> bool {
        true
    }

    async fn next_entry(
        &mut self,
    ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>;

    async fn run_multithreaded(
        &mut self,
        threads: usize,
        func: AsyncDirectoryStreamWalkFn,
    ) -> Result<(), anyhow::Error> {
        let semaphore = Arc::new(Semaphore::new(threads));
        let error = Arc::new(RwLock::new(None));

        while let Some(entry) = self.next_entry().await {
            match entry {
                Ok((file_type, path, stream)) => {
                    let semaphore = Arc::clone(&semaphore);
                    let error = Arc::clone(&error);
                    let func = func.clone();

                    if crate::unlikely(error.read().is_some()) {
                        break;
                    }

                    if self.supports_multithreading() {
                        let permit = match semaphore.acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => break,
                        };
                        tokio::spawn(async move {
                            let _permit = permit;
                            match func(file_type, path, stream).await {
                                Ok(_) => {}
                                Err(err) => {
                                    *error.write() = Some(err);
                                }
                            }
                        });
                    } else {
                        match func(file_type, path, stream).await {
                            Ok(_) => {}
                            Err(err) => return Err(err),
                        }
                    }
                }
                Err(err) => return Err(err),
            }
        }

        semaphore.acquire_many(threads as u32).await.ok();

        if let Some(err) = error.write().take() {
            return Err(err);
        }

        Ok(())
    }
}

#[async_trait::async_trait]
pub trait VirtualReadableFilesystem: Send + Sync {
    fn is_primary_server_fs(&self) -> bool {
        false
    }
    fn is_fast(&self) -> bool {
        false
    }
    fn is_writable(&self) -> bool {
        false
    }

    fn backing_server(&self) -> &crate::server::Server;

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error>;
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error>;
    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error>;
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error>;

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error>;
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error>;

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error>;
    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error>;
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error>;
    async fn async_walk_dir_files<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_paths: Vec<PathBuf>,
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let root_path = path.as_ref().to_path_buf();
        let is_ignored = move |file_type, path: PathBuf| {
            let stripped_path = path.strip_prefix(&root_path).unwrap_or(&path);
            if file_paths.iter().any(|p| stripped_path.starts_with(p)) {
                is_ignored(file_type, path)
            } else {
                None
            }
        };
        self.async_walk_dir(path, IsIgnoredFn::from(is_ignored))
            .await
    }
    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error>;
    async fn async_walk_dir_files_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_paths: Vec<PathBuf>,
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        let root_path = path.as_ref().to_path_buf();
        let is_ignored = move |file_type, path: PathBuf| {
            let stripped_path = path.strip_prefix(&root_path).unwrap_or(&path);
            if file_paths.iter().any(|p| stripped_path.starts_with(p)) {
                is_ignored(file_type, path)
            } else {
                None
            }
        };
        self.async_walk_dir_stream(path, IsIgnoredFn::from(is_ignored))
            .await
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error>;
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error>;
    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error>;
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error>;

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: super::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error>;
    async fn async_read_dir_files_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_paths: Vec<PathBuf>,
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: super::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error> {
        let root_path = path.as_ref().to_path_buf();
        let is_ignored = move |file_type, path: PathBuf| {
            let stripped_path = path.strip_prefix(&root_path).unwrap_or(&path);
            if file_paths.iter().any(|p| stripped_path.starts_with(p)) {
                is_ignored(file_type, path)
            } else {
                None
            }
        };
        self.async_read_dir_archive(
            path,
            archive_format,
            compression_level,
            progress,
            IsIgnoredFn::from(is_ignored),
        )
        .await
    }

    async fn close(&self) -> Result<(), anyhow::Error>;
}

#[async_trait::async_trait]
pub trait VirtualWritableFilesystem: VirtualReadableFilesystem {
    fn create_dir_all(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error>;
    async fn async_create_dir_all(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error>;
    fn remove_dir_all(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error>;
    async fn async_remove_dir_all(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error>;
    fn remove_file(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error>;
    async fn async_remove_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error>;

    fn create_symlink(
        &self,
        original: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error>;
    async fn async_create_symlink(
        &self,
        original: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error>;
    async fn async_create_symlink_contents(
        &self,
        contents: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error>;
    fn create_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<WritableFileStream, anyhow::Error> {
        Ok(self.create_seekable_file(path)? as WritableFileStream)
    }
    async fn async_create_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<AsyncWritableFileStream, anyhow::Error> {
        Ok(self.async_create_seekable_file(path).await? as AsyncWritableFileStream)
    }
    fn create_seekable_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<WritableSeekableFileStream, anyhow::Error>;
    async fn async_create_seekable_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<AsyncWritableSeekableFileStream, anyhow::Error>;
    fn open_file_with_options(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        options: cap_std::fs::OpenOptions,
    ) -> Result<ReadableWritableSeekableFileStream, anyhow::Error>;
    async fn async_open_file_with_options(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        options: cap_std::fs::OpenOptions,
    ) -> Result<AsyncReadableWritableSeekableFileStream, anyhow::Error>;

    fn set_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        permissions: PortablePermissions,
    ) -> Result<(), anyhow::Error>;
    async fn async_set_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        permissions: PortablePermissions,
    ) -> Result<(), anyhow::Error>;
    fn set_times(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error>;
    async fn async_set_times(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error>;
    fn rename(
        &self,
        from: &(dyn AsRef<Path> + Send + Sync),
        to: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
    ) -> Result<(), anyhow::Error>;
    async fn async_rename(
        &self,
        from: &(dyn AsRef<Path> + Send + Sync),
        to: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
    ) -> Result<(), anyhow::Error>;
}
