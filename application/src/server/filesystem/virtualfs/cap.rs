use super::{
    AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, AsyncReadableFileStream,
    AsyncWritableSeekableFileStream, ByteRange, DirectoryListing, DirectoryWalkFilterFn,
    DirectoryWalkFn, FileMetadata, FileRead, FileType, IsIgnoredFn, VirtualWalkEntry,
    WritableSeekableFileStream,
};
use crate::{
    io::{abort::AbortListener, compression::CompressionLevel},
    models::DirectoryEntry,
    server::filesystem::{
        DirectoryEntryOptions, PreparedDirectoryEntry,
        archive::StreamableArchiveFormat,
        cap::name_and_type,
        listing::{ListingWork, check_aborted},
        virtualfs::{
            AsyncReadableWritableSeekableFileStream, DirectoryWalk,
            ReadableWritableSeekableFileStream,
        },
    },
    utils::{CmpExt, PortablePermissions},
};
use std::{
    cmp::Ordering,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;

fn group_window(start: usize, end: usize, len: usize) -> Option<Range<usize>> {
    let start = start.min(len);
    let end = end.min(len);

    if start >= end { None } else { Some(start..end) }
}

fn sort_window<T>(items: &mut [T], window: Range<usize>, cmp: impl Fn(&T, &T) -> Ordering) {
    if window.start >= window.end || window.end > items.len() {
        return;
    }

    items.select_nth_unstable_by(window.end - 1, &cmp);
    if window.start > 0
        && window.start + 1 < window.end
        && let Some(prefix) = items.get_mut(..window.end - 1)
    {
        prefix.select_nth_unstable_by(window.start, &cmp);
    }

    if let Some(window) = items.get_mut(window) {
        window.sort_unstable_by(&cmp);
    }
}

struct StattedDirectoryEntry {
    path: PathBuf,
    entry: Option<cap_std::fs::DirEntry>,
    metadata: cap_std::fs::Metadata,
}

enum ListingResult<T> {
    Complete(DirectoryListing),
    Pending {
        total_entries: usize,
        entries: Vec<T>,
    },
}

#[derive(Clone)]
pub struct VirtualCapFilesystem {
    pub inner: crate::server::filesystem::cap::CapFilesystem,
    pub server: crate::server::Server,
    pub is_primary_server_fs: bool,
    pub is_writable: bool,
    pub is_ignored: Option<IsIgnoredFn>,
}

impl VirtualCapFilesystem {
    pub fn with_is_ignored(mut self, is_ignored: IsIgnoredFn) -> Self {
        if let Some(existing_is_ignored) = self.is_ignored {
            self.is_ignored = Some(existing_is_ignored.merge(is_ignored));
        } else {
            self.is_ignored = Some(is_ignored);
        }

        self
    }

    fn denied() -> anyhow::Error {
        anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        ))
    }

    pub fn check_ignored(
        &self,
        file_type: FileType,
        path: impl Into<PathBuf>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.into();
        let Some(is_ignored) = &self.is_ignored else {
            return Ok(path);
        };
        let Some(path) = (is_ignored)(file_type, path) else {
            return Err(Self::denied());
        };

        Ok(path)
    }

    pub async fn async_check_ignored(
        &self,
        file_type: FileType,
        path: impl Into<PathBuf>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.into();
        let Some(is_ignored) = &self.is_ignored else {
            return Ok(path);
        };
        let Some(path) = is_ignored.call_async(file_type, path).await else {
            return Err(Self::denied());
        };

        Ok(path)
    }

    pub fn is_denied(&self, file_type: FileType, path: &Path) -> bool {
        self.check_ignored(file_type, path).is_err()
    }

    pub async fn async_is_denied(&self, file_type: FileType, path: &Path) -> bool {
        self.async_check_ignored(file_type, path).await.is_err()
    }

    #[inline]
    fn check_writable(&self) -> Result<(), anyhow::Error> {
        if !self.is_writable {
            Err(anyhow::anyhow!("filesystem is read-only"))
        } else {
            Ok(())
        }
    }

    fn stat_directory_entry(
        &self,
        path: PathBuf,
        entry: cap_std::fs::DirEntry,
    ) -> Result<StattedDirectoryEntry, anyhow::Error> {
        let entry = if !cfg!(windows) && path.file_name() == Some(entry.file_name().as_os_str()) {
            Some(entry)
        } else {
            None
        };

        let metadata = match &entry {
            Some(entry) => entry.metadata()?,
            None => self.inner.symlink_metadata(&path)?,
        };

        Ok(StattedDirectoryEntry {
            path,
            entry,
            metadata,
        })
    }

    fn prepare_statted_directory_entry(
        &self,
        statted: StattedDirectoryEntry,
    ) -> Result<PreparedDirectoryEntry, anyhow::Error> {
        let StattedDirectoryEntry {
            path,
            entry,
            metadata,
        } = statted;

        let checked_path = self.check_ignored(metadata.file_type().into(), &path)?;
        let mut prepared = self.server.filesystem.prepare_api_entry_cap_blocking(
            &self.inner,
            checked_path,
            metadata,
        );

        if prepared.metadata.is_file() && prepared.path == path {
            prepared.directory_entry = entry;
        }

        Ok(prepared)
    }

    fn prepare_directory_entry(
        &self,
        path: PathBuf,
        entry: cap_std::fs::DirEntry,
    ) -> Result<PreparedDirectoryEntry, anyhow::Error> {
        self.prepare_statted_directory_entry(self.stat_directory_entry(path, entry)?)
    }

    fn select_prepared_entries(
        &self,
        entries: Vec<(bool, PreparedDirectoryEntry)>,
        sort: crate::models::DirectorySortingMode,
        per_page: Option<usize>,
        page: usize,
        listener: &AbortListener,
    ) -> Result<Vec<PreparedDirectoryEntry>, anyhow::Error> {
        use crate::models::DirectorySortingMode::*;

        if matches!(sort, NameAsc | NameDesc) {
            return Ok(entries.into_iter().map(|(_, entry)| entry).collect());
        }

        let options = DirectoryEntryOptions::server_fs(self.is_primary_server_fs);
        let mut keyed = Vec::with_capacity(entries.len());

        for (directory, prepared) in entries {
            check_aborted(listener)?;

            let key: i128 = match sort {
                SizeAsc | SizeDesc => self
                    .server
                    .filesystem
                    .prepared_entry_sort_size_blocking(&prepared, options)
                    .0
                    .into(),
                PhysicalSizeAsc | PhysicalSizeDesc => self
                    .server
                    .filesystem
                    .prepared_entry_sort_size_blocking(&prepared, options)
                    .1
                    .into(),
                ModifiedAsc | ModifiedDesc => prepared.modified_secs().into(),
                CreatedAsc | CreatedDesc => prepared.created_secs().into(),
                NameAsc | NameDesc => 0,
            };

            keyed.push((directory, key, prepared));
        }

        let ascending = matches!(sort, SizeAsc | PhysicalSizeAsc | ModifiedAsc | CreatedAsc);
        keyed.sort_by(|(a_dir, a_key, _), (b_dir, b_key, _)| {
            b_dir.cmp(a_dir).then_with(|| {
                if ascending {
                    a_key.cmp(b_key)
                } else {
                    b_key.cmp(a_key)
                }
            })
        });

        check_aborted(listener)?;

        let start = per_page.map_or(0, |per_page| {
            page.saturating_sub(1).saturating_mul(per_page)
        });

        Ok(keyed
            .into_iter()
            .skip(start)
            .take(per_page.unwrap_or(usize::MAX))
            .map(|(_, _, entry)| entry)
            .collect())
    }

    fn finish_prepared_entries(
        &self,
        prepared: Vec<PreparedDirectoryEntry>,
        listener: &AbortListener,
    ) -> Result<Vec<DirectoryEntry>, anyhow::Error> {
        let options = DirectoryEntryOptions::server_fs(self.is_primary_server_fs);
        let mut entries = Vec::with_capacity(prepared.len());

        for prepared in prepared {
            check_aborted(listener)?;

            entries.push(self.server.filesystem.finish_api_entry_cap_blocking(
                &self.inner,
                prepared,
                options,
            ));
        }

        Ok(entries)
    }

    fn finish_small_listing(
        &self,
        total_entries: usize,
        prepared: Vec<PreparedDirectoryEntry>,
        listener: &AbortListener,
    ) -> Result<ListingResult<PreparedDirectoryEntry>, anyhow::Error> {
        if prepared.len() > ListingWork::SMALL_LIMIT {
            return Ok(ListingResult::Pending {
                total_entries,
                entries: prepared,
            });
        }

        Ok(ListingResult::Complete(DirectoryListing {
            total_entries,
            entries: self.finish_prepared_entries(prepared, listener)?,
        }))
    }
}

#[async_trait::async_trait]
impl super::VirtualReadableFilesystem for VirtualCapFilesystem {
    fn is_primary_server_fs(&self) -> bool {
        self.is_primary_server_fs
    }
    fn is_fast(&self) -> bool {
        true
    }
    fn is_writable(&self) -> bool {
        self.is_writable
    }

    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.metadata(path)?;
        let metadata: FileMetadata = metadata.into();

        self.check_ignored(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.async_metadata(path).await?;
        let metadata: FileMetadata = metadata.into();

        self.async_check_ignored(metadata.file_type, path.as_ref())
            .await?;

        Ok(metadata)
    }

    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.symlink_metadata(path)?;
        let metadata: FileMetadata = metadata.into();

        self.check_ignored(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;
        let metadata: FileMetadata = metadata.into();

        self.async_check_ignored(metadata.file_type, path.as_ref())
            .await?;

        Ok(metadata)
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;

        let path = self
            .async_check_ignored(metadata.file_type().into(), path.as_ref())
            .await?;

        self.server
            .filesystem
            .to_api_entry_cap(
                &self.inner,
                path,
                metadata,
                DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            )
            .await
    }

    fn directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let metadata = self.inner.symlink_metadata(path)?;
        let path = self.check_ignored(metadata.file_type().into(), path.as_ref())?;

        Ok(self.server.filesystem.to_api_entry_buffer_blocking(
            path,
            &metadata,
            DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            Some(buffer),
            None,
            None,
        ))
    }
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let this = self.clone();
        let path = path.as_ref().to_path_buf();
        let buffer = buffer.to_owned();

        tokio::task::spawn_blocking(move || this.directory_entry_buffer(&path, &buffer)).await?
    }

    fn directory_entry_from_metadata(
        &self,
        path: &Path,
        metadata: &cap_std::fs::Metadata,
        buffer: Option<&[u8]>,
    ) -> Option<DirectoryEntry> {
        if metadata.is_dir() {
            return None;
        }

        Some(self.server.filesystem.to_api_file_entry_buffer(
            path.to_path_buf(),
            metadata,
            DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            buffer,
        ))
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        let path = path.as_ref().to_path_buf();
        let is_ignored = match &self.is_ignored {
            Some(existing) => existing.clone().merge(is_ignored),
            None => is_ignored,
        };
        let work = Arc::clone(&self.server.filesystem.app_state.listing_work);

        let initial = work
            .run({
                let this = self.clone();
                let path = path.clone();

                move |listener| {
                    use crate::models::DirectorySortingMode::*;

                    let mut directory_entries = Vec::new();
                    let mut other_entries = Vec::new();
                    let mut scratch = PathBuf::new();
                    let mut dir = this.inner.read_dir(&path)?;

                    while let Some(item) = dir.next() {
                        check_aborted(listener)?;

                        let Ok(entry) = item else { break };
                        let (file_type, name) = name_and_type(&entry);

                        scratch.clear();
                        scratch.push(&path);
                        scratch.push(&name);
                        match is_ignored(file_type, std::mem::take(&mut scratch)) {
                            Some(kept) => scratch = kept,
                            None => continue,
                        }

                        if file_type.is_dir() {
                            directory_entries.push((name, entry));
                        } else {
                            other_entries.push((name, entry));
                        }
                    }

                    check_aborted(listener)?;

                    let total_entries = directory_entries.len() + other_entries.len();
                    let (directory_window, other_window) = if matches!(sort, NameAsc | NameDesc) {
                        let descending = matches!(sort, NameDesc);
                        let cmp =
                            |(a, _): &(String, cap_std::fs::DirEntry),
                             (b, _): &(String, cap_std::fs::DirEntry)| {
                                let ordering =
                                    a.cmp_ascii_case_insensitive(b).then_with(|| a.cmp(b));
                                if descending {
                                    ordering.reverse()
                                } else {
                                    ordering
                                }
                            };

                        let start = per_page.map_or(0, |per_page| {
                            page.saturating_sub(1).saturating_mul(per_page)
                        });
                        let end =
                            per_page.map_or(usize::MAX, |per_page| start.saturating_add(per_page));

                        let directory_window = group_window(start, end, directory_entries.len());
                        if let Some(window) = directory_window.clone() {
                            sort_window(&mut directory_entries, window, cmp);
                        }

                        let other_window = group_window(
                            start.saturating_sub(directory_entries.len()),
                            end.saturating_sub(directory_entries.len()),
                            other_entries.len(),
                        );
                        if let Some(window) = other_window.clone() {
                            sort_window(&mut other_entries, window, cmp);
                        }

                        (
                            directory_window.unwrap_or(0..0),
                            other_window.unwrap_or(0..0),
                        )
                    } else {
                        (0..directory_entries.len(), 0..other_entries.len())
                    };

                    let candidates: Vec<_> = directory_entries
                        .into_iter()
                        .skip(directory_window.start)
                        .take(directory_window.len())
                        .map(|(name, entry)| (true, name, entry))
                        .chain(
                            other_entries
                                .into_iter()
                                .skip(other_window.start)
                                .take(other_window.len())
                                .map(|(name, entry)| (false, name, entry)),
                        )
                        .collect();

                    if candidates.len() > ListingWork::SMALL_LIMIT {
                        return Ok(ListingResult::Pending {
                            total_entries,
                            entries: candidates,
                        });
                    }

                    let mut prepared = Vec::with_capacity(candidates.len());
                    for (directory, name, entry) in candidates {
                        check_aborted(listener)?;

                        if let Ok(entry) = this.prepare_directory_entry(path.join(name), entry) {
                            prepared.push((directory, entry));
                        }
                    }

                    let prepared =
                        this.select_prepared_entries(prepared, sort, per_page, page, listener)?;

                    Ok(ListingResult::Complete(DirectoryListing {
                        total_entries,
                        entries: this.finish_prepared_entries(prepared, listener)?,
                    }))
                }
            })
            .await?;

        let (total_entries, candidates) = match initial {
            ListingResult::Complete(listing) => return Ok(listing),
            ListingResult::Pending {
                total_entries,
                entries,
            } => (total_entries, entries),
        };

        let statted = work
            .map_ordered(candidates, {
                let this = self.clone();

                move |(directory, name, entry)| {
                    (directory, this.stat_directory_entry(path.join(name), entry))
                }
            })
            .await?;

        let selected = work
            .run({
                let this = self.clone();

                move |listener| {
                    let mut prepared = Vec::with_capacity(statted.len());

                    for (directory, statted) in statted {
                        check_aborted(listener)?;

                        let Ok(statted) = statted else { continue };
                        if let Ok(entry) = this.prepare_statted_directory_entry(statted) {
                            prepared.push((directory, entry));
                        }
                    }

                    let prepared =
                        this.select_prepared_entries(prepared, sort, per_page, page, listener)?;
                    this.finish_small_listing(total_entries, prepared, listener)
                }
            })
            .await?;

        let (total_entries, selected) = match selected {
            ListingResult::Complete(listing) => return Ok(listing),
            ListingResult::Pending {
                total_entries,
                entries,
            } => (total_entries, entries),
        };

        let entries = work
            .map_ordered(selected, {
                let this = self.clone();
                let options = DirectoryEntryOptions::server_fs(this.is_primary_server_fs);

                move |prepared| {
                    this.server.filesystem.finish_api_entry_cap_blocking(
                        &this.inner,
                        prepared,
                        options,
                    )
                }
            })
            .await?;

        Ok(DirectoryListing {
            total_entries,
            entries,
        })
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let walk_dir = self.inner.walk_dir(path)?.with_is_ignored(
            if let Some(existing_is_ignored) = &self.is_ignored {
                existing_is_ignored.clone().merge(is_ignored)
            } else {
                is_ignored
            },
        );

        struct IgnoreWalkDir {
            inner: crate::server::filesystem::cap::WalkDir,
        }

        impl DirectoryWalk for IgnoreWalkDir {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.inner.next_entry().map(|res| {
                    res.map(|entry| (entry.file_type(), entry.path))
                        .map_err(|err| err.into())
                })
            }

            fn next_walk_entry(&mut self) -> Option<Result<VirtualWalkEntry, anyhow::Error>> {
                self.inner.next_entry().map(|res| {
                    res.map(VirtualWalkEntry::with_source)
                        .map_err(|err| err.into())
                })
            }

            fn run_parallel(
                &mut self,
                threads: usize,
                filter: Option<DirectoryWalkFilterFn>,
                func: DirectoryWalkFn,
            ) -> Result<(), anyhow::Error> {
                self.inner.run_parallel(
                    threads,
                    filter,
                    Arc::new(move |entry| func(VirtualWalkEntry::with_source(entry))),
                )
            }
        }

        Ok(Box::new(IgnoreWalkDir { inner: walk_dir }))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let walk_dir = self.inner.async_walk_dir(path).await?.with_is_ignored(
            if let Some(existing_is_ignored) = &self.is_ignored {
                existing_is_ignored.clone().merge(is_ignored)
            } else {
                is_ignored
            },
        );

        struct IgnoreAsyncWalkDir {
            inner: crate::server::filesystem::cap::AsyncWalkDir,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryWalk for IgnoreAsyncWalkDir {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.inner.next_entry().await.map(|res| {
                    res.map(|entry| (entry.file_type(), entry.path))
                        .map_err(|err| err.into())
                })
            }

            async fn next_walk_entry(&mut self) -> Option<Result<VirtualWalkEntry, anyhow::Error>> {
                self.inner.next_entry().await.map(|res| {
                    res.map(VirtualWalkEntry::with_source)
                        .map_err(|err| err.into())
                })
            }
        }

        Ok(Box::new(IgnoreAsyncWalkDir { inner: walk_dir }))
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        let walk_dir = self.inner.async_walk_dir(path).await?.with_is_ignored(
            if let Some(existing_is_ignored) = &self.is_ignored {
                existing_is_ignored.clone().merge(is_ignored)
            } else {
                is_ignored
            },
        );

        struct IgnoreAsyncWalkDir<'a> {
            inner_fs: &'a crate::server::filesystem::cap::CapFilesystem,
            inner: crate::server::filesystem::cap::AsyncWalkDir,
        }

        #[async_trait::async_trait]
        impl<'a> AsyncDirectoryStreamWalk for IgnoreAsyncWalkDir<'a> {
            async fn next_entry(
                &mut self,
            ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>
            {
                let entry = self.inner.next_entry().await?;

                let (file_type, path) = match entry {
                    Ok(entry) => (entry.file_type(), entry.path),
                    Err(err) => return Some(Err(err.into())),
                };

                let reader: AsyncReadableFileStream = if file_type.is_file() {
                    match self.inner_fs.async_open(&path).await {
                        Ok(file) => Box::new(file),
                        Err(_) => Box::new(tokio::io::empty()),
                    }
                } else {
                    Box::new(tokio::io::empty())
                };

                Some(Ok((file_type, path, reader)))
            }
        }

        Ok(Box::new(IgnoreAsyncWalkDir {
            inner_fs: &self.inner,
            inner: walk_dir,
        }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let path = self.check_ignored(FileType::File, path.as_ref())?;
        let file = self.inner.open(path)?;

        Ok(FileRead::from_file(file, range)?)
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let path = self
            .async_check_ignored(FileType::File, path.as_ref())
            .await?;
        let file = self.inner.async_open(path).await?;

        Ok(AsyncFileRead::from_file(file, range).await?)
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let path = self.check_ignored(FileType::Symlink, path.as_ref())?;
        let link_path = self.inner.read_link(&path)?;

        Ok(link_path)
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let path = self
            .async_check_ignored(FileType::Symlink, path.as_ref())
            .await?;
        let link_path = self.inner.async_read_link(&path).await?;

        Ok(link_path)
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FalliblePipeReader, anyhow::Error> {
        let names = self.inner.async_read_dir_all(path).await?;
        let file_compression_threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;
        let (reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new(reader);

        tokio::spawn({
            let filesystem = self.inner.clone();
            let is_ignored = if let Some(existing_is_ignored) = &self.is_ignored {
                existing_is_ignored.clone().merge(is_ignored)
            } else {
                is_ignored
            };
            let path = path.as_ref().to_path_buf();

            async move {
                let writer = writer.into_sync();

                match archive_format {
                    StreamableArchiveFormat::Zip => {
                        match crate::server::filesystem::archive::create::create_zip_streaming(
                            filesystem,
                            writer,
                            &path,
                            names,
                            progress,
                            is_ignored,
                            crate::server::filesystem::archive::create::CreateZipOptions {
                                compression_level,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                                signal.succeed();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create zip archive for cap vfs: {}",
                                    err
                                );
                                signal.fail(err);
                            }
                        }
                    }
                    f if f.is_tar() => {
                        match crate::server::filesystem::archive::create::create_tar(
                            filesystem,
                            writer,
                            &path,
                            names,
                            progress,
                            is_ignored,
                            crate::server::filesystem::archive::create::CreateTarOptions {
                                compression_type: archive_format.compression_format(),
                                compression_level,
                                threads: file_compression_threads,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                                signal.succeed();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create tar archive for cap vfs: {}",
                                    err
                                );
                                signal.fail(err);
                            }
                        }
                    }
                    f if f.is_itaf() => {
                        match crate::server::filesystem::archive::create::create_itaf(
                            filesystem,
                            writer,
                            &path,
                            names,
                            progress,
                            is_ignored,
                            crate::server::filesystem::archive::create::CreateItafOptions {
                                compression_type: archive_format.compression_format(),
                                compression_level,
                                threads: file_compression_threads,
                                crc_enabled: true,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                                signal.succeed();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create itaf archive for cap vfs: {}",
                                    err
                                );
                                signal.fail(err);
                            }
                        }
                    }
                    _ => {
                        tracing::error!(
                            "unsupported archive format for cap vfs: {}",
                            archive_format.extension()
                        );
                        signal.fail(format!(
                            "unsupported archive format: {}",
                            archive_format.extension()
                        ));
                    }
                }
            }
        });

        Ok(reader)
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        self.inner.close();
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::VirtualWritableFilesystem for VirtualCapFilesystem {
    fn create_dir_all(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(FileType::Dir, path.as_ref())?;

        if self.is_primary_server_fs {
            self.server.filesystem.create_chowned_dir_all(&path)?;
        } else {
            self.inner.create_dir_all(&path)?;
        }

        Ok(())
    }
    async fn async_create_dir_all(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self
            .async_check_ignored(FileType::Dir, path.as_ref())
            .await?;

        if self.is_primary_server_fs {
            self.server
                .filesystem
                .async_create_chowned_dir_all(&path)
                .await?;
        } else {
            self.inner.async_create_dir_all(&path).await?;
        }

        Ok(())
    }

    fn remove_dir_all(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(FileType::Dir, path.as_ref())?;

        self.inner.remove_dir_all(path)?;

        Ok(())
    }
    async fn async_remove_dir_all(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self
            .async_check_ignored(FileType::Dir, path.as_ref())
            .await?;

        self.inner.async_remove_dir_all(path).await?;

        Ok(())
    }

    fn remove_file(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(FileType::File, path.as_ref())?;

        self.inner.remove_file(path)?;

        Ok(())
    }
    async fn async_remove_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self
            .async_check_ignored(FileType::File, path.as_ref())
            .await?;

        self.inner.async_remove_file(path).await?;

        Ok(())
    }

    fn create_symlink(
        &self,
        original: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let original = self.check_ignored(FileType::File, original.as_ref())?;
        let link = self.check_ignored(FileType::Symlink, link.as_ref())?;

        self.inner.symlink(original, &link)?;
        if self.is_primary_server_fs {
            self.server.filesystem.chown_path(&link)?;
        }

        Ok(())
    }
    async fn async_create_symlink(
        &self,
        original: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let original = self
            .async_check_ignored(FileType::File, original.as_ref())
            .await?;
        let link = self
            .async_check_ignored(FileType::Symlink, link.as_ref())
            .await?;

        self.inner.async_symlink(original, &link).await?;
        if self.is_primary_server_fs {
            self.server.filesystem.async_chown_path(&link).await?;
        }

        Ok(())
    }

    async fn async_create_symlink_contents(
        &self,
        contents: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let link = self
            .async_check_ignored(FileType::Symlink, link.as_ref())
            .await?;

        self.inner
            .async_symlink_contents(contents.as_ref(), &link)
            .await?;
        if self.is_primary_server_fs {
            self.server.filesystem.async_chown_path(&link).await?;
        }

        Ok(())
    }

    fn create_seekable_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<WritableSeekableFileStream, anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(FileType::File, path.as_ref())?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::ServerFile::new(
                self.server.clone(),
                &path,
                None,
                None,
            )?;

            Ok(Box::new(file))
        } else {
            let file = self.inner.create(path)?;

            Ok(Box::new(file))
        }
    }
    async fn async_create_seekable_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<AsyncWritableSeekableFileStream, anyhow::Error> {
        self.check_writable()?;
        let path = self
            .async_check_ignored(FileType::File, path.as_ref())
            .await?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::AsyncServerFile::new(
                self.server.clone(),
                &path,
                None,
                None,
            )
            .await?;

            Ok(Box::new(file))
        } else {
            let file = self.inner.async_create(path).await?;

            Ok(Box::new(file))
        }
    }
    fn open_file_with_options(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        options: cap_std::fs::OpenOptions,
    ) -> Result<ReadableWritableSeekableFileStream, anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(FileType::File, path.as_ref())?;

        let file = self.inner.open_with(&path, options)?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::ServerFile::new_file(
                self.server.clone(),
                &path,
                file,
                0,
            )?;

            Ok(Box::new(file))
        } else {
            Ok(Box::new(file))
        }
    }
    async fn async_open_file_with_options(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        options: cap_std::fs::OpenOptions,
    ) -> Result<AsyncReadableWritableSeekableFileStream, anyhow::Error> {
        self.check_writable()?;
        let path = self
            .async_check_ignored(FileType::File, path.as_ref())
            .await?;

        let file = self.inner.async_open_with(&path, options).await?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::AsyncServerFile::new_file(
                self.server.clone(),
                &path,
                file,
                0,
            )?;

            Ok(Box::new(file))
        } else {
            Ok(Box::new(file))
        }
    }

    fn set_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        permissions: PortablePermissions,
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(file_type, path.as_ref())?;

        self.inner.set_permissions(path, permissions)?;

        Ok(())
    }
    async fn async_set_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        permissions: PortablePermissions,
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.async_check_ignored(file_type, path.as_ref()).await?;

        self.inner.async_set_permissions(path, permissions).await?;

        Ok(())
    }

    fn set_times(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(file_type, path.as_ref())?;

        self.inner.set_times(path, modification_time, access_time)?;

        Ok(())
    }
    async fn async_set_times(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let path = self.async_check_ignored(file_type, path.as_ref()).await?;

        self.inner
            .async_set_times(path, modification_time, access_time)
            .await?;

        Ok(())
    }

    fn rename(
        &self,
        from: &(dyn AsRef<Path> + Send + Sync),
        to: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let from = self.check_ignored(file_type, from.as_ref())?;
        let to = self.check_ignored(file_type, to.as_ref())?;

        self.inner.rename(from, &self.inner, to)?;

        Ok(())
    }
    async fn async_rename(
        &self,
        from: &(dyn AsRef<Path> + Send + Sync),
        to: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
    ) -> Result<(), anyhow::Error> {
        self.check_writable()?;
        let from = self.async_check_ignored(file_type, from.as_ref()).await?;
        let to = self.async_check_ignored(file_type, to.as_ref()).await?;

        self.inner.async_rename(from, &self.inner, to).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::DirectorySortingMode::*,
        routes::{AppState, State},
        server::{
            Server,
            filesystem::{
                Filesystem, cap::CapFilesystem, usage::SpaceDelta,
                virtualfs::VirtualReadableFilesystem,
            },
        },
    };
    use std::time::Duration;

    const SORTS: [crate::models::DirectorySortingMode; 10] = [
        NameAsc,
        NameDesc,
        SizeAsc,
        SizeDesc,
        PhysicalSizeAsc,
        PhysicalSizeDesc,
        ModifiedAsc,
        ModifiedDesc,
        CreatedAsc,
        CreatedDesc,
    ];

    const EXTRA_FILES: [usize; 2] = [0, ListingWork::SMALL_LIMIT + 32];

    struct ListingFixture {
        state: State,
        server: Server,
        cap: CapFilesystem,
        fs: VirtualCapFilesystem,
        ignored: IsIgnoredFn,

        _temp: tempfile::TempDir,
    }

    impl ListingFixture {
        async fn new(extra_files: usize) -> Result<Self, anyhow::Error> {
            let temp = tempfile::tempdir()?;
            let state = AppState::mock();
            state
                .config
                .mutate_in_place_for_testing()
                .system
                .data_directory =
                crate::config::SystemPath::new(temp.path().to_string_lossy().into_owned());

            let server = Server::mock(uuid::Uuid::new_v4(), Arc::clone(&state));
            server.filesystem.disk_checker.abort();

            let root = &server.filesystem.base_path;
            std::fs::create_dir_all(root.join("cached"))?;
            std::fs::create_dir(root.join("uncached"))?;
            std::fs::create_dir(root.join("nested"))?;
            std::fs::write(root.join("nested/data.bin"), b"nested text")?;

            for (name, contents) in [
                ("a.txt", b"hello".as_slice()),
                ("b.bin", b"\x00\xff\x01".as_slice()),
                ("empty.txt", b"".as_slice()),
                ("z.txt", b"last file".as_slice()),
                ("denied.txt", b"hidden".as_slice()),
                ("request-denied.txt", b"hidden".as_slice()),
            ] {
                std::fs::write(root.join(name), contents)?;
            }

            #[cfg(unix)]
            for (name, target) in [
                ("file-link", "a.txt"),
                ("dir-link", "cached"),
                ("broken-link", "missing"),
                ("denied-link", "denied.txt"),
                ("nested/parent-link", "../a.txt"),
                ("nested/denied-link", "../denied.txt"),
            ] {
                std::os::unix::fs::symlink(target, root.join(name))?;
            }

            for i in 0..extra_files {
                std::fs::write(root.join(format!("extra-{i:03}.txt")), b"same size")?;
            }

            let cap = CapFilesystem::new(root).await?;
            server.filesystem.inner.store(Some(cap.get_inner()?));
            server
                .filesystem
                .disk_usage
                .write()
                .await
                .update_size(Path::new("cached"), SpaceDelta::new(123, 4096));
            server.filesystem.update_ignored(&["denied.txt"]).await;

            let mut fs = cap
                .get_virtual(server.clone())
                .with_is_ignored(Filesystem::deny_filter(&server));
            fs.is_primary_server_fs = true;

            let ignored: IsIgnoredFn =
                crate::server::filesystem::build_gitignore_matcher(["request-denied.txt"].iter())?
                    .into();

            Ok(Self {
                state,
                server,
                cap,
                fs,
                ignored,
                _temp: temp,
            })
        }

        async fn read_dir(
            &self,
            path: &str,
            per_page: Option<usize>,
            page: usize,
            sort: crate::models::DirectorySortingMode,
        ) -> Result<DirectoryListing, anyhow::Error> {
            self.fs
                .async_read_dir(&path, per_page, page, self.ignored.clone(), sort)
                .await
        }
    }

    /// One blocking worker on purpose: a listing stage that waits on a second one deadlocks here
    /// instead of quietly passing.
    fn with_one_blocking_worker<F, Fut>(test: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), anyhow::Error>>,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("creating listing test runtime failed");

        let result =
            runtime.block_on(async { tokio::time::timeout(Duration::from_secs(30), test()).await });

        runtime.shutdown_timeout(Duration::from_secs(1));
        result
            .expect("listing stalled with one blocking worker")
            .expect("listing test failed");
    }

    #[test]
    fn buffered_entries_match_async_lookup_without_runtime() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;

            for path in [
                "a.txt",
                "cached",
                "nested/data.bin",
                "denied.txt",
                "missing",
            ] {
                let filesystem = fixture.fs.clone();
                let sync = std::thread::spawn(move || {
                    assert!(tokio::runtime::Handle::try_current().is_err());
                    filesystem.directory_entry_buffer(&path, b"plain text")
                })
                .join()
                .expect("buffered entry worker panicked");
                let asynchronous = fixture
                    .fs
                    .async_directory_entry_buffer(&path, b"plain text")
                    .await;

                match (sync, asynchronous) {
                    (Ok(sync), Ok(asynchronous)) => {
                        assert_eq!(
                            serde_json::to_value(&sync)?,
                            serde_json::to_value(asynchronous)?
                        );
                        if path == "cached" {
                            assert_eq!((sync.size, sync.size_physical), (123, 4096));
                            assert_eq!(sync.mime, "inode/directory");
                        }
                    }
                    (Err(sync), Err(asynchronous)) => {
                        assert_eq!(sync.to_string(), asynchronous.to_string());
                    }
                    _ => panic!("sync and async buffered entries differ for {path}"),
                }
            }

            #[cfg(unix)]
            for path in ["file-link", "dir-link", "broken-link"] {
                let filesystem = fixture.fs.clone();
                let sync = std::thread::spawn(move || {
                    filesystem.directory_entry_buffer(&path, b"plain text")
                })
                .join()
                .expect("symlink entry worker panicked")?;
                let asynchronous = fixture
                    .fs
                    .async_directory_entry_buffer(&path, b"plain text")
                    .await?;
                assert!(sync.symlink);
                assert_eq!(
                    serde_json::to_value(sync)?,
                    serde_json::to_value(asynchronous)?
                );
            }

            Ok(())
        });
    }

    #[test]
    fn listing_applies_server_and_request_deny_filters() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    let listing = fixture.read_dir("", None, 1, sort).await?;
                    let names: Vec<_> = listing
                        .entries
                        .iter()
                        .map(|entry| entry.name.as_str())
                        .collect();

                    assert!(!names.contains(&"denied.txt"));
                    assert!(!names.contains(&"denied-link"));
                    assert!(!names.contains(&"request-denied.txt"));

                    assert!(names.contains(&"uncached"));
                    assert!(names.contains(&"a.txt"));

                    #[cfg(unix)]
                    for name in ["file-link", "dir-link", "broken-link"] {
                        assert!(names.contains(&name));
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn listing_entries_match_single_entry_lookups() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    fixture.state.mime_cache.invalidate_all();
                    let listing = fixture.read_dir("", None, 1, sort).await?;

                    assert_eq!(listing.total_entries, listing.entries.len());

                    fixture.state.mime_cache.invalidate_all();
                    for entry in &listing.entries {
                        let expected = fixture
                            .fs
                            .async_directory_entry(&entry.name.as_str())
                            .await?;

                        assert_eq!(
                            serde_json::to_value(entry)?,
                            serde_json::to_value(expected)?
                        );

                        if entry.name == "cached" {
                            assert_eq!((entry.size, entry.size_physical), (123, 4096));
                        }
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn warm_listing_matches_the_cold_listing() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    fixture.state.mime_cache.invalidate_all();
                    let cold = fixture.read_dir("", None, 1, sort).await?;
                    let warm = fixture.read_dir("", None, 1, sort).await?;

                    assert_eq!(
                        serde_json::to_value(warm.entries)?,
                        serde_json::to_value(cold.entries)?
                    );
                }
            }

            Ok(())
        });
    }

    #[test]
    fn paged_listing_concatenates_to_the_unpaged_listing() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;
                let per_page = if extra_files == 0 { 2 } else { 80 };

                for sort in SORTS {
                    let listing = fixture.read_dir("", None, 1, sort).await?;
                    let expected = serde_json::to_value(&listing.entries)?;

                    let mut paged = Vec::new();
                    for page in 1..=listing.total_entries.div_ceil(per_page) {
                        let result = fixture.read_dir("", Some(per_page), page, sort).await?;

                        assert_eq!(result.total_entries, listing.total_entries);
                        paged.extend(result.entries);
                    }

                    assert_eq!(serde_json::to_value(paged)?, expected);
                }
            }

            Ok(())
        });
    }

    #[test]
    fn nested_listing_hides_denied_links_and_stays_editable() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    fixture.state.mime_cache.invalidate_all();
                    let nested = fixture.read_dir("nested", None, 1, sort).await?;

                    assert!(
                        nested
                            .entries
                            .iter()
                            .all(|entry| entry.name != "denied-link")
                    );

                    for entry in &nested.entries {
                        let expected = fixture
                            .fs
                            .async_directory_entry(&Path::new("nested").join(&entry.name))
                            .await?;

                        assert_eq!(
                            serde_json::to_value(entry)?,
                            serde_json::to_value(expected)?
                        );
                        assert!(entry.editable);
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn listing_and_single_entry_share_one_blocking_worker() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            fixture.state.mime_cache.invalidate_all();

            let prepared = fixture
                .server
                .filesystem
                .prepare_api_entry_cap(
                    &fixture.cap,
                    PathBuf::from("nested/data.bin"),
                    fixture.cap.symlink_metadata("nested/data.bin")?,
                )
                .await;

            let (entry, listing) = tokio::try_join!(
                fixture.server.filesystem.finish_api_entry_cap(
                    &fixture.cap,
                    prepared,
                    DirectoryEntryOptions::server_fs(true),
                ),
                fixture.read_dir("nested", None, 1, NameAsc),
            )?;

            assert!(entry.editable);
            assert!(listing.entries.iter().any(|entry| entry.name == "data.bin"));

            Ok(())
        });
    }

    #[test]
    fn large_listing_keeps_filter_order_and_skips_vanished_entries() -> Result<(), anyhow::Error> {
        use std::sync::Mutex;

        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            for i in 0..100 {
                std::fs::write(temp.path().join(format!("file-{i:03}.txt")), b"same size")?;
            }

            let state = AppState::mock();
            let server = Server::mock(uuid::Uuid::new_v4(), Arc::clone(&state));
            server.filesystem.disk_checker.abort();

            let cap = CapFilesystem::new(temp.path()).await?;
            let mut enumeration = Vec::new();
            let mut directory = cap.read_dir("")?;

            while let Some(entry) = directory.next() {
                enumeration.push(PathBuf::from(entry?.file_name()));
            }

            let calls = Arc::new(Mutex::new(Vec::new()));
            let filter = IsIgnoredFn::from({
                let calls = Arc::clone(&calls);
                let root = temp.path().to_path_buf();

                move |_, path: PathBuf| {
                    let mut calls = calls.lock().unwrap();
                    calls.push(path.clone());

                    if calls.len() == 100 {
                        std::fs::remove_file(root.join("file-050.txt")).unwrap();
                    }

                    Some(path)
                }
            });

            let fs = cap.get_virtual(server).with_is_ignored(filter);
            let listing = fs
                .async_read_dir(&"", None, 1, Default::default(), NameDesc)
                .await?;
            let expected: Vec<_> = (0..100)
                .rev()
                .filter(|i| *i != 50)
                .map(|i| PathBuf::from(format!("file-{i:03}.txt")))
                .collect();

            assert_eq!(listing.total_entries, 100);
            assert_eq!(listing.entries.len(), 99);
            assert_eq!(
                listing
                    .entries
                    .iter()
                    .map(|entry| PathBuf::from(entry.name.as_str()))
                    .collect::<Vec<_>>(),
                expected
            );

            let calls = calls.lock().unwrap();
            assert_eq!(
                calls.iter().take(100).cloned().collect::<Vec<_>>(),
                enumeration
            );
            assert_eq!(
                calls.iter().skip(100).cloned().collect::<Vec<_>>(),
                expected
            );

            Ok(())
        })
    }

    #[cfg(unix)]
    #[test]
    fn retained_directory_entry_and_rewritten_path_open_the_right_file() -> Result<(), anyhow::Error>
    {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            std::fs::create_dir(temp.path().join("nested"))?;
            std::fs::write(temp.path().join("nested/data.bin"), b"retained text")?;
            std::fs::write(temp.path().join("other.bin"), b"\x89PNG\r\n\x1a\n")?;

            let state = AppState::mock();
            let server = Server::mock(uuid::Uuid::new_v4(), Arc::clone(&state));
            server.filesystem.disk_checker.abort();

            let cap = CapFilesystem::new(temp.path()).await?;
            let fs = cap.get_virtual(server);
            let mut directory = cap.read_dir("nested")?;
            let entry = directory
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing entry"))??;

            std::fs::rename(temp.path().join("nested"), temp.path().join("moved"))?;

            let prepared = fs.prepare_directory_entry(PathBuf::from("nested/data.bin"), entry)?;
            assert!(prepared.directory_entry.is_some());

            let entry = fs
                .server
                .filesystem
                .finish_api_entry_cap(&cap, prepared, Default::default())
                .await?;

            assert_eq!(entry.mime, "application/octet-stream");
            assert!(entry.editable);

            state.mime_cache.invalidate_all();
            let fs = fs.with_is_ignored(IsIgnoredFn::new(
                |_, _| Some(PathBuf::from("other.bin")),
                |_, _| async { Some(PathBuf::from("other.bin")) },
            ));
            let mut directory = cap.read_dir("moved")?;
            let entry = directory
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing entry"))??;

            let prepared = fs.prepare_directory_entry(PathBuf::from("moved/data.bin"), entry)?;
            assert!(prepared.directory_entry.is_none());

            let entry = fs
                .server
                .filesystem
                .finish_api_entry_cap(&cap, prepared, Default::default())
                .await?;

            assert_eq!(entry.name, "other.bin");
            assert_eq!(entry.mime, "image/png");

            Ok(())
        })
    }
}
