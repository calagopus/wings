use super::{
    AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, AsyncReadableFileStream,
    AsyncWritableSeekableFileStream, ByteRange, DirectoryListing, FileMetadata, FileRead, FileType,
    IsIgnoredFn, WritableSeekableFileStream,
};
use crate::{
    io::compression::CompressionLevel,
    models::DirectoryEntry,
    server::filesystem::{
        DirectoryEntryOptions,
        archive::StreamableArchiveFormat,
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

    async fn async_prepare_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<crate::server::filesystem::PreparedDirectoryEntry, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;
        let path = self
            .async_check_ignored(metadata.file_type().into(), path.as_ref())
            .await?;

        Ok(self
            .server
            .filesystem
            .prepare_api_entry_cap(&self.inner, path, metadata)
            .await)
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

        Ok(self
            .server
            .filesystem
            .to_api_entry_cap(
                &self.inner,
                path,
                metadata,
                DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            )
            .await)
    }

    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;

        let path = self
            .async_check_ignored(metadata.file_type().into(), path.as_ref())
            .await?;

        Ok(self
            .server
            .filesystem
            .to_api_entry_buffer(
                path,
                &metadata,
                DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
                Some(buffer),
                None,
                None,
            )
            .await)
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
        let this = self.clone();
        let runtime = tokio::runtime::Handle::current();

        tokio::task::spawn_blocking(move || {
            use crate::models::DirectorySortingMode::*;

            let mut directory_entries = Vec::new();
            let mut other_entries = Vec::new();
            let mut scratch = PathBuf::new();

            let mut dir = this.inner.read_dir(&path)?;
            while let Some(item) = dir.next_entry() {
                let Ok((file_type, entry)) = item else { break };

                scratch.clear();
                scratch.push(&path);
                scratch.push(&entry);

                match is_ignored(file_type, std::mem::take(&mut scratch)) {
                    Some(kept) => scratch = kept,
                    None => continue,
                }

                if file_type.is_dir() {
                    directory_entries.push(entry);
                } else {
                    other_entries.push(entry);
                }
            }

            let total_entries = directory_entries.len() + other_entries.len();

            if matches!(sort, NameAsc | NameDesc) {
                let descending = matches!(sort, NameDesc);
                let cmp = |a: &String, b: &String| {
                    let ordering = a.cmp_ascii_case_insensitive(b).then_with(|| a.cmp(b));

                    if descending {
                        ordering.reverse()
                    } else {
                        ordering
                    }
                };

                let start = per_page.map_or(0, |per_page| {
                    page.saturating_sub(1).saturating_mul(per_page)
                });
                let end = per_page.map_or(usize::MAX, |per_page| start.saturating_add(per_page));

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

                let mut entries = Vec::new();
                for entry in directory_window
                    .into_iter()
                    .flat_map(|window| directory_entries.get(window).unwrap_or_default())
                    .chain(
                        other_window
                            .into_iter()
                            .flat_map(|window| other_entries.get(window).unwrap_or_default()),
                    )
                {
                    if let Ok(entry) =
                        runtime.block_on(this.async_directory_entry(&path.join(entry)))
                    {
                        entries.push(entry);
                    }
                }

                Ok(DirectoryListing {
                    total_entries,
                    entries,
                })
            } else {
                let options = DirectoryEntryOptions::server_fs(this.is_primary_server_fs);

                let prepare_group = |names: Vec<String>| {
                    let mut out = Vec::with_capacity(names.len());
                    for entry in names {
                        let Ok(prepared) = runtime
                            .block_on(this.async_prepare_directory_entry(&path.join(&entry)))
                        else {
                            continue;
                        };

                        let key: i128 = match sort {
                            SizeAsc | SizeDesc => runtime
                                .block_on(
                                    this.server
                                        .filesystem
                                        .prepared_entry_sort_size(&prepared, options),
                                )
                                .0
                                .into(),
                            PhysicalSizeAsc | PhysicalSizeDesc => runtime
                                .block_on(
                                    this.server
                                        .filesystem
                                        .prepared_entry_sort_size(&prepared, options),
                                )
                                .1
                                .into(),
                            ModifiedAsc | ModifiedDesc => prepared.modified_secs().into(),
                            CreatedAsc | CreatedDesc => prepared.created_secs().into(),
                            NameAsc | NameDesc => 0,
                        };

                        out.push((key, prepared));
                    }
                    out
                };

                let mut dir_keyed = prepare_group(directory_entries);
                let mut file_keyed = prepare_group(other_entries);

                let ascending =
                    matches!(sort, SizeAsc | PhysicalSizeAsc | ModifiedAsc | CreatedAsc);
                let cmp = |a: &(i128, _), b: &(i128, _)| {
                    if ascending {
                        a.0.cmp(&b.0)
                    } else {
                        b.0.cmp(&a.0)
                    }
                };
                dir_keyed.sort_by(cmp);
                file_keyed.sort_by(cmp);

                let merged = dir_keyed.into_iter().chain(file_keyed).map(|(_, p)| p);
                let paged: Vec<_> = if let Some(per_page) = per_page {
                    let start = page.saturating_sub(1).saturating_mul(per_page);
                    merged.skip(start).take(per_page).collect()
                } else {
                    merged.collect()
                };

                let mut entries = Vec::with_capacity(paged.len());
                for prepared in paged {
                    entries.push(
                        runtime.block_on(this.server.filesystem.finish_api_entry_cap(
                            &this.inner,
                            prepared,
                            options,
                        )),
                    );
                }

                Ok(DirectoryListing {
                    total_entries,
                    entries,
                })
            }
        })
        .await?
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
                self.inner
                    .next_entry()
                    .map(|res| res.map_err(|err| err.into()))
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
                self.inner
                    .next_entry()
                    .await
                    .map(|res| res.map_err(|err| err.into()))
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
                    Ok((file_type, path)) => (file_type, path),
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
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error> {
        let names = self.inner.async_read_dir_all(path).await?;
        let file_compression_threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
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
                let writer = tokio_util::io::SyncIoBridge::new(writer);

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
