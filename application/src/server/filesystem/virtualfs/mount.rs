use super::{
    AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, ByteRange, DirectoryListing,
    FileMetadata, FileRead, IsIgnoredFn, VirtualReadableFilesystem, cap::VirtualCapFilesystem,
};
use crate::{
    io::compression::CompressionLevel,
    models::{DirectoryEntry, DirectorySortingMode},
    routes::MimeCacheValue,
    server::filesystem::{
        archive::StreamableArchiveFormat, cap::FileType, encode_mode, virtualfs::DirectoryWalk,
    },
    utils::{CmpExt, PortablePermissions},
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

pub struct MountInfo {
    pub relative_target: PathBuf,
}

pub struct VirtualMountFilesystem {
    pub inner: VirtualCapFilesystem,
    pub mounts: Vec<MountInfo>,
}

impl VirtualMountFilesystem {
    fn is_virtual_dir(&self, path: &Path) -> bool {
        self.is_gateway(path) && !self.inner.is_denied(FileType::Dir, path)
    }

    async fn async_is_virtual_dir(&self, path: &Path) -> bool {
        self.is_gateway(path) && !self.inner.async_is_denied(FileType::Dir, path).await
    }

    fn is_gateway(&self, path: &Path) -> bool {
        path != Path::new("")
            && self
                .mounts
                .iter()
                .any(|m| m.relative_target.starts_with(path))
    }

    fn virtual_dir_entry(path: &Path) -> DirectoryEntry {
        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(0o755),
            mode_bits: compact_str::format_compact!("{:o}", 0o755),
            size: 0,
            size_physical: 0,
            editable: false,
            inner_editable: false,
            directory: true,
            file: false,
            symlink: true,
            r#virtual: true,
            mime: MimeCacheValue::directory().mime,
            modified: Default::default(),
            created: Default::default(),
        }
    }

    fn virtual_dir_metadata() -> FileMetadata {
        FileMetadata {
            file_type: FileType::Dir,
            permissions: PortablePermissions::from_mode_dir(0o40755),
            size: 0,
            modified: None,
            created: None,
        }
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualMountFilesystem {
    fn is_primary_server_fs(&self) -> bool {
        self.inner.is_primary_server_fs
    }
    fn is_fast(&self) -> bool {
        true
    }
    fn is_writable(&self) -> bool {
        self.inner.is_writable
    }

    fn backing_server(&self) -> &crate::server::Server {
        &self.inner.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        match self.inner.metadata(path) {
            Ok(m) => Ok(m),
            Err(_) if self.is_virtual_dir(path.as_ref()) => Ok(Self::virtual_dir_metadata()),
            Err(err) => Err(err),
        }
    }

    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        match self.inner.async_metadata(path).await {
            Ok(m) => Ok(m),
            Err(err) => {
                if self.async_is_virtual_dir(path.as_ref()).await {
                    Ok(Self::virtual_dir_metadata())
                } else {
                    Err(err)
                }
            }
        }
    }

    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        match self.inner.symlink_metadata(path) {
            Ok(m) => Ok(m),
            Err(_) if self.is_virtual_dir(path.as_ref()) => Ok(Self::virtual_dir_metadata()),
            Err(err) => Err(err),
        }
    }

    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        match self.inner.async_symlink_metadata(path).await {
            Ok(m) => Ok(m),
            Err(err) => {
                if self.async_is_virtual_dir(path.as_ref()).await {
                    Ok(Self::virtual_dir_metadata())
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        match self.inner.async_directory_entry(path).await {
            Ok(e) => Ok(e),
            Err(err) => {
                if self.async_is_virtual_dir(path.as_ref()).await {
                    Ok(Self::virtual_dir_entry(path.as_ref()))
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        match self.inner.async_directory_entry_buffer(path, buffer).await {
            Ok(e) => Ok(e),
            Err(err) => {
                if self.async_is_virtual_dir(path.as_ref()).await {
                    Ok(Self::virtual_dir_entry(path.as_ref()))
                } else {
                    Err(err)
                }
            }
        }
    }

    fn directory_entry_from_metadata(
        &self,
        path: &Path,
        metadata: &cap_std::fs::Metadata,
        buffer: Option<&[u8]>,
    ) -> Option<DirectoryEntry> {
        self.inner
            .directory_entry_from_metadata(path, metadata, buffer)
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        let listing_path = path.as_ref();

        let projects_virtual_dir = self.mounts.iter().any(|mount| {
            let remaining = if listing_path == Path::new("") {
                Some(mount.relative_target.as_path())
            } else if mount.relative_target.starts_with(listing_path) {
                mount.relative_target.strip_prefix(listing_path).ok()
            } else {
                None
            };

            remaining.is_some_and(|remaining| remaining.components().next().is_some())
        });

        if !projects_virtual_dir {
            return self
                .inner
                .async_read_dir(path, per_page, page, is_ignored, sort)
                .await;
        }

        let inner_listing = match self
            .inner
            .async_read_dir(path, None, 1, is_ignored.clone(), sort)
            .await
        {
            Ok(l) => l.entries,
            Err(_) => vec![],
        };

        let existing_names: HashSet<&str> = inner_listing.iter().map(|e| e.name.as_str()).collect();

        let gateway_names: HashSet<String> = self
            .mounts
            .iter()
            .filter_map(|mount| {
                let remaining = if listing_path == Path::new("") {
                    Some(mount.relative_target.as_path())
                } else if mount.relative_target.starts_with(listing_path) {
                    mount.relative_target.strip_prefix(listing_path).ok()
                } else {
                    None
                };

                remaining
                    .and_then(|remaining| remaining.components().next())
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
            })
            .collect();

        let mut virtual_dirs = Vec::new();
        let mut seen_virtual = HashSet::new();

        for mount in &self.mounts {
            let remaining = if listing_path == Path::new("") {
                Some(mount.relative_target.as_path())
            } else if mount.relative_target.starts_with(listing_path) {
                mount.relative_target.strip_prefix(listing_path).ok()
            } else {
                None
            };

            let Some(remaining) = remaining else {
                continue;
            };

            let next_comp = match remaining.components().next() {
                Some(c) => c.as_os_str().to_string_lossy().into_owned(),
                None => continue,
            };

            if existing_names.contains(next_comp.as_str())
                || !seen_virtual.insert(next_comp.clone())
            {
                continue;
            }

            let virtual_path = if listing_path == Path::new("") {
                PathBuf::from(&next_comp)
            } else {
                listing_path.join(&next_comp)
            };

            if let Some(virtual_path) = is_ignored.call_async(FileType::Dir, virtual_path).await
                && !self
                    .inner
                    .async_is_denied(FileType::Dir, &virtual_path)
                    .await
            {
                virtual_dirs.push(Self::virtual_dir_entry(&virtual_path));
            }
        }

        let (mut inner_dirs, inner_non_dirs): (Vec<_>, Vec<_>) =
            inner_listing.into_iter().partition(|e| e.directory);

        for entry in &mut inner_dirs {
            if gateway_names.contains(entry.name.as_str()) {
                entry.r#virtual = true;
            }
        }

        virtual_dirs.sort_unstable_by(|a, b| a.name.cmp_ascii_case_insensitive(&b.name));
        if matches!(sort, DirectorySortingMode::NameDesc) {
            virtual_dirs.reverse();
        }

        inner_dirs.splice(0..0, virtual_dirs);

        let total_entries = inner_dirs.len() + inner_non_dirs.len();

        let all_entries: Vec<DirectoryEntry> =
            inner_dirs.into_iter().chain(inner_non_dirs).collect();

        if let Some(per_page) = per_page {
            let start = page.saturating_sub(1).saturating_mul(per_page);
            Ok(DirectoryListing {
                total_entries,
                entries: all_entries.into_iter().skip(start).take(per_page).collect(),
            })
        } else {
            Ok(DirectoryListing {
                total_entries,
                entries: all_entries,
            })
        }
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        self.inner.walk_dir(path, is_ignored)
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        self.inner.async_walk_dir(path, is_ignored).await
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        self.inner.async_walk_dir_stream(path, is_ignored).await
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        self.inner.read_file(path, range)
    }

    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        self.inner.async_read_file(path, range).await
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.inner.read_symlink(path)
    }

    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.inner.async_read_symlink(path).await
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error> {
        self.inner
            .async_read_dir_archive(
                path,
                archive_format,
                compression_level,
                progress,
                is_ignored,
            )
            .await
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        self.inner.close().await
    }
}
