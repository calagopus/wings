use crate::{
    io::{
        SafeSliceExt, UninterruptedReadExt,
        compression::{CompressionLevel, writer::CompressionWriter},
    },
    models::DirectoryEntry,
    routes::MimeCacheValue,
    server::filesystem::{
        archive::{
            StreamableArchiveFormat, multi_reader::MultiReader, zip_entry_get_modified_time,
        },
        cap::FileType,
        encode_mode,
        usage::SpaceDelta,
        virtualfs::{
            AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, AsyncReadableFileStream,
            ByteRange, DirectoryListing, DirectoryWalk, FileMetadata, FileRead, IsIgnoredFn,
            VirtualReadableFilesystem,
        },
    },
    utils::{CmpExt, PortablePermissions},
};
use compact_str::ToCompactString;
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use std::{
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub trait BetterZipArchiveExt<R: Read + Seek> {
    fn better_by_path(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<zip::read::ZipFile<'_, R>, zip::result::ZipError>;
    fn better_index_for_path(&self, path: impl AsRef<Path>) -> Option<usize>;
}

impl<R: Read + Seek + Clone> BetterZipArchiveExt<R> for zip::ZipArchive<R> {
    fn better_by_path(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<zip::read::ZipFile<'_, R>, zip::result::ZipError> {
        match self.index_for_path(path.as_ref()) {
            Some(index) => self.by_index(index),
            None => self.by_name(&format!("{}/", path.as_ref().display())),
        }
    }

    fn better_index_for_path(&self, path: impl AsRef<Path>) -> Option<usize> {
        match self.index_for_path(path.as_ref()) {
            Some(index) => Some(index),
            None => self.index_for_name(&format!("{}/", path.as_ref().display())),
        }
    }
}

pub struct SortableZipEntry {
    pub name: PathBuf,
    pub size: u64,
    pub size_compressed: u64,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub created: chrono::DateTime<chrono::Utc>,
}

impl SortableZipEntry {
    pub fn new(
        name: PathBuf,
        entry: &zip::read::ZipFile<'_, impl Read + Seek>,
        archive_created: &chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            name,
            size: entry.size(),
            size_compressed: entry.compressed_size(),
            modified: crate::server::filesystem::archive::zip_entry_get_modified_time(entry)
                .map(|dt| dt.into())
                .unwrap_or_default(),
            created: crate::server::filesystem::archive::zip_entry_get_created_time(entry)
                .map(|dt| dt.into())
                .unwrap_or_else(|| *archive_created),
        }
    }

    pub fn cmp_sort(
        &self,
        other: &Self,
        sort: crate::models::DirectorySortingMode,
    ) -> std::cmp::Ordering {
        use crate::models::DirectorySortingMode::*;

        match sort {
            NameAsc => self.name.cmp_ascii_case_insensitive(&other.name),
            NameDesc => other.name.cmp_ascii_case_insensitive(&self.name),
            SizeAsc => self.size.cmp(&other.size),
            SizeDesc => other.size.cmp(&self.size),
            PhysicalSizeAsc => self.size_compressed.cmp(&other.size_compressed),
            PhysicalSizeDesc => other.size_compressed.cmp(&self.size_compressed),
            ModifiedAsc => self.modified.cmp(&other.modified),
            ModifiedDesc => other.modified.cmp(&self.modified),
            CreatedAsc => self.created.cmp(&other.created),
            CreatedDesc => other.created.cmp(&self.created),
        }
    }
}

#[derive(Clone)]
pub struct VirtualZipArchive {
    pub server: crate::server::Server,
    pub archive: zip::ZipArchive<MultiReader>,
    pub archive_created: chrono::DateTime<chrono::Utc>,
    pub mime_cache: moka::sync::Cache<usize, MimeCacheValue>,
    pub sizes: Arc<crate::server::filesystem::usage::DiskUsage>,
}

impl VirtualZipArchive {
    pub fn new(
        server: crate::server::Server,
        mut archive: zip::ZipArchive<MultiReader>,
        archive_created: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let mut sizes = crate::server::filesystem::usage::DiskUsage::default();

        for i in 0..archive.len() {
            let Ok(entry) = archive.by_index(i) else {
                continue;
            };
            let Some(name) = entry.enclosed_name() else {
                continue;
            };

            if entry.is_dir() {
                let delta = SpaceDelta::new(entry.size() as i64, entry.compressed_size() as i64);
                sizes.update_size(&name, delta);
            } else {
                let parent = name.parent().unwrap_or(Path::new(""));
                let delta = SpaceDelta::new(entry.size() as i64, entry.compressed_size() as i64);
                sizes.update_size(parent, delta);
            }
        }

        Self {
            server,
            archive,
            archive_created,
            mime_cache: moka::sync::Cache::new(10240),
            sizes: Arc::new(sizes),
        }
    }

    pub async fn open(
        server: crate::server::Server,
        archive_path: &Path,
    ) -> Result<Self, anyhow::Error> {
        let file = server
            .filesystem
            .async_open(archive_path)
            .await?
            .into_std()
            .await;
        let reader = MultiReader::new(Arc::new(file))?;

        let archive = tokio::task::spawn_blocking(
            move || -> Result<zip::ZipArchive<MultiReader>, anyhow::Error> {
                let archive = zip::ZipArchive::new(reader)?;
                Ok(archive)
            },
        )
        .await??;

        let metadata = server.filesystem.async_metadata(archive_path).await?;

        Ok(Self::new(
            server,
            archive,
            metadata
                .created()
                .map_or_else(|_| Default::default(), |dt| dt.into_std().into()),
        ))
    }

    fn is_virtual_directory(
        sizes: &crate::server::filesystem::usage::DiskUsage,
        path: &Path,
    ) -> bool {
        sizes.get_path(path).is_some()
    }

    fn virtual_directory_entry(
        archive_created: &chrono::DateTime<chrono::Utc>,
        path: &Path,
        sizes: &crate::server::filesystem::usage::DiskUsage,
    ) -> DirectoryEntry {
        let space = sizes.get_size(path).unwrap_or_default();

        let detected_mime = MimeCacheValue::directory();
        let mode: u32 = 0o755;

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(mode),
            mode_bits: compact_str::format_compact!("{:o}", mode & 0o777),
            size: space.get_logical(),
            size_physical: space.get_physical(),
            editable: false,
            inner_editable: false,
            directory: true,
            file: false,
            symlink: false,
            r#virtual: true,
            mime: detected_mime.mime,
            modified: Default::default(),
            created: *archive_created,
        }
    }

    fn zip_entry_to_directory_entry(
        archive_created: &chrono::DateTime<chrono::Utc>,
        path: &Path,
        entry_index: usize,
        mime_cache: &moka::sync::Cache<usize, MimeCacheValue>,
        sizes: &crate::server::filesystem::usage::DiskUsage,
        buffer: Option<&[u8]>,
        mut entry: zip::read::ZipFile<impl Read + Seek>,
    ) -> DirectoryEntry {
        let (size, size_physical) = if entry.is_dir() {
            let space = sizes.get_size(path).unwrap_or_default();
            (space.get_logical(), space.get_physical())
        } else {
            (entry.size(), entry.compressed_size())
        };

        let detected_mime = if entry.is_dir() {
            MimeCacheValue::directory()
        } else if entry.is_symlink() {
            MimeCacheValue::symlink()
        } else if let Some(detected_mime) = mime_cache.get(&entry_index) {
            detected_mime
        } else if let Some(buffer) = buffer {
            let detected_mime = crate::utils::detect_mime_type(path, Some(buffer));

            mime_cache.insert(entry_index, detected_mime);
            detected_mime
        } else if entry.size() == 0 {
            MimeCacheValue::text()
        } else {
            let mut buffer = [0; 64];
            let buffer = if entry.read_uninterrupted(&mut buffer).is_err() {
                None
            } else {
                Some(&buffer[..])
            };

            let detected_mime = crate::utils::detect_mime_type(path, buffer);

            mime_cache.insert(entry_index, detected_mime);
            detected_mime
        };

        let mode = entry
            .unix_mode()
            .unwrap_or(if entry.is_dir() { 0o755 } else { 0o644 });

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(mode),
            mode_bits: compact_str::format_compact!("{:o}", mode & 0o777),
            size,
            size_physical,
            editable: entry.is_file() && detected_mime.valid_utf8,
            inner_editable: entry.is_file() && detected_mime.valid_inner_utf8,
            directory: entry.is_dir(),
            file: entry.is_file(),
            symlink: entry.is_symlink(),
            r#virtual: true,
            mime: detected_mime.mime,
            modified: crate::server::filesystem::archive::zip_entry_get_modified_time(&entry)
                .map(|dt| dt.into())
                .unwrap_or_default(),
            created: crate::server::filesystem::archive::zip_entry_get_created_time(&entry)
                .map(|dt| dt.into())
                .unwrap_or_else(|| *archive_created),
        }
    }

    fn zip_entry_to_file_type(entry: &zip::read::ZipFile<impl Read + Seek>) -> FileType {
        match () {
            _ if entry.is_dir() => FileType::Dir,
            _ if entry.is_file() => FileType::File,
            _ if entry.is_symlink() => FileType::Symlink,
            _ => FileType::Unknown,
        }
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualZipArchive {
    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let path_ref = path.as_ref();

        if path_ref == Path::new("") || path_ref == Path::new("/") {
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(0o755),
                size: 0,
                modified: None,
                created: None,
            });
        }

        let mut archive = self.archive.clone();

        match archive.better_by_path(path_ref) {
            Ok(entry) => Ok(FileMetadata {
                file_type: Self::zip_entry_to_file_type(&entry),
                permissions: if let Some(mode) = entry.unix_mode() {
                    if entry.is_dir() {
                        PortablePermissions::from_mode_dir(mode)
                    } else {
                        PortablePermissions::from_mode_file(mode)
                    }
                } else if entry.is_dir() {
                    PortablePermissions::from_mode_dir(0o755)
                } else {
                    PortablePermissions::from_mode_file(0o644)
                },
                size: entry.size(),
                modified: crate::server::filesystem::archive::zip_entry_get_modified_time(&entry),
                created: crate::server::filesystem::archive::zip_entry_get_created_time(&entry),
            }),
            Err(e) => {
                if Self::is_virtual_directory(&self.sizes, path_ref) {
                    Ok(FileMetadata {
                        file_type: FileType::Dir,
                        permissions: PortablePermissions::from_mode_dir(0o755),
                        size: 0,
                        modified: None,
                        created: None,
                    })
                } else {
                    Err(e.into())
                }
            }
        }
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.metadata(path)
    }

    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.metadata(path)
    }
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.metadata(path)
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let mut archive = self.archive.clone();
        let archive_created = self.archive_created;
        let mime_cache = self.mime_cache.clone();
        let sizes = self.sizes.clone();
        let path = path.as_ref().to_path_buf();

        let entry =
            tokio::task::spawn_blocking(move || -> Result<DirectoryEntry, anyhow::Error> {
                match archive.better_index_for_path(&path) {
                    Some(entry_index) => {
                        let entry = archive.by_index(entry_index)?;
                        Ok(Self::zip_entry_to_directory_entry(
                            &archive_created,
                            &path,
                            entry_index,
                            &mime_cache,
                            &sizes,
                            None,
                            entry,
                        ))
                    }
                    None if Self::is_virtual_directory(&sizes, &path) => Ok(
                        Self::virtual_directory_entry(&archive_created, &path, &sizes),
                    ),
                    None => Err(zip::result::ZipError::FileNotFound.into()),
                }
            })
            .await??;

        Ok(entry)
    }

    fn directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let mut archive = self.archive.clone();
        let path = path.as_ref();

        match archive.better_index_for_path(path) {
            Some(entry_index) => {
                let entry = archive.by_index(entry_index)?;
                Ok(Self::zip_entry_to_directory_entry(
                    &self.archive_created,
                    path,
                    entry_index,
                    &self.mime_cache,
                    &self.sizes,
                    Some(buffer),
                    entry,
                ))
            }
            None if Self::is_virtual_directory(&self.sizes, path) => Ok(
                Self::virtual_directory_entry(&self.archive_created, path, &self.sizes),
            ),
            None => Err(zip::result::ZipError::FileNotFound.into()),
        }
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

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        let mut archive = self.archive.clone();
        let archive_created = self.archive_created;
        let mime_cache = self.mime_cache.clone();
        let sizes = self.sizes.clone();
        let path = path.as_ref().to_path_buf();

        let entries =
            tokio::task::spawn_blocking(move || -> Result<DirectoryListing, anyhow::Error> {
                let mut directory_entries: Vec<(Option<usize>, SortableZipEntry)> = Vec::new();
                let mut other_entries: Vec<(usize, SortableZipEntry)> = Vec::new();

                if let Some(node) = sizes.get_path(&path) {
                    for (child_name, child_node) in node.get_entries() {
                        let child_path = path.join(child_name.as_str());
                        let zip_index = archive.better_index_for_path(&child_path);

                        let (modified, created) = if let Some(idx) = zip_index {
                            let entry = archive.by_index(idx)?;
                            let m =
                                crate::server::filesystem::archive::zip_entry_get_modified_time(
                                    &entry,
                                )
                                .map(|dt| dt.into())
                                .unwrap_or_default();
                            let c = crate::server::filesystem::archive::zip_entry_get_created_time(
                                &entry,
                            )
                            .map(|dt| dt.into())
                            .unwrap_or(archive_created);
                            (m, c)
                        } else {
                            (archive_created, archive_created)
                        };

                        let Some(filtered_name) = (is_ignored)(FileType::Dir, child_path) else {
                            continue;
                        };

                        directory_entries.push((
                            zip_index,
                            SortableZipEntry {
                                name: filtered_name,
                                size: child_node.space.get_logical(),
                                size_compressed: child_node.space.get_physical(),
                                modified,
                                created,
                            },
                        ));
                    }
                }

                let path_len = path.components().count();
                for i in 0..archive.len() {
                    let entry = archive.by_index(i)?;
                    if entry.is_dir() {
                        continue;
                    }
                    let name = match entry.enclosed_name() {
                        Some(name) => name,
                        None => continue,
                    };

                    if !name.starts_with(&path) || name == path {
                        continue;
                    }
                    if name.components().count() != path_len + 1 {
                        continue;
                    }

                    let file_type = Self::zip_entry_to_file_type(&entry);
                    let Some(filtered_name) = (is_ignored)(file_type, name) else {
                        continue;
                    };

                    other_entries.push((
                        i,
                        SortableZipEntry::new(filtered_name, &entry, &archive_created),
                    ));
                }

                directory_entries.sort_unstable_by(|a, b| a.1.cmp_sort(&b.1, sort));
                other_entries.sort_unstable_by(|a, b| a.1.cmp_sort(&b.1, sort));

                let total_entries = directory_entries.len() + other_entries.len();
                let mut entries = Vec::new();

                let merged = directory_entries
                    .into_iter()
                    .chain(other_entries.into_iter().map(|(i, s)| (Some(i), s)));

                if let Some(per_page) = per_page {
                    let start = (page - 1) * per_page;

                    for (zip_index, sortable) in merged.skip(start).take(per_page) {
                        match zip_index {
                            Some(idx) => {
                                let entry = archive.by_index(idx)?;
                                let entry_path = match entry.enclosed_name() {
                                    Some(name) => name,
                                    None => continue,
                                };
                                entries.push(Self::zip_entry_to_directory_entry(
                                    &archive_created,
                                    &entry_path,
                                    idx,
                                    &mime_cache,
                                    &sizes,
                                    None,
                                    entry,
                                ));
                            }
                            None => {
                                entries.push(Self::virtual_directory_entry(
                                    &archive_created,
                                    &sortable.name,
                                    &sizes,
                                ));
                            }
                        }
                    }
                } else {
                    for (zip_index, sortable) in merged {
                        match zip_index {
                            Some(idx) => {
                                let entry = archive.by_index(idx)?;
                                let entry_path = match entry.enclosed_name() {
                                    Some(name) => name,
                                    None => continue,
                                };
                                entries.push(Self::zip_entry_to_directory_entry(
                                    &archive_created,
                                    &entry_path,
                                    idx,
                                    &mime_cache,
                                    &sizes,
                                    None,
                                    entry,
                                ));
                            }
                            None => {
                                entries.push(Self::virtual_directory_entry(
                                    &archive_created,
                                    &sortable.name,
                                    &sizes,
                                ));
                            }
                        }
                    }
                }

                Ok(DirectoryListing {
                    total_entries,
                    entries,
                })
            })
            .await??;

        Ok(entries)
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        struct IgnoreWalkDir {
            path: PathBuf,
            archive: zip::ZipArchive<MultiReader>,
            current_index: usize,
            is_ignored: IsIgnoredFn,
        }

        impl DirectoryWalk for IgnoreWalkDir {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                while self.current_index < self.archive.len() {
                    let entry = self.archive.by_index(self.current_index).ok()?;
                    self.current_index += 1;

                    let name = match entry.enclosed_name() {
                        Some(name) => name.to_path_buf(),
                        None => continue,
                    };

                    if !name.starts_with(&self.path) || name == self.path {
                        continue;
                    }

                    let file_type = VirtualZipArchive::zip_entry_to_file_type(&entry);

                    if let Some(name) = (self.is_ignored)(file_type, name.to_path_buf()) {
                        return Some(Ok((file_type, name)));
                    }
                }
                None
            }
        }

        Ok(Box::new(IgnoreWalkDir {
            path: path.as_ref().to_path_buf(),
            archive: self.archive.clone(),
            current_index: 0,
            is_ignored,
        }))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        struct IgnoreAsyncWalkDir {
            path: PathBuf,
            archive: zip::ZipArchive<MultiReader>,
            current_index: usize,
            is_ignored: IsIgnoredFn,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryWalk for IgnoreAsyncWalkDir {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                while self.current_index < self.archive.len() {
                    let entry = self.archive.by_index(self.current_index).ok()?;
                    self.current_index += 1;

                    let name = match entry.enclosed_name() {
                        Some(name) => name.to_path_buf(),
                        None => continue,
                    };

                    if !name.starts_with(&self.path) || name == self.path {
                        continue;
                    }

                    let file_type = VirtualZipArchive::zip_entry_to_file_type(&entry);

                    if let Some(name) = self
                        .is_ignored
                        .call_async(file_type, name.to_path_buf())
                        .await
                    {
                        return Some(Ok((file_type, name)));
                    }
                }
                None
            }
        }

        Ok(Box::new(IgnoreAsyncWalkDir {
            path: path.as_ref().to_path_buf(),
            archive: self.archive.clone(),
            current_index: 0,
            is_ignored,
        }))
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        struct IgnoreAsyncWalkDir {
            path: PathBuf,
            archive: zip::ZipArchive<MultiReader>,
            current_index: usize,
            is_ignored: IsIgnoredFn,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryStreamWalk for IgnoreAsyncWalkDir {
            async fn next_entry(
                &mut self,
            ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>
            {
                while self.current_index < self.archive.len() {
                    let entry = self.archive.by_index(self.current_index).ok()?;
                    let i = self.current_index;
                    self.current_index += 1;

                    let name = match entry.enclosed_name() {
                        Some(name) => name.to_path_buf(),
                        None => continue,
                    };

                    if !name.starts_with(&self.path) || name == self.path {
                        continue;
                    }

                    let file_type = VirtualZipArchive::zip_entry_to_file_type(&entry);

                    if let Some(name) = self.is_ignored.call_async(file_type, name).await {
                        if entry.is_file() {
                            let (reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
                            let (reader, signal) =
                                crate::io::fallible_reader::FallibleReader::new_with_eof(reader);
                            let mut writer = writer.into_sync();

                            drop(entry);

                            crate::spawn_blocking_signalled(signal, {
                                let mut archive = self.archive.clone();

                                move || -> Result<(), anyhow::Error> {
                                    let mut entry = archive.by_index(i)?;
                                    crate::io::pipe::copy_and_shutdown(&mut entry, &mut writer)?;

                                    Ok(())
                                }
                            });

                            return Some(Ok((file_type, name, Box::new(reader))));
                        } else {
                            return Some(Ok((file_type, name, Box::new(tokio::io::empty()))));
                        }
                    }
                }
                None
            }
        }

        Ok(Box::new(IgnoreAsyncWalkDir {
            path: path.as_ref().to_path_buf(),
            archive: self.archive.clone(),
            current_index: 0,
            is_ignored,
        }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let mut archive = self.archive.clone();
        let size = archive.better_by_path(path.as_ref())?.size();

        #[ouroboros::self_referencing]
        pub struct ZipFileReader {
            archive: zip::ZipArchive<MultiReader>,

            #[borrows(mut archive)]
            #[covariant]
            entry: zip::read::ZipFile<'this, MultiReader>,
        }

        impl std::io::Read for ZipFileReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.with_entry_mut(|entry| entry.read(buf))
            }
        }

        Ok(FileRead {
            size,
            total_size: size,
            reader_range: None,
            reader: Box::new(ZipFileReader::try_new(archive, |archive| {
                archive.better_by_path(path.as_ref())
            })?),
        })
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let mut archive = self.archive.clone();

        let size = archive.better_by_path(path.as_ref())?.size();
        let (pipe_reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (pipe_reader, signal) =
            crate::io::fallible_reader::FallibleReader::new_with_eof(pipe_reader);
        let mut writer = writer.into_sync();

        let path = path.as_ref().to_path_buf();
        crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
            let mut entry = archive.better_by_path(&path)?;
            crate::io::pipe::copy_and_shutdown(&mut entry, &mut writer)?;

            Ok(())
        });

        Ok(AsyncFileRead {
            size,
            total_size: size,
            reader_range: None,
            reader: Box::new(pipe_reader),
        })
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let mut archive = self.archive.clone();
        let mut entry = archive.better_by_path(path.as_ref())?;

        if entry.size() > 1024 {
            return Err(anyhow::anyhow!(
                "symlink target size exceeds maximum allowed size"
            ));
        }
        if !entry.is_symlink() {
            return Err(anyhow::anyhow!("not a symlink"));
        }

        let mut symlink_target = String::new();
        entry.read_to_string(&mut symlink_target)?;

        Ok(PathBuf::from(symlink_target))
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let mut archive = self.archive.clone();
        let entry = archive.better_by_path(path.as_ref())?;

        if entry.size() > 1024 {
            return Err(anyhow::anyhow!(
                "symlink target size exceeds maximum allowed size"
            ));
        }
        if !entry.is_symlink() {
            return Err(anyhow::anyhow!("not a symlink"));
        }

        drop(entry);

        let path = path.as_ref().to_path_buf();
        let symlink_target =
            tokio::task::spawn_blocking(move || -> Result<String, anyhow::Error> {
                let mut entry = archive.better_by_path(&path)?;
                let mut symlink_target = String::new();
                entry.read_to_string(&mut symlink_target)?;
                Ok(symlink_target)
            })
            .await??;

        Ok(PathBuf::from(symlink_target))
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FalliblePipeReader, anyhow::Error> {
        let mut archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();

        let (pipe_reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (pipe_reader, signal) = crate::io::fallible_reader::FallibleReader::new(pipe_reader);

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let writer = writer.into_sync();
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    for i in 0..archive.len() {
                        let entry = archive.by_index(i)?;
                        let name = match entry.enclosed_name() {
                            Some(name) => name,
                            None => continue,
                        };

                        let name = match name.strip_prefix(&path) {
                            Ok(name) => name,
                            Err(_) => continue,
                        };

                        if name.components().count() == 0 {
                            continue;
                        }

                        if (is_ignored)(
                            VirtualZipArchive::zip_entry_to_file_type(&entry),
                            name.to_path_buf(),
                        )
                        .is_none()
                        {
                            continue;
                        }

                        if entry.is_dir() {
                            zip.add_directory(name.to_string_lossy(), entry.options())?;
                        } else {
                            let entry_size = entry.size();
                            zip.raw_copy_file_to_path(entry, name)?;
                            progress.increment_bytes(entry_size);
                            progress.increment_files();
                        }
                    }

                    let mut inner = zip.finish()?.into_inner();
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            f if f.is_tar() => {
                let writer = CompressionWriter::new(
                    writer.into_sync(),
                    f.compression_format(),
                    compression_level,
                    self.server
                        .app_state
                        .config
                        .load()
                        .api
                        .file_compression_threads,
                )?;

                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let mut tar = tar::Builder::new(writer);
                    tar.mode(tar::HeaderMode::Complete);

                    for i in 0..archive.len() {
                        let entry = archive.by_index(i)?;
                        let name = match entry.enclosed_name() {
                            Some(name) => name,
                            None => continue,
                        };

                        let name = match name.strip_prefix(&path) {
                            Ok(name) => name,
                            Err(_) => continue,
                        };

                        if name.components().count() == 0 {
                            continue;
                        }

                        if (is_ignored)(
                            VirtualZipArchive::zip_entry_to_file_type(&entry),
                            name.to_path_buf(),
                        )
                        .is_none()
                        {
                            continue;
                        }

                        let mut entry_header = tar::Header::new_gnu();
                        entry_header.set_size(0);
                        if let Some(mode) = entry.unix_mode() {
                            entry_header.set_mode(mode);
                        }
                        entry_header.set_mtime(
                            zip_entry_get_modified_time(&entry)
                                .map(|dt| {
                                    dt.duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                })
                                .unwrap_or_default(),
                        );

                        if entry.is_dir() {
                            entry_header.set_entry_type(tar::EntryType::Directory);

                            tar.append_data(&mut entry_header, name, std::io::empty())?;
                        } else if entry.is_file() {
                            entry_header.set_entry_type(tar::EntryType::Regular);
                            entry_header.set_size(entry.size());

                            let reader = progress.counting_reader(entry);

                            tar.append_data(&mut entry_header, name, reader)?;
                            progress.increment_files();
                        } else if entry.is_symlink() && (1..=2048).contains(&entry.size()) {
                            entry_header.set_entry_type(tar::EntryType::Symlink);

                            let link_name = std::io::read_to_string(entry)?;
                            tar.append_link(&mut entry_header, name, link_name)?;
                            progress.increment_files();
                        }
                    }

                    tar.finish()?;
                    let mut inner = tar.into_inner()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            f if f.is_itaf() => {
                let writer = CompressionWriter::new(
                    writer.into_sync(),
                    f.compression_format(),
                    compression_level,
                    self.server
                        .app_state
                        .config
                        .load()
                        .api
                        .file_compression_threads,
                )?;

                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let mut itaf_enc = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;

                    let mut entries: Vec<(PathBuf, usize)> = Vec::new();
                    for i in 0..archive.len() {
                        let entry = archive.by_index(i)?;
                        if entry.is_dir() {
                            continue;
                        }
                        let name = match entry.enclosed_name() {
                            Some(n) => n,
                            None => continue,
                        };
                        let relative = match name.strip_prefix(&path) {
                            Ok(r) => r.to_path_buf(),
                            Err(_) => continue,
                        };
                        if relative.components().count() == 0 {
                            continue;
                        }
                        let file_type = VirtualZipArchive::zip_entry_to_file_type(&entry);
                        let Some(relative) = (is_ignored)(file_type, relative) else {
                            continue;
                        };
                        entries.push((relative, i));
                    }
                    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

                    let mut dir_stack = Vec::new();

                    for (relative, zip_index) in entries {
                        let components: Vec<_> = relative
                            .components()
                            .filter_map(|c| match c {
                                std::path::Component::Normal(s) => Some(s.to_string_lossy()),
                                _ => None,
                            })
                            .collect();
                        let Some(name) = components.last() else {
                            continue;
                        };

                        let parent = components.get_slice(..components.len() - 1)?;

                        let shared = dir_stack
                            .iter()
                            .zip(parent.iter())
                            .take_while(|(a, b)| a == b)
                            .count();
                        while dir_stack.len() > shared {
                            itaf_enc.exit_dir()?;
                            dir_stack.pop();
                        }

                        for component in parent.get_slice(shared..)? {
                            itaf_enc.enter_dir(
                                component,
                                &Metadata {
                                    uid: 0,
                                    gid: 0,
                                    mode: 0o755,
                                    modified: std::time::SystemTime::now(),
                                },
                            )?;
                            dir_stack.push(component.to_compact_string());
                        }

                        let entry = archive.by_index(zip_index)?;
                        let mtime = zip_entry_get_modified_time(&entry)
                            .unwrap_or_else(std::time::SystemTime::now);
                        let meta = Metadata {
                            uid: 0,
                            gid: 0,
                            mode: entry.unix_mode().unwrap_or(0o644),
                            modified: mtime,
                        };
                        let size = entry.size();

                        if entry.is_symlink() && (1..=2048).contains(&size) {
                            let link_target = std::io::read_to_string(entry)?;
                            if itaf::spec::validate_name(name).is_ok() {
                                itaf_enc.add_symlink(name, &link_target, false, &meta)?;
                                progress.increment_files();
                            }
                        } else if entry.is_file() {
                            let reader = progress.counting_reader(entry);
                            let mut reader =
                                crate::io::fixed_reader::FixedReader::new_with_fixed_bytes(
                                    reader,
                                    size as usize,
                                );
                            itaf_enc.add_file(name, &meta, size, &mut { reader })?;
                            progress.increment_files();
                        }
                    }

                    while !dir_stack.is_empty() {
                        itaf_enc.exit_dir()?;
                        dir_stack.pop();
                    }

                    let mut inner = itaf_enc.finish()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            _ => {
                tracing::error!(
                    "unsupported archive format for zip vfs: {}",
                    archive_format.extension()
                );
            }
        }

        Ok(pipe_reader)
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn async_file_reads_finish_and_release_producer_on_drop() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("creating archive test runtime failed");

        let result = runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                let temp = tempfile::tempdir()?;
                let state = crate::routes::AppState::mock();
                state
                    .config
                    .mutate_in_place_for_testing()
                    .system
                    .data_directory =
                    crate::config::SystemPath::new(temp.path().to_string_lossy().into_owned());
                let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);
                server.filesystem.disk_checker.abort();

                let payload = vec![b'x'; crate::BUFFER_SIZE * 4];
                let mut file = tempfile::tempfile()?;
                {
                    let mut zip = zip::ZipWriter::new(&mut file);
                    zip.start_file(
                        "entry.txt",
                        zip::write::SimpleFileOptions::default()
                            .compression_method(zip::CompressionMethod::Stored),
                    )?;
                    zip.write_all(&payload)?;
                    zip.finish()?;
                }

                let mut backing_file = file.try_clone()?;
                let archive = VirtualZipArchive::new(
                    server,
                    zip::ZipArchive::new(MultiReader::new(Arc::new(file))?)?,
                    Default::default(),
                );
                let mut complete = archive.async_read_file(&"entry.txt", None).await?;
                let mut contents = Vec::new();
                complete.reader.read_to_end(&mut contents).await?;
                assert_eq!(contents, payload);

                let mut partial = archive.async_read_file(&"entry.txt", None).await?;
                let mut byte = [0];
                partial.reader.read_exact(&mut byte).await?;
                drop(partial);

                tokio::task::spawn_blocking(|| {}).await?;

                let data_start = archive
                    .archive
                    .clone()
                    .by_index(0)?
                    .data_start()
                    .ok_or_else(|| anyhow::anyhow!("ZIP entry has no data offset"))?;
                backing_file.seek(std::io::SeekFrom::Start(data_start))?;
                backing_file.write_all(b"y")?;

                let mut corrupted = archive.async_read_file(&"entry.txt", None).await?;
                let err = corrupted
                    .reader
                    .read_to_end(&mut Vec::new())
                    .await
                    .expect_err("corrupt ZIP entry must report its checksum failure");
                assert!(err.to_string().contains("Invalid checksum"));

                Ok::<_, anyhow::Error>(())
            })
            .await
        });

        runtime.shutdown_timeout(std::time::Duration::from_millis(100));
        result
            .expect("archive producer remained blocked after reader drop")
            .expect("archive streaming test failed");
    }
}
