use crate::{
    io::{
        SafeSliceExt, SafeWriteExt, UninterruptedReadExt,
        compression::{CompressionLevel, writer::CompressionWriter},
    },
    models::{DirectoryEntry, DirectorySortingMode},
    routes::MimeCacheValue,
    server::filesystem::{
        archive::{StreamableArchiveFormat, multi_reader::MultiReader},
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
use chrono::{Datelike, Timelike};
use compact_str::ToCompactString;
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub trait CmpSortExt {
    fn cmp_sort(
        &self,
        other: &Self,
        sort: crate::models::DirectorySortingMode,
    ) -> std::cmp::Ordering;
}

impl CmpSortExt for sevenz_rust2::ArchiveEntry {
    fn cmp_sort(
        &self,
        other: &Self,
        sort: crate::models::DirectorySortingMode,
    ) -> std::cmp::Ordering {
        use crate::models::DirectorySortingMode::*;

        match sort {
            NameAsc => self.name().cmp_ascii_case_insensitive(other.name()),
            NameDesc => other.name().cmp_ascii_case_insensitive(self.name()),
            SizeAsc => self.size.cmp(&other.size),
            SizeDesc => other.size.cmp(&self.size),
            PhysicalSizeAsc => self.compressed_size.cmp(&other.compressed_size),
            PhysicalSizeDesc => other.compressed_size.cmp(&self.compressed_size),
            ModifiedAsc => self.last_modified_date().cmp(&other.last_modified_date()),
            ModifiedDesc => other.last_modified_date().cmp(&self.last_modified_date()),
            CreatedAsc => self.creation_date().cmp(&other.creation_date()),
            CreatedDesc => other.creation_date().cmp(&self.creation_date()),
        }
    }
}

#[derive(Clone)]
pub struct VirtualSevenZipArchive {
    pub server: crate::server::Server,
    pub archive: Arc<sevenz_rust2::Archive>,
    pub archive_created: chrono::DateTime<chrono::Utc>,
    pub mime_cache: moka::sync::Cache<usize, MimeCacheValue>,
    pub reader: MultiReader,
    pub sizes: Arc<crate::server::filesystem::usage::DiskUsage>,
}

impl VirtualSevenZipArchive {
    pub fn new(
        server: crate::server::Server,
        archive: Arc<sevenz_rust2::Archive>,
        archive_created: chrono::DateTime<chrono::Utc>,
        reader: MultiReader,
    ) -> Self {
        let mut sizes = crate::server::filesystem::usage::DiskUsage::default();

        for entry in archive.files.iter() {
            let name = Path::new(entry.name());
            let delta = SpaceDelta::new(entry.size as i64, entry.compressed_size as i64);

            if entry.is_directory() {
                sizes.update_size(name, delta);
            } else {
                let parent = name.parent().unwrap_or(Path::new(""));
                sizes.update_size(parent, delta);
            }
        }

        Self {
            server,
            archive,
            archive_created,
            mime_cache: moka::sync::Cache::new(10240),
            reader,
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

        let archive = tokio::task::spawn_blocking({
            let mut reader = reader.clone();

            move || {
                let password = sevenz_rust2::Password::empty();
                sevenz_rust2::Archive::read(&mut reader, &password)
            }
        })
        .await??;

        let metadata = server.filesystem.async_metadata(archive_path).await?;

        Ok(Self::new(
            server,
            Arc::new(archive),
            metadata
                .created()
                .map_or_else(|_| Default::default(), |dt| dt.into_std().into()),
            reader,
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

    #[allow(clippy::too_many_arguments)]
    fn seven_zip_entry_to_directory_entry(
        archive_created: &chrono::DateTime<chrono::Utc>,
        path: &Path,
        entry_index: usize,
        mime_cache: &moka::sync::Cache<usize, MimeCacheValue>,
        sizes: &crate::server::filesystem::usage::DiskUsage,
        buffer: Option<&[u8]>,
        entry: &sevenz_rust2::ArchiveEntry,
        reader: &mut dyn Read,
    ) -> DirectoryEntry {
        let (size, size_physical) = if entry.is_directory() {
            let space = sizes.get_size(path).unwrap_or_default();
            (space.get_logical(), space.get_physical())
        } else {
            (entry.size, entry.compressed_size)
        };

        let detected_mime = if entry.is_directory() {
            MimeCacheValue::directory()
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
            let buffer = if reader.read_uninterrupted(&mut buffer).is_err() {
                None
            } else {
                Some(&buffer[..])
            };

            let detected_mime = crate::utils::detect_mime_type(path, buffer);

            mime_cache.insert(entry_index, detected_mime);
            detected_mime
        };

        let mode = if entry.is_directory() { 0o755 } else { 0o644 };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(mode),
            mode_bits: compact_str::format_compact!("{:o}", mode),
            size,
            size_physical,
            editable: !entry.is_directory() && detected_mime.valid_utf8,
            inner_editable: !entry.is_directory() && detected_mime.valid_inner_utf8,
            directory: entry.is_directory(),
            file: !entry.is_directory(),
            symlink: false,
            r#virtual: true,
            mime: detected_mime.mime,
            modified: if entry.has_last_modified_date {
                std::time::SystemTime::from(entry.last_modified_date).into()
            } else {
                Default::default()
            },
            created: if entry.has_creation_date {
                std::time::SystemTime::from(entry.creation_date).into()
            } else {
                *archive_created
            },
        }
    }

    fn seven_zip_entry_to_file_type(entry: &sevenz_rust2::ArchiveEntry) -> FileType {
        if entry.is_directory() {
            FileType::Dir
        } else {
            FileType::File
        }
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualSevenZipArchive {
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

        let entry = self
            .archive
            .files
            .iter()
            .find(|entry| Path::new(entry.name()) == path_ref);

        if let Some(entry) = entry {
            return Ok(FileMetadata {
                file_type: Self::seven_zip_entry_to_file_type(entry),
                permissions: if entry.is_directory() {
                    PortablePermissions::from_mode_dir(0o755)
                } else {
                    PortablePermissions::from_mode_file(0o644)
                },
                size: entry.size(),
                modified: if entry.has_last_modified_date {
                    Some(std::time::SystemTime::from(entry.last_modified_date))
                } else {
                    None
                },
                created: if entry.has_creation_date {
                    Some(std::time::SystemTime::from(entry.creation_date))
                } else {
                    None
                },
            });
        }

        if Self::is_virtual_directory(&self.sizes, path_ref) {
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(0o755),
                size: 0,
                modified: None,
                created: None,
            });
        }

        Err(anyhow::anyhow!("Entry not found"))
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
        let archive = self.archive.clone();
        let archive_created = self.archive_created;
        let mime_cache = self.mime_cache.clone();
        let sizes = self.sizes.clone();
        let mut reader = self.reader.clone();
        let path = path.as_ref().to_path_buf();

        let entry =
            tokio::task::spawn_blocking(move || -> Result<DirectoryEntry, anyhow::Error> {
                let found = archive
                    .files
                    .iter()
                    .enumerate()
                    .find(|(_, entry)| Path::new(entry.name()) == path);

                let (entry_index, entry) = match found {
                    Some(v) => v,
                    None => {
                        if Self::is_virtual_directory(&sizes, &path) {
                            return Ok(Self::virtual_directory_entry(
                                &archive_created,
                                &path,
                                &sizes,
                            ));
                        }
                        return Err(anyhow::anyhow!("Entry not found"));
                    }
                };

                match archive.stream_map.file_block_index.get(entry_index) {
                    Some(Some(block_index))
                        if !mime_cache.contains_key(&entry_index) && !entry.is_directory() =>
                    {
                        let password = sevenz_rust2::Password::empty();
                        let folder = sevenz_rust2::BlockDecoder::new(
                            1,
                            *block_index,
                            &archive,
                            &password,
                            &mut reader,
                        );

                        let mut result = None;

                        folder
                            .for_each_entries(&mut |block_entry, reader| {
                                if block_entry.name() == entry.name() {
                                    result = Some(Self::seven_zip_entry_to_directory_entry(
                                        &archive_created,
                                        &path,
                                        entry_index,
                                        &mime_cache,
                                        &sizes,
                                        None,
                                        entry,
                                        reader,
                                    ));
                                    return Ok(true);
                                }
                                std::io::copy(reader, &mut std::io::sink())?;
                                Ok(false)
                            })
                            .ok();

                        result
                            .ok_or_else(|| anyhow::anyhow!("Failed to read 7z entry for metadata"))
                    }
                    _ => Ok(Self::seven_zip_entry_to_directory_entry(
                        &archive_created,
                        &path,
                        entry_index,
                        &mime_cache,
                        &sizes,
                        None,
                        entry,
                        &mut std::io::empty(),
                    )),
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
        let path = path.as_ref();

        let found = self
            .archive
            .files
            .iter()
            .enumerate()
            .find(|(_, entry)| Path::new(entry.name()) == path);

        let (entry_index, entry) = match found {
            Some(v) => v,
            None => {
                if Self::is_virtual_directory(&self.sizes, path) {
                    return Ok(Self::virtual_directory_entry(
                        &self.archive_created,
                        path,
                        &self.sizes,
                    ));
                }
                return Err(anyhow::anyhow!("Entry not found"));
            }
        };

        Ok(Self::seven_zip_entry_to_directory_entry(
            &self.archive_created,
            path,
            entry_index,
            &self.mime_cache,
            &self.sizes,
            Some(buffer),
            entry,
            &mut std::io::empty(),
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

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        let archive = self.archive.clone();
        let archive_created = self.archive_created;
        let mime_cache = self.mime_cache.clone();
        let mut reader = self.reader.clone();
        let sizes = self.sizes.clone();
        let path = path.as_ref().to_path_buf();

        let entries =
            tokio::task::spawn_blocking(move || -> Result<DirectoryListing, anyhow::Error> {
                enum DirItem<'a> {
                    Dir {
                        path: PathBuf,
                        real_entry: Option<(usize, &'a sevenz_rust2::ArchiveEntry)>,
                    },
                    File {
                        index: usize,
                        entry: &'a sevenz_rust2::ArchiveEntry,
                    },
                }

                let mut directory_entries: Vec<DirItem<'_>> = Vec::new();
                let mut other_entries: Vec<(usize, &sevenz_rust2::ArchiveEntry)> = Vec::new();

                if let Some(node) = sizes.get_path(&path) {
                    for (child_name, _child_node) in node.get_entries() {
                        let Some(filtered_path) =
                            (is_ignored)(FileType::Dir, path.join(child_name.as_str()))
                        else {
                            continue;
                        };

                        let real_entry = archive
                            .files
                            .iter()
                            .enumerate()
                            .find(|(_, e)| Path::new(e.name()) == filtered_path);

                        directory_entries.push(DirItem::Dir {
                            path: filtered_path,
                            real_entry,
                        });
                    }
                }

                let path_len = path.components().count();
                for (i, entry) in archive.files.iter().enumerate() {
                    if entry.is_directory() {
                        continue;
                    }

                    let name = Path::new(entry.name());
                    if !name.starts_with(&path) || name == path {
                        continue;
                    }
                    if name.components().count() != path_len + 1 {
                        continue;
                    }

                    if (is_ignored)(
                        Self::seven_zip_entry_to_file_type(entry),
                        name.to_path_buf(),
                    )
                    .is_none()
                    {
                        continue;
                    }

                    other_entries.push((i, entry));
                }

                directory_entries.sort_by(|a, b| {
                    let (a_path, a_real) = match a {
                        DirItem::Dir { path, real_entry } => (path, real_entry.as_ref()),
                        _ => return std::cmp::Ordering::Equal,
                    };
                    let (b_path, b_real) = match b {
                        DirItem::Dir { path, real_entry } => (path, real_entry.as_ref()),
                        _ => return std::cmp::Ordering::Equal,
                    };

                    match sort {
                        DirectorySortingMode::SizeAsc
                        | DirectorySortingMode::SizeDesc
                        | DirectorySortingMode::PhysicalSizeAsc
                        | DirectorySortingMode::PhysicalSizeDesc => {
                            let a_space = sizes.get_size(a_path).unwrap_or_default();
                            let b_space = sizes.get_size(b_path).unwrap_or_default();
                            match sort {
                                DirectorySortingMode::SizeAsc => {
                                    a_space.get_logical().cmp(&b_space.get_logical())
                                }
                                DirectorySortingMode::SizeDesc => {
                                    b_space.get_logical().cmp(&a_space.get_logical())
                                }
                                DirectorySortingMode::PhysicalSizeAsc => {
                                    a_space.get_physical().cmp(&b_space.get_physical())
                                }
                                DirectorySortingMode::PhysicalSizeDesc => {
                                    b_space.get_physical().cmp(&a_space.get_physical())
                                }
                                _ => std::cmp::Ordering::Equal,
                            }
                        }
                        _ => match (a_real, b_real) {
                            (Some((_, ae)), Some((_, be))) => ae.cmp_sort(be, sort),
                            (Some(_), None) => std::cmp::Ordering::Less,
                            (None, Some(_)) => std::cmp::Ordering::Greater,
                            (None, None) => a_path.cmp(b_path),
                        },
                    }
                });
                other_entries.sort_unstable_by(|a, b| a.1.cmp_sort(b.1, sort));

                let total_entries = directory_entries.len() + other_entries.len();
                let mut entries = Vec::new();

                let merged = directory_entries.into_iter().chain(
                    other_entries
                        .into_iter()
                        .map(|(i, e)| DirItem::File { index: i, entry: e }),
                );

                let target_entries: Vec<_> = if let Some(per_page) = per_page {
                    let start = (page - 1) * per_page;
                    merged.skip(start).take(per_page).collect()
                } else {
                    merged.collect()
                };

                for item in target_entries {
                    match item {
                        DirItem::Dir {
                            real_entry: Some((entry_index, archive_entry)),
                            ..
                        } => {
                            entries.push(Self::seven_zip_entry_to_directory_entry(
                                &archive_created,
                                Path::new(archive_entry.name()),
                                entry_index,
                                &mime_cache,
                                &sizes,
                                None,
                                archive_entry,
                                &mut std::io::empty(),
                            ));
                        }
                        DirItem::Dir {
                            path: dir_path,
                            real_entry: None,
                        } => {
                            entries.push(Self::virtual_directory_entry(
                                &archive_created,
                                &dir_path,
                                &sizes,
                            ));
                        }
                        DirItem::File {
                            index: entry_index,
                            entry: archive_entry,
                        } => {
                            let entry_path = Path::new(archive_entry.name());
                            let needs_read = !mime_cache.contains_key(&entry_index);

                            match archive.stream_map.file_block_index.get(entry_index) {
                                Some(Some(block_index)) if needs_read => {
                                    let password = sevenz_rust2::Password::empty();
                                    let folder = sevenz_rust2::BlockDecoder::new(
                                        1,
                                        *block_index,
                                        &archive,
                                        &password,
                                        &mut reader,
                                    );

                                    let mut entry_processed = false;
                                    folder.for_each_entries(&mut |entry, reader| {
                                        let p = entry.name();
                                        if p != archive_entry.name() {
                                            std::io::copy(reader, &mut std::io::sink())?;
                                            return Ok(true);
                                        }

                                        entries.push(Self::seven_zip_entry_to_directory_entry(
                                            &archive_created,
                                            entry_path,
                                            entry_index,
                                            &mime_cache,
                                            &sizes,
                                            None,
                                            archive_entry,
                                            reader,
                                        ));
                                        entry_processed = true;
                                        Ok(false)
                                    })?;

                                    if !entry_processed {
                                        entries.push(Self::seven_zip_entry_to_directory_entry(
                                            &archive_created,
                                            entry_path,
                                            entry_index,
                                            &mime_cache,
                                            &sizes,
                                            None,
                                            archive_entry,
                                            &mut std::io::empty(),
                                        ));
                                    }
                                }
                                _ => entries.push(Self::seven_zip_entry_to_directory_entry(
                                    &archive_created,
                                    entry_path,
                                    entry_index,
                                    &mime_cache,
                                    &sizes,
                                    None,
                                    archive_entry,
                                    &mut std::io::empty(),
                                )),
                            };
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
            archive: Arc<sevenz_rust2::Archive>,
            current_index: usize,
            is_ignored: IsIgnoredFn,
        }

        impl DirectoryWalk for IgnoreWalkDir {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                while self.current_index < self.archive.files.len() {
                    let entry = self.archive.files.get(self.current_index)?;
                    self.current_index += 1;

                    let name = Path::new(entry.name());

                    if !name.starts_with(&self.path) || name == self.path {
                        continue;
                    }

                    let file_type = VirtualSevenZipArchive::seven_zip_entry_to_file_type(entry);

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
        struct AsyncIgnoreWalkDir {
            path: PathBuf,
            archive: Arc<sevenz_rust2::Archive>,
            current_index: usize,
            is_ignored: IsIgnoredFn,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryWalk for AsyncIgnoreWalkDir {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                while self.current_index < self.archive.files.len() {
                    let entry = self.archive.files.get(self.current_index)?;
                    self.current_index += 1;

                    let name = Path::new(entry.name());

                    if !name.starts_with(&self.path) || name == self.path {
                        continue;
                    }

                    let file_type = VirtualSevenZipArchive::seven_zip_entry_to_file_type(entry);

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

        Ok(Box::new(AsyncIgnoreWalkDir {
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
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        let archive = self.archive.clone();
        let mut reader = self.reader.clone();
        let root_path = path.as_ref().to_path_buf();

        tokio::task::spawn_blocking(move || {
            let mut target_files_by_block: HashMap<usize, HashSet<String>> = HashMap::new();
            let mut loose_files: VecDeque<(String, FileType)> = VecDeque::new();

            for (i, entry) in archive.files.iter().enumerate() {
                let name_path = Path::new(entry.name());

                if !name_path.starts_with(&root_path) || name_path == root_path {
                    continue;
                }

                let file_type = VirtualSevenZipArchive::seven_zip_entry_to_file_type(entry);

                if (is_ignored)(file_type, name_path.to_path_buf()).is_some() {
                    if entry.is_directory() {
                        loose_files.push_back((entry.name().to_string(), file_type));
                    } else if let Some(Some(block_index)) =
                        archive.stream_map.file_block_index.get(i)
                    {
                        target_files_by_block
                            .entry(*block_index)
                            .or_default()
                            .insert(entry.name().to_string());
                    } else {
                        loose_files.push_back((entry.name().to_string(), file_type));
                    }
                }
            }

            while let Some((name, ft)) = loose_files.pop_front() {
                let res = Ok((
                    ft,
                    PathBuf::from(name),
                    Box::new(tokio::io::empty()) as AsyncReadableFileStream,
                ));
                if tx.blocking_send(res).is_err() {
                    return;
                }
            }

            let mut sorted_blocks: Vec<_> = target_files_by_block.keys().cloned().collect();
            sorted_blocks.sort_unstable();

            for block_index in sorted_blocks {
                if tx.is_closed() {
                    return;
                }

                let Some(targets) = &target_files_by_block.get(&block_index) else {
                    continue;
                };

                let password = sevenz_rust2::Password::empty();
                let folder = sevenz_rust2::BlockDecoder::new(
                    1,
                    block_index,
                    &archive,
                    &password,
                    &mut reader,
                );

                if let Err(err) = folder.for_each_entries(&mut |entry, entry_reader| {
                    if targets.contains(entry.name()) {
                        let (pipe_reader, pipe_writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
                        let (pipe_reader, signal) =
                            crate::io::fallible_reader::FallibleReader::new_with_eof(pipe_reader);
                        let mut pipe_writer = pipe_writer.into_sync();

                        let send_result = tx.blocking_send(Ok((
                            FileType::File,
                            PathBuf::from(entry.name()),
                            Box::new(pipe_reader),
                        )));

                        if send_result.is_err() {
                            return Ok(false);
                        }

                        match crate::io::pipe::copy_and_shutdown(entry_reader, &mut pipe_writer) {
                            Ok(true) => signal.succeed(),
                            Ok(false) => {
                                if tx.is_closed() {
                                    return Ok(false);
                                }

                                std::io::copy(entry_reader, &mut std::io::sink())?;

                                return Ok(true);
                            }
                            Err(err) => {
                                signal.fail(&err);

                                return Err(err.into());
                            }
                        }
                    } else {
                        std::io::copy(entry_reader, &mut std::io::sink())?;
                    }
                    Ok(true)
                }) {
                    tx.blocking_send(Err(err.into())).ok();
                    return;
                }
            }
        });

        struct ChannelStreamWalker {
            rx: tokio::sync::mpsc::Receiver<
                Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>,
            >,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryStreamWalk for ChannelStreamWalker {
            async fn next_entry(
                &mut self,
            ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>
            {
                self.rx.recv().await
            }
        }

        Ok(Box::new(ChannelStreamWalker { rx }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let archive = self.archive.clone();
        let mut reader = self.reader.clone();
        let path = path.as_ref().to_path_buf();

        let (entry_index, size) = match archive
            .files
            .iter()
            .enumerate()
            .find(|f| Path::new(f.1.name()) == path)
        {
            Some((i, entry)) => (i, entry.size),
            None => return Err(anyhow::anyhow!("7z archive entry not found")),
        };

        let (pipe_reader, mut writer) = std::io::pipe()?;

        tokio::task::spawn_blocking(move || {
            if let Some(Some(block_index)) = archive.stream_map.file_block_index.get(entry_index) {
                let password = sevenz_rust2::Password::empty();
                let folder = sevenz_rust2::BlockDecoder::new(
                    1,
                    *block_index,
                    &archive,
                    &password,
                    &mut reader,
                );

                let _ = folder.for_each_entries(&mut |entry, reader| {
                    let entry_path = Path::new(entry.name());
                    if entry_path != path {
                        std::io::copy(reader, &mut std::io::sink())?;
                        return Ok(true);
                    }

                    let mut buffer = vec![0; crate::BUFFER_SIZE];
                    loop {
                        match reader.read_uninterrupted(&mut buffer) {
                            Ok(0) => break,
                            Ok(bytes_read) => {
                                if writer.safe_write_all(&buffer, bytes_read).is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                tracing::error!("error reading from 7z entry: {:#?}", err);
                                break;
                            }
                        }
                    }

                    Ok(true)
                });
            };
        });

        Ok(FileRead {
            size,
            total_size: size,
            reader_range: None,
            reader: Box::new(pipe_reader),
        })
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let archive = self.archive.clone();
        let mut reader = self.reader.clone();
        let path = path.as_ref().to_path_buf();

        let (entry_index, size) = match archive
            .files
            .iter()
            .enumerate()
            .find(|f| Path::new(f.1.name()) == path)
        {
            Some((i, entry)) => (i, entry.size),
            None => return Err(anyhow::anyhow!("7z archive entry not found")),
        };

        let (pipe_reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (pipe_reader, signal) =
            crate::io::fallible_reader::FallibleReader::new_with_eof(pipe_reader);
        let mut writer = writer.into_sync();

        crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
            if let Some(Some(block_index)) = archive.stream_map.file_block_index.get(entry_index) {
                let password = sevenz_rust2::Password::empty();
                let folder = sevenz_rust2::BlockDecoder::new(
                    1,
                    *block_index,
                    &archive,
                    &password,
                    &mut reader,
                );

                folder.for_each_entries(&mut |entry, reader| {
                    let entry_path = Path::new(entry.name());
                    if entry_path != path {
                        std::io::copy(reader, &mut std::io::sink())?;

                        return Ok(true);
                    }

                    Ok(crate::io::pipe::copy_and_shutdown(reader, &mut writer)?)
                })?;
            }

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
        _path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        Err(anyhow::anyhow!("Symlinks not supported in 7z archives"))
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.read_symlink(path)
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FalliblePipeReader, anyhow::Error> {
        let archive = self.archive.clone();
        let mut reader = self.reader.clone();
        let path = path.as_ref().to_path_buf();

        let (pipe_reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (pipe_reader, signal) = crate::io::fallible_reader::FallibleReader::new(pipe_reader);

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let writer = writer.into_sync();
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    for (i, entry) in archive.files.iter().enumerate() {
                        let name = match Path::new(entry.name()).strip_prefix(&path) {
                            Ok(name) => name,
                            Err(_) => continue,
                        };

                        if name.components().count() == 0 {
                            continue;
                        }

                        if (is_ignored)(
                            VirtualSevenZipArchive::seven_zip_entry_to_file_type(entry),
                            name.to_path_buf(),
                        )
                        .is_none()
                        {
                            continue;
                        }

                        let mut zip_options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .large_file(true);

                        if entry.has_last_modified_date {
                            let mtime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(
                                std::time::SystemTime::from(entry.last_modified_date),
                            );

                            if let Ok(mtime) = zip::DateTime::from_date_and_time(
                                mtime.year() as u16,
                                mtime.month() as u8,
                                mtime.day() as u8,
                                mtime.hour() as u8,
                                mtime.minute() as u8,
                                mtime.second() as u8,
                            ) {
                                zip_options = zip_options.last_modified_time(mtime);
                            }
                        }

                        if entry.is_directory() {
                            zip.add_directory(name.to_string_lossy(), zip_options)?;
                        } else {
                            zip.start_file(name.to_string_lossy(), zip_options)?;

                            progress.increment_files();

                            if let Some(Some(block_index)) =
                                archive.stream_map.file_block_index.get(i)
                            {
                                let password = sevenz_rust2::Password::empty();
                                let folder = sevenz_rust2::BlockDecoder::new(
                                    1,
                                    *block_index,
                                    &archive,
                                    &password,
                                    &mut reader,
                                );

                                let entry_size = entry.size;

                                folder
                                    .for_each_entries(&mut |block_entry, reader| {
                                        if block_entry.name() != entry.name() {
                                            std::io::copy(reader, &mut std::io::sink())?;
                                            return Ok(true);
                                        }

                                        crate::io::copy_shared(&mut read_buffer, reader, &mut zip)?;

                                        progress.increment_bytes(entry_size);

                                        Ok(false)
                                    })
                                    .unwrap_or_default();
                            };
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

                    for (i, entry) in archive.files.iter().enumerate() {
                        let name = match Path::new(entry.name()).strip_prefix(&path) {
                            Ok(name) => name,
                            Err(_) => continue,
                        };

                        if name.components().count() == 0 {
                            continue;
                        }

                        if (is_ignored)(
                            VirtualSevenZipArchive::seven_zip_entry_to_file_type(entry),
                            name.to_path_buf(),
                        )
                        .is_none()
                        {
                            continue;
                        }

                        let mut entry_header = tar::Header::new_gnu();
                        entry_header.set_size(0);
                        if entry.has_last_modified_date {
                            entry_header.set_mtime(
                                std::time::SystemTime::from(entry.last_modified_date)
                                    .elapsed()
                                    .unwrap_or_default()
                                    .as_secs(),
                            );
                        }

                        if entry.is_directory() {
                            entry_header.set_entry_type(tar::EntryType::Directory);

                            tar.append_data(&mut entry_header, name, std::io::empty())?;
                        } else {
                            entry_header.set_entry_type(tar::EntryType::Regular);
                            entry_header.set_size(entry.size);

                            progress.increment_files();

                            if let Some(Some(block_index)) =
                                archive.stream_map.file_block_index.get(i)
                            {
                                let password = sevenz_rust2::Password::empty();
                                let folder = sevenz_rust2::BlockDecoder::new(
                                    1,
                                    *block_index,
                                    &archive,
                                    &password,
                                    &mut reader,
                                );

                                folder
                                    .for_each_entries(&mut |block_entry, reader| {
                                        if block_entry.name() != entry.name() {
                                            std::io::copy(reader, &mut std::io::sink())?;
                                            return Ok(true);
                                        }

                                        let reader = progress.counting_reader(reader);

                                        tar.append_data(&mut entry_header, name, reader)?;

                                        Ok(false)
                                    })
                                    .unwrap_or_default();
                            };
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
                    for (i, entry) in archive.files.iter().enumerate() {
                        if entry.is_directory() {
                            continue;
                        }
                        let relative = match Path::new(entry.name()).strip_prefix(&path) {
                            Ok(r) => r.to_path_buf(),
                            Err(_) => continue,
                        };
                        if relative.components().count() == 0 {
                            continue;
                        }
                        let Some(relative) = (is_ignored)(
                            VirtualSevenZipArchive::seven_zip_entry_to_file_type(entry),
                            relative,
                        ) else {
                            continue;
                        };
                        entries.push((relative, i));
                    }
                    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

                    let mut dir_stack = Vec::new();

                    for (relative, entry_index) in entries {
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

                        if let Some(invalid) = components
                            .iter()
                            .find(|c| itaf::spec::validate_name(c).is_err())
                        {
                            tracing::debug!(
                                path = %relative.display(),
                                "skipping 7z entry while creating itaf archive, invalid name component: {invalid:?}"
                            );
                            continue;
                        }

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

                        let Some(entry) = &archive.files.get(entry_index) else {
                            continue;
                        };
                        let mtime = if entry.has_last_modified_date {
                            std::time::SystemTime::from(entry.last_modified_date)
                        } else {
                            std::time::SystemTime::now()
                        };
                        let meta = Metadata {
                            uid: 0,
                            gid: 0,
                            mode: 0o644,
                            modified: mtime,
                        };
                        let size = entry.size;

                        progress.increment_files();

                        if let Some(Some(block_index)) =
                            archive.stream_map.file_block_index.get(entry_index)
                        {
                            let password = sevenz_rust2::Password::empty();
                            let folder = sevenz_rust2::BlockDecoder::new(
                                1,
                                *block_index,
                                &archive,
                                &password,
                                &mut reader,
                            );

                            folder
                                .for_each_entries(&mut |block_entry, block_reader| {
                                    if block_entry.name() != entry.name() {
                                        std::io::copy(block_reader, &mut std::io::sink())?;
                                        return Ok(true);
                                    }

                                    let src = progress.counting_reader(block_reader);
                                    let mut src =
                                        crate::io::fixed_reader::FixedReader::new_with_fixed_bytes(
                                            src,
                                            size as usize,
                                        );
                                    itaf_enc.add_file(name, &meta, size, &mut { src })?;

                                    Ok(false)
                                })
                                .map_err(|err| {
                                    anyhow::anyhow!("failed to write 7z entry to itaf: {err}")
                                })?;
                        } else {
                            itaf_enc.add_file(name, &meta, size, &mut std::io::empty())?;
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
                    "unsupported archive format for 7z vfs: {}",
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
    fn solid_walker_drains_dropped_entries_before_continuing() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("creating solid archive test runtime failed");

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

                let first = vec![b'a'; crate::BUFFER_SIZE * 4];
                let second = vec![b'b'; crate::BUFFER_SIZE * 4];
                let entries = ["first.txt", "second.txt"]
                    .into_iter()
                    .map(|name| sevenz_rust2::ArchiveEntry {
                        name: name.into(),
                        has_stream: true,
                        ..Default::default()
                    })
                    .collect();
                let mut writer = sevenz_rust2::ArchiveWriter::new(tempfile::tempfile()?)?;
                writer.push_archive_entries(
                    entries,
                    vec![
                        sevenz_rust2::SourceReader::new(first.as_slice()),
                        sevenz_rust2::SourceReader::new(second.as_slice()),
                    ],
                )?;
                let mut reader = MultiReader::new(Arc::new(writer.finish()?))?;
                let archive =
                    sevenz_rust2::Archive::read(&mut reader, &sevenz_rust2::Password::empty())?;
                assert!(archive.is_solid);
                assert_eq!(archive.blocks.len(), 1);

                let filesystem = VirtualSevenZipArchive::new(
                    server,
                    Arc::new(archive),
                    Default::default(),
                    reader,
                );
                let mut walker = filesystem
                    .async_walk_dir_stream(&"", IsIgnoredFn::default())
                    .await?;
                let (_, name, mut stream) = walker.next_entry().await.expect("first entry")?;
                assert_eq!(name, Path::new("first.txt"));
                stream.read_exact(&mut [0]).await?;
                drop(stream);

                let (_, name, mut stream) = walker.next_entry().await.expect("second entry")?;
                assert_eq!(name, Path::new("second.txt"));
                let mut contents = Vec::new();
                stream.read_to_end(&mut contents).await?;
                assert_eq!(contents, second);
                assert!(walker.next_entry().await.is_none());

                Ok::<_, anyhow::Error>(())
            })
            .await
        });

        runtime.shutdown_timeout(std::time::Duration::from_millis(100));
        result
            .expect("solid archive walker stalled after reader drop")
            .expect("solid archive continuation failed");
    }
}
