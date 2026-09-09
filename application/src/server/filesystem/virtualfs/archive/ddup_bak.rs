use crate::{
    io::{
        UninterruptedReadExt,
        compression::{CompressionLevel, writer::CompressionWriter},
        fixed_reader::FixedReader,
    },
    models::DirectoryEntry,
    routes::MimeCacheValue,
    server::filesystem::{
        archive::StreamableArchiveFormat,
        cap::FileType,
        encode_mode,
        usage::SpaceDelta,
        virtualfs::{
            AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, AsyncReadableFileStream,
            ByteRange, DirectoryListing, DirectoryWalk, FileMetadata, FileRead, IsIgnoredFn,
            ReadableFileStream, VirtualReadableFilesystem,
        },
    },
    utils::{CmpExt, PortablePermissions},
};
use chrono::{Datelike, Timelike};
use ddup_bak::archive::entries::Entry;
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use std::{
    collections::VecDeque,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

trait EntryReaderExt {
    fn entry_reader(
        &self,
        entry: ddup_bak::archive::entries::Entry,
    ) -> Result<ReadableFileStream, anyhow::Error>;
}

impl EntryReaderExt for Option<Arc<ddup_bak::repository::Repository>> {
    fn entry_reader(
        &self,
        entry: ddup_bak::archive::entries::Entry,
    ) -> Result<ReadableFileStream, anyhow::Error> {
        Ok(if let Some(repository) = self {
            Box::new(repository.entry_reader(entry)?)
        } else {
            match entry {
                ddup_bak::archive::entries::Entry::File(file) => Box::new(file),
                _ => {
                    return Err(anyhow::anyhow!("Entry reader is only available for files"));
                }
            }
        })
    }
}

fn entry_size_recursive(entry: &Entry) -> (u64, u64) {
    let mut logical = 0;
    let mut physical = 0;
    let mut stack = vec![entry];

    while let Some(entry) = stack.pop() {
        match entry {
            Entry::File(file) => {
                logical += file.size_real;
                physical += file.size_compressed.unwrap_or(file.size_real);
            }
            Entry::Directory(dir) => stack.extend(dir.entries.iter()),
            Entry::Symlink(link) => {
                logical += link.target.len() as u64;
                physical += link.target.len() as u64;
            }
        }
    }

    (logical, physical)
}

pub trait CmpSortExt {
    fn cmp_sort(
        &self,
        other: &Self,
        sort: crate::models::DirectorySortingMode,
    ) -> std::cmp::Ordering;
}

impl CmpSortExt for Entry {
    fn cmp_sort(
        &self,
        other: &Self,
        sort: crate::models::DirectorySortingMode,
    ) -> std::cmp::Ordering {
        use crate::models::DirectorySortingMode::*;

        match sort {
            NameAsc => self.name().cmp_ascii_case_insensitive(other.name()),
            NameDesc => other.name().cmp_ascii_case_insensitive(self.name()),
            SizeAsc | SizeDesc | PhysicalSizeAsc | PhysicalSizeDesc => {
                let (a_log, a_phy) = entry_size_recursive(self);
                let (b_log, b_phy) = entry_size_recursive(other);
                match sort {
                    SizeAsc => a_log.cmp(&b_log),
                    SizeDesc => b_log.cmp(&a_log),
                    PhysicalSizeAsc => a_phy.cmp(&b_phy),
                    PhysicalSizeDesc => b_phy.cmp(&a_phy),
                    _ => std::cmp::Ordering::Equal,
                }
            }
            ModifiedAsc | CreatedAsc => self.mtime().cmp(&other.mtime()),
            ModifiedDesc | CreatedDesc => other.mtime().cmp(&self.mtime()),
        }
    }
}

#[derive(Clone)]
pub struct VirtualDdupBakArchive {
    pub server: crate::server::Server,
    pub archive: Arc<ddup_bak::archive::Archive>,
    pub archive_created: chrono::DateTime<chrono::Utc>,
    pub repository: Option<Arc<ddup_bak::repository::Repository>>,
    pub sizes: Arc<crate::server::filesystem::usage::DiskUsage>,
    pub mime_cache: moka::sync::Cache<u64, MimeCacheValue>,
}

fn sort_dir_entries_by_size(
    entries: &mut Vec<&Entry>,
    sort: crate::models::DirectorySortingMode,
    sizes: &crate::server::filesystem::usage::DiskUsage,
    parent_path: &Path,
) {
    use crate::models::DirectorySortingMode::*;
    match sort {
        SizeAsc | SizeDesc | PhysicalSizeAsc | PhysicalSizeDesc => {
            entries.sort_unstable_by(|a, b| {
                let a_space = sizes
                    .get_size(&parent_path.join(a.name()))
                    .unwrap_or_default();
                let b_space = sizes
                    .get_size(&parent_path.join(b.name()))
                    .unwrap_or_default();
                match sort {
                    SizeAsc => a_space.get_logical().cmp(&b_space.get_logical()),
                    SizeDesc => b_space.get_logical().cmp(&a_space.get_logical()),
                    PhysicalSizeAsc => a_space.get_physical().cmp(&b_space.get_physical()),
                    PhysicalSizeDesc => b_space.get_physical().cmp(&a_space.get_physical()),
                    _ => std::cmp::Ordering::Equal,
                }
            });
        }
        _ => entries.sort_unstable_by(|a, b| a.cmp_sort(b, sort)),
    }
}

fn populate_disk_usage(
    entries: &[Entry],
    prefix: &Path,
    sizes: &mut crate::server::filesystem::usage::DiskUsage,
) {
    let mut stack: Vec<(PathBuf, &Entry)> =
        entries.iter().map(|e| (prefix.to_path_buf(), e)).collect();

    while let Some((prefix, entry)) = stack.pop() {
        let entry_path = prefix.join(entry.name());
        match entry {
            Entry::File(file) => {
                let delta = SpaceDelta::new(
                    file.size_real as i64,
                    file.size_compressed.unwrap_or(file.size_real) as i64,
                );
                sizes.update_size(&prefix, delta);
            }
            Entry::Directory(dir) => {
                sizes.update_size(&entry_path, SpaceDelta::new(0, 0));
                for child in dir.entries.iter() {
                    stack.push((entry_path.clone(), child));
                }
            }
            Entry::Symlink(link) => {
                let len = link.target.len() as i64;
                sizes.update_size(&prefix, SpaceDelta::new(len, len));
            }
        }
    }
}

impl VirtualDdupBakArchive {
    pub fn new(
        server: crate::server::Server,
        archive: Arc<ddup_bak::archive::Archive>,
        archive_created: chrono::DateTime<chrono::Utc>,
        repository: Option<Arc<ddup_bak::repository::Repository>>,
    ) -> Self {
        let mut sizes = crate::server::filesystem::usage::DiskUsage::default();
        populate_disk_usage(archive.entries(), Path::new(""), &mut sizes);

        Self {
            server,
            archive,
            archive_created,
            repository,
            sizes: Arc::new(sizes),
            mime_cache: moka::sync::Cache::new(10240),
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
        let archive =
            tokio::task::spawn_blocking(move || ddup_bak::archive::Archive::open_file(file))
                .await??;

        let metadata = server.filesystem.async_metadata(archive_path).await?;

        Ok(Self::new(
            server,
            Arc::new(archive),
            metadata
                .created()
                .map_or_else(|_| Default::default(), |dt| dt.into_std().into()),
            None,
        ))
    }

    fn ddup_bak_entry_to_directory_entry(
        archive_created: &chrono::DateTime<chrono::Utc>,
        path: &Path,
        entry: &ddup_bak::archive::entries::Entry,
        repository: &Option<Arc<ddup_bak::repository::Repository>>,
        mime_cache: &moka::sync::Cache<u64, MimeCacheValue>,
        buffer: Option<&[u8]>,
    ) -> DirectoryEntry {
        let (size, size_physical) = entry_size_recursive(entry);

        let detected_mime = match entry {
            Entry::Directory(_) => MimeCacheValue::directory(),
            Entry::Symlink(_) => MimeCacheValue::symlink(),
            Entry::File(file) => {
                if let Some(detected_mime) = mime_cache.get(&file.offset) {
                    detected_mime
                } else if file.size == 0 {
                    MimeCacheValue::text()
                } else {
                    let detected_mime = match buffer {
                        Some(buffer) => crate::utils::detect_mime_type(path, Some(buffer)),
                        None => {
                            if let Ok(mut reader) =
                                repository.entry_reader(Entry::File(file.clone()))
                            {
                                let mut buffer = [0; 64];
                                let buffer = if reader.read_uninterrupted(&mut buffer).is_err() {
                                    None
                                } else {
                                    Some(&buffer[..])
                                };

                                crate::utils::detect_mime_type(path, buffer)
                            } else {
                                crate::utils::detect_mime_type(path, None)
                            }
                        }
                    };

                    mime_cache.insert(file.offset, detected_mime);
                    detected_mime
                }
            }
        };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(entry.mode().bits()),
            mode_bits: compact_str::format_compact!("{:o}", entry.mode().bits() & 0o777),
            size,
            size_physical,
            editable: entry.is_file() && detected_mime.valid_utf8,
            inner_editable: entry.is_file() && detected_mime.valid_inner_utf8,
            directory: entry.is_directory(),
            file: entry.is_file(),
            symlink: entry.is_symlink(),
            r#virtual: true,
            mime: detected_mime.mime,
            modified: chrono::DateTime::from_timestamp(
                entry
                    .mtime()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                0,
            )
            .unwrap_or_default(),
            created: *archive_created,
        }
    }

    fn ddup_bak_entry_to_file_type(entry: &ddup_bak::archive::entries::Entry) -> FileType {
        match entry {
            ddup_bak::archive::entries::Entry::Directory(_) => FileType::Dir,
            ddup_bak::archive::entries::Entry::File(_) => FileType::File,
            ddup_bak::archive::entries::Entry::Symlink(_) => FileType::Symlink,
        }
    }

    fn tar_convert_entries(
        entry: &Entry,
        repository: &Option<Arc<ddup_bak::repository::Repository>>,
        archive: &mut tar::Builder<impl Write + 'static>,
        parent_path: &Path,
        progress: &crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: &IsIgnoredFn,
    ) -> Result<(), anyhow::Error> {
        let mut stack: Vec<(PathBuf, &Entry)> = vec![(parent_path.to_path_buf(), entry)];

        while let Some((parent_path, entry)) = stack.pop() {
            let path = parent_path.join(entry.name());

            let Some(path) = (is_ignored)(Self::ddup_bak_entry_to_file_type(entry), path) else {
                continue;
            };

            let mut entry_header = tar::Header::new_gnu();
            entry_header.set_size(0);
            entry_header.set_mode(entry.mode().bits());
            entry_header.set_mtime(
                entry
                    .mtime()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            );

            match entry {
                Entry::Directory(dir) => {
                    entry_header.set_entry_type(tar::EntryType::Directory);

                    archive.append_data(&mut entry_header, &path, std::io::empty())?;

                    for child in dir.entries.iter().rev() {
                        stack.push((path.clone(), child));
                    }
                }
                Entry::File(file) => {
                    entry_header.set_entry_type(tar::EntryType::Regular);
                    entry_header.set_size(file.size_real);

                    let reader = progress
                        .counting_reader(repository.entry_reader(Entry::File(file.clone()))?);
                    let reader = FixedReader::new_with_fixed_bytes(reader, file.size_real as usize);

                    archive.append_data(&mut entry_header, &path, reader)?;
                    progress.increment_files();
                }
                Entry::Symlink(link) => {
                    entry_header.set_entry_type(tar::EntryType::Symlink);

                    archive.append_link(&mut entry_header, &path, &link.target)?;
                    progress.increment_files();
                }
            }
        }

        Ok(())
    }

    fn itaf_convert_entries<W: Write>(
        entry: &Entry,
        repository: &Option<Arc<ddup_bak::repository::Repository>>,
        itaf_enc: &mut ItafEncoder<W>,
        parent_path: &Path,
        progress: &crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: &IsIgnoredFn,
    ) -> Result<(), anyhow::Error> {
        enum Work<'a> {
            Visit {
                parent_path: PathBuf,
                entry: &'a Entry,
            },
            ExitDir,
        }

        let mut stack: Vec<Work> = vec![Work::Visit {
            parent_path: parent_path.to_path_buf(),
            entry,
        }];

        while let Some(work) = stack.pop() {
            let (parent_path, entry) = match work {
                Work::ExitDir => {
                    itaf_enc.exit_dir()?;
                    continue;
                }
                Work::Visit { parent_path, entry } => (parent_path, entry),
            };

            let path = parent_path.join(entry.name());

            let Some(path) = (is_ignored)(Self::ddup_bak_entry_to_file_type(entry), path) else {
                continue;
            };

            let mtime = entry
                .mtime()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let meta = Metadata {
                uid: 0,
                gid: 0,
                mode: entry.mode().bits(),
                modified: std::time::UNIX_EPOCH + mtime,
            };
            let name: compact_str::CompactString = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into();

            match entry {
                Entry::Directory(dir) => {
                    if itaf::spec::validate_name(&name).is_ok() {
                        itaf_enc.enter_dir(&name, &meta)?;
                        stack.push(Work::ExitDir);
                        for child in dir.entries.iter().rev() {
                            stack.push(Work::Visit {
                                parent_path: path.clone(),
                                entry: child,
                            });
                        }
                    }
                }
                Entry::File(file) => {
                    if itaf::spec::validate_name(&name).is_ok() {
                        let reader = progress
                            .counting_reader(repository.entry_reader(Entry::File(file.clone()))?);
                        let mut reader =
                            FixedReader::new_with_fixed_bytes(reader, file.size_real as usize);
                        itaf_enc.add_file(&name, &meta, file.size_real, &mut { reader })?;
                        progress.increment_files();
                    }
                }
                Entry::Symlink(link) => {
                    if itaf::spec::validate_name(&name).is_ok() {
                        itaf_enc.add_symlink(&name, &link.target, false, &meta)?;
                        progress.increment_files();
                    }
                }
            }
        }

        Ok(())
    }

    fn zip_convert_entries(
        entry: &Entry,
        repository: &Option<Arc<ddup_bak::repository::Repository>>,
        zip: &mut zip::ZipWriter<zip::write::StreamWriter<crate::io::pipe::SyncPipeWriter>>,
        compression_level: CompressionLevel,
        parent_path: &Path,
        progress: &crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: &IsIgnoredFn,
    ) -> Result<(), anyhow::Error> {
        let mut stack: Vec<(PathBuf, &Entry)> = vec![(parent_path.to_path_buf(), entry)];

        while let Some((parent_path, entry)) = stack.pop() {
            let path = parent_path.join(entry.name());

            let Some(path) = (is_ignored)(Self::ddup_bak_entry_to_file_type(entry), path) else {
                continue;
            };

            let size = match entry {
                Entry::File(file) => file.size,
                _ => 0,
            };

            let mut options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_level(Some(compression_level.to_deflate_level() as i64))
                .unix_permissions(entry.mode().bits())
                .large_file(size >= u32::MAX as u64);
            {
                let mtime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(entry.mtime());

                options = options.last_modified_time(zip::DateTime::from_date_and_time(
                    mtime.year() as u16,
                    mtime.month() as u8,
                    mtime.day() as u8,
                    mtime.hour() as u8,
                    mtime.minute() as u8,
                    mtime.second() as u8,
                )?);
            }

            match entry {
                Entry::Directory(dir) => {
                    zip.add_directory(path.to_string_lossy(), options)?;

                    for child in dir.entries.iter().rev() {
                        stack.push((path.clone(), child));
                    }
                }
                Entry::File(file) => {
                    let reader = progress
                        .counting_reader(repository.entry_reader(Entry::File(file.clone()))?);
                    let mut reader =
                        FixedReader::new_with_fixed_bytes(reader, file.size_real as usize);

                    zip.start_file(path.to_string_lossy(), options)?;
                    crate::io::copy(&mut reader, zip)?;
                    progress.increment_files();
                }
                Entry::Symlink(link) => {
                    zip.add_symlink(&link.name, &link.target, options)?;
                    progress.increment_files();
                }
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualDdupBakArchive {
    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        if path.as_ref() == Path::new("") || path.as_ref() == Path::new("/") {
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(0o755),
                size: 0,
                modified: None,
                created: None,
            });
        }

        let archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();

        let entry = archive.find_archive_entry(&path).ok_or_else(|| {
            anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            ))
        })?;

        Ok(FileMetadata {
            file_type: Self::ddup_bak_entry_to_file_type(entry),
            permissions: match entry {
                ddup_bak::archive::entries::Entry::Directory(_) => {
                    PortablePermissions::from_mode_dir(entry.mode().bits())
                }
                _ => PortablePermissions::from_mode_file(entry.mode().bits()),
            },
            size: match &entry {
                ddup_bak::archive::entries::Entry::File(f) => f.size_real,
                _ => 0,
            },
            modified: Some(
                std::time::SystemTime::UNIX_EPOCH
                    + entry.mtime().duration_since(std::time::UNIX_EPOCH)?,
            ),
            created: None,
        })
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
        let repository = self.repository.clone();
        let mime_cache = self.mime_cache.clone();
        let path = path.as_ref().to_path_buf();

        tokio::task::spawn_blocking(move || -> Result<DirectoryEntry, anyhow::Error> {
            let entry = archive.find_archive_entry(&path).ok_or_else(|| {
                anyhow::anyhow!(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "File not found"
                ))
            })?;

            Ok(Self::ddup_bak_entry_to_directory_entry(
                &archive_created,
                &path,
                entry,
                &repository,
                &mime_cache,
                None,
            ))
        })
        .await?
    }

    fn directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let path = path.as_ref();

        let entry = self.archive.find_archive_entry(path).ok_or_else(|| {
            anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            ))
        })?;

        Ok(Self::ddup_bak_entry_to_directory_entry(
            &self.archive_created,
            path,
            entry,
            &self.repository,
            &self.mime_cache,
            Some(buffer),
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
        let repository = self.repository.clone();
        let mime_cache = self.mime_cache.clone();
        let sizes = self.sizes.clone();
        let path = path.as_ref().to_path_buf();

        let entries =
            tokio::task::spawn_blocking(move || -> Result<DirectoryListing, anyhow::Error> {
                let entry = match archive.find_archive_entry(&path) {
                    Some(entry) => entry,
                    None => {
                        let directory_entry_count = archive
                            .entries()
                            .iter()
                            .filter(|e| e.is_directory())
                            .count();

                        let mut directory_entries = Vec::new();
                        directory_entries.reserve_exact(directory_entry_count);
                        let mut other_entries = Vec::new();
                        other_entries
                            .reserve_exact(archive.entries().len() - directory_entry_count);

                        let mut scratch = PathBuf::new();
                        for entry in archive.entries() {
                            scratch.clear();
                            scratch.push(entry.name());
                            match (is_ignored)(
                                Self::ddup_bak_entry_to_file_type(entry),
                                std::mem::take(&mut scratch),
                            ) {
                                Some(kept) => scratch = kept,
                                None => continue,
                            }

                            if entry.is_directory() {
                                directory_entries.push(entry);
                            } else {
                                other_entries.push(entry);
                            }
                        }

                        sort_dir_entries_by_size(&mut directory_entries, sort, &sizes, &path);
                        other_entries.sort_unstable_by(|a, b| a.cmp_sort(b, sort));

                        let total_entries = directory_entries.len() + other_entries.len();
                        let mut entries = Vec::new();

                        if let Some(per_page) = per_page {
                            let start = (page - 1) * per_page;

                            for entry in directory_entries
                                .into_iter()
                                .chain(other_entries)
                                .skip(start)
                                .take(per_page)
                            {
                                let path = path.join(entry.name());
                                entries.push(Self::ddup_bak_entry_to_directory_entry(
                                    &archive_created,
                                    &path,
                                    entry,
                                    &repository,
                                    &mime_cache,
                                    None,
                                ));
                            }
                        } else {
                            for entry in directory_entries.into_iter().chain(other_entries) {
                                let path = path.join(entry.name());
                                entries.push(Self::ddup_bak_entry_to_directory_entry(
                                    &archive_created,
                                    &path,
                                    entry,
                                    &repository,
                                    &mime_cache,
                                    None,
                                ));
                            }
                        }

                        return Ok(DirectoryListing {
                            total_entries,
                            entries,
                        });
                    }
                };

                match entry {
                    ddup_bak::archive::entries::Entry::Directory(dir) => {
                        let mut directory_entries = Vec::new();
                        directory_entries
                            .reserve_exact(dir.entries.iter().filter(|e| e.is_directory()).count());
                        let mut other_entries = Vec::new();
                        other_entries.reserve_exact(
                            dir.entries.iter().filter(|e| !e.is_directory()).count(),
                        );

                        let mut scratch = PathBuf::new();
                        for entry in &dir.entries {
                            scratch.clear();
                            scratch.push(entry.name());
                            match (is_ignored)(
                                Self::ddup_bak_entry_to_file_type(entry),
                                std::mem::take(&mut scratch),
                            ) {
                                Some(kept) => scratch = kept,
                                None => continue,
                            }

                            if entry.is_directory() {
                                directory_entries.push(entry);
                            } else {
                                other_entries.push(entry);
                            }
                        }

                        sort_dir_entries_by_size(&mut directory_entries, sort, &sizes, &path);
                        other_entries.sort_unstable_by(|a, b| a.cmp_sort(b, sort));

                        let total_entries = directory_entries.len() + other_entries.len();
                        let mut entries = Vec::new();

                        if let Some(per_page) = per_page {
                            let start = (page - 1) * per_page;

                            for entry in directory_entries
                                .into_iter()
                                .chain(other_entries)
                                .skip(start)
                                .take(per_page)
                            {
                                let path = path.join(entry.name());
                                entries.push(Self::ddup_bak_entry_to_directory_entry(
                                    &archive_created,
                                    &path,
                                    entry,
                                    &repository,
                                    &mime_cache,
                                    None,
                                ));
                            }
                        } else {
                            for entry in directory_entries.into_iter().chain(other_entries) {
                                let path = path.join(entry.name());
                                entries.push(Self::ddup_bak_entry_to_directory_entry(
                                    &archive_created,
                                    &path,
                                    entry,
                                    &repository,
                                    &mime_cache,
                                    None,
                                ));
                            }
                        }

                        Ok(DirectoryListing {
                            total_entries,
                            entries,
                        })
                    }
                    _ => Err(anyhow::anyhow!("Expected a directory entry")),
                }
            })
            .await??;

        Ok(entries)
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();

        let entry = archive.find_archive_entry(&path).ok_or_else(|| {
            anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            ))
        })?;

        let size = match entry {
            ddup_bak::archive::entries::Entry::File(file) => file.size_real,
            _ => return Err(anyhow::anyhow!("Not a file")),
        };

        let entry_reader = self.repository.entry_reader(entry.clone())?;

        Ok(FileRead {
            size,
            total_size: size,
            reader_range: None,
            reader: entry_reader,
        })
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();

        let entry = archive.find_archive_entry(&path).ok_or_else(|| {
            anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            ))
        })?;

        let size = match entry {
            ddup_bak::archive::entries::Entry::File(file) => file.size_real,
            _ => return Err(anyhow::anyhow!("Not a file")),
        };

        let mut entry_reader = self.repository.entry_reader(entry.clone())?;
        let (reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new_with_eof(reader);
        let mut writer = writer.into_sync();

        crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
            crate::io::pipe::copy_and_shutdown(&mut entry_reader, &mut writer)?;

            Ok(())
        });

        Ok(AsyncFileRead {
            size,
            total_size: size,
            reader_range: None,
            reader: Box::new(reader),
        })
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let archive = self.archive.clone();
        let entry = archive
            .find_archive_entry(path.as_ref())
            .ok_or_else(|| anyhow::anyhow!("Entry not found"))?;

        match entry {
            ddup_bak::archive::entries::Entry::Symlink(link) => Ok(PathBuf::from(&link.target)),
            _ => Err(anyhow::anyhow!("Not a symlink")),
        }
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
        let path = path.as_ref().to_path_buf();
        let repository = self.repository.clone();

        let (pipe_reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (pipe_reader, signal) = crate::io::fallible_reader::FallibleReader::new(pipe_reader);

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let writer = writer.into_sync();
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    match archive.find_archive_entry(&path) {
                        Some(entry) => {
                            let entry = match entry {
                                ddup_bak::archive::entries::Entry::Directory(entry) => entry,
                                _ => {
                                    return Err(anyhow::anyhow!(std::io::Error::new(
                                        std::io::ErrorKind::NotFound,
                                        "File not found"
                                    )));
                                }
                            };

                            for entry in entry.entries.iter() {
                                Self::zip_convert_entries(
                                    entry,
                                    &repository,
                                    &mut zip,
                                    compression_level,
                                    Path::new(""),
                                    &progress,
                                    &is_ignored,
                                )?;
                            }
                        }
                        None => {
                            if path.components().count() == 0 {
                                for entry in archive.entries() {
                                    Self::zip_convert_entries(
                                        entry,
                                        &repository,
                                        &mut zip,
                                        compression_level,
                                        Path::new(""),
                                        &progress,
                                        &is_ignored,
                                    )?;
                                }
                            }
                        }
                    };

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

                    match archive.find_archive_entry(&path) {
                        Some(entry) => {
                            let entry = match entry {
                                ddup_bak::archive::entries::Entry::Directory(entry) => entry,
                                _ => {
                                    return Err(anyhow::anyhow!(std::io::Error::new(
                                        std::io::ErrorKind::NotFound,
                                        "File not found"
                                    )));
                                }
                            };

                            for entry in entry.entries.iter() {
                                Self::tar_convert_entries(
                                    entry,
                                    &repository,
                                    &mut tar,
                                    Path::new(""),
                                    &progress,
                                    &is_ignored,
                                )?;
                            }
                        }
                        None => {
                            if path.components().count() == 0 {
                                for entry in archive.entries() {
                                    Self::tar_convert_entries(
                                        entry,
                                        &repository,
                                        &mut tar,
                                        Path::new(""),
                                        &progress,
                                        &is_ignored,
                                    )?;
                                }
                            }
                        }
                    };

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

                    match archive.find_archive_entry(&path) {
                        Some(entry) => {
                            let entry = match entry {
                                ddup_bak::archive::entries::Entry::Directory(entry) => entry,
                                _ => {
                                    return Err(anyhow::anyhow!(std::io::Error::new(
                                        std::io::ErrorKind::NotFound,
                                        "File not found"
                                    )));
                                }
                            };

                            for entry in entry.entries.iter() {
                                Self::itaf_convert_entries(
                                    entry,
                                    &repository,
                                    &mut itaf_enc,
                                    Path::new(""),
                                    &progress,
                                    &is_ignored,
                                )?;
                            }
                        }
                        None => {
                            if path.components().count() == 0 {
                                for entry in archive.entries() {
                                    Self::itaf_convert_entries(
                                        entry,
                                        &repository,
                                        &mut itaf_enc,
                                        Path::new(""),
                                        &progress,
                                        &is_ignored,
                                    )?;
                                }
                            }
                        }
                    };

                    let mut inner = itaf_enc.finish()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            _ => {
                tracing::error!(
                    "unsupported archive format for ddup_bak vfs: {}",
                    archive_format.extension()
                );
            }
        }

        Ok(pipe_reader)
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        struct IgnoreWalkDir {
            queue: VecDeque<(PathBuf, ddup_bak::archive::entries::Entry)>,
            is_ignored: IsIgnoredFn,
        }

        impl DirectoryWalk for IgnoreWalkDir {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                if let Some((path, entry)) = self.queue.pop_front() {
                    let file_type = VirtualDdupBakArchive::ddup_bak_entry_to_file_type(&entry);

                    if let ddup_bak::archive::entries::Entry::Directory(dir) = &entry {
                        for child in &dir.entries {
                            let child_path = path.join(child.name());
                            let child_type =
                                VirtualDdupBakArchive::ddup_bak_entry_to_file_type(child);

                            if let Some(child_path) = (self.is_ignored)(child_type, child_path) {
                                self.queue.push_back((child_path, child.clone()));
                            }
                        }
                    }
                    return Some(Ok((file_type, path)));
                }
                None
            }
        }

        let archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();
        let mut queue = VecDeque::new();

        if let Some(entry) = archive.find_archive_entry(&path) {
            if let ddup_bak::archive::entries::Entry::Directory(dir) = entry {
                for child in &dir.entries {
                    let child_path = path.join(child.name());
                    let child_type = Self::ddup_bak_entry_to_file_type(child);
                    if let Some(child_path) = (is_ignored)(child_type, child_path) {
                        queue.push_back((child_path, child.clone()));
                    }
                }
            }
        } else if path.components().count() == 0 {
            for child in archive.entries() {
                let child_path = path.join(child.name());
                let child_type = Self::ddup_bak_entry_to_file_type(child);
                if let Some(child_path) = (is_ignored)(child_type, child_path) {
                    queue.push_back((child_path, child.clone()));
                }
            }
        }

        Ok(Box::new(IgnoreWalkDir { queue, is_ignored }))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        struct AsyncIgnoreWalkDir {
            queue: VecDeque<(PathBuf, ddup_bak::archive::entries::Entry)>,
            is_ignored: IsIgnoredFn,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryWalk for AsyncIgnoreWalkDir {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                if let Some((path, entry)) = self.queue.pop_front() {
                    let file_type = VirtualDdupBakArchive::ddup_bak_entry_to_file_type(&entry);

                    if let ddup_bak::archive::entries::Entry::Directory(dir) = &entry {
                        for child in &dir.entries {
                            let child_path = path.join(child.name());
                            let child_type =
                                VirtualDdupBakArchive::ddup_bak_entry_to_file_type(child);

                            if let Some(child_path) =
                                self.is_ignored.call_async(child_type, child_path).await
                            {
                                self.queue.push_back((child_path, child.clone()));
                            }
                        }
                    }
                    return Some(Ok((file_type, path)));
                }
                None
            }
        }

        let archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();
        let mut queue = VecDeque::new();

        if let Some(entry) = archive.find_archive_entry(&path) {
            if let ddup_bak::archive::entries::Entry::Directory(dir) = entry {
                for child in &dir.entries {
                    let child_path = path.join(child.name());
                    let child_type = Self::ddup_bak_entry_to_file_type(child);
                    if let Some(child_path) = is_ignored.call_async(child_type, child_path).await {
                        queue.push_back((child_path, child.clone()));
                    }
                }
            }
        } else if path.components().count() == 0 {
            for child in archive.entries() {
                let child_path = path.join(child.name());
                let child_type = Self::ddup_bak_entry_to_file_type(child);
                if let Some(child_path) = is_ignored.call_async(child_type, child_path).await {
                    queue.push_back((child_path, child.clone()));
                }
            }
        }

        Ok(Box::new(AsyncIgnoreWalkDir { queue, is_ignored }))
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        struct DdupStreamWalk {
            repository: Option<Arc<ddup_bak::repository::Repository>>,
            queue: VecDeque<(PathBuf, ddup_bak::archive::entries::Entry)>,
            is_ignored: IsIgnoredFn,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryStreamWalk for DdupStreamWalk {
            async fn next_entry(
                &mut self,
            ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>
            {
                if let Some((path, entry)) = self.queue.pop_front() {
                    let file_type = VirtualDdupBakArchive::ddup_bak_entry_to_file_type(&entry);

                    if let ddup_bak::archive::entries::Entry::Directory(dir) = &entry {
                        for child in &dir.entries {
                            let child_path = path.join(child.name());
                            let child_type =
                                VirtualDdupBakArchive::ddup_bak_entry_to_file_type(child);
                            if let Some(child_path) =
                                self.is_ignored.call_async(child_type, child_path).await
                            {
                                self.queue.push_back((child_path, child.clone()));
                            }
                        }
                    }

                    let stream: AsyncReadableFileStream = if entry.is_file() {
                        match self.repository.entry_reader(entry) {
                            Ok(mut entry_reader) => {
                                let (reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
                                let (reader, signal) =
                                    crate::io::fallible_reader::FallibleReader::new_with_eof(
                                        reader,
                                    );
                                let mut writer = writer.into_sync();
                                crate::spawn_blocking_signalled(
                                    signal,
                                    move || -> Result<(), anyhow::Error> {
                                        crate::io::pipe::copy_and_shutdown(
                                            &mut entry_reader,
                                            &mut writer,
                                        )?;

                                        Ok(())
                                    },
                                );
                                Box::new(reader)
                            }
                            Err(err) => return Some(Err(err)),
                        }
                    } else {
                        Box::new(tokio::io::empty())
                    };

                    return Some(Ok((file_type, path, stream)));
                }
                None
            }
        }

        let archive = self.archive.clone();
        let path = path.as_ref().to_path_buf();
        let mut queue = VecDeque::new();

        if let Some(entry) = archive.find_archive_entry(&path) {
            if let ddup_bak::archive::entries::Entry::Directory(dir) = entry {
                for child in &dir.entries {
                    let child_path = path.join(child.name());
                    let child_type = Self::ddup_bak_entry_to_file_type(child);
                    if let Some(child_path) = is_ignored.call_async(child_type, child_path).await {
                        queue.push_back((child_path, child.clone()));
                    }
                }
            }
        } else if path.components().count() == 0 {
            for child in archive.entries() {
                let child_path = path.join(child.name());
                let child_type = Self::ddup_bak_entry_to_file_type(child);
                if let Some(child_path) = is_ignored.call_async(child_type, child_path).await {
                    queue.push_back((child_path, child.clone()));
                }
            }
        }

        Ok(Box::new(DdupStreamWalk {
            repository: self.repository.clone(),
            queue,
            is_ignored,
        }))
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
