use crate::{
    io::{
        SafeSliceExt,
        abort::{AbortGuard, AbortListener, AbortReader, AbortWriter},
        compression::{CompressionType, reader::CompressionReaderMt},
        counting_writer::CountingWriter,
    },
    server::filesystem::cap::FileType,
    threading::InFlightPermit,
    utils::PortablePermissions,
};
use serde::{Deserialize, Serialize};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};
use utoipa::ToSchema;

pub mod create;
pub mod multi_reader;

const TAR_CHUNK_BYTES: usize = 1024 * 1024;
const TAR_IN_FLIGHT_CHUNKS: usize = 64;
/// Jobs queued per tar writer. Queued content is already bounded by the in-flight
/// chunk permits, so this only has to be deep enough that the reader can move on
/// to the next directory while a writer drains the previous one.
const TAR_WRITER_QUEUE_JOBS: usize = TAR_IN_FLIGHT_CHUNKS;
/// Bytes a zip worker collects before writing, so an inflate step of a few KiB
/// does not become a write syscall of its own.
const ZIP_COPY_BUFFER: usize = 256 * 1024;
/// Entries of one directory handed to a zip worker at a time; larger directories
/// are split so a single huge one still spreads across the workers.
const ZIP_GROUP_MAX_ENTRIES: usize = 512;
/// Bytes of one directory handed to a zip worker at a time, so a directory of a
/// few large files is still shared between workers instead of extracted by one.
const ZIP_GROUP_MAX_BYTES: u64 = 16 * 1024 * 1024;

enum TarContent {
    Whole(Vec<u8>, InFlightPermit),
    Chunks(async_channel::Receiver<(Vec<u8>, InFlightPermit)>),
}

enum TarJob {
    File {
        path: PathBuf,
        content: TarContent,
        permissions: Option<PortablePermissions>,
        modified_time: Option<std::time::SystemTime>,
    },
    Symlink {
        path: PathBuf,
        link: PathBuf,
        modified_time: Option<std::time::SystemTime>,
    },
}

/// Picks the writer for an entry by its parent directory, so every file of a
/// directory is created by the same thread and writers do not serialize on the
/// directory's inode lock.
fn tar_shard(path: &Path, shards: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    path.parent().unwrap_or(path).hash(&mut hasher);

    (hasher.finish() % shards.max(1) as u64) as usize
}

fn apply_tar_job(
    destination_filesystem: &Arc<dyn super::virtualfs::VirtualWritableFilesystem>,
    progress: &create::ArchiveProgress,
    job: TarJob,
) -> Result<(), anyhow::Error> {
    match job {
        TarJob::File {
            path,
            content,
            permissions,
            modified_time,
        } => {
            let run = || -> Result<(), anyhow::Error> {
                let mut writer = destination_filesystem.create_file_with_metadata(
                    &path,
                    permissions,
                    modified_time,
                )?;

                match content {
                    TarContent::Whole(data, _permit) => writer.write_all(&data)?,
                    TarContent::Chunks(chunks) => {
                        while let Ok((chunk, _permit)) = chunks.recv_blocking() {
                            writer.write_all(&chunk)?;
                        }
                    }
                }

                writer.flush()?;
                drop(writer);

                progress.increment_files();

                Ok(())
            };

            if let Err(err) = run() {
                tracing::debug!(
                    path = %path.display(),
                    "failed to extract file from archive: {:#?}",
                    err
                );

                return Err(err);
            }
        }
        TarJob::Symlink {
            path,
            link,
            modified_time,
        } => {
            if let Err(err) = destination_filesystem.create_symlink(&link, &path) {
                tracing::debug!(
                    path = %path.display(),
                    "failed to create symlink from archive: {:#?}",
                    err
                );
            } else if let Some(modified_time) = modified_time {
                destination_filesystem.set_times(&path, FileType::Symlink, modified_time, None)?;
            }
        }
    }

    Ok(())
}

enum ZipEntryKind {
    File,
    Symlink,
}

struct ZipEntryPlan {
    index: usize,
    kind: ZipEntryKind,
    path: PathBuf,
    size: u64,
    permissions: Option<PortablePermissions>,
    modified_time: Option<std::time::SystemTime>,
}

struct ZipDirectory {
    path: PathBuf,
    mode: u32,
    modified_time: Option<std::time::SystemTime>,
}

/// Splits a plan sorted by parent directory into runs a single worker extracts,
/// so no two workers create files in the same directory at the same time.
fn zip_entry_groups(plan: &[ZipEntryPlan]) -> Vec<std::ops::Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    let mut bytes = 0;

    for (index, entry) in plan.iter().enumerate() {
        let same_parent = plan
            .get(start)
            .is_some_and(|first| first.path.parent() == entry.path.parent());

        if index > start
            && (!same_parent
                || index - start >= ZIP_GROUP_MAX_ENTRIES
                || bytes >= ZIP_GROUP_MAX_BYTES)
        {
            groups.push(start..index);
            start = index;
            bytes = 0;
        }

        bytes += entry.size;
    }

    if start < plan.len() {
        groups.push(start..plan.len());
    }

    groups
}

fn resolve_entry_path(destination: &Path, path: &Path) -> Option<PathBuf> {
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return None;
    }

    Some(super::cap::CapFilesystem::resolve_path(
        &destination.join(path),
    ))
}

pub fn generated_archive_name(extension: &str) -> compact_str::CompactString {
    compact_str::format_compact!(
        "archive-{}.{}",
        chrono::Local::now().format("%Y-%m-%dT%H%M%S%z"),
        extension
    )
}

#[derive(Debug, Clone, Copy)]
pub enum ArchiveType {
    None,
    Tar,
    Zip,
    Rar,
    SevenZip,
    Ddup,
    Pxar,
}

#[derive(Debug, ToSchema, Deserialize, Serialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Tar,
    #[default]
    TarGz,
    TarXz,
    TarLzip,
    TarBz2,
    TarLz4,
    TarZstd,
    Zip,
    SevenZip,
}

impl ArchiveFormat {
    #[inline]
    pub fn variants() -> &'static [ArchiveFormat] {
        &[
            ArchiveFormat::Tar,
            ArchiveFormat::TarGz,
            ArchiveFormat::TarXz,
            ArchiveFormat::TarLzip,
            ArchiveFormat::TarBz2,
            ArchiveFormat::TarLz4,
            ArchiveFormat::TarZstd,
            ArchiveFormat::Zip,
            ArchiveFormat::SevenZip,
        ]
    }

    #[inline]
    pub fn compression_format(self) -> CompressionType {
        match self {
            ArchiveFormat::Tar => CompressionType::None,
            ArchiveFormat::TarGz => CompressionType::Gz,
            ArchiveFormat::TarXz => CompressionType::Xz,
            ArchiveFormat::TarLzip => CompressionType::Lzip,
            ArchiveFormat::TarBz2 => CompressionType::Bz2,
            ArchiveFormat::TarLz4 => CompressionType::Lz4,
            ArchiveFormat::TarZstd => CompressionType::Zstd,
            _ => CompressionType::None,
        }
    }

    #[inline]
    pub fn extension(self) -> &'static str {
        match self {
            ArchiveFormat::Tar => "tar",
            ArchiveFormat::TarGz => "tar.gz",
            ArchiveFormat::TarXz => "tar.xz",
            ArchiveFormat::TarLzip => "tar.lz",
            ArchiveFormat::TarBz2 => "tar.bz2",
            ArchiveFormat::TarLz4 => "tar.lz4",
            ArchiveFormat::TarZstd => "tar.zst",
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::SevenZip => "7z",
        }
    }

    #[inline]
    pub fn mime_type(self) -> &'static str {
        match self {
            ArchiveFormat::Tar => "application/x-tar",
            ArchiveFormat::TarGz => "application/gzip",
            ArchiveFormat::TarXz => "application/x-xz",
            ArchiveFormat::TarLzip => "application/x-lzip",
            ArchiveFormat::TarBz2 => "application/x-bzip2",
            ArchiveFormat::TarLz4 => "application/x-lz4",
            ArchiveFormat::TarZstd => "application/zstd",
            ArchiveFormat::Zip => "application/zip",
            ArchiveFormat::SevenZip => "application/x-7z-compressed",
        }
    }
}

impl std::str::FromStr for ArchiveFormat {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with(".tar") {
            Ok(ArchiveFormat::Tar)
        } else if s.ends_with(".tar.gz") {
            Ok(ArchiveFormat::TarGz)
        } else if s.ends_with(".tar.xz") {
            Ok(ArchiveFormat::TarXz)
        } else if s.ends_with(".tar.lz") {
            Ok(ArchiveFormat::TarLzip)
        } else if s.ends_with(".tar.bz2") {
            Ok(ArchiveFormat::TarBz2)
        } else if s.ends_with(".tar.lz4") {
            Ok(ArchiveFormat::TarLz4)
        } else if s.ends_with(".tar.zst") {
            Ok(ArchiveFormat::TarZstd)
        } else if s.ends_with(".zip") {
            Ok(ArchiveFormat::Zip)
        } else if s.ends_with(".7z") {
            Ok(ArchiveFormat::SevenZip)
        } else {
            Err("Invalid archive format")
        }
    }
}

#[derive(ToSchema, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum StreamableArchiveFormat {
    Tar,
    #[default]
    TarGz,
    TarXz,
    TarLzip,
    TarBz2,
    TarLz4,
    TarZstd,

    Itaf,
    ItafGz,
    ItafXz,
    ItafLzip,
    ItafBz2,
    ItafLz4,
    ItafZstd,

    Zip,
}

impl StreamableArchiveFormat {
    #[inline]
    pub fn compression_format(self) -> CompressionType {
        match self {
            StreamableArchiveFormat::Tar | StreamableArchiveFormat::Itaf => CompressionType::None,
            StreamableArchiveFormat::TarGz | StreamableArchiveFormat::ItafGz => CompressionType::Gz,
            StreamableArchiveFormat::TarXz | StreamableArchiveFormat::ItafXz => CompressionType::Xz,
            StreamableArchiveFormat::TarLzip | StreamableArchiveFormat::ItafLzip => {
                CompressionType::Lzip
            }
            StreamableArchiveFormat::TarBz2 | StreamableArchiveFormat::ItafBz2 => {
                CompressionType::Bz2
            }
            StreamableArchiveFormat::TarLz4 | StreamableArchiveFormat::ItafLz4 => {
                CompressionType::Lz4
            }
            StreamableArchiveFormat::TarZstd | StreamableArchiveFormat::ItafZstd => {
                CompressionType::Zstd
            }
            StreamableArchiveFormat::Zip => CompressionType::None,
        }
    }

    #[inline]
    pub fn extension(self) -> &'static str {
        match self {
            StreamableArchiveFormat::Tar => "tar",
            StreamableArchiveFormat::TarGz => "tar.gz",
            StreamableArchiveFormat::TarXz => "tar.xz",
            StreamableArchiveFormat::TarLzip => "tar.lz",
            StreamableArchiveFormat::TarBz2 => "tar.bz2",
            StreamableArchiveFormat::TarLz4 => "tar.lz4",
            StreamableArchiveFormat::TarZstd => "tar.zst",
            StreamableArchiveFormat::Itaf => "itaf",
            StreamableArchiveFormat::ItafGz => "itaf.gz",
            StreamableArchiveFormat::ItafXz => "itaf.xz",
            StreamableArchiveFormat::ItafLzip => "itaf.lz",
            StreamableArchiveFormat::ItafBz2 => "itaf.bz2",
            StreamableArchiveFormat::ItafLz4 => "itaf.lz4",
            StreamableArchiveFormat::ItafZstd => "itaf.zst",
            StreamableArchiveFormat::Zip => "zip",
        }
    }

    #[inline]
    pub fn mime_type(self) -> &'static str {
        match self {
            StreamableArchiveFormat::Tar => "application/x-tar",
            StreamableArchiveFormat::TarGz | StreamableArchiveFormat::ItafGz => "application/gzip",
            StreamableArchiveFormat::TarXz | StreamableArchiveFormat::ItafXz => "application/x-xz",
            StreamableArchiveFormat::TarLzip | StreamableArchiveFormat::ItafLzip => {
                "application/x-lzip"
            }
            StreamableArchiveFormat::TarBz2 | StreamableArchiveFormat::ItafBz2 => {
                "application/x-bzip2"
            }
            StreamableArchiveFormat::TarLz4 | StreamableArchiveFormat::ItafLz4 => {
                "application/x-lz4"
            }
            StreamableArchiveFormat::TarZstd | StreamableArchiveFormat::ItafZstd => {
                "application/zstd"
            }
            StreamableArchiveFormat::Itaf => "application/octet-stream",
            StreamableArchiveFormat::Zip => "application/zip",
        }
    }

    #[inline]
    pub const fn is_tar(self) -> bool {
        matches!(
            self,
            StreamableArchiveFormat::Tar
                | StreamableArchiveFormat::TarGz
                | StreamableArchiveFormat::TarXz
                | StreamableArchiveFormat::TarLzip
                | StreamableArchiveFormat::TarBz2
                | StreamableArchiveFormat::TarLz4
                | StreamableArchiveFormat::TarZstd
        )
    }

    #[inline]
    pub const fn is_itaf(self) -> bool {
        matches!(
            self,
            StreamableArchiveFormat::Itaf
                | StreamableArchiveFormat::ItafGz
                | StreamableArchiveFormat::ItafXz
                | StreamableArchiveFormat::ItafLzip
                | StreamableArchiveFormat::ItafBz2
                | StreamableArchiveFormat::ItafLz4
                | StreamableArchiveFormat::ItafZstd
        )
    }
}

pub fn zip_entry_get_modified_time(
    entry: &zip::read::ZipFile<impl std::io::Read>,
) -> Option<std::time::SystemTime> {
    for field in entry.extra_data_fields() {
        if let zip::extra_fields::ExtraField::ExtendedTimestamp(ext) = field
            && let Some(mod_time) = ext.mod_time()
        {
            return Some(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mod_time as u64),
            );
        }

        if let zip::extra_fields::ExtraField::Ntfs(ntfs) = field {
            let mtime = sevenz_rust2::NtTime::new(ntfs.mtime());

            return Some(std::time::SystemTime::from(mtime));
        }
    }

    if let Some(time) = entry.last_modified()
        && time.is_valid()
    {
        let chrono_date = chrono::NaiveDate::from_ymd_opt(
            time.year() as i32,
            time.month() as u32,
            time.day() as u32,
        )?;
        let chrono_time = chrono::NaiveTime::from_hms_opt(
            time.hour() as u32,
            time.minute() as u32,
            time.second() as u32,
        )?;

        return Some(
            std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(
                    chrono_date.and_time(chrono_time).and_utc().timestamp() as u64,
                ),
        );
    }

    None
}

pub fn zip_entry_get_created_time(
    entry: &zip::read::ZipFile<impl std::io::Read>,
) -> Option<std::time::SystemTime> {
    for field in entry.extra_data_fields() {
        if let zip::extra_fields::ExtraField::ExtendedTimestamp(ext) = field
            && let Some(cr_time) = ext.cr_time()
        {
            return Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(cr_time as u64));
        }

        if let zip::extra_fields::ExtraField::Ntfs(ntfs) = field {
            let ctime = sevenz_rust2::NtTime::new(ntfs.ctime());

            return Some(std::time::SystemTime::from(ctime));
        }
    }

    None
}

pub struct Archive {
    pub compression: CompressionType,
    pub archive: ArchiveType,

    pub server: crate::server::Server,

    pub file: File,
    pub path: PathBuf,
}

impl Archive {
    pub const MAX_DIRECTORY_MTIME_ENTRIES: usize = 10_000_000;

    pub async fn open(server: crate::server::Server, path: PathBuf) -> Result<Self, anyhow::Error> {
        let mut file = server.filesystem.async_open(&path).await?;

        let mut header = [0; 64];
        #[allow(clippy::unused_io_amount)]
        file.read(&mut header).await?;

        let (compression_format, archive_format) = Self::detect(&path, &header);

        tracing::debug!(
            path = %path.display(),
            "inferred archive format: {:?}, compression format: {:?}",
            archive_format,
            compression_format
        );

        Ok(Self {
            compression: compression_format,
            archive: archive_format,
            server,
            file,
            path,
        })
    }

    pub fn detect(path: impl AsRef<Path>, header: &[u8]) -> (CompressionType, ArchiveType) {
        let path = path.as_ref();
        let inferred = infer::get(header);

        let get_archive_format = || -> ArchiveType {
            match path.extension() {
                Some(ext)
                    if [
                        "tar", "tgz", "tbz", "tbz2", "txz", "tlz", "tlz", "tlzf", "tlz4", "tzst",
                    ]
                    .contains(&ext.to_str().unwrap_or_default()) =>
                {
                    ArchiveType::Tar
                }
                Some(ext) if ext == "ddup" => ArchiveType::Ddup,
                Some(ext) if ext == "pxar" => ArchiveType::Pxar,
                _ => path
                    .file_stem()
                    .map_or(ArchiveType::None, |stem| match stem.to_str() {
                        Some(s) if s.ends_with(".tar") => ArchiveType::Tar,
                        Some(s) if s.ends_with(".pxar") => ArchiveType::Pxar,
                        _ => ArchiveType::None,
                    }),
            }
        };

        if pbs_client::pxar::is_pxar_header(header) {
            return (CompressionType::None, ArchiveType::Pxar);
        }

        match inferred.map(|f| f.mime_type()) {
            Some("application/zip") => (CompressionType::None, ArchiveType::Zip),
            Some("application/x-tar") => (CompressionType::None, ArchiveType::Tar),
            Some("application/vnd.rar") => (CompressionType::None, ArchiveType::Rar),
            Some("application/x-7z-compressed") => (CompressionType::None, ArchiveType::SevenZip),
            mime => (
                mime.map_or(CompressionType::None, |mime| {
                    CompressionType::from_mime(mime)
                }),
                get_archive_format(),
            ),
        }
    }

    pub async fn extract(
        mut self,
        destination: PathBuf,
        destination_filesystem: Arc<dyn super::virtualfs::VirtualWritableFilesystem>,
        progress: create::ArchiveProgress,
        total: Option<Arc<AtomicU64>>,
    ) -> Result<(), anyhow::Error> {
        self.file.seek(SeekFrom::Start(0)).await?;

        match self.archive {
            ArchiveType::None => {
                let file_name = match self.path.file_stem() {
                    Some(stem) => destination.join(stem),
                    None => return Err(anyhow::anyhow!("Invalid file name")),
                };

                if destination_filesystem.is_primary_server_fs()
                    && self
                        .server
                        .filesystem
                        .async_is_ignored(&file_name, FileType::File)
                        .await
                {
                    return Err(anyhow::anyhow!("Destination file is ignored"));
                }

                let metadata = self.server.filesystem.async_metadata(&self.path).await?;

                if let Some(total) = &total {
                    total.store(metadata.len(), Ordering::Relaxed);
                }

                let file = self.file.into_std().await;
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = progress.counting_reader(file);
                    let reader = CompressionReaderMt::new(
                        reader,
                        self.compression,
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;
                    let mut reader = AbortReader::new(reader, listener);

                    let mut writer = destination_filesystem.create_file_with_metadata(
                        &file_name,
                        Some(metadata.permissions().into()),
                        metadata.modified().ok().map(|modified| modified.into_std()),
                    )?;

                    crate::io::copy(&mut reader, &mut writer)?;
                    writer.flush()?;
                    drop(writer);

                    progress.increment_files();

                    Ok(())
                })
                .await??;

                drop(guard);
            }
            ArchiveType::Tar => {
                let file = self.file.into_std().await;
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = progress.counting_reader(file);
                    let reader = CompressionReaderMt::new(
                        reader,
                        self.compression,
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;
                    let reader = AbortReader::new(reader, listener.clone());

                    if let Some(total) = total
                        && let Ok(metadata) = self.server.filesystem.metadata(&self.path)
                    {
                        total.store(metadata.len(), Ordering::Relaxed);
                    }

                    let mut archive = tar::Archive::new(reader);
                    archive.set_ignore_zeros(true);
                    let mut directory_entries = chunked_vec::ChunkedVec::new();
                    let entries = archive.entries()?;

                    let threads = crate::threading::resolve_threads(
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    );
                    let limit = crate::threading::InFlightLimit::new(TAR_IN_FLIGHT_CHUNKS);
                    let error = Arc::new(crate::threading::SharedError::new());

                    std::thread::scope(|scope| -> Result<(), anyhow::Error> {
                        let mut senders = Vec::with_capacity(threads);

                        for _ in 0..threads {
                            let (sender, receiver) =
                                async_channel::bounded::<TarJob>(TAR_WRITER_QUEUE_JOBS);
                            senders.push(sender);

                            let destination_filesystem = Arc::clone(&destination_filesystem);
                            let progress = progress.clone();
                            let error = Arc::clone(&error);
                            let listener = listener.clone();

                            scope.spawn(move || {
                                while let Ok(job) = receiver.recv_blocking() {
                                    if listener.is_aborted() || error.stopped() {
                                        receiver.close();
                                        continue;
                                    }

                                    if let Err(err) =
                                        apply_tar_job(&destination_filesystem, &progress, job)
                                    {
                                        error.fail(err);
                                    }
                                }
                            });
                        }

                        let mut last_parent = None;
                        for entry in entries {
                            if error.stopped() {
                                break;
                            }

                            let mut entry = entry?;
                            let path = entry.path()?;

                            let Some(destination_path) =
                                resolve_entry_path(&destination, path.as_ref())
                            else {
                                continue;
                            };
                            let header = entry.header();

                            if destination_filesystem.is_primary_server_fs()
                                && self.server.filesystem.is_ignored(
                                    &destination_path,
                                    FileType::from_is_dir(header.entry_type().is_dir()),
                                )
                            {
                                continue;
                            }

                            match header.entry_type() {
                                tar::EntryType::Directory => {
                                    destination_filesystem.create_dir_all(&destination_path)?;
                                    if let Ok(permissions) =
                                        header.mode().map(PortablePermissions::from_mode_dir)
                                    {
                                        destination_filesystem.set_permissions(
                                            &destination_path,
                                            FileType::Dir,
                                            permissions,
                                        )?;
                                    }

                                    if let Ok(modified_time) = header.mtime()
                                        && directory_entries.len()
                                            < Self::MAX_DIRECTORY_MTIME_ENTRIES
                                        && std::time::UNIX_EPOCH
                                            .checked_add(std::time::Duration::from_secs(
                                                modified_time,
                                            ))
                                            .is_some()
                                    {
                                        directory_entries.push((destination_path, modified_time));
                                    }
                                }
                                tar::EntryType::Regular => {
                                    let Some(sender) =
                                        senders.get(tar_shard(&destination_path, threads))
                                    else {
                                        continue;
                                    };

                                    let permissions =
                                        header.mode().map(PortablePermissions::from_mode_file).ok();
                                    let modified_time =
                                        header.mtime().ok().and_then(|modified_time| {
                                            std::time::UNIX_EPOCH.checked_add(
                                                std::time::Duration::from_secs(modified_time),
                                            )
                                        });
                                    let size = entry.size();

                                    if let Some(parent) = destination_path.parent()
                                        && last_parent.as_deref() != Some(parent)
                                    {
                                        destination_filesystem.create_dir_all(&parent)?;
                                        last_parent = Some(parent.to_path_buf());
                                    }

                                    if size <= TAR_CHUNK_BYTES as u64 {
                                        let permit = limit.acquire();
                                        let mut data = Vec::with_capacity(size as usize);
                                        entry.read_to_end(&mut data)?;

                                        if sender
                                            .send_blocking(TarJob::File {
                                                path: destination_path,
                                                content: TarContent::Whole(data, permit),
                                                permissions,
                                                modified_time,
                                            })
                                            .is_err()
                                        {
                                            break;
                                        }
                                    } else {
                                        let (chunks, receiver) = async_channel::bounded(2);

                                        if sender
                                            .send_blocking(TarJob::File {
                                                path: destination_path,
                                                content: TarContent::Chunks(receiver),
                                                permissions,
                                                modified_time,
                                            })
                                            .is_err()
                                        {
                                            break;
                                        }

                                        loop {
                                            let permit = limit.acquire();
                                            let mut chunk = Vec::with_capacity(TAR_CHUNK_BYTES);

                                            if entry
                                                .by_ref()
                                                .take(TAR_CHUNK_BYTES as u64)
                                                .read_to_end(&mut chunk)?
                                                == 0
                                            {
                                                break;
                                            }

                                            if chunks.send_blocking((chunk, permit)).is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                tar::EntryType::Symlink => {
                                    let Some(sender) =
                                        senders.get(tar_shard(&destination_path, threads))
                                    else {
                                        continue;
                                    };

                                    let link = entry
                                        .link_name()
                                        .unwrap_or_default()
                                        .unwrap_or_default()
                                        .into_owned();
                                    let modified_time =
                                        header.mtime().ok().and_then(|modified_time| {
                                            std::time::UNIX_EPOCH.checked_add(
                                                std::time::Duration::from_secs(modified_time),
                                            )
                                        });

                                    if sender
                                        .send_blocking(TarJob::Symlink {
                                            path: destination_path,
                                            link,
                                            modified_time,
                                        })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }

                        drop(senders);

                        Ok(())
                    })?;

                    if let Some(err) = error.take() {
                        return Err(err);
                    }

                    for (destination_path, modified_time) in directory_entries {
                        destination_filesystem.set_times(
                            &destination_path,
                            FileType::Dir,
                            std::time::UNIX_EPOCH
                                .checked_add(std::time::Duration::from_secs(modified_time))
                                .unwrap_or_else(std::time::SystemTime::now),
                            None,
                        )?;
                    }

                    Ok(())
                })
                .await??;

                drop(guard)
            }
            ArchiveType::Zip => {
                let file = Arc::new(self.file.into_std().await);
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = multi_reader::MultiReader::new(file)?;
                    let reader = AbortReader::new(reader, listener);
                    let mut archive = zip::ZipArchive::new(reader)?;

                    let mut plan = Vec::with_capacity(archive.len());
                    let mut directories = Vec::new();
                    let mut entry_total = 0;

                    for index in 0..archive.len() {
                        let entry = archive.by_index(index)?;
                        let Some(path) = entry.enclosed_name() else {
                            continue;
                        };
                        let Some(destination_path) = resolve_entry_path(&destination, &path)
                        else {
                            continue;
                        };

                        if destination_filesystem.is_primary_server_fs()
                            && self.server.filesystem.is_ignored(
                                &destination_path,
                                FileType::from_is_dir(entry.is_dir()),
                            )
                        {
                            continue;
                        }

                        if entry.is_dir() {
                            directories.push(ZipDirectory {
                                path: destination_path,
                                mode: entry.unix_mode().unwrap_or(0o755),
                                modified_time: zip_entry_get_modified_time(&entry),
                            });
                        } else if entry.is_file() {
                            entry_total += entry.size();
                            plan.push(ZipEntryPlan {
                                index,
                                kind: ZipEntryKind::File,
                                path: destination_path,
                                size: entry.size(),
                                permissions: entry
                                    .unix_mode()
                                    .map(PortablePermissions::from_mode_file),
                                modified_time: zip_entry_get_modified_time(&entry),
                            });
                        } else if entry.is_symlink() && (1..=2048).contains(&entry.size()) {
                            entry_total += entry.size();
                            plan.push(ZipEntryPlan {
                                index,
                                kind: ZipEntryKind::Symlink,
                                path: destination_path,
                                size: entry.size(),
                                permissions: None,
                                modified_time: zip_entry_get_modified_time(&entry),
                            });
                        }
                    }

                    if let Some(total) = total {
                        total.store(entry_total, Ordering::Relaxed);
                    }

                    for directory in &directories {
                        destination_filesystem.create_dir_all(&directory.path)?;
                        destination_filesystem.set_permissions(
                            &directory.path,
                            FileType::Dir,
                            PortablePermissions::from_mode_dir(directory.mode),
                        )?;
                    }

                    plan.sort_by(|a, b| a.path.parent().cmp(&b.path.parent()));
                    let groups = zip_entry_groups(&plan);

                    let mut last_parent = None;
                    for group in &groups {
                        if let Some(entry) = plan.get(group.start)
                            && let Some(parent) = entry.path.parent()
                            && last_parent != Some(parent)
                        {
                            destination_filesystem.create_dir_all(&parent)?;
                            last_parent = Some(parent);
                        }
                    }

                    let pool = crate::threading::build_pool(
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;

                    let error = Arc::new(crate::threading::SharedError::new());
                    let group_index = AtomicUsize::new(0);

                    pool.in_place_scope(|scope| {
                        let plan = &plan;
                        let groups = &groups;
                        let group_index = &group_index;
                        let archive = &archive;
                        let progress = &progress;
                        let destination_filesystem = &destination_filesystem;
                        let error = &error;

                        scope.spawn_broadcast(move |_, _| {
                            let mut archive = archive.clone();
                            let mut buffer = vec![0; ZIP_COPY_BUFFER];

                            let mut run = || -> Result<(), anyhow::Error> {
                                loop {
                                    if error.stopped() {
                                        return Ok(());
                                    }

                                    let group = group_index.fetch_add(1, Ordering::SeqCst);
                                    let Some(range) = groups.get(group) else {
                                        return Ok(());
                                    };

                                    for entry in plan.get_slice(range.clone())? {
                                        if error.stopped() {
                                            return Ok(());
                                        }

                                        match entry.kind {
                                            ZipEntryKind::File => {
                                                let zip_entry = archive.by_index(entry.index)?;
                                                let mut writer = destination_filesystem
                                                    .create_file_with_metadata(
                                                        &entry.path,
                                                        entry.permissions,
                                                        entry.modified_time,
                                                    )?;
                                                let mut reader =
                                                    progress.counting_reader(zip_entry);

                                                crate::io::copy_shared(
                                                    &mut buffer,
                                                    &mut reader,
                                                    &mut writer,
                                                )?;
                                                writer.flush()?;
                                                drop(writer);

                                                progress.increment_files();
                                            }
                                            ZipEntryKind::Symlink => {
                                                let mut zip_entry =
                                                    archive.by_index(entry.index)?;
                                                let link = std::io::read_to_string(&mut zip_entry)
                                                    .unwrap_or_default();

                                                if let Err(err) = destination_filesystem
                                                    .create_symlink(&link, &entry.path)
                                                {
                                                    tracing::debug!(
                                                        path = %entry.path.display(),
                                                        "failed to create symlink from archive: {:#?}",
                                                        err
                                                    );
                                                } else if let Some(modified_time) =
                                                    entry.modified_time
                                                {
                                                    destination_filesystem.set_times(
                                                        &entry.path,
                                                        FileType::Symlink,
                                                        modified_time,
                                                        None,
                                                    )?;
                                                }

                                                progress.increment_bytes(zip_entry.size());
                                            }
                                        }
                                    }
                                }
                            };

                            if let Err(err) = run() {
                                error.fail(err);
                            }
                        });
                    });

                    if let Some(err) = error.take() {
                        return Err(err);
                    }

                    for directory in directories {
                        if let Some(modified_time) = directory.modified_time {
                            destination_filesystem.set_times(
                                &directory.path,
                                FileType::Dir,
                                modified_time,
                                None,
                            )?;
                        }
                    }

                    Ok(())
                })
                .await??;

                drop(guard);
            }
            ArchiveType::Rar => {
                let (guard, listener) = AbortGuard::new();

                fn dos_time_to_unix(dos_time: u32) -> Option<u64> {
                    let seconds = (dos_time & 0x1F) * 2;
                    let minutes = (dos_time >> 5) & 0x3F;
                    let hours = (dos_time >> 11) & 0x1F;
                    let day = (dos_time >> 16) & 0x1F;
                    let month = (dos_time >> 21) & 0x0F;
                    let year = ((dos_time >> 25) & 0x7F) + 1980;

                    let date = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)?;
                    let time = chrono::NaiveTime::from_hms_opt(hours, minutes, seconds)?;

                    Some(chrono::NaiveDateTime::new(date, time).and_utc().timestamp() as u64)
                }

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    #[cfg(target_os = "linux")]
                    let archive_path = Path::new("/proc/self/fd")
                        .join(std::os::fd::AsRawFd::as_raw_fd(&self.file).to_string());
                    #[cfg(not(target_os = "linux"))]
                    let archive_path = {
                        drop(self.file);

                        self.server
                            .filesystem
                            .base_path
                            .join(self.server.filesystem.relative_path(&self.path))
                    };

                    if let Some(total) = total {
                        let mut entry_total = 0;
                        let archive = unrar::Archive::new(&archive_path).open_for_listing()?;
                        for entry in archive.flatten() {
                            entry_total += entry.unpacked_size;
                        }

                        total.store(entry_total, Ordering::Relaxed);
                    }

                    let mut archive = unrar::Archive::new(&archive_path).open_for_processing()?;
                    let mut directory_entries = chunked_vec::ChunkedVec::new();
                    let mut last_parent = None;

                    loop {
                        let entry = match archive.read_header()? {
                            Some(entry) => entry,
                            None => break,
                        };

                        let Some(destination_path) =
                            resolve_entry_path(&destination, &entry.entry().filename)
                        else {
                            archive = entry.skip()?;
                            continue;
                        };

                        if destination_filesystem.is_primary_server_fs()
                            && self.server.filesystem.is_ignored(
                                &destination_path,
                                FileType::from_is_dir(entry.entry().is_directory()),
                            )
                        {
                            archive = entry.skip()?;
                            continue;
                        }

                        if listener.is_aborted() {
                            return Err(anyhow::anyhow!("operation aborted"));
                        }

                        if entry.entry().is_directory() {
                            destination_filesystem.create_dir_all(&destination_path)?;

                            if let Some(modified_time) = dos_time_to_unix(entry.entry().file_time)
                                && directory_entries.len() < Self::MAX_DIRECTORY_MTIME_ENTRIES
                            {
                                directory_entries.push((destination_path, modified_time));
                            }

                            archive = entry.skip()?;
                            continue;
                        } else {
                            if let Some(parent) = destination_path.parent()
                                && last_parent.as_deref() != Some(parent)
                            {
                                destination_filesystem.create_dir_all(&parent)?;
                                last_parent = Some(parent.to_path_buf());
                            }

                            let modified_time =
                                dos_time_to_unix(entry.entry().file_time).map(|secs| {
                                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
                                });

                            let writer = destination_filesystem.create_file(&destination_path)?;
                            let writer = AbortWriter::new(writer, listener.clone());
                            let writer: Box<dyn Write + Send + Sync> = match progress.clone_bytes()
                            {
                                Some(bytes_processed) => Box::new(
                                    CountingWriter::new_with_bytes_written(writer, bytes_processed),
                                ),
                                None => Box::new(writer),
                            };

                            let (unrar::Stream(writer, err), processed_archive) =
                                entry.read_to_stream(writer)?;
                            if let Some(mut writer) = writer {
                                writer.flush()?;
                            }

                            if let Some(err) = err {
                                return Err(err.into());
                            }

                            if let Some(modified_time) = modified_time {
                                destination_filesystem.set_times(
                                    &destination_path,
                                    FileType::File,
                                    modified_time,
                                    None,
                                )?;
                            }

                            progress.increment_files();

                            archive = processed_archive;
                        }
                    }

                    for (destination_path, modified_time) in directory_entries {
                        destination_filesystem.set_times(
                            &destination_path,
                            FileType::Dir,
                            std::time::UNIX_EPOCH
                                .checked_add(std::time::Duration::from_secs(modified_time))
                                .unwrap_or_else(std::time::SystemTime::now),
                            None,
                        )?;
                    }

                    Ok(())
                })
                .await??;

                drop(guard);
            }
            ArchiveType::SevenZip => {
                let file = Arc::new(self.file.into_std().await);
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = multi_reader::MultiReader::new(file)?;
                    let reader = AbortReader::new(reader, listener);
                    let password = sevenz_rust2::Password::empty();
                    let archive = sevenz_rust2::Archive::read(&mut reader.clone(), &password)?;

                    if let Some(total) = total {
                        total.store(
                            archive.files.iter().map(|f| f.size).sum(),
                            Ordering::Relaxed,
                        );
                    }

                    let pool = crate::threading::build_pool(
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;

                    let error = Arc::new(crate::threading::SharedError::new());

                    pool.in_place_scope(|scope| {
                        for block_index in 0..archive.blocks.len() {
                            let archive = archive.clone();
                            let progress = progress.clone();
                            let mut reader = reader.clone();
                            let destination = destination.clone();
                            let server = self.server.clone();
                            let destination_filesystem = destination_filesystem.clone();
                            let error_clone = Arc::clone(&error);

                            scope.spawn(move |_| {
                                if error_clone.stopped() {
                                    return;
                                }

                                let password = sevenz_rust2::Password::empty();
                                let folder = sevenz_rust2::BlockDecoder::new(
                                    1,
                                    block_index,
                                    &archive,
                                    &password,
                                    &mut reader,
                                );

                                let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                                let mut last_parent = None;
                                if let Err(err) = folder.for_each_entries(&mut |entry, reader| {
                                    let path = entry.name();
                                    if path.starts_with('/') || path.starts_with('\\') {
                                        return Ok(true);
                                    }

                                    let Some(destination_path) =
                                        resolve_entry_path(&destination, Path::new(path))
                                    else {
                                        return Ok(true);
                                    };

                                    if destination_filesystem.is_primary_server_fs()
                                        && server.filesystem.is_ignored(
                                            &destination_path,
                                            FileType::from_is_dir(entry.is_directory()),
                                        )
                                    {
                                        return Ok(true);
                                    }

                                    if entry.is_directory() {
                                        if let Err(err) =
                                            destination_filesystem.create_dir_all(&destination_path)
                                        {
                                            return Err(sevenz_rust2::Error::Other(
                                                err.to_string().into(),
                                            ));
                                        }
                                    } else {
                                        if let Some(parent) = destination_path.parent()
                                            && last_parent.as_deref() != Some(parent)
                                        {
                                            if let Err(err) =
                                                destination_filesystem.create_dir_all(&parent)
                                            {
                                                return Err(sevenz_rust2::Error::Other(
                                                    err.to_string().into(),
                                                ));
                                            }
                                            last_parent = Some(parent.to_path_buf());
                                        }

                                        let modified_time = if entry.has_last_modified_date {
                                            Some(entry.last_modified_date.into())
                                        } else {
                                            None
                                        };

                                        let mut writer = destination_filesystem
                                            .create_file(&destination_path)
                                            .map_err(|e| std::io::Error::other(e.to_string()))?;

                                        let mut reader: Box<dyn Read> =
                                            Box::new(progress.counting_reader(reader));

                                        crate::io::copy_shared(
                                            &mut read_buffer,
                                            &mut reader,
                                            &mut writer,
                                        )?;
                                        writer.flush()?;
                                        drop(writer);

                                        if let Some(modified_time) = modified_time {
                                            destination_filesystem
                                                .set_times(
                                                    &destination_path,
                                                    FileType::File,
                                                    modified_time,
                                                    None,
                                                )
                                                .map_err(|e| {
                                                    std::io::Error::other(e.to_string())
                                                })?;
                                        }

                                        progress.increment_files();
                                    }

                                    Ok(true)
                                }) {
                                    error_clone.fail(err);
                                }
                            });
                        }
                    });

                    if let Some(err) = error.take() {
                        Err(err.into())
                    } else {
                        for entry in archive.files {
                            if entry.is_directory() && entry.has_last_modified_date {
                                let path = entry.name();
                                if path.starts_with('/') || path.starts_with('\\') {
                                    continue;
                                }

                                let Some(destination_path) =
                                    resolve_entry_path(&destination, Path::new(path))
                                else {
                                    continue;
                                };

                                if destination_filesystem.is_primary_server_fs()
                                    && self.server.filesystem.is_ignored(
                                        &destination_path,
                                        FileType::from_is_dir(entry.is_directory()),
                                    )
                                {
                                    continue;
                                }

                                destination_filesystem.set_times(
                                    &destination_path,
                                    FileType::from_is_dir(entry.is_directory()),
                                    entry.last_modified_date.into(),
                                    None,
                                )?;
                            }
                        }

                        Ok(())
                    }
                })
                .await??;

                drop(guard);
            }
            ArchiveType::Ddup => {
                let mut file = self.file.into_std().await;
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    file.seek(SeekFrom::Start(0))?;
                    let archive = ddup_bak::archive::Archive::open_file(file)?;

                    if let Some(total) = total {
                        fn recursive_size(entry: &ddup_bak::archive::entries::Entry) -> u64 {
                            match entry {
                                ddup_bak::archive::entries::Entry::File(file) => file.size,
                                ddup_bak::archive::entries::Entry::Directory(dir) => {
                                    dir.entries.iter().map(recursive_size).sum()
                                }
                                _ => 0,
                            }
                        }

                        total.store(
                            archive.entries().iter().map(recursive_size).sum(),
                            Ordering::Relaxed,
                        );
                    }

                    let pool = crate::threading::build_pool(
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;

                    #[allow(clippy::too_many_arguments)]
                    fn recursive_traverse(
                        scope: &rayon::Scope,
                        listener: &AbortListener,
                        progress: &create::ArchiveProgress,
                        error: &Arc<crate::threading::SharedError<std::io::Error>>,
                        server: &crate::server::Server,
                        destination_filesystem: &Arc<
                            dyn crate::server::filesystem::virtualfs::VirtualWritableFilesystem,
                        >,
                        destination: &Path,
                        entry: ddup_bak::archive::entries::Entry,
                    ) -> Result<(), anyhow::Error> {
                        if error.stopped() {
                            return Ok(());
                        }

                        let Some(destination_path) =
                            resolve_entry_path(destination, Path::new(entry.name()))
                        else {
                            return Ok(());
                        };

                        if destination_filesystem.is_primary_server_fs()
                            && server.filesystem.is_ignored(
                                &destination_path,
                                FileType::from_is_dir(entry.is_directory()),
                            )
                        {
                            return Ok(());
                        }

                        if listener.is_aborted() {
                            return Err(anyhow::anyhow!("operation aborted"));
                        }

                        match entry {
                            ddup_bak::archive::entries::Entry::Directory(dir) => {
                                destination_filesystem.create_dir_all(&destination_path)?;
                                destination_filesystem.set_permissions(
                                    &destination_path,
                                    FileType::Dir,
                                    PortablePermissions::from_mode_dir(dir.mode.bits()),
                                )?;

                                for entry in dir.entries {
                                    recursive_traverse(
                                        scope,
                                        listener,
                                        progress,
                                        error,
                                        server,
                                        destination_filesystem,
                                        &destination_path,
                                        entry,
                                    )?;
                                }

                                destination_filesystem.set_times(
                                    &destination_path,
                                    FileType::Dir,
                                    dir.mtime,
                                    None,
                                )?;
                            }
                            ddup_bak::archive::entries::Entry::File(file) => {
                                let permissions =
                                    PortablePermissions::from_mode_file(file.mode.bits());
                                let mtime = file.mtime;

                                let mut writer =
                                    destination_filesystem.create_file(&destination_path)?;

                                let reader = AbortReader::new(file, listener.clone());
                                let mut reader: Box<dyn Read + Send> =
                                    Box::new(progress.counting_reader(reader));

                                let error = Arc::clone(error);
                                let destination_filesystem = Arc::clone(destination_filesystem);
                                let progress = progress.clone();
                                scope.spawn(move |_| {
                                    let mut run = || -> Result<(), std::io::Error> {
                                        crate::io::copy(&mut reader, &mut writer)?;
                                        writer.flush()?;

                                        destination_filesystem
                                            .set_permissions(
                                                &destination_path,
                                                FileType::File,
                                                permissions,
                                            )
                                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                                        destination_filesystem
                                            .set_times(
                                                &destination_path,
                                                FileType::File,
                                                mtime,
                                                None,
                                            )
                                            .map_err(|e| std::io::Error::other(e.to_string()))?;

                                        progress.increment_files();

                                        Ok(())
                                    };

                                    if let Err(err) = run() {
                                        tracing::debug!(
                                            path = %destination_path.display(),
                                            "failed to extract file from archive: {:#?}",
                                            err
                                        );

                                        error.fail(err);
                                    }
                                });
                            }
                            ddup_bak::archive::entries::Entry::Symlink(link) => {
                                if let Err(err) = destination_filesystem
                                    .create_symlink(&link.target, &destination_path)
                                {
                                    tracing::debug!(
                                        path = %destination_path.display(),
                                        "failed to create symlink from archive: {:#?}",
                                        err
                                    );
                                } else {
                                    destination_filesystem.set_times(
                                        &destination_path,
                                        FileType::Symlink,
                                        link.mtime,
                                        None,
                                    )?;
                                }
                            }
                        }

                        Ok(())
                    }

                    let error = Arc::new(crate::threading::SharedError::new());

                    pool.in_place_scope(|scope| -> Result<(), anyhow::Error> {
                        for entry in archive.into_entries() {
                            recursive_traverse(
                                scope,
                                &listener,
                                &progress,
                                &error,
                                &self.server,
                                &destination_filesystem,
                                &destination,
                                entry,
                            )?;
                        }

                        Ok(())
                    })?;

                    if let Some(err) = error.take() {
                        return Err(err.into());
                    }

                    Ok(())
                })
                .await??;

                drop(guard);
            }
            ArchiveType::Pxar => {
                let file = self.file.into_std().await;
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = progress.counting_reader(file);
                    let reader = CompressionReaderMt::new(
                        reader,
                        self.compression,
                        self.server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;
                    let reader = AbortReader::new(reader, listener);
                    let reader =
                        std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

                    if let Some(total) = total
                        && let Ok(metadata) = self.server.filesystem.metadata(&self.path)
                    {
                        total.store(metadata.len(), Ordering::Relaxed);
                    }

                    let mut decoder = pbs_client::pxar::decoder::Decoder::from_std(reader)?;
                    let mut directory_entries = chunked_vec::ChunkedVec::new();
                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    let mut last_parent = None;

                    while let Some(entry) = decoder.next() {
                        let entry = entry?;

                        let relative = match entry.path().strip_prefix("/") {
                            Ok(relative) if !relative.as_os_str().is_empty() => relative,
                            _ => continue,
                        };
                        let Some(destination_path) = resolve_entry_path(&destination, relative)
                        else {
                            continue;
                        };

                        let is_dir = matches!(entry.kind(), pbs_client::pxar::EntryKind::Directory);
                        if destination_filesystem.is_primary_server_fs()
                            && self
                                .server
                                .filesystem
                                .is_ignored(&destination_path, FileType::from_is_dir(is_dir))
                        {
                            continue;
                        }

                        let stat = entry.metadata().stat;
                        let modified_time = std::time::UNIX_EPOCH.checked_add(
                            std::time::Duration::from_secs(stat.mtime.secs.max(0) as u64),
                        );

                        match entry.kind() {
                            pbs_client::pxar::EntryKind::Directory => {
                                let permissions = PortablePermissions::from_mode_dir(stat.mode);
                                destination_filesystem.create_dir_all(&destination_path)?;
                                destination_filesystem.set_permissions(
                                    &destination_path,
                                    FileType::Dir,
                                    permissions,
                                )?;
                                if let Some(modified_time) = modified_time
                                    && directory_entries.len() < Self::MAX_DIRECTORY_MTIME_ENTRIES
                                {
                                    directory_entries.push((destination_path, modified_time));
                                }
                            }
                            pbs_client::pxar::EntryKind::File { .. } => {
                                if let Some(parent) = destination_path.parent()
                                    && last_parent.as_deref() != Some(parent)
                                {
                                    destination_filesystem.create_dir_all(&parent)?;
                                    last_parent = Some(parent.to_path_buf());
                                }

                                let permissions = PortablePermissions::from_mode_file(stat.mode);
                                let mut writer =
                                    destination_filesystem.create_file(&destination_path)?;

                                if let Some(mut contents) = decoder.contents()? {
                                    crate::io::copy_shared(
                                        &mut read_buffer,
                                        &mut contents,
                                        &mut writer,
                                    )?;
                                }
                                writer.flush()?;
                                drop(writer);

                                destination_filesystem.set_permissions(
                                    &destination_path,
                                    FileType::File,
                                    permissions,
                                )?;
                                if let Some(modified_time) = modified_time {
                                    destination_filesystem.set_times(
                                        &destination_path,
                                        FileType::File,
                                        modified_time,
                                        None,
                                    )?;
                                }

                                progress.increment_files();
                            }
                            pbs_client::pxar::EntryKind::Symlink(target) => {
                                let target = target.as_os_str().to_os_string();

                                if let Err(err) = destination_filesystem
                                    .create_symlink(&target, &destination_path)
                                {
                                    tracing::debug!(
                                        path = %destination_path.display(),
                                        "failed to create symlink from archive: {:#?}",
                                        err
                                    );
                                } else if let Some(modified_time) = modified_time {
                                    destination_filesystem.set_times(
                                        &destination_path,
                                        FileType::Symlink,
                                        modified_time,
                                        None,
                                    )?;
                                }
                            }
                        }
                    }

                    for (destination_path, modified_time) in directory_entries {
                        destination_filesystem.set_times(
                            &destination_path,
                            FileType::Dir,
                            modified_time,
                            None,
                        )?;
                    }

                    Ok(())
                })
                .await??;

                drop(guard);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{routes::AppState, server::Server};

    // tar_shard

    #[test]
    fn tar_shard_is_stable_per_path() {
        for shards in [1usize, 2, 3, 4, 8] {
            for path in [
                "world/region/r.0.0.mca",
                "plugins/config.yml",
                "server.properties",
                "a",
                "nested/deep/deeper/file.bin",
            ] {
                let shard = tar_shard(Path::new(path), shards);

                assert_eq!(
                    shard,
                    tar_shard(Path::new(path), shards),
                    "{path} moved between writers"
                );
                assert!(shard < shards, "{path} picked a writer that does not exist");
            }
        }
    }

    #[test]
    fn tar_shard_keeps_a_directory_on_one_writer() {
        for shards in [2usize, 4, 8] {
            let writer = tar_shard(Path::new("world/region/r.0.0.mca"), shards);

            for i in 0..64 {
                let path = format!("world/region/r.{}.{}.mca", i / 8, i % 8);

                assert_eq!(
                    tar_shard(Path::new(&path), shards),
                    writer,
                    "{path} left its directory's writer"
                );
            }
        }
    }

    #[test]
    fn tar_shard_spreads_directories_across_writers() {
        let mut paths = Vec::new();
        for i in 0..200 {
            paths.push(format!("world/region-{i}/r.0.0.mca"));
            paths.push(format!("plugins/plugin-{i:03}/config.yml"));
            paths.push(format!("libraries/library-{i}/library.jar"));
        }

        for shards in [2usize, 4, 8] {
            let mut counts = vec![0usize; shards];

            for path in &paths {
                if let Some(count) = counts.get_mut(tar_shard(Path::new(path), shards)) {
                    *count += 1;
                }
            }

            // half of an even share, far looser than the measured spread
            let floor = paths.len() / shards / 2;

            assert!(
                counts.iter().all(|&count| count > floor),
                "uneven spread at {shards} shards: {counts:?}"
            );
        }
    }

    #[test]
    fn tar_shard_survives_a_zero_thread_count() {
        assert_eq!(tar_shard(Path::new("a.txt"), 0), 0);
    }

    // zip_entry_groups

    fn plan_entry(index: usize, path: &str) -> ZipEntryPlan {
        sized_plan_entry(index, path, 0)
    }

    fn sized_plan_entry(index: usize, path: &str, size: u64) -> ZipEntryPlan {
        ZipEntryPlan {
            index,
            kind: ZipEntryKind::File,
            path: PathBuf::from(path),
            size,
            permissions: None,
            modified_time: None,
        }
    }

    #[test]
    fn zip_entry_groups_splits_on_parent_directory() {
        let plan = [
            plan_entry(0, "a/one"),
            plan_entry(1, "a/two"),
            plan_entry(2, "b/one"),
            plan_entry(3, "c/d/one"),
            plan_entry(4, "c/d/two"),
            plan_entry(5, "c/d/three"),
        ];

        assert_eq!(zip_entry_groups(&plan), vec![0..2, 2..3, 3..6]);
        assert!(zip_entry_groups(&[]).is_empty());
    }

    #[test]
    fn zip_entry_groups_caps_a_huge_directory() {
        let plan: Vec<_> = (0..ZIP_GROUP_MAX_ENTRIES * 2 + 5)
            .map(|i| plan_entry(i, &format!("big/file-{i}")))
            .collect();

        let groups = zip_entry_groups(&plan);

        assert_eq!(groups.len(), 3);
        assert!(
            groups
                .iter()
                .all(|group| group.len() <= ZIP_GROUP_MAX_ENTRIES)
        );
        assert_eq!(
            groups.iter().map(|group| group.len()).sum::<usize>(),
            plan.len()
        );
        assert_eq!(groups.first().map(|group| group.start), Some(0));
    }

    #[test]
    fn zip_entry_groups_caps_bytes_per_group() {
        let plan: Vec<_> = (0..6)
            .map(|i| sized_plan_entry(i, &format!("region/r.{i}.mca"), ZIP_GROUP_MAX_BYTES / 2))
            .collect();

        assert_eq!(zip_entry_groups(&plan), vec![0..2, 2..4, 4..6]);

        let huge = [
            sized_plan_entry(0, "libraries/one.jar", ZIP_GROUP_MAX_BYTES * 3),
            sized_plan_entry(1, "libraries/two.jar", 10),
        ];

        assert_eq!(zip_entry_groups(&huge), vec![0..1, 1..2]);
    }

    // tar extraction

    struct ExtractFixture {
        server: Server,
        root: PathBuf,

        _temp: tempfile::TempDir,
    }

    impl ExtractFixture {
        async fn new(threads: usize) -> Result<Self, anyhow::Error> {
            let temp = tempfile::tempdir()?;
            let state = AppState::mock();
            {
                let config = state.config.mutate_in_place_for_testing();
                config.system.data_directory =
                    crate::config::SystemPath::new(temp.path().to_string_lossy().into_owned());
                config.api.file_decompression_threads = threads;
            }

            let server = Server::mock(uuid::Uuid::new_v4(), Arc::clone(&state));
            server.filesystem.disk_checker.abort();

            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir_all(&root)?;

            let cap = crate::server::filesystem::cap::CapFilesystem::new(&root).await?;
            server.filesystem.inner.store(Some(cap.get_inner()?));

            Ok(Self {
                server,
                root,
                _temp: temp,
            })
        }

        fn build(
            &self,
            entries: impl FnOnce(&mut tar::Builder<std::fs::File>),
        ) -> Result<(), anyhow::Error> {
            let file = std::fs::File::create(self.root.join("input.tar"))?;
            let mut builder = tar::Builder::new(file);
            entries(&mut builder);
            builder.finish()?;

            Ok(())
        }

        async fn extract(&self) -> Result<PathBuf, anyhow::Error> {
            let archive = Archive::open(self.server.clone(), PathBuf::from("input.tar")).await?;
            let (destination, filesystem) = self
                .server
                .filesystem
                .resolve_writable_fs(&self.server, "out")
                .await;

            archive
                .extract(
                    destination,
                    filesystem,
                    create::ArchiveProgress::default(),
                    None,
                )
                .await?;

            Ok(self.root.join("out"))
        }
    }

    fn file_header(size: u64, mode: u32, mtime: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(mode);
        header.set_mtime(mtime);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        header
    }

    fn add_file(builder: &mut tar::Builder<std::fs::File>, name: &str, data: &[u8]) {
        let mut header = file_header(data.len() as u64, 0o644, 1_700_000_000);
        builder
            .append_data(&mut header, name, data)
            .expect("append file");
    }

    fn random(len: usize) -> Vec<u8> {
        let mut state = 0x51edu64;

        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn extracted_tree_matches_the_archive_at_every_thread_count() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            for threads in [1, 2, 4] {
                let fixture = ExtractFixture::new(threads).await?;
                let big = random(5 * 1024 * 1024 + 13);
                let small = random(4096);

                fixture.build(|builder| {
                    let mut directory = tar::Header::new_gnu();
                    directory.set_size(0);
                    directory.set_mode(0o755);
                    directory.set_mtime(1_700_000_000);
                    directory.set_entry_type(tar::EntryType::Directory);
                    directory.set_cksum();
                    builder
                        .append_data(&mut directory, "plugins/", std::io::empty())
                        .expect("append dir");

                    for i in 0..50 {
                        add_file(builder, &format!("plugins/config-{i:02}.yml"), &small);
                    }
                    add_file(builder, "world.mca", &big);
                    add_file(builder, "server.properties", b"motd=hello");
                })?;

                let out = fixture.extract().await?;

                assert_eq!(
                    std::fs::read(out.join("world.mca"))?,
                    big,
                    "multi-chunk entry differs with {threads} threads"
                );
                assert_eq!(std::fs::read(out.join("server.properties"))?, b"motd=hello");

                for i in 0..50 {
                    assert_eq!(
                        std::fs::read(out.join(format!("plugins/config-{i:02}.yml")))?,
                        small,
                        "config-{i:02} differs with {threads} threads"
                    );
                }
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn duplicate_entries_keep_the_last_write() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let fixture = ExtractFixture::new(4).await?;

            fixture.build(|builder| {
                for i in 0..32 {
                    add_file(builder, &format!("dupe-{i:02}.txt"), b"first");
                    add_file(builder, &format!("dupe-{i:02}.txt"), b"second");
                }
            })?;

            let out = fixture.extract().await?;

            for i in 0..32 {
                assert_eq!(
                    std::fs::read(out.join(format!("dupe-{i:02}.txt")))?,
                    b"second",
                    "dupe-{i:02} did not keep the last write"
                );
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn a_symlink_replacing_a_file_is_not_racy() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            // symlinks shard on the path they occupy, so this cannot be
            // reordered against the file it replaces
            let fixture = ExtractFixture::new(4).await?;

            fixture.build(|builder| {
                add_file(builder, "target.txt", b"target");

                for i in 0..16 {
                    add_file(builder, &format!("link-{i:02}"), b"replaced");

                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o777);
                    header.set_mtime(1_700_000_000);
                    header.set_entry_type(tar::EntryType::Symlink);
                    builder
                        .append_link(&mut header, format!("link-{i:02}"), "target.txt")
                        .expect("append symlink");
                }
            })?;

            let out = fixture.extract().await?;

            for i in 0..16 {
                let path = out.join(format!("link-{i:02}"));
                let metadata = std::fs::symlink_metadata(&path)?;

                assert!(
                    metadata.file_type().is_symlink() || std::fs::read(&path)? == b"replaced",
                    "link-{i:02} is neither the symlink nor the file it replaced"
                );
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn directory_mtimes_survive_the_writers() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let fixture = ExtractFixture::new(4).await?;
            let mtime = 1_600_000_000;

            fixture.build(|builder| {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(mtime);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                builder
                    .append_data(&mut header, "world/", std::io::empty())
                    .expect("append dir");

                for i in 0..64 {
                    add_file(builder, &format!("world/r.{i}.mca"), b"region");
                }
            })?;

            let out = fixture.extract().await?;
            let modified = std::fs::metadata(out.join("world"))?.modified()?;
            let seconds = modified
                .duration_since(std::time::UNIX_EPOCH)
                .expect("directory mtime before the epoch")
                .as_secs();

            assert_eq!(
                seconds, mtime,
                "directory mtime was clobbered by the files written into it"
            );

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn file_modes_and_mtimes_are_preserved() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            use std::os::unix::fs::PermissionsExt;

            let fixture = ExtractFixture::new(2).await?;

            fixture.build(|builder| {
                let mut header = file_header(5, 0o600, 1_500_000_000);
                builder
                    .append_data(&mut header, "private.key", b"hello".as_slice())
                    .expect("append file");
            })?;

            let out = fixture.extract().await?;
            let metadata = std::fs::metadata(out.join("private.key"))?;

            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                metadata
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("mtime before the epoch")
                    .as_secs(),
                1_500_000_000
            );

            Ok(())
        })
    }

    // resolve_entry_path

    #[test]
    fn resolve_entry_path_resolves_plain_entries_under_the_destination() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("a/b.txt")),
            Some(PathBuf::from("logs/a/b.txt"))
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("a/b.txt")),
            Some(PathBuf::from("a/b.txt"))
        );
    }

    #[test]
    fn resolve_entry_path_strips_current_dir_components_that_tar_writers_emit() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("./a/./b.txt")),
            Some(PathBuf::from("logs/a/b.txt"))
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("./server.properties")),
            Some(PathBuf::from("server.properties"))
        );
    }

    #[test]
    fn resolve_entry_path_rejects_parent_dir_escapes() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("../config/secrets.yml")),
            None
        );
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("a/../../config/secrets.yml")),
            None
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("x/../config/config.yml")),
            None
        );
    }

    #[test]
    fn resolve_entry_path_rejects_absolute_entries() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("/config/secrets.yml")),
            None
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("/etc/passwd")),
            None
        );
    }
}
