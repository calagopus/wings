use crate::{
    io::{
        ReadSeek,
        abort::{AbortGuard, AbortListener, AbortReader, AbortWriter},
        compression::{CompressionType, reader::CompressionReaderMt},
        counting_reader::CountingReader,
        counting_writer::CountingWriter,
    },
    utils::PortablePermissions,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
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

#[derive(Debug, Clone, Copy)]
pub enum ArchiveType {
    None,
    Tar,
    Zip,
    Rar,
    SevenZip,
    Ddup,
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
                _ => path.file_stem().map_or(ArchiveType::None, |stem| {
                    if stem.to_str().is_some_and(|s| s.ends_with(".tar")) {
                        ArchiveType::Tar
                    } else {
                        ArchiveType::None
                    }
                }),
            }
        };

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
        progress: Option<Arc<AtomicU64>>,
        total: Option<Arc<AtomicU64>>,
    ) -> Result<(), anyhow::Error> {
        self.file.seek(SeekFrom::Start(0)).await?;

        match self.archive {
            ArchiveType::None => {
                let file_name = match self.path.file_stem() {
                    Some(stem) => destination.join(stem),
                    None => return Err(anyhow::anyhow!("Invalid file name")),
                };

                let metadata = self.server.filesystem.async_metadata(&self.path).await?;

                let file = self.file.into_std().await;
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader: Box<dyn ReadSeek + Send> = match progress {
                        Some(progress) => {
                            Box::new(CountingReader::new_with_bytes_read(file, progress))
                        }
                        None => Box::new(file),
                    };
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

                    let mut writer = super::file::ServerFile::new(
                        self.server.clone(),
                        &file_name,
                        Some(metadata.permissions().into()),
                        metadata.modified().map(|t| t.into_std()).ok(),
                    )?;

                    crate::io::copy(&mut reader, &mut writer)?;
                    writer.flush()?;

                    Ok(())
                })
                .await??;

                drop(guard);
            }
            ArchiveType::Tar => {
                let file = self.file.into_std().await;
                let (guard, listener) = AbortGuard::new();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader: Box<dyn ReadSeek + Send> = match progress {
                        Some(progress) => {
                            Box::new(CountingReader::new_with_bytes_read(file, progress))
                        }
                        None => Box::new(file),
                    };
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

                    if let Some(total) = total
                        && let Ok(metadata) = self.server.filesystem.metadata(&self.path)
                    {
                        total.store(metadata.len(), Ordering::Relaxed);
                    }

                    let mut archive = tar::Archive::new(reader);
                    archive.set_ignore_zeros(true);
                    let mut directory_entries = chunked_vec::ChunkedVec::new();
                    let mut entries = archive.entries()?;

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    while let Some(Ok(mut entry)) = entries.next() {
                        let path = entry.path()?;

                        if path.is_absolute() {
                            continue;
                        }

                        let destination_path = destination.join(path.as_ref());
                        let header = entry.header();

                        if self
                            .server
                            .filesystem
                            .is_ignored(&destination_path, header.entry_type().is_dir())
                        {
                            continue;
                        }

                        match header.entry_type() {
                            tar::EntryType::Directory => {
                                self.server
                                    .filesystem
                                    .create_chowned_dir_all(&destination_path)?;
                                if let Ok(permissions) =
                                    header.mode().map(PortablePermissions::from_mode)
                                {
                                    self.server
                                        .filesystem
                                        .set_permissions(&destination_path, permissions)?;
                                }

                                if let Ok(modified_time) = header.mtime() {
                                    directory_entries.push((destination_path, modified_time));
                                }
                            }
                            tar::EntryType::Regular => {
                                if let Some(parent) = destination_path.parent() {
                                    self.server.filesystem.create_chowned_dir_all(parent)?;
                                }

                                let mut writer = super::file::ServerFile::new(
                                    self.server.clone(),
                                    &destination_path,
                                    header.mode().map(PortablePermissions::from_mode).ok(),
                                    header
                                        .mtime()
                                        .map(|t| {
                                            std::time::UNIX_EPOCH
                                                + std::time::Duration::from_secs(t)
                                        })
                                        .ok(),
                                )?;

                                crate::io::copy_shared(&mut read_buffer, &mut entry, &mut writer)?;
                                writer.flush()?;
                            }
                            tar::EntryType::Symlink => {
                                let link =
                                    entry.link_name().unwrap_or_default().unwrap_or_default();

                                if let Err(err) =
                                    self.server.filesystem.symlink(link, &destination_path)
                                {
                                    tracing::debug!(
                                        path = %path.display(),
                                        "failed to create symlink from archive: {:#?}",
                                        err
                                    );
                                } else if let Ok(modified_time) = header.mtime() {
                                    self.server.filesystem.set_times(
                                        &destination_path,
                                        std::time::UNIX_EPOCH
                                            + std::time::Duration::from_secs(modified_time),
                                        None,
                                    )?;
                                }
                            }
                            _ => {}
                        }
                    }

                    for (destination_path, modified_time) in directory_entries {
                        self.server.filesystem.set_times(
                            &destination_path,
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified_time),
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
                    let entry_index = Arc::new(AtomicUsize::new(0));

                    if let Some(total) = total {
                        let mut entry_total = 0;
                        for i in 0..archive.len() {
                            let entry = archive.by_index(i)?;
                            entry_total += entry.size();
                        }

                        total.store(entry_total, Ordering::Relaxed);
                    }

                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(
                            self.server
                                .app_state
                                .config
                                .load()
                                .api
                                .file_decompression_threads,
                        )
                        .build()?;

                    let error = Arc::new(RwLock::new(None));

                    pool.in_place_scope(|scope| {
                        let archive = archive.clone();
                        let destination = destination.clone();
                        let server = self.server.clone();
                        let error_clone = Arc::clone(&error);

                        scope.spawn_broadcast(move |_, _| {
                            let mut archive = archive.clone();
                            let progress = progress.clone();
                            let entry_index = Arc::clone(&entry_index);
                            let error_clone2 = Arc::clone(&error_clone);
                            let destination = destination.clone();
                            let server = server.clone();

                            let mut run = move || -> Result<(), anyhow::Error> {
                                let mut read_buffer = vec![0; crate::BUFFER_SIZE];

                                loop {
                                    if error_clone2.read().is_some() {
                                        return Ok(());
                                    }

                                    let i = entry_index.fetch_add(1, Ordering::SeqCst);
                                    if i >= archive.len() {
                                        return Ok(());
                                    }

                                    let mut entry = archive.by_index(i)?;
                                    let path = match entry.enclosed_name() {
                                        Some(path) => path,
                                        None => continue,
                                    };

                                    if path.is_absolute() {
                                        continue;
                                    }

                                    let destination_path = destination.join(path);

                                    if server
                                        .filesystem
                                        .is_ignored(&destination_path, entry.is_dir())
                                    {
                                        continue;
                                    }

                                    if entry.is_dir() {
                                        server
                                            .filesystem
                                            .create_chowned_dir_all(&destination_path)?;
                                        server.filesystem.set_permissions(
                                            &destination_path,
                                            PortablePermissions::from_mode(
                                                entry.unix_mode().unwrap_or(0o755),
                                            ),
                                        )?;
                                    } else if entry.is_file() {
                                        if let Some(parent) = destination_path.parent() {
                                            server.filesystem.create_chowned_dir_all(parent)?;
                                        }

                                        let mut writer = super::file::ServerFile::new(
                                            server.clone(),
                                            &destination_path,
                                            entry.unix_mode().map(PortablePermissions::from_mode),
                                            zip_entry_get_modified_time(&entry),
                                        )?;

                                        let mut reader: Box<dyn Read> = match &progress {
                                            Some(progress) => {
                                                Box::new(CountingReader::new_with_bytes_read(
                                                    entry,
                                                    Arc::clone(progress),
                                                ))
                                            }
                                            None => Box::new(entry),
                                        };

                                        crate::io::copy_shared(
                                            &mut read_buffer,
                                            &mut reader,
                                            &mut writer,
                                        )?;
                                        writer.flush()?;
                                    } else if entry.is_symlink()
                                        && (1..=2048).contains(&entry.size())
                                    {
                                        let link =
                                            std::io::read_to_string(&mut entry).unwrap_or_default();

                                        if let Err(err) =
                                            server.filesystem.symlink(link, &destination_path)
                                        {
                                            tracing::debug!(
                                                path = %destination_path.display(),
                                                "failed to create symlink from archive: {:#?}",
                                                err
                                            );
                                        } else if let Some(modified_time) =
                                            zip_entry_get_modified_time(&entry)
                                        {
                                            server.filesystem.set_times(
                                                &destination_path,
                                                modified_time,
                                                None,
                                            )?;
                                        }

                                        if let Some(progress) = &progress {
                                            progress.fetch_add(entry.size(), Ordering::Relaxed);
                                        }
                                    }
                                }
                            };

                            if let Err(err) = run() {
                                error_clone.write().replace(err);
                            }
                        });
                    });

                    if let Some(err) = error.write().take() {
                        Err(err)
                    } else {
                        for i in 0..archive.len() {
                            let entry = archive.by_index(i)?;

                            if entry.is_dir() {
                                let path = match entry.enclosed_name() {
                                    Some(path) => path,
                                    None => continue,
                                };

                                if path.is_absolute() {
                                    continue;
                                }

                                let destination_path = destination.join(path);

                                if self
                                    .server
                                    .filesystem
                                    .is_ignored(&destination_path, entry.is_dir())
                                {
                                    continue;
                                }

                                if let Some(modified_time) = zip_entry_get_modified_time(&entry) {
                                    self.server.filesystem.set_times(
                                        &destination_path,
                                        modified_time,
                                        None,
                                    )?;
                                }
                            }
                        }

                        Ok(())
                    }
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

                    if seconds >= 60
                        || minutes >= 60
                        || hours >= 24
                        || !(1..=31).contains(&day)
                        || !(1..=12).contains(&month)
                    {
                        return None;
                    }

                    let date = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)?;
                    let time = chrono::NaiveTime::from_hms_opt(hours, minutes, seconds)?;

                    Some(chrono::NaiveDateTime::new(date, time).and_utc().timestamp() as u64)
                }

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    drop(self.file);

                    if let Some(total) = total {
                        let mut entry_total = 0;
                        let archive = unrar::Archive::new_owned(
                            self.server
                                .filesystem
                                .base_path
                                .join(self.server.filesystem.relative_path(&self.path)),
                        )
                        .open_for_listing()?;
                        for entry in archive.flatten() {
                            entry_total += entry.unpacked_size;
                        }

                        total.store(entry_total, Ordering::Relaxed);
                    }

                    let mut archive = unrar::Archive::new_owned(
                        self.server
                            .filesystem
                            .base_path
                            .join(self.server.filesystem.relative_path(&self.path)),
                    )
                    .open_for_processing()?;
                    let mut directory_entries = chunked_vec::ChunkedVec::new();

                    loop {
                        let entry = match archive.read_header()? {
                            Some(entry) => entry,
                            None => break,
                        };

                        let path = &entry.entry().filename;
                        if path.is_absolute() {
                            archive = entry.skip()?;
                            continue;
                        }

                        if self
                            .server
                            .filesystem
                            .is_ignored(path, entry.entry().is_directory())
                        {
                            archive = entry.skip()?;
                            continue;
                        }

                        if listener.is_aborted() {
                            return Err(anyhow::anyhow!("operation aborted"));
                        }

                        let destination_path = destination.join(path);

                        if entry.entry().is_directory() {
                            self.server
                                .filesystem
                                .create_chowned_dir_all(&destination_path)?;

                            if let Some(modified_time) = dos_time_to_unix(entry.entry().file_time) {
                                directory_entries.push((destination_path, modified_time));
                            }

                            archive = entry.skip()?;
                            continue;
                        } else {
                            if let Some(parent) = destination_path.parent() {
                                self.server.filesystem.create_chowned_dir_all(parent)?;
                            }

                            let writer = super::file::ServerFile::new(
                                self.server.clone(),
                                &destination_path,
                                None,
                                dos_time_to_unix(entry.entry().file_time).map(|secs| {
                                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
                                }),
                            )?;
                            let writer = AbortWriter::new(writer, listener.clone());
                            let writer: Box<dyn Write + Send + Sync> = match &progress {
                                Some(progress) => Box::new(CountingWriter::new_with_bytes_written(
                                    writer,
                                    Arc::clone(progress),
                                )),
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

                            archive = processed_archive;
                        }
                    }

                    for (destination_path, modified_time) in directory_entries {
                        self.server.filesystem.set_times(
                            &destination_path,
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified_time),
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

                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(
                            self.server
                                .app_state
                                .config
                                .load()
                                .api
                                .file_decompression_threads,
                        )
                        .build()?;

                    let error = Arc::new(RwLock::new(None));

                    pool.in_place_scope(|scope| {
                        for block_index in 0..archive.blocks.len() {
                            let archive = archive.clone();
                            let progress = progress.clone();
                            let mut reader = reader.clone();
                            let destination = destination.clone();
                            let server = self.server.clone();
                            let error_clone = Arc::clone(&error);

                            scope.spawn(move |_| {
                                if error_clone.read().is_some() {
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
                                if let Err(err) = folder.for_each_entries(&mut |entry, reader| {
                                    let path = entry.name();
                                    if path.starts_with('/') || path.starts_with('\\') {
                                        return Ok(true);
                                    }

                                    let destination_path = destination.join(path);

                                    if server
                                        .filesystem
                                        .is_ignored(&destination_path, entry.is_directory())
                                    {
                                        return Ok(true);
                                    }

                                    if entry.is_directory() {
                                        if let Err(err) = server
                                            .filesystem
                                            .create_chowned_dir_all(&destination_path)
                                        {
                                            return Err(sevenz_rust2::Error::Other(
                                                err.to_string().into(),
                                            ));
                                        }
                                    } else {
                                        if let Some(parent) = destination_path.parent()
                                            && let Err(err) =
                                                server.filesystem.create_chowned_dir_all(parent)
                                        {
                                            return Err(sevenz_rust2::Error::Other(
                                                err.to_string().into(),
                                            ));
                                        }

                                        let mut writer = super::file::ServerFile::new(
                                            server.clone(),
                                            &destination_path,
                                            None,
                                            if entry.has_last_modified_date {
                                                Some(entry.last_modified_date.into())
                                            } else {
                                                None
                                            },
                                        )
                                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                                        let mut reader: Box<dyn Read> = match &progress {
                                            Some(progress) => {
                                                Box::new(CountingReader::new_with_bytes_read(
                                                    reader,
                                                    Arc::clone(progress),
                                                ))
                                            }
                                            None => Box::new(reader),
                                        };

                                        crate::io::copy_shared(
                                            &mut read_buffer,
                                            &mut reader,
                                            &mut writer,
                                        )?;
                                        writer.flush()?;
                                    }

                                    Ok(true)
                                }) {
                                    error_clone.write().replace(err);
                                }
                            });
                        }
                    });

                    if let Some(err) = error.write().take() {
                        Err(err.into())
                    } else {
                        for entry in archive.files {
                            if entry.is_directory() && entry.has_last_modified_date {
                                let path = entry.name();
                                if path.starts_with('/') || path.starts_with('\\') {
                                    continue;
                                }

                                let destination_path = destination.join(path);

                                if self
                                    .server
                                    .filesystem
                                    .is_ignored(&destination_path, entry.is_directory())
                                {
                                    continue;
                                }

                                self.server.filesystem.set_times(
                                    &destination_path,
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

                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(
                            self.server
                                .app_state
                                .config
                                .load()
                                .api
                                .file_decompression_threads,
                        )
                        .build()?;

                    fn recursive_traverse(
                        scope: &rayon::Scope,
                        listener: &AbortListener,
                        progress: &Option<Arc<AtomicU64>>,
                        server: &crate::server::Server,
                        destination: &Path,
                        entry: ddup_bak::archive::entries::Entry,
                    ) -> Result<(), anyhow::Error> {
                        let destination_path = destination.join(entry.name());
                        if server
                            .filesystem
                            .is_ignored(&destination_path, entry.is_directory())
                        {
                            return Ok(());
                        }

                        if listener.is_aborted() {
                            return Err(anyhow::anyhow!("operation aborted"));
                        }

                        match entry {
                            ddup_bak::archive::entries::Entry::Directory(dir) => {
                                server
                                    .filesystem
                                    .create_chowned_dir_all(&destination_path)?;
                                server.filesystem.set_permissions(
                                    &destination_path,
                                    PortablePermissions::from_mode(dir.mode.bits()),
                                )?;

                                for entry in dir.entries {
                                    recursive_traverse(
                                        scope,
                                        listener,
                                        progress,
                                        server,
                                        &destination_path,
                                        entry,
                                    )?;
                                }

                                server
                                    .filesystem
                                    .set_times(&destination_path, dir.mtime, None)?;
                            }
                            ddup_bak::archive::entries::Entry::File(file) => {
                                let mut writer = super::file::ServerFile::new(
                                    server.clone(),
                                    &destination_path,
                                    Some(PortablePermissions::from_mode(file.mode.bits())),
                                    Some(file.mtime),
                                )?;

                                let reader = AbortReader::new(file, listener.clone());
                                let mut reader: Box<dyn Read + Send> = match progress {
                                    Some(progress) => {
                                        Box::new(CountingReader::new_with_bytes_read(
                                            reader,
                                            Arc::clone(progress),
                                        ))
                                    }
                                    None => Box::new(reader),
                                };

                                scope.spawn(move |_| {
                                    let mut run = || -> Result<(), std::io::Error> {
                                        crate::io::copy(&mut reader, &mut writer)?;
                                        writer.flush()?;

                                        Ok(())
                                    };

                                    if let Err(err) = run() {
                                        tracing::debug!(
                                            path = %destination_path.display(),
                                            "failed to extract file from archive: {:#?}",
                                            err
                                        );
                                    }
                                });
                            }
                            ddup_bak::archive::entries::Entry::Symlink(link) => {
                                if let Err(err) =
                                    server.filesystem.symlink(link.target, &destination_path)
                                {
                                    tracing::debug!(
                                        path = %destination_path.display(),
                                        "failed to create symlink from archive: {:#?}",
                                        err
                                    );
                                } else {
                                    server.filesystem.set_times(
                                        &destination_path,
                                        link.mtime,
                                        None,
                                    )?;
                                }
                            }
                        }

                        Ok(())
                    }

                    pool.in_place_scope(|scope| {
                        for entry in archive.into_entries() {
                            recursive_traverse(
                                scope,
                                &listener,
                                &progress,
                                &self.server,
                                &destination,
                                entry,
                            )?;
                        }

                        Ok(())
                    })
                })
                .await??;

                drop(guard);
            }
        }

        Ok(())
    }
}
