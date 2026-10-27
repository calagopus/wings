use crate::{
    io::{
        SafeDigestExt,
        compression::{CompressionType, reader::AsyncCompressionReader, writer::CompressionWriter},
        limited_reader::LimitedReader,
        limited_writer::LimitedWriter,
        range_reader::AsyncRangeReader,
    },
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::{
        backup::{
            Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt, BackupStream,
            BackupStreamCreateExt, BackupStreamExt, BackupTestExt, DumpReader,
        },
        filesystem::{
            archive::{
                Archive, ArchiveFormat, ExtractOptions, StreamableArchiveFormat,
                multi_reader::MultiReader,
            },
            virtualfs::{
                ByteRange, VirtualReadableFilesystem,
                archive::{seven_zip::VirtualSevenZipArchive, zip::VirtualZipArchive},
            },
        },
    },
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use sha2::Digest;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncReadExt;

pub enum WingsBackupFile {
    Archive(ArchiveFormat),
    Dump {
        extension: compact_str::CompactString,
        compression: CompressionType,
    },
}

impl WingsBackupFile {
    #[inline]
    pub fn compression_suffix(compression: CompressionType) -> &'static str {
        match compression {
            CompressionType::None => "",
            CompressionType::Gz => ".gz",
            CompressionType::Xz => ".xz",
            CompressionType::Lzip => ".lz",
            CompressionType::Bz2 => ".bz2",
            CompressionType::Lz4 => ".lz4",
            CompressionType::Zstd => ".zst",
        }
    }

    #[inline]
    pub fn extension(&self) -> compact_str::CompactString {
        match self {
            Self::Archive(format) => format.extension().into(),
            Self::Dump {
                extension,
                compression,
            } => compact_str::format_compact!(
                "{extension}{}",
                Self::compression_suffix(*compression)
            ),
        }
    }

    #[inline]
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Archive(format) => format.mime_type(),
            Self::Dump { compression, .. } => match compression {
                CompressionType::None => "application/octet-stream",
                CompressionType::Gz => "application/gzip",
                CompressionType::Xz => "application/x-xz",
                CompressionType::Lzip => "application/x-lzip",
                CompressionType::Bz2 => "application/x-bzip2",
                CompressionType::Lz4 => "application/x-lz4",
                CompressionType::Zstd => "application/zstd",
            },
        }
    }

    #[inline]
    pub fn archive_format(&self) -> Option<ArchiveFormat> {
        match self {
            Self::Archive(format) => Some(*format),
            Self::Dump { .. } => None,
        }
    }

    pub fn parse_dump(rest: &str) -> Option<Self> {
        if rest.is_empty() || rest.ends_with(".part") || rest.contains(".s3.") {
            return None;
        }

        let (extension, compression) = crate::server::backup::parse_dump_extension(rest).ok()?;

        Some(Self::Dump {
            extension: extension.into(),
            compression,
        })
    }
}

pub struct WingsBackup {
    uuid: uuid::Uuid,
    pub format: WingsBackupFile,

    pub path: PathBuf,
}

impl WingsBackup {
    #[inline]
    fn get_dump_file_name(
        config: &crate::config::Config,
        uuid: uuid::Uuid,
        extension: &str,
        compression: CompressionType,
    ) -> PathBuf {
        config
            .resolve_as_path(|cfg| &cfg.system.backup_directory)
            .join(format!(
                "{uuid}.{extension}{}",
                WingsBackupFile::compression_suffix(compression)
            ))
    }

    /// Keeps the source encoding when it already matches the target or when no
    /// compression is configured, so dumps are never compressed twice.
    #[inline]
    fn dump_stored_compression(
        source: CompressionType,
        target: CompressionType,
    ) -> CompressionType {
        if target == CompressionType::None {
            source
        } else {
            target
        }
    }

    async fn find_dump_file(
        config: &crate::config::Config,
        uuid: uuid::Uuid,
    ) -> Option<(WingsBackupFile, PathBuf)> {
        let mut futures = Vec::new();
        futures.reserve_exact(
            super::super::DATABASE_DUMP_EXTENSIONS.len() * CompressionType::variants().len(),
        );
        for extension in super::super::DATABASE_DUMP_EXTENSIONS {
            for compression in CompressionType::variants() {
                let file_name = Self::get_dump_file_name(config, uuid, extension, *compression);
                futures.push(async move {
                    (
                        tokio::fs::metadata(&file_name).await.is_ok(),
                        *extension,
                        *compression,
                        file_name,
                    )
                });
            }
        }

        let results = futures::future::join_all(futures).await;
        for (found, extension, compression, file_name) in results {
            if found {
                return Some((
                    WingsBackupFile::Dump {
                        extension: extension.into(),
                        compression,
                    },
                    file_name,
                ));
            }
        }

        None
    }

    #[inline]
    fn get_format_file_name(
        config: &crate::config::Config,
        uuid: uuid::Uuid,
        format: ArchiveFormat,
    ) -> PathBuf {
        config
            .resolve_as_path(|cfg| &cfg.system.backup_directory)
            .join(format!("{uuid}.{}", format.extension()))
    }

    #[inline]
    fn get_file_name(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Self::get_format_file_name(
            config,
            uuid,
            config.load().system.backups.wings.archive_format,
        )
    }

    #[inline]
    pub async fn get_first_file_name(
        config: &crate::config::Config,
        uuid: uuid::Uuid,
    ) -> Result<(WingsBackupFile, PathBuf), anyhow::Error> {
        let mut futures = Vec::new();
        futures.reserve_exact(ArchiveFormat::variants().len());
        for format in ArchiveFormat::variants() {
            let file_name = Self::get_format_file_name(config, uuid, *format);
            futures.push(async move {
                (
                    tokio::fs::metadata(&file_name).await.is_ok(),
                    *format,
                    file_name,
                )
            });
        }

        let results = futures::future::join_all(futures).await;
        for (found, format, file_name) in results {
            if found {
                return Ok((WingsBackupFile::Archive(format), file_name));
            }
        }

        if let Some(found) = Self::find_dump_file(config, uuid).await {
            return Ok(found);
        }

        Err(anyhow::anyhow!("no backup file found for backup {}", uuid))
    }
}

#[async_trait::async_trait]
impl BackupStreamCreateExt for WingsBackup {
    async fn create_from_stream(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
        extension: &str,
        source_compression: CompressionType,
        reader: DumpReader,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let config = state.config.load();
        let target_compression = config
            .system
            .backups
            .wings
            .archive_format
            .compression_format();
        let compression_level = config.system.backups.compression_level;
        let threads = config.system.backups.wings.create_threads;
        let write_limit = config.system.backups.write_limit.as_bytes();
        drop(config);

        let compression = Self::dump_stored_compression(source_compression, target_compression);
        let (reader, write_compression) = if compression == source_compression {
            (reader, CompressionType::None)
        } else {
            (
                super::decompress_dump(reader, source_compression),
                compression,
            )
        };

        let file_name = Self::get_dump_file_name(&state.config, uuid, extension, compression);
        let part_file_name = file_name.with_extension(format!(
            "{}.part",
            file_name
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default()
        ));

        let file = tokio::fs::File::create(&part_file_name)
            .await?
            .into_std()
            .await;

        let write_result = tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let writer = LimitedWriter::new_with_bytes_per_second(file, write_limit);
            let mut writer =
                CompressionWriter::new(writer, write_compression, compression_level, threads)?;
            let mut reader = tokio_util::io::SyncIoBridge::new(reader);

            crate::io::copy(&mut reader, &mut writer)?;
            writer.finish()?.into_inner().sync_all()?;

            Ok(())
        })
        .await?;

        if let Err(err) = write_result {
            tokio::fs::remove_file(&part_file_name).await.ok();

            return Err(err);
        }

        tokio::fs::rename(&part_file_name, &file_name).await?;

        let mut checksum_writer = sha2::Sha256::new();
        let mut file = tokio::fs::File::open(&file_name).await?;
        let mut buffer = crate::io::mem_buffer(crate::BUFFER_SIZE);

        loop {
            match file.read(&mut buffer).await? {
                0 => break,
                bytes_read => checksum_writer.safe_update(&buffer, bytes_read)?,
            }
        }

        let size = tokio::fs::metadata(&file_name).await?.len();

        if size == 0 {
            tokio::fs::remove_file(&file_name).await.ok();

            return Err(anyhow::anyhow!("database dump is 0 bytes"));
        }

        Ok(RawServerBackup {
            checksum: hex::encode(checksum_writer.finalize()),
            checksum_type: "sha256".into(),
            size,
            files: 0,
            successful: true,
            browsable: false,
            streaming: false,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupStreamExt for WingsBackup {
    async fn read_stream(
        &self,
        _state: &crate::routes::State,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<BackupStream, anyhow::Error> {
        let WingsBackupFile::Dump {
            extension,
            compression,
        } = &self.format
        else {
            return Err(anyhow::anyhow!("backup is not a database dump"));
        };

        let file = tokio::fs::File::open(&self.path).await?;
        let file_name = compact_str::format_compact!("{}.{extension}", self.uuid);

        Ok(match compression {
            CompressionType::None => BackupStream {
                size: Some(file.metadata().await?.len()),
                reader: Box::new(file),
                file_name,
            },
            compression => BackupStream {
                size: None,
                reader: Box::new(AsyncCompressionReader::new(
                    file.into_std().await,
                    *compression,
                )),
                file_name,
            },
        })
    }
}

#[async_trait::async_trait]
impl BackupFindExt for WingsBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        Ok(Self::get_first_file_name(&state.config, uuid).await.is_ok())
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        if let Ok((format, path)) = Self::get_first_file_name(&state.config, uuid).await {
            Ok(Some(Backup::Wings(Self { uuid, format, path })))
        } else {
            Ok(None)
        }
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for WingsBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        ignore: crate::server::filesystem::ignore_list::IgnoreList,
        _ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let file_name = Self::get_file_name(&server.app_state.config, uuid);
        let file = tokio::fs::File::create(&file_name).await?.into_std().await;

        let total_task = {
            let filesystem = server.filesystem.clone();
            let ignore = ignore.clone();
            let total = Arc::clone(&total);

            async move {
                tokio::task::spawn_blocking(move || {
                    let mut walker = filesystem
                        .walk_dir(Path::new(""))?
                        .with_is_ignored(ignore.into());
                    while let Some(Ok(entry)) = walker.next_entry() {
                        let metadata = match entry.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => continue,
                        };

                        total.fetch_add(metadata.len(), Ordering::Relaxed);
                    }

                    Ok::<_, anyhow::Error>(())
                })
                .await?
            }
        };

        let archive_task = {
            let progress = progress.clone();
            async move {
                let sources = server.filesystem.async_read_dir_all(Path::new("")).await?;
                let writer = LimitedWriter::new_with_bytes_per_second(
                    file,
                    server
                        .app_state
                        .config
                        .load()
                        .system
                        .backups
                        .write_limit
                        .as_bytes(),
                );

                let file = match server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .wings
                    .archive_format
                {
                    ArchiveFormat::Tar
                    | ArchiveFormat::TarGz
                    | ArchiveFormat::TarXz
                    | ArchiveFormat::TarLzip
                    | ArchiveFormat::TarBz2
                    | ArchiveFormat::TarLz4
                    | ArchiveFormat::TarZstd => {
                        crate::server::filesystem::archive::create::create_tar(
                            server.filesystem.clone(),
                            writer,
                            Path::new(""),
                            sources,
                            progress.clone(),
                            ignore.into(),
                            crate::server::filesystem::archive::create::CreateTarOptions {
                                compression_type: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .wings
                                    .archive_format
                                    .compression_format(),
                                compression_level: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .compression_level,
                                threads: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .wings
                                    .create_threads,
                            },
                        )
                        .await
                    }
                    ArchiveFormat::Zip => {
                        crate::server::filesystem::archive::create::create_zip(
                            server.filesystem.clone(),
                            writer,
                            Path::new(""),
                            sources,
                            progress.clone(),
                            ignore.into(),
                            crate::server::filesystem::archive::create::CreateZipOptions {
                                compression_level: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .compression_level,
                                threads: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .wings
                                    .create_threads,
                            },
                        )
                        .await
                    }
                    ArchiveFormat::SevenZip => {
                        crate::server::filesystem::archive::create::create_7z(
                            server.filesystem.clone(),
                            writer,
                            Path::new(""),
                            sources,
                            progress.clone(),
                            ignore.into(),
                            crate::server::filesystem::archive::create::Create7zOptions {
                                compression_level: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .compression_level,
                                threads: server
                                    .app_state
                                    .config
                                    .load()
                                    .system
                                    .backups
                                    .wings
                                    .create_threads,
                            },
                        )
                        .await
                    }
                }?;

                tokio::task::spawn_blocking(move || file.into_inner().sync_all()).await??;

                Ok(())
            }
        };

        tokio::try_join!(total_task, archive_task)?;

        let mut checksum_writer = sha2::Sha256::new();
        let mut file = tokio::fs::File::open(&file_name).await?;
        let mut buffer = crate::io::mem_buffer(crate::BUFFER_SIZE);

        loop {
            match file.read(&mut buffer).await? {
                0 => break,
                bytes_read => checksum_writer.safe_update(&buffer, bytes_read)?,
            }
        }

        let size = tokio::fs::metadata(file_name).await?.len();

        if size == 0 {
            return Err(anyhow::anyhow!(
                "backup file is 0 bytes, this should not be possible"
            ));
        }

        Ok(RawServerBackup {
            checksum: hex::encode(checksum_writer.finalize()),
            checksum_type: "sha256".into(),
            size,
            files: progress
                .clone_files()
                .map_or(0, |files| files.load(Ordering::Relaxed)),
            successful: true,
            browsable: matches!(
                server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .wings
                    .archive_format,
                ArchiveFormat::Zip | ArchiveFormat::SevenZip
            ),
            streaming: false,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for WingsBackup {
    #[inline]
    fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    async fn download_info(
        &self,
    ) -> Result<crate::server::backup::BackupDownloadInfo, anyhow::Error> {
        let size = tokio::fs::metadata(&self.path)
            .await
            .ok()
            .map(|metadata| metadata.len());

        Ok(crate::server::backup::BackupDownloadInfo {
            archive_format: self.format.archive_format(),
            size,
        })
    }

    async fn download(
        &self,
        _state: &crate::routes::State,
        _archive_format: StreamableArchiveFormat,
        range: Option<ByteRange>,
    ) -> Result<ApiResponse, anyhow::Error> {
        let file = tokio::fs::File::open(&self.path).await?;
        let metadata = file.metadata().await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_DISPOSITION,
            HeaderValue::try_from(format!(
                "attachment; filename={}.{}",
                self.uuid,
                self.format.extension()
            ))?,
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static(self.format.mime_type()),
        );
        headers.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse()?);

        Ok(if let Some(range) = range {
            let reader = AsyncRangeReader::new(file, range, metadata.len()).await?;

            headers.insert(axum::http::header::CONTENT_LENGTH, reader.len().into());
            headers.insert(
                axum::http::header::CONTENT_RANGE,
                range.get_header_value(metadata.len()),
            );

            ApiResponse::new_stream_with_capacity(reader, crate::FILE_STREAM_BUFFER_SIZE)
                .with_headers(headers)
                .with_status(StatusCode::PARTIAL_CONTENT)
        } else {
            headers.insert(axum::http::header::CONTENT_LENGTH, metadata.len().into());

            ApiResponse::new_stream_with_capacity(file, crate::FILE_STREAM_BUFFER_SIZE)
                .with_headers(headers)
        })
    }

    async fn restore(
        &self,
        server: &crate::server::Server,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let WingsBackupFile::Archive(format) = &self.format else {
            return Err(anyhow::anyhow!(
                "database dumps cannot be restored to server files"
            ));
        };
        let format = *format;

        let file = tokio::fs::File::open(&self.path).await?;
        let size = file.metadata().await?.len();
        let file = file.into_std().await;

        let config = server.app_state.config.load();
        let read_limit = config.system.backups.read_limit.as_bytes();
        let threads = match format {
            ArchiveFormat::Zip | ArchiveFormat::SevenZip => {
                Some(config.system.backups.wings.restore_threads)
            }
            _ => None,
        };
        drop(config);

        // an unlimited file keeps lock-free positioned reads instead of seeking
        // under the shared reader's lock
        let archive = if read_limit == 0 {
            Archive::from_file(
                server.clone(),
                format.compression_format(),
                format.archive_type(),
                file,
                self.path.clone(),
                Some(size),
            )
        } else {
            Archive::from_seekable(
                server.clone(),
                format.compression_format(),
                format.archive_type(),
                LimitedReader::new_with_bytes_per_second(file, read_limit),
                Some(size),
            )
        };

        let (destination, destination_filesystem) =
            server.filesystem.resolve_writable_fs(server, "").await;

        archive
            .extract(
                destination,
                destination_filesystem,
                progress,
                Some(total),
                ExtractOptions {
                    threads,
                    on_file: Some(Arc::new({
                        let server = server.clone();

                        move |path| super::log_restoring(&server, path)
                    })),
                    ..Default::default()
                },
            )
            .await
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        tokio::fs::remove_file(&self.path).await?;

        state
            .backup_manager
            .invalidate_cached_browse(self.uuid)
            .await;

        Ok(())
    }

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        match &self.format {
            WingsBackupFile::Archive(ArchiveFormat::Zip) => {
                let reader = Arc::new(tokio::fs::File::open(&self.path).await?.into_std().await);
                let archive = tokio::task::spawn_blocking(move || {
                    crate::server::filesystem::archive::open_zip(MultiReader::new(reader)?)
                })
                .await??;

                let metadata = tokio::fs::metadata(&self.path).await?;

                Ok(Arc::new(VirtualZipArchive::new(
                    server.clone(),
                    archive,
                    metadata
                        .created()
                        .map_or_else(|_| Default::default(), |dt| dt.into()),
                )))
            }
            WingsBackupFile::Archive(ArchiveFormat::SevenZip) => {
                let reader = Arc::new(tokio::fs::File::open(&self.path).await?.into_std().await);
                let password = sevenz_rust2::Password::empty();
                let (reader, archive) = tokio::task::spawn_blocking(move || {
                    let mut reader = MultiReader::new(reader)?;

                    Ok::<_, sevenz_rust2::Error>((
                        reader.clone(),
                        sevenz_rust2::Archive::read(&mut reader, &password)?,
                    ))
                })
                .await??;

                let metadata = tokio::fs::metadata(&self.path).await?;

                Ok(Arc::new(VirtualSevenZipArchive::new(
                    server.clone(),
                    Arc::new(archive),
                    metadata
                        .created()
                        .map_or_else(|_| Default::default(), |dt| dt.into()),
                    reader,
                )))
            }
            _ => Err(anyhow::anyhow!(
                "this backup adapter does not support browsing files"
            )),
        }
    }
}

#[async_trait::async_trait]
impl BackupTestExt for WingsBackup {
    type Configuration = ();

    async fn test(
        state: &crate::routes::State,
        _configuration: Option<Self::Configuration>,
    ) -> Result<(), anyhow::Error> {
        super::probe_backup_directory(&state.config).await
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for WingsBackup {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let file_name = Self::get_file_name(&server.app_state.config, uuid);
        if tokio::fs::metadata(&file_name).await.is_ok() {
            tokio::fs::remove_file(&file_name).await?;
        }

        let prefix = format!("{uuid}.");
        let mut entries = tokio::fs::read_dir(
            server
                .app_state
                .config
                .resolve_as_path(|cfg| &cfg.system.backup_directory),
        )
        .await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let Some(rest) = file_name
                .to_str()
                .and_then(|name| name.strip_prefix(&prefix))
            else {
                continue;
            };

            if rest.contains(".s3.") {
                continue;
            }

            if rest.ends_with(".part") || WingsBackupFile::parse_dump(rest).is_some() {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // WingsBackup::dump_stored_compression
    #[test]
    fn dump_stored_compression_never_double_compresses() {
        assert_eq!(
            WingsBackup::dump_stored_compression(CompressionType::Gz, CompressionType::None),
            CompressionType::Gz
        );
        assert_eq!(
            WingsBackup::dump_stored_compression(CompressionType::None, CompressionType::None),
            CompressionType::None
        );
        assert_eq!(
            WingsBackup::dump_stored_compression(CompressionType::Zstd, CompressionType::Zstd),
            CompressionType::Zstd
        );
        assert_eq!(
            WingsBackup::dump_stored_compression(CompressionType::Gz, CompressionType::Zstd),
            CompressionType::Zstd
        );
        assert_eq!(
            WingsBackup::dump_stored_compression(CompressionType::None, CompressionType::Xz),
            CompressionType::Xz
        );
    }
}
