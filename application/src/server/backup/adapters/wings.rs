use crate::{
    io::{
        SafeDigestExt, compression::reader::CompressionReaderMt, counting_reader::CountingReader,
        limited_reader::LimitedReader, limited_writer::LimitedWriter,
        range_reader::AsyncRangeReader,
    },
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::{
                ArchiveFormat, StreamableArchiveFormat, multi_reader::MultiReader,
                zip_entry_get_modified_time,
            },
            virtualfs::{
                ByteRange, VirtualReadableFilesystem,
                archive::{seven_zip::VirtualSevenZipArchive, zip::VirtualZipArchive},
            },
        },
    },
    utils::PortablePermissions,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use parking_lot::RwLock;
use sha2::Digest;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::io::AsyncReadExt;

pub struct WingsBackup {
    uuid: uuid::Uuid,
    pub format: ArchiveFormat,

    pub path: PathBuf,
}

impl WingsBackup {
    #[inline]
    fn get_format_file_name(
        config: &crate::config::Config,
        uuid: uuid::Uuid,
        format: ArchiveFormat,
    ) -> PathBuf {
        Path::new(&config.load().system.backup_directory)
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
    ) -> Result<(ArchiveFormat, PathBuf), anyhow::Error> {
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
                return Ok((format, file_name));
            }
        }

        Err(anyhow::anyhow!("no backup file found for backup {}", uuid))
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
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        _ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let file_name = Self::get_file_name(&server.app_state.config, uuid);
        let file = tokio::fs::File::create(&file_name).await?.into_std().await;

        let total_task = {
            let server = server.clone();
            let ignore = ignore.clone();

            async move {
                let mut walker = server
                    .filesystem
                    .async_walk_dir(Path::new(""))
                    .await?
                    .with_is_ignored(ignore.into());
                let mut total_files = 0;
                while let Some(Ok((_, path))) = walker.next_entry().await {
                    let metadata = match server.filesystem.async_symlink_metadata(&path).await {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };

                    total.fetch_add(metadata.len(), Ordering::Relaxed);
                    if !metadata.is_dir() {
                        total_files += 1;
                    }
                }

                Ok::<_, anyhow::Error>(total_files)
            }
        };

        let archive_task = async move {
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
                        Some(progress),
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
                        Some(progress),
                        ignore.into(),
                        crate::server::filesystem::archive::create::CreateZipOptions {
                            compression_level: server
                                .app_state
                                .config
                                .load()
                                .system
                                .backups
                                .compression_level,
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
                        Some(progress),
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
        };

        let (total_files, _) = tokio::try_join!(total_task, archive_task)?;

        let mut checksum_writer = sha2::Sha256::new();
        let mut file = tokio::fs::File::open(&file_name).await?;
        let mut buffer = vec![0; crate::BUFFER_SIZE];

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
            files: total_files,
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

            ApiResponse::new_stream(reader)
                .with_headers(headers)
                .with_status(StatusCode::PARTIAL_CONTENT)
        } else {
            headers.insert(axum::http::header::CONTENT_LENGTH, metadata.len().into());

            ApiResponse::new_stream(file).with_headers(headers)
        })
    }

    async fn restore(
        &self,
        server: &crate::server::Server,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let file = tokio::fs::File::open(&self.path).await?.into_std().await;

        match self.format {
            ArchiveFormat::Tar
            | ArchiveFormat::TarGz
            | ArchiveFormat::TarXz
            | ArchiveFormat::TarLzip
            | ArchiveFormat::TarBz2
            | ArchiveFormat::TarLz4
            | ArchiveFormat::TarZstd => {
                let compression_type = self.format.compression_format();
                let server = server.clone();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    total.store(file.metadata()?.len(), Ordering::SeqCst);

                    let reader = LimitedReader::new_with_bytes_per_second(
                        file,
                        server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .read_limit
                            .as_bytes(),
                    );
                    let reader = CountingReader::new_with_bytes_read(reader, progress);
                    let reader = CompressionReaderMt::new(
                        reader,
                        compression_type,
                        server
                            .app_state
                            .config
                            .load()
                            .api
                            .file_decompression_threads,
                    )?;

                    let mut archive = tar::Archive::new(reader);
                    let mut directory_entries = Vec::new();
                    let mut entries = archive.entries()?;

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    while let Some(Ok(mut entry)) = entries.next() {
                        let path = entry.path()?;

                        if path.is_absolute() {
                            continue;
                        }

                        let destination_path = path.as_ref();
                        let header = entry.header();

                        match header.entry_type() {
                            tar::EntryType::Directory => {
                                server.filesystem.create_chowned_dir_all(destination_path)?;
                                if let Ok(permissions) =
                                    header.mode().map(PortablePermissions::from_mode)
                                {
                                    server
                                        .filesystem
                                        .set_permissions(destination_path, permissions)?;
                                }

                                if let Ok(modified_time) = header.mtime() {
                                    directory_entries
                                        .push((destination_path.to_path_buf(), modified_time));
                                }
                            }
                            tar::EntryType::Regular => {
                                server.log_daemon(compact_str::format_compact!(
                                    "(restoring): {}",
                                    path.display()
                                ));

                                if let Some(parent) = destination_path.parent() {
                                    server.filesystem.create_chowned_dir_all(parent)?;
                                }

                                let mut writer = crate::server::filesystem::file::ServerFile::new(
                                    server.clone(),
                                    destination_path,
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

                                if let Err(err) = server.filesystem.symlink(link, destination_path)
                                {
                                    tracing::debug!(
                                        path = %destination_path.display(),
                                        "failed to create symlink from archive: {:#?}",
                                        err
                                    );
                                } else if let Ok(modified_time) = header.mtime() {
                                    server.filesystem.set_times(
                                        destination_path,
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
                        server
                            .filesystem
                            .set_times(
                                &destination_path,
                                std::time::UNIX_EPOCH
                                    + std::time::Duration::from_secs(modified_time),
                                None,
                            )
                            .ok();
                    }

                    Ok(())
                })
                .await??;
            }
            ArchiveFormat::Zip => {
                let server = server.clone();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = MultiReader::new(Arc::new(file))?;
                    let mut archive = zip::ZipArchive::new(reader)?;
                    let entry_index = Arc::new(AtomicUsize::new(0));

                    for i in 0..archive.len() {
                        let entry = archive.by_index(i)?;

                        if entry.enclosed_name().is_none() {
                            continue;
                        }

                        total.fetch_add(entry.size(), Ordering::SeqCst);
                    }

                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(server.app_state.config.load().system.backups.wings.restore_threads)
                        .build()?;

                    let error = Arc::new(RwLock::new(None));

                    pool.in_place_scope(|scope| {
                        let archive = archive.clone();
                        let server = server.clone();
                        let error_clone = Arc::clone(&error);

                        scope.spawn_broadcast(move |_, _| {
                            let mut archive = archive.clone();
                            let progress = Arc::clone(&progress);
                            let entry_index = Arc::clone(&entry_index);
                            let error_clone2 = Arc::clone(&error_clone);
                            let server = server.clone();

                            let mut run = move || -> Result<(), anyhow::Error> {
                                let mut read_buffer = vec![0; crate::BUFFER_SIZE];

                                loop {
                                    if error_clone2.read().is_some() {
                                        return Ok(());
                                    }

                                    let i =
                                        entry_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

                                    if entry.is_dir() {
                                        server.filesystem.create_chowned_dir_all(&path)?;
                                        server.filesystem.set_permissions(
                                            &path,
                                            PortablePermissions::from_mode(
                                                entry.unix_mode().unwrap_or(0o755),
                                            ),
                                        )?;
                                    } else if entry.is_file() {
                                        server.log_daemon(compact_str::format_compact!("(restoring): {}", path.display()));

                                        if let Some(parent) = path.parent() {
                                            server.filesystem.create_chowned_dir_all(parent)?;
                                        }

                                        let mut writer = crate::server::filesystem::file::ServerFile::new(
                                            server.clone(),
                                            &path,
                                            entry.unix_mode().map(PortablePermissions::from_mode),
                                            crate::server::filesystem::archive::zip_entry_get_modified_time(&entry),
                                        )?;
                                        let mut reader = CountingReader::new_with_bytes_read(
                                            entry,
                                            Arc::clone(&progress),
                                        );

                                        if let Err(err) = crate::io::copy_shared(&mut read_buffer, &mut reader, &mut writer) {
                                            if err.kind() == std::io::ErrorKind::InvalidData {
                                                tracing::warn!(
                                                    path = %path.display(),
                                                    "corrupted backup file: {:#?}",
                                                    err
                                                );
                                            } else {
                                                Err(err)?;
                                            }
                                        }
                                        writer.flush()?;
                                    } else if entry.is_symlink() && (1..=2048).contains(&entry.size()) {
                                        let link = std::io::read_to_string(&mut entry).unwrap_or_default();

                                        if let Err(err) = server.filesystem.symlink(link, &path) {
                                            tracing::debug!(
                                                path = %path.display(),
                                                "failed to create symlink from backup: {:#?}",
                                                err
                                            );
                                        } else if let Some(modified_time) = zip_entry_get_modified_time(&entry) {
                                            server.filesystem.set_times(
                                                &path,
                                                modified_time,
                                                None,
                                            )?;
                                        }
                                    }
                                }
                            };

                            if let Err(err) = run() {
                                error_clone.write().replace(err);
                            }
                        });
                    });

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

                            if server
                                .filesystem
                                .is_ignored(&path, entry.is_dir())
                            {
                                continue;
                            }

                            if let Some(modified_time) = zip_entry_get_modified_time(&entry) {
                                server.filesystem.set_times(
                                    &path,
                                    modified_time,
                                    None,
                                ).ok();
                            }
                        }
                    }

                    if let Some(err) = error.write().take() {
                        Err(err)
                    } else {
                        Ok(())
                    }
                })
                .await??;
            }
            ArchiveFormat::SevenZip => {
                let server = server.clone();

                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = MultiReader::new(Arc::new(file))?;
                    let password = sevenz_rust2::Password::empty();
                    let archive = sevenz_rust2::Archive::read(&mut reader.clone(), &password)?;

                    total.store(
                        archive.files.iter().map(|f| f.size).sum(),
                        Ordering::Relaxed,
                    );

                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(
                            server
                                .app_state
                                .config
                                .load()
                                .system
                                .backups
                                .wings
                                .restore_threads,
                        )
                        .build()?;

                    let error = Arc::new(RwLock::new(None));

                    pool.in_place_scope(|scope| {
                        for block_index in 0..archive.blocks.len() {
                            let archive = archive.clone();
                            let progress = progress.clone();
                            let mut reader = reader.clone();
                            let server = server.clone();
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

                                    let destination_path = Path::new(path);

                                    if server
                                        .filesystem
                                        .is_ignored(destination_path, entry.is_directory())
                                    {
                                        return Ok(true);
                                    }

                                    if entry.is_directory() {
                                        if let Err(err) = server
                                            .filesystem
                                            .create_chowned_dir_all(destination_path)
                                        {
                                            return Err(sevenz_rust2::Error::Other(
                                                err.to_string().into(),
                                            ));
                                        }
                                    } else {
                                        server.log_daemon(compact_str::format_compact!(
                                            "(restoring): {path}"
                                        ));

                                        if let Some(parent) = destination_path.parent()
                                            && let Err(err) =
                                                server.filesystem.create_chowned_dir_all(parent)
                                        {
                                            return Err(sevenz_rust2::Error::Other(
                                                err.to_string().into(),
                                            ));
                                        }

                                        let mut writer =
                                            crate::server::filesystem::file::ServerFile::new(
                                                server.clone(),
                                                destination_path,
                                                None,
                                                if entry.has_last_modified_date {
                                                    Some(entry.last_modified_date.into())
                                                } else {
                                                    None
                                                },
                                            )
                                            .map_err(|e| std::io::Error::other(e.to_string()))?;

                                        let mut reader = CountingReader::new_with_bytes_read(
                                            reader,
                                            Arc::clone(&progress),
                                        );

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

                                let destination_path = Path::new(path);

                                if server
                                    .filesystem
                                    .is_ignored(destination_path, entry.is_directory())
                                {
                                    continue;
                                }

                                server
                                    .filesystem
                                    .set_times(
                                        destination_path,
                                        entry.last_modified_date.into(),
                                        None,
                                    )
                                    .ok();
                            }
                        }

                        Ok(())
                    }
                })
                .await??;
            }
        };

        Ok(())
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
        match self.format {
            ArchiveFormat::Zip => {
                let reader = Arc::new(tokio::fs::File::open(&self.path).await?.into_std().await);
                let archive = tokio::task::spawn_blocking(move || {
                    zip::ZipArchive::new(MultiReader::new(reader)?)
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
            ArchiveFormat::SevenZip => {
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
impl BackupCleanExt for WingsBackup {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let file_name = Self::get_file_name(&server.app_state.config, uuid);
        if tokio::fs::metadata(&file_name).await.is_err() {
            return Ok(());
        }

        tokio::fs::remove_file(&file_name).await?;

        Ok(())
    }
}
