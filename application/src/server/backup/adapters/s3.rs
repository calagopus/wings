use crate::{
    io::{
        SafeAsyncWriteExt, SafeDigestExt, SafeSliceMutExt,
        compression::{CompressionType, reader::CompressionReader},
        counting_reader::CountingReader,
        limited_reader::{AsyncLimitedReader, LimitedReader},
        limited_writer::LimitedWriter,
    },
    remote::backups::RawServerBackup,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::StreamableArchiveFormat,
            virtualfs::{ByteRange, VirtualReadableFilesystem},
        },
    },
    utils::PortablePermissions,
};
use futures::TryStreamExt;
use sha2::Digest;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::RwLock,
};

static CLIENT: RwLock<Option<Arc<reqwest::Client>>> = RwLock::const_new(None);

#[inline]
async fn get_client(server: &crate::server::Server) -> Arc<reqwest::Client> {
    if let Some(client) = CLIENT.read().await.as_ref() {
        return Arc::clone(client);
    }

    let client = Arc::new(
        reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(
                server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .s3
                    .part_upload_timeout,
            ))
            .tls_danger_accept_invalid_certs(server.app_state.config.ignore_certificate_errors)
            .build()
            .expect("failed to build HTTP client"),
    );

    *CLIENT.write().await = Some(Arc::clone(&client));
    client
}

pub struct S3Backup {
    uuid: uuid::Uuid,
}

impl S3Backup {
    #[inline]
    fn get_file_name(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Path::new(&config.load().system.backup_directory).join(format!("{uuid}.s3.tar.gz"))
    }

    #[inline]
    fn get_scratch_file_name(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Path::new(&config.load().system.backup_directory).join(format!("{uuid}.s3.part"))
    }

    async fn upload_part(
        server: &crate::server::Server,
        scratch: &mut tokio::fs::File,
        valid_len: u64,
        url: &str,
        part_number: usize,
        backup_uuid: uuid::Uuid,
    ) -> Result<String, anyhow::Error> {
        let retry_limit = server.app_state.config.load().system.backups.s3.retry_limit;
        let mut attempts = 0;

        loop {
            attempts += 1;
            if attempts > retry_limit {
                return Err(anyhow::anyhow!(
                    "failed to upload s3 part after {} attempts",
                    retry_limit
                ));
            }

            tracing::debug!(
                "uploading s3 backup part {} of size {} for backup {} for {}",
                part_number,
                valid_len,
                backup_uuid,
                server.uuid
            );

            scratch.seek(std::io::SeekFrom::Start(0)).await?;

            let reader_handle = scratch.try_clone().await?;
            let reader = reader_handle.take(valid_len);
            let reader = AsyncLimitedReader::new_with_bytes_per_second(
                reader,
                server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .write_limit
                    .as_bytes(),
            );

            let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(
                reader,
                crate::BUFFER_SIZE,
            ));

            match get_client(server)
                .await
                .put(url)
                .header("Content-Length", valid_len)
                .header("Content-Type", "application/gzip")
                .body(body)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    let etag = response
                        .headers()
                        .get("ETag")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    return Ok(etag);
                }
                Ok(response) => {
                    tracing::error!(
                        backup = %backup_uuid,
                        server = %server.uuid,
                        "failed to upload s3 backup part {}: status code {}",
                        part_number,
                        response.status()
                    );
                }
                Err(err) => {
                    tracing::error!(
                        backup = %backup_uuid,
                        server = %server.uuid,
                        "failed to upload s3 backup part {}: {:#?}",
                        part_number,
                        err
                    );

                    tokio::time::sleep(std::time::Duration::from_secs(attempts.pow(2))).await;
                }
            }
        }
    }

    async fn create_streaming(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        part_size: u64,
        initial_urls: Vec<String>,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let scratch_path = Self::get_scratch_file_name(&server.app_state.config, uuid);
        let mut scratch = tokio::fs::OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(&scratch_path)
            .await?;

        let (mut archive_reader, archive_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let total_task = {
            let total = Arc::clone(&total);
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

        let archive_task = {
            let server = server.clone();
            let ignore = ignore.clone();
            let progress = Arc::clone(&progress);

            async move {
                let sources = server.filesystem.async_read_dir_all(Path::new("")).await?;
                let writer = tokio_util::io::SyncIoBridge::new(archive_writer);
                let writer = LimitedWriter::new_with_bytes_per_second(
                    writer,
                    server
                        .app_state
                        .config
                        .load()
                        .system
                        .backups
                        .write_limit
                        .as_bytes(),
                );

                let file = crate::server::filesystem::archive::create::create_tar(
                    server.filesystem.clone(),
                    writer,
                    Path::new(""),
                    sources,
                    Some(Arc::clone(&progress)),
                    ignore.into(),
                    crate::server::filesystem::archive::create::CreateTarOptions {
                        compression_type: CompressionType::Gz,
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
                            .s3
                            .create_threads,
                    },
                )
                .await?;

                file.into_inner().into_inner().shutdown().await?;

                Ok::<_, anyhow::Error>(())
            }
        };

        let upload_task = {
            let server = server.clone();
            let scratch = &mut scratch;

            async move {
                let mut hasher = sha2::Sha256::new();
                let mut total_size: u64 = 0;
                let mut parts = Vec::new();

                let mut url_queue: std::collections::VecDeque<String> =
                    initial_urls.into_iter().collect();
                let mut part_number = 1;
                let mut buffer = vec![0u8; crate::BUFFER_SIZE];

                'parts: loop {
                    scratch.seek(std::io::SeekFrom::Start(0)).await?;

                    let mut valid_len: u64 = 0;
                    let mut eof = false;

                    while valid_len < part_size {
                        let want =
                            std::cmp::min(buffer.len() as u64, part_size - valid_len) as usize;
                        let bytes_read = archive_reader.read(buffer.get_slice_mut(..want)?).await?;
                        if crate::unlikely(bytes_read == 0) {
                            eof = true;
                            break;
                        }

                        hasher.safe_update(&buffer, bytes_read)?;
                        scratch.safe_write_all(&buffer, bytes_read).await?;

                        valid_len += bytes_read as u64;
                        total.fetch_add(bytes_read as u64, Ordering::Relaxed);
                    }

                    scratch.flush().await?;

                    if valid_len == 0 {
                        break 'parts;
                    }

                    let url = match url_queue.pop_front() {
                        Some(url) => url,
                        None => {
                            let (_, new_urls) = server
                                .app_state
                                .config
                                .client
                                .backup_s3_part_urls(uuid, part_number)
                                .await?;
                            url_queue.extend(new_urls);

                            url_queue.pop_front().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "failed to retrieve presigned URL for part {} of backup {}",
                                    part_number,
                                    uuid
                                )
                            })?
                        }
                    };

                    let etag =
                        Self::upload_part(&server, scratch, valid_len, &url, part_number, uuid)
                            .await?;

                    parts.push(crate::remote::backups::RawServerBackupPart { etag, part_number });
                    total_size += valid_len;
                    part_number += 1;

                    if eof {
                        break 'parts;
                    }
                }

                Ok::<_, anyhow::Error>((hex::encode(hasher.finalize()), parts, total_size))
            }
        };

        let ((checksum, parts, size), total_files, _) =
            tokio::try_join!(upload_task, total_task, archive_task)?;

        drop(scratch);
        if let Err(err) = tokio::fs::remove_file(&scratch_path).await {
            tracing::warn!(
                backup = %uuid,
                "failed to remove s3 scratch file: {:?}",
                err
            );
        }

        Ok(RawServerBackup {
            checksum,
            checksum_type: "sha256".into(),
            size,
            files: total_files,
            successful: true,
            browsable: false,
            streaming: false,
            parts,
        })
    }

    async fn create_buffered(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let file_name = Self::get_file_name(&server.app_state.config, uuid);
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_name)
            .await?;

        let (mut checksum_reader, checksum_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let checksum_task = async {
            let mut hasher = sha2::Sha256::new();

            let mut buffer = vec![0; crate::BUFFER_SIZE];
            loop {
                let bytes_read = checksum_reader.read(&mut buffer).await?;
                if crate::unlikely(bytes_read == 0) {
                    break;
                }

                hasher.safe_update(&buffer, bytes_read)?;
                file.safe_write_all(&buffer, bytes_read).await?;
                total.fetch_add(bytes_read as u64, Ordering::Relaxed);
            }

            Ok::<_, anyhow::Error>(hex::encode(hasher.finalize()))
        };

        let total_task = {
            let total = Arc::clone(&total);
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

        let archive_task = async {
            let sources = server.filesystem.async_read_dir_all(Path::new("")).await?;
            let writer = tokio_util::io::SyncIoBridge::new(checksum_writer);
            let writer = LimitedWriter::new_with_bytes_per_second(
                writer,
                server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .write_limit
                    .as_bytes(),
            );

            let file = crate::server::filesystem::archive::create::create_tar(
                server.filesystem.clone(),
                writer,
                Path::new(""),
                sources,
                Some(Arc::clone(&progress)),
                ignore.into(),
                crate::server::filesystem::archive::create::CreateTarOptions {
                    compression_type: CompressionType::Gz,
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
                        .s3
                        .create_threads,
                },
            )
            .await?;

            file.into_inner().into_inner().shutdown().await?;

            Ok(())
        };

        let (checksum, total_files, _) = tokio::try_join!(checksum_task, total_task, archive_task)?;

        let size = file.metadata().await?.len();
        let (part_size, part_urls) = server
            .app_state
            .config
            .client
            .backup_upload_urls(uuid, size)
            .await?;

        let mut remaining_size = size;
        let mut parts = Vec::with_capacity(part_urls.len());
        for (i, url) in part_urls.into_iter().enumerate() {
            let offset = size - remaining_size;
            let this_part_size = std::cmp::min(remaining_size, part_size);

            let retry_limit = server.app_state.config.load().system.backups.s3.retry_limit;
            let mut attempts = 0;
            let etag = loop {
                attempts += 1;
                if attempts > retry_limit {
                    return Err(anyhow::anyhow!(
                        "failed to upload s3 part after {} attempts",
                        retry_limit
                    ));
                }

                tracing::debug!(
                    "uploading s3 backup part {} of size {} for backup {} for {}",
                    i + 1,
                    this_part_size,
                    uuid,
                    server.uuid
                );

                file.seek(std::io::SeekFrom::Start(offset)).await?;
                let reader_handle = file.try_clone().await?;
                let reader = reader_handle.take(this_part_size);
                let reader = AsyncLimitedReader::new_with_bytes_per_second(
                    reader,
                    server
                        .app_state
                        .config
                        .load()
                        .system
                        .backups
                        .write_limit
                        .as_bytes(),
                );

                let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(
                    reader,
                    crate::BUFFER_SIZE,
                ));

                match get_client(server)
                    .await
                    .put(&url)
                    .header("Content-Length", this_part_size)
                    .header("Content-Type", "application/gzip")
                    .body(body)
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => {
                        break response
                            .headers()
                            .get("ETag")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                    }
                    Ok(response) => {
                        tracing::error!(
                            backup = %uuid,
                            server = %server.uuid,
                            "failed to upload s3 backup part {}: status code {}",
                            i + 1,
                            response.status()
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                            backup = %uuid,
                            server = %server.uuid,
                            "failed to upload s3 backup part {}: {:#?}",
                            i + 1,
                            err
                        );

                        tokio::time::sleep(std::time::Duration::from_secs(attempts.pow(2))).await;
                    }
                }
            };

            parts.push(crate::remote::backups::RawServerBackupPart {
                etag,
                part_number: i + 1,
            });
            remaining_size -= this_part_size;
        }

        if remaining_size > 0 {
            return Err(anyhow::anyhow!("failed to upload all parts"));
        }

        drop(file);
        tokio::fs::remove_file(&file_name).await?;

        Ok(RawServerBackup {
            checksum,
            checksum_type: "sha256".into(),
            size,
            files: total_files,
            successful: true,
            browsable: false,
            streaming: false,
            parts,
        })
    }
}

#[async_trait::async_trait]
impl BackupFindExt for S3Backup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        let path = Self::get_file_name(&state.config, uuid);
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn find(
        _state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        Ok(Some(Backup::S3(S3Backup { uuid })))
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for S3Backup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        _ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        match server
            .app_state
            .config
            .client
            .backup_s3_part_urls(uuid, 1)
            .await
        {
            Ok((part_size, urls)) => {
                tracing::debug!(
                    backup = %uuid,
                    "using streaming s3 backup path (part_size = {}, initial urls = {})",
                    part_size,
                    urls.len()
                );
                Self::create_streaming(server, uuid, progress, total, ignore, part_size, urls).await
            }
            Err(err) => {
                tracing::debug!(
                    backup = %uuid,
                    "streaming s3 backup endpoint unavailable, falling back to buffered path: {:?}",
                    err
                );
                Self::create_buffered(server, uuid, progress, total, ignore).await
            }
        }
    }
}

#[async_trait::async_trait]
impl BackupExt for S3Backup {
    #[inline]
    fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    async fn download(
        &self,
        _state: &crate::routes::State,
        _archive_format: StreamableArchiveFormat,
        _range: Option<ByteRange>,
    ) -> Result<crate::response::ApiResponse, anyhow::Error> {
        Err(anyhow::anyhow!(
            "this backup adapter does not support downloads"
        ))
    }

    async fn restore(
        &self,
        server: &crate::server::Server,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let download_url = match download_url {
            Some(download_url) => download_url,
            None => {
                return Err(anyhow::anyhow!(
                    "unable to extract download_url from s3 backup restore request"
                ));
            }
        };

        let response = get_client(server)
            .await
            .get(download_url.as_str())
            .send()
            .await?;
        if let Some(content_length) = response.content_length() {
            total.store(content_length, Ordering::SeqCst);
        }

        let reader = tokio_util::io::StreamReader::new(Box::pin(
            response.bytes_stream().map_err(std::io::Error::other),
        ));

        let server = server.clone();

        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let reader = tokio_util::io::SyncIoBridge::new(reader);
            let reader = LimitedReader::new_with_bytes_per_second(
                reader,
                server.app_state.config.load().system.backups.read_limit.as_bytes(),
            );
            let reader = CountingReader::new_with_bytes_read(reader, progress);
            let reader = CompressionReader::new(
                reader,
                CompressionType::Gz,
            )?;
            let reader = std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

            let mut archive = tar::Archive::new(reader);
            let mut directory_entries = Vec::new();
            let entries = archive.entries()?;

            let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
            for entry in entries {
                let mut entry = entry?;
                let path = entry.path()?;

                if path.is_absolute() {
                    continue;
                }

                let header = entry.header();
                match header.entry_type() {
                    tar::EntryType::Directory => {
                        server.filesystem.create_chowned_dir_all(path.as_ref())?;
                        server
                            .filesystem
                            .set_permissions(
                                path.as_ref(),
                                PortablePermissions::from_mode(header.mode().unwrap_or(0o755)),
                            )?;

                        if let Ok(modified_time) = header.mtime() {
                            directory_entries.push((path.to_path_buf(), modified_time));
                        }
                    }
                    tar::EntryType::Regular => {
                        server.log_daemon(compact_str::format_compact!("(restoring): {}", path.display()));

                        if let Some(parent) = path.parent() {
                            server.filesystem.create_chowned_dir_all(parent)?;
                        }

                        let mut writer = crate::server::filesystem::file::ServerFile::new(
                            server.clone(),
                            &path,
                            Some(PortablePermissions::from_mode(header.mode().unwrap_or(0o644))),
                            header
                                .mtime()
                                .map(|t| std::time::UNIX_EPOCH + std::time::Duration::from_secs(t))
                                .ok(),
                        )?;

                        crate::io::copy_shared(&mut read_buffer, &mut entry, &mut writer)?;
                        writer.flush()?;
                    }
                    tar::EntryType::Symlink => {
                        let link = entry.link_name().unwrap_or_default().unwrap_or_default();

                        if let Err(err) = server.filesystem.symlink(link, path.as_ref()) {
                            tracing::debug!(path = %path.display(), "failed to create symlink from backup: {:?}", err);
                        } else if let Ok(modified_time) = header.mtime() {
                            server
                                .filesystem
                                .set_times(
                                    path.as_ref(),
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
                server.filesystem.set_times(
                    &destination_path,
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified_time),
                    None,
                )?;
            }

            Ok(())
        })
        .await??;

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        let file_name = Self::get_file_name(&state.config, self.uuid);
        if tokio::fs::metadata(&file_name).await.is_ok() {
            tokio::fs::remove_file(&file_name).await?;
        }

        state
            .backup_manager
            .invalidate_cached_browse(self.uuid)
            .await;

        Ok(())
    }

    async fn browse(
        &self,
        _server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        Err(anyhow::anyhow!(
            "this backup adapter does not support browsing files"
        ))
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for S3Backup {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let file_name = Self::get_file_name(&server.app_state.config, uuid);
        if tokio::fs::metadata(&file_name).await.is_ok() {
            tokio::fs::remove_file(&file_name).await?;
        }

        let scratch = Self::get_scratch_file_name(&server.app_state.config, uuid);
        if tokio::fs::metadata(&scratch).await.is_ok() {
            tokio::fs::remove_file(&scratch).await?;
        }

        Ok(())
    }
}
