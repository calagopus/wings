use crate::{
    io::{
        SafeAsyncWriteExt, SafeDigestExt, SafeSliceMutExt,
        compression::{
            CompressionType,
            reader::{AsyncCompressionReader, CompressionReader},
            writer::CompressionWriter,
        },
        limited_reader::{AsyncLimitedReader, LimitedReader},
        limited_writer::LimitedWriter,
    },
    remote::backups::RawServerBackup,
    server::{
        backup::{
            Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt, BackupStream,
            BackupStreamCreateExt, BackupStreamExt, DumpReader,
        },
        filesystem::{
            archive::{Archive, ArchiveFormat, StreamableArchiveFormat},
            virtualfs::{ByteRange, VirtualReadableFilesystem},
        },
    },
    utils::PortablePermissions,
};
use compact_str::ToCompactString;
use futures::TryStreamExt;
use sha2::Digest;
use std::{
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

static CLIENT: OnceLock<Arc<reqwest::Client>> = OnceLock::new();

fn get_client(config: &Arc<crate::config::Config>) -> Arc<reqwest::Client> {
    CLIENT
        .get_or_init(|| {
            Arc::new(
                reqwest::ClientBuilder::new()
                    .timeout(std::time::Duration::from_secs(
                        config.load().system.backups.s3.part_upload_timeout,
                    ))
                    .tls_danger_accept_invalid_certs(config.ignore_certificate_errors)
                    .build()
                    .expect("failed to build HTTP client"),
            )
        })
        .clone()
}

pub struct S3Backup {
    uuid: uuid::Uuid,
}

impl S3Backup {
    /// A client for uploads to the given presigned URL's host, routed through
    /// the congestion control proxy when one could be started - backup uploads
    /// are long-haul flows where loss-based congestion control collapses. The
    /// returned proxy must stay alive for as long as the client is used;
    /// without one the shared direct client is handed out instead.
    async fn upload_client(
        config: &Arc<crate::config::Config>,
        sample_url: Option<&str>,
    ) -> (
        Option<crate::net::CongestionControlProxy>,
        Arc<reqwest::Client>,
    ) {
        let proxy = match sample_url.and_then(|url| reqwest::Url::parse(url).ok()) {
            Some(parsed) => match (parsed.host_str(), parsed.port_or_known_default()) {
                (Some(host), Some(port)) => {
                    crate::net::CongestionControlProxy::start(config, host.to_string(), port).await
                }
                _ => None,
            },
            None => None,
        };

        let client = match &proxy {
            Some(active_proxy) => {
                let mut builder = reqwest::ClientBuilder::new()
                    .timeout(std::time::Duration::from_secs(
                        config.load().system.backups.s3.part_upload_timeout,
                    ))
                    .tls_danger_accept_invalid_certs(config.ignore_certificate_errors);

                match reqwest::Proxy::all(active_proxy.url()) {
                    Ok(reqwest_proxy) => builder = builder.proxy(reqwest_proxy),
                    Err(err) => {
                        tracing::debug!("failed to construct s3 upload proxy definition: {}", err);
                    }
                }

                match builder.build() {
                    Ok(client) => Arc::new(client),
                    Err(_) => get_client(config),
                }
            }
            None => get_client(config),
        };

        (proxy, client)
    }
    #[inline]
    fn get_file_name(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        config
            .resolve_as_path(|cfg| &cfg.system.backup_directory)
            .join(format!("{uuid}.s3.tar.gz"))
    }

    #[inline]
    fn get_scratch_file_name(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        config
            .resolve_as_path(|cfg| &cfg.system.backup_directory)
            .join(format!("{uuid}.s3.part"))
    }

    async fn upload_part(
        config: &Arc<crate::config::Config>,
        client: &reqwest::Client,
        scratch: &mut tokio::fs::File,
        valid_len: u64,
        url: &str,
        part_number: usize,
        backup_uuid: uuid::Uuid,
    ) -> Result<String, anyhow::Error> {
        let retry_limit = config.load().system.backups.s3.retry_limit;
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
                "uploading s3 backup part {} of size {} for backup {}",
                part_number,
                valid_len,
                backup_uuid
            );

            scratch.seek(std::io::SeekFrom::Start(0)).await?;

            let reader_handle = scratch.try_clone().await?;
            let reader = reader_handle.take(valid_len);
            let reader = AsyncLimitedReader::new_with_bytes_per_second(
                reader,
                config.load().system.backups.write_limit.as_bytes(),
            );

            let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(
                reader,
                crate::BUFFER_SIZE,
            ));

            match client
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
                        "failed to upload s3 backup part {}: status code {}",
                        part_number,
                        response.status()
                    );
                }
                Err(err) => {
                    tracing::error!(
                        backup = %backup_uuid,
                        "failed to upload s3 backup part {}: {:#?}",
                        part_number,
                        err.without_url()
                    );

                    tokio::time::sleep(std::time::Duration::from_secs(attempts.pow(2))).await;
                }
            }
        }
    }

    async fn upload_parts(
        config: &Arc<crate::config::Config>,
        uuid: uuid::Uuid,
        mut reader: impl AsyncRead + Unpin,
        part_size: u64,
        initial_urls: Vec<String>,
        total: Arc<AtomicU64>,
    ) -> Result<
        (
            String,
            Vec<crate::remote::backups::RawServerBackupPart>,
            u64,
        ),
        anyhow::Error,
    > {
        if part_size == 0 {
            return Err(anyhow::anyhow!(
                "remote returned a part size of 0 for s3 backup, cannot upload backup"
            ));
        }

        let scratch_path = Self::get_scratch_file_name(config, uuid);
        let mut scratch = tokio::fs::OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(&scratch_path)
            .await?;

        let result = async {
            let mut hasher = sha2::Sha256::new();
            let mut total_size: u64 = 0;
            let mut parts = Vec::new();

            let mut url_queue: std::collections::VecDeque<String> =
                initial_urls.into_iter().collect();
            let mut part_number = 1;
            let mut buffer = vec![0; crate::BUFFER_SIZE];

            let (_upload_proxy, upload_http) =
                Self::upload_client(config, url_queue.front().map(String::as_str)).await;

            'parts: loop {
                scratch.seek(std::io::SeekFrom::Start(0)).await?;

                let mut valid_len: u64 = 0;
                let mut eof = false;

                while valid_len < part_size {
                    let want = std::cmp::min(buffer.len() as u64, part_size - valid_len) as usize;
                    let bytes_read = reader.read(buffer.get_slice_mut(..want)?).await?;
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
                        let (_, new_urls) =
                            config.client.backup_s3_part_urls(uuid, part_number).await?;
                        url_queue.extend(new_urls);

                        url_queue.pop_front().ok_or_else(|| {
                            anyhow::anyhow!(
                                "failed to retrieve presigned URL for part {} of backup",
                                part_number
                            )
                        })?
                    }
                };

                let etag = Self::upload_part(
                    config,
                    &upload_http,
                    &mut scratch,
                    valid_len,
                    &url,
                    part_number,
                    uuid,
                )
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
        .await;

        drop(scratch);
        if let Err(err) = tokio::fs::remove_file(&scratch_path).await {
            tracing::warn!(
                backup = %uuid,
                "failed to remove s3 scratch file: {:?}",
                err
            );
        }

        result
    }

    /// The panel names the object after the backup, so its final path segment
    /// carries the compression Wings must apply.
    fn compression_from_url(url: &reqwest::Url) -> CompressionType {
        CompressionType::from_file_name(
            url.path_segments()
                .and_then(|mut segments| segments.next_back())
                .unwrap_or_default(),
        )
    }

    async fn create_streaming(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        part_size: u64,
        initial_urls: Vec<String>,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let url = match initial_urls
            .first()
            .map(|url| reqwest::Url::parse(url))
            .transpose()
        {
            Ok(Some(url)) => url,
            Ok(None) => {
                return Err(anyhow::anyhow!(
                    "no initial urls provided for s3 backup, cannot upload backup"
                ));
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "failed to parse initial url for s3 backup: {:?}",
                    err
                ));
            }
        };

        let (archive_reader, archive_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let total_task = {
            let filesystem = server.filesystem.clone();
            let total = Arc::clone(&total);
            let ignore = ignore.clone();

            async move {
                tokio::task::spawn_blocking(move || {
                    let mut walker = filesystem
                        .walk_dir(Path::new(""))?
                        .with_is_ignored(ignore.into());
                    let mut total_files = 0;
                    while let Some(Ok(entry)) = walker.next_entry() {
                        let metadata = match entry.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => continue,
                        };

                        total.fetch_add(metadata.len(), Ordering::Relaxed);
                        if !metadata.is_dir() {
                            total_files += 1;
                        }
                    }

                    Ok::<_, anyhow::Error>(total_files)
                })
                .await?
            }
        };

        let archive_task = {
            let server = server.clone();
            let ignore = ignore.clone();
            let progress = progress.clone();

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
                    progress.clone(),
                    ignore.into(),
                    crate::server::filesystem::archive::create::CreateTarOptions {
                        compression_type: ArchiveFormat::from_str(
                            url.path_segments()
                                .and_then(|mut segments| segments.next_back())
                                .unwrap_or_default(),
                        )
                        .map_err(|_| {
                            anyhow::anyhow!(
                                "failed to determine compression format from url path for s3 backup"
                            )
                        })?
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
                            .s3
                            .create_threads,
                    },
                )
                .await?;

                file.into_inner().into_inner().shutdown().await?;

                Ok::<_, anyhow::Error>(())
            }
        };

        let upload_task = Self::upload_parts(
            &server.app_state.config,
            uuid,
            archive_reader,
            part_size,
            initial_urls,
            Arc::clone(&total),
        );

        let ((checksum, parts, size), total_files, _) =
            tokio::try_join!(upload_task, total_task, archive_task)?;

        if size == 0 {
            return Err(anyhow::anyhow!(
                "s3 backup archive is 0 bytes, this should not be possible"
            ));
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
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
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
            let filesystem = server.filesystem.clone();
            let total = Arc::clone(&total);
            let ignore = ignore.clone();

            async move {
                tokio::task::spawn_blocking(move || {
                    let mut walker = filesystem
                        .walk_dir(Path::new(""))?
                        .with_is_ignored(ignore.into());
                    let mut total_files = 0;
                    while let Some(Ok(entry)) = walker.next_entry() {
                        let metadata = match entry.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => continue,
                        };

                        total.fetch_add(metadata.len(), Ordering::Relaxed);
                        if !metadata.is_dir() {
                            total_files += 1;
                        }
                    }

                    Ok::<_, anyhow::Error>(total_files)
                })
                .await?
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
                progress.clone(),
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
        if size == 0 {
            return Err(anyhow::anyhow!(
                "s3 backup archive is 0 bytes, this should not be possible"
            ));
        }

        let (part_size, part_urls) = server
            .app_state
            .config
            .client
            .backup_upload_urls(uuid, size)
            .await?;
        if part_size == 0 {
            return Err(anyhow::anyhow!(
                "remote returned a part size of 0 for s3 backup, cannot upload backup"
            ));
        }

        let (_upload_proxy, upload_http) = Self::upload_client(
            &server.app_state.config,
            part_urls.first().map(String::as_str),
        )
        .await;

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

                match upload_http
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
                            err.without_url()
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
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
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
impl BackupStreamCreateExt for S3Backup {
    async fn create_from_stream(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
        _extension: &str,
        reader: DumpReader,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let (part_size, initial_urls) = state.config.client.backup_s3_part_urls(uuid, 1).await?;

        let url = initial_urls
            .first()
            .map(|url| reqwest::Url::parse(url))
            .transpose()
            .map_err(|err| anyhow::anyhow!("failed to parse initial url for s3 backup: {:?}", err))?
            .ok_or_else(|| {
                anyhow::anyhow!("no initial urls provided for s3 backup, cannot upload backup")
            })?;
        let compression = Self::compression_from_url(&url);

        let config = state.config.load();
        let compression_level = config.system.backups.compression_level;
        let threads = config.system.backups.s3.create_threads;
        let write_limit = config.system.backups.write_limit.as_bytes();
        drop(config);

        let (compressed_reader, compressed_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let compress_task = tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let writer = LimitedWriter::new_with_bytes_per_second(
                tokio_util::io::SyncIoBridge::new(compressed_writer),
                write_limit,
            );
            let mut writer =
                CompressionWriter::new(writer, compression, compression_level, threads)?;
            let mut reader = tokio_util::io::SyncIoBridge::new(reader);

            crate::io::copy(&mut reader, &mut writer)?;
            writer.finish()?.into_inner().shutdown()?;

            Ok(())
        });

        let total = Arc::new(AtomicU64::new(0));
        let upload_task = Self::upload_parts(
            &state.config,
            uuid,
            compressed_reader,
            part_size,
            initial_urls,
            Arc::clone(&total),
        );

        let (upload_result, compress_result) = tokio::join!(upload_task, compress_task);
        compress_result??;
        let (checksum, parts, size) = upload_result?;

        if size == 0 {
            return Err(anyhow::anyhow!("database dump is 0 bytes"));
        }

        Ok(RawServerBackup {
            checksum,
            checksum_type: "sha256".into(),
            size,
            files: 0,
            successful: true,
            browsable: false,
            streaming: false,
            parts,
        })
    }
}

#[async_trait::async_trait]
impl BackupStreamExt for S3Backup {
    async fn read_stream(
        &self,
        state: &crate::routes::State,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<BackupStream, anyhow::Error> {
        let download_url = download_url.ok_or_else(|| {
            anyhow::anyhow!("unable to read s3 database backup without download_url")
        })?;
        let url = reqwest::Url::parse(&download_url)
            .map_err(|err| anyhow::anyhow!("failed to parse s3 download url: {:?}", err))?;
        let compression = Self::compression_from_url(&url);

        let file_name = url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(|name| {
                name.strip_suffix(super::wings::WingsBackupFile::compression_suffix(
                    compression,
                ))
                .unwrap_or(name)
            })
            .filter(|name| !name.is_empty())
            .map(compact_str::CompactString::from)
            .unwrap_or_else(|| self.uuid.to_compact_string());

        let response = get_client(&state.config)
            .get(url)
            .send()
            .await?
            .error_for_status()?;
        let content_length = response.content_length();

        let reader = AsyncLimitedReader::new_with_bytes_per_second(
            tokio_util::io::StreamReader::new(
                response.bytes_stream().map_err(std::io::Error::other),
            ),
            state.config.load().system.backups.read_limit.as_bytes(),
        );

        Ok(match compression {
            CompressionType::None => BackupStream {
                reader: Box::new(reader),
                size: content_length,
                file_name,
            },
            compression => BackupStream {
                reader: Box::new(AsyncCompressionReader::new(
                    tokio_util::io::SyncIoBridge::new(reader),
                    compression,
                )),
                size: None,
                file_name,
            },
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for S3Backup {
    #[inline]
    fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    async fn download_info(
        &self,
    ) -> Result<crate::server::backup::BackupDownloadInfo, anyhow::Error> {
        Err(anyhow::anyhow!(
            "this backup adapter does not support downloads"
        ))
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
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
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

        let url = match reqwest::Url::parse(&download_url) {
            Ok(url) => url,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "failed to parse download_url from s3 backup restore request: {:?}",
                    err
                ));
            }
        };

        let response = get_client(&server.app_state.config)
            .get(url.clone())
            .send()
            .await
            .map_err(|err| err.without_url())?;
        if let Some(content_length) = response.content_length() {
            total.store(content_length, Ordering::SeqCst);
        }

        let reader = tokio_util::io::StreamReader::new(Box::pin(
            response
                .bytes_stream()
                .map_err(|err| std::io::Error::other(err.without_url())),
        ));

        let server = server.clone();

        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let reader = tokio_util::io::SyncIoBridge::new(reader);
            let reader = LimitedReader::new_with_bytes_per_second(
                reader,
                server.app_state.config.load().system.backups.read_limit.as_bytes(),
            );
            let reader = progress.counting_reader(reader);
            let reader = CompressionReader::new(
                reader,
                ArchiveFormat::from_str(url.path_segments().and_then(|mut segments| segments.next_back()).unwrap_or_default())
                    .map_err(|_| anyhow::anyhow!("failed to determine archive format from download_url"))?.compression_format(),
            )?;
            let reader = std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

            let mut archive = tar::Archive::new(reader);
            let mut directory_entries = chunked_vec::ChunkedVec::new();
            let mut last_parent = None;
            let entries = archive.entries()?;

            let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
            for entry in entries {
                let mut entry = entry?;
                let path = server.filesystem.relative_path(&entry.path()?);

                if path.as_os_str().is_empty() {
                    continue;
                }

                let header = entry.header();
                match header.entry_type() {
                    tar::EntryType::Directory => {
                        server.filesystem.create_chowned_dir_all(path.as_path())?;
                        server
                            .filesystem
                            .set_permissions(
                                path.as_path(),
                                PortablePermissions::from_mode_dir(header.mode().unwrap_or(0o755)),
                            )?;

                        if let Ok(modified_time) = header.mtime() && directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES {
                            directory_entries.push((path.to_path_buf(), modified_time));
                        }
                    }
                    tar::EntryType::Regular => {
                        server.log_daemon(compact_str::format_compact!("(restoring): {}", path.display()));

                        if let Some(parent) = path.parent()
                            && last_parent.as_deref() != Some(parent)
                        {
                            server.filesystem.create_chowned_dir_all(parent)?;
                            last_parent = Some(parent.to_path_buf());
                        }

                        let mut writer = crate::server::filesystem::file::ServerFile::new(
                            server.clone(),
                            &path,
                            Some(PortablePermissions::from_mode_file(header.mode().unwrap_or(0o644))),
                            header
                                .mtime()
                                .map(|t| std::time::UNIX_EPOCH + std::time::Duration::from_secs(t))
                                .ok(),
                        )?;

                        crate::io::copy_shared(&mut read_buffer, &mut entry, &mut writer)?;
                        writer.flush()?;

                        progress.increment_files();
                    }
                    tar::EntryType::Symlink => {
                        let link = entry.link_name().unwrap_or_default().unwrap_or_default();

                        if let Err(err) = server.filesystem.symlink(link, path.as_path()) {
                            tracing::debug!(path = %path.display(), "failed to create symlink from backup: {:?}", err);
                        } else {
                            progress.increment_files();

                            if let Ok(modified_time) = header.mtime() {
                                server
                                    .filesystem
                                    .set_times(
                                        path.as_path(),
                                        std::time::UNIX_EPOCH
                                            + std::time::Duration::from_secs(modified_time),
                                        None,
                                    )?;
                            }
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
