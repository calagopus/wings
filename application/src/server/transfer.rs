use crate::{
    io::{
        compression::{CompressionLevel, CompressionType},
        counting_reader::AsyncCountingReader,
        hash_reader::AsyncHashReader,
    },
    server::filesystem::archive::StreamableArchiveFormat,
};
use futures::FutureExt;
use human_bytes::human_bytes;
use serde::Deserialize;
use sha2::Digest;
use std::{
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    task::{AbortHandle, JoinHandle},
};
use utoipa::ToSchema;

#[derive(Clone, Copy, ToSchema, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum TransferArchiveFormat {
    Tar,
    #[default]
    TarGz,
    TarXz,
    TarLzip,
    TarBz2,
    TarLz4,
    TarZstd,
}

impl TransferArchiveFormat {
    #[inline]
    pub fn compression_format(self) -> CompressionType {
        match self {
            TransferArchiveFormat::Tar => CompressionType::None,
            TransferArchiveFormat::TarGz => CompressionType::Gz,
            TransferArchiveFormat::TarXz => CompressionType::Xz,
            TransferArchiveFormat::TarLzip => CompressionType::Lzip,
            TransferArchiveFormat::TarBz2 => CompressionType::Bz2,
            TransferArchiveFormat::TarLz4 => CompressionType::Lz4,
            TransferArchiveFormat::TarZstd => CompressionType::Zstd,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            TransferArchiveFormat::Tar => "tar",
            TransferArchiveFormat::TarGz => "tar.gz",
            TransferArchiveFormat::TarXz => "tar.xz",
            TransferArchiveFormat::TarLzip => "tar.lz",
            TransferArchiveFormat::TarBz2 => "tar.bz2",
            TransferArchiveFormat::TarLz4 => "tar.lz4",
            TransferArchiveFormat::TarZstd => "tar.zst",
        }
    }
}

impl From<TransferArchiveFormat> for StreamableArchiveFormat {
    fn from(format: TransferArchiveFormat) -> Self {
        match format {
            TransferArchiveFormat::Tar => StreamableArchiveFormat::Tar,
            TransferArchiveFormat::TarGz => StreamableArchiveFormat::TarGz,
            TransferArchiveFormat::TarXz => StreamableArchiveFormat::TarXz,
            TransferArchiveFormat::TarLzip => StreamableArchiveFormat::TarLzip,
            TransferArchiveFormat::TarBz2 => StreamableArchiveFormat::TarBz2,
            TransferArchiveFormat::TarLz4 => StreamableArchiveFormat::TarLz4,
            TransferArchiveFormat::TarZstd => StreamableArchiveFormat::TarZstd,
        }
    }
}

impl std::str::FromStr for TransferArchiveFormat {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with(".tar") {
            Ok(TransferArchiveFormat::Tar)
        } else if s.ends_with(".tar.gz") {
            Ok(TransferArchiveFormat::TarGz)
        } else if s.ends_with(".tar.xz") {
            Ok(TransferArchiveFormat::TarXz)
        } else if s.ends_with(".tar.lz") {
            Ok(TransferArchiveFormat::TarLzip)
        } else if s.ends_with(".tar.bz2") {
            Ok(TransferArchiveFormat::TarBz2)
        } else if s.ends_with(".tar.lz4") {
            Ok(TransferArchiveFormat::TarLz4)
        } else if s.ends_with(".tar.zst") {
            Ok(TransferArchiveFormat::TarZstd)
        } else {
            Err("Invalid archive format")
        }
    }
}

pub struct OutgoingServerTransfer {
    pub bytes_archived: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,

    server: super::Server,
    archive_format: TransferArchiveFormat,
    compression_level: CompressionLevel,
    pub task: Option<tokio::task::JoinHandle<()>>,
}

impl OutgoingServerTransfer {
    pub fn new(
        server: &super::Server,
        archive_format: TransferArchiveFormat,
        compression_level: CompressionLevel,
    ) -> Self {
        Self {
            bytes_archived: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            server: server.clone(),
            archive_format,
            compression_level,
            task: None,
        }
    }

    fn log(server: &super::Server, message: &str) {
        let prelude = ansi_term::Color::Yellow.bold().paint(format!(
            "{} [Transfer System] [Source Node]:",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));

        server
            .websocket
            .send(super::websocket::WebsocketMessage::new(
                super::websocket::WebsocketEvent::ServerTransferLogs,
                [compact_str::format_compact!("{prelude} {message}")].into(),
            ))
            .ok();
    }

    async fn transfer_failure(server: &super::Server) {
        server
            .app_state
            .config
            .client
            .set_server_transfer(server.uuid, false, Vec::new())
            .await
            .ok();
        server.outgoing_transfer.write().await.take();

        server.transferring.store(false, Ordering::SeqCst);
        server
            .websocket
            .send(super::websocket::WebsocketMessage::new(
                super::websocket::WebsocketEvent::ServerTransferStatus,
                ["failure".into()].into(),
            ))
            .ok();
    }

    pub fn start(
        &mut self,
        backup_manager: &Arc<super::backup::manager::BackupManager>,
        url: String,
        token: String,
        backups: Vec<uuid::Uuid>,
        delete_backups: bool,
        multiplex_streams: usize,
    ) -> Result<(), anyhow::Error> {
        let backup_manager = Arc::clone(backup_manager);
        let bytes_archived = Arc::clone(&self.bytes_archived);
        let bytes_sent = Arc::clone(&self.bytes_sent);
        let archive_format = self.archive_format;
        let compression_level = self.compression_level;
        let server = self.server.clone();

        tracing::info!(
            server = %server.uuid,
            "starting outgoing server transfer"
        );

        let old_task = self.task.replace(tokio::spawn(async move {
            if server.state.get_state() != super::state::ServerState::Offline
                && let Err(err) = server
                    .stop_with_kill_timeout(std::time::Duration::from_secs(15), true)
                    .await
            {
                tracing::error!(
                    server = %server.uuid,
                    "failed to stop server: {:#?}",
                    err
                );

                Self::transfer_failure(&server).await;
                return;
            }

            Self::log(&server, "Preparing to stream server data to destination...");
            server
                .websocket
                .send(super::websocket::WebsocketMessage::new(
                    super::websocket::WebsocketEvent::ServerTransferStatus,
                    ["processing".into()].into(),
                ))
                .ok();

            let (files_sender, files_receiver) = async_channel::bounded(256);

            let (checksum_sender, checksum_receiver) = tokio::sync::oneshot::channel();
            let (mut checksummed_reader, checksummed_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
            let (reader, mut writer) = tokio::io::simplex(crate::BUFFER_SIZE);

            fn get_archive_task(
                files_receiver: async_channel::Receiver<PathBuf>,
                bytes_archived: Arc<AtomicU64>,
                server: super::Server,
                writer: tokio_util::io::SyncIoBridge<tokio::io::WriteHalf<tokio::io::SimplexStream>>,
                options: crate::server::filesystem::archive::create::CreateTarOptions
            ) -> Pin<Box<impl Future<Output = Result<(), anyhow::Error>>>> {
                Box::pin(async move {
                    let writer = crate::server::filesystem::archive::create::create_tar_distributed(
                        server.filesystem.clone(),
                        writer,
                        Path::new(""),
                        files_receiver,
                        Some(Arc::clone(&bytes_archived)),
                        options,
                    )
                    .await?;

                    writer.into_inner().shutdown().await?;

                    Ok(())
                })
            }

            let archive_task = get_archive_task(
                files_receiver.clone(),
                Arc::clone(&bytes_archived),
                server.clone(),
                tokio_util::io::SyncIoBridge::new(checksummed_writer),
                crate::server::filesystem::archive::create::CreateTarOptions {
                    compression_type: archive_format.compression_format(),
                    compression_level,
                    threads: server.app_state.config.api.file_compression_threads,
                },
            );

            let checksum_task = Box::pin({
                let bytes_sent = Arc::clone(&bytes_sent);

                async move {
                    let mut hasher = sha2::Sha256::new();

                    let mut buffer = vec![0; crate::BUFFER_SIZE];
                    loop {
                        let bytes_read = checksummed_reader.read(&mut buffer).await?;
                        if crate::unlikely(bytes_read == 0) {
                            break;
                        }

                        hasher.update(&buffer[..bytes_read]);
                        writer.write_all(&buffer[..bytes_read]).await?;
                        bytes_sent.fetch_add(bytes_read as u64, Ordering::Relaxed);
                    }

                    checksum_sender
                        .send(format!("{:x}", hasher.finalize()))
                        .ok();
                    writer.shutdown().await?;

                    Ok::<_, anyhow::Error>(())
                }
            });

            let file_collector_task = Box::pin({
                let server = server.clone();

                async move {
                    let mut walker = server.filesystem.async_walk_dir("").await?;
                    while let Some(Ok((_, entry))) = walker.next_entry().await {
                        files_sender.send(entry).await?;
                    }

                    Ok::<_, anyhow::Error>(())
                }
            });

            let mut form = reqwest::multipart::Form::new()
                .part(
                    "archive",
                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                        tokio_util::io::ReaderStream::with_capacity(reader, crate::BUFFER_SIZE),
                    ))
                    .file_name(format!("archive.{}", archive_format.extension()))
                    .mime_str("application/x-tar")
                    .unwrap(),
                )
                .part(
                    "checksum",
                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                        checksum_receiver.into_stream()
                    ))
                    .file_name("checksum")
                    .mime_str("text/plain")
                    .unwrap(),
                );

            let mut total_bytes = server.filesystem.get_apparent_cached_size();

            if let Ok(install_logs) = crate::server::installation::ServerInstaller::get_install_logs(&server).await {
                total_bytes += install_logs.metadata().await.map(|m| m.len()).unwrap_or(0);

                form = form.part(
                    "install-logs",
                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                        tokio_util::io::ReaderStream::with_capacity(
                            AsyncCountingReader::new_with_bytes_read(
                                install_logs,
                                Arc::clone(&bytes_archived),
                            ),
                            crate::BUFFER_SIZE,
                        ),
                    ))
                    .file_name("install.log")
                    .mime_str("text/plain")
                    .unwrap(),
                );
            }

            for backup in &backups {
                if let Ok(Some(backup)) = backup_manager.find(*backup).await {
                    match backup.adapter() {
                        super::backup::adapters::BackupAdapter::Wings => {
                            let hasher = Arc::new(Mutex::new(sha2::Sha256::new()));

                            let file_name = match super::backup::adapters::wings::WingsBackup::get_first_file_name(&server.app_state.config, backup.uuid()).await {
                                Ok((_, file_name)) => file_name,
                                Err(err) => {
                                    tracing::error!(
                                        server = %server.uuid,
                                        "failed to get first file name for backup {}: {}",
                                        backup.uuid(),
                                        err
                                    );
                                    continue;
                                }
                            };
                            let reader = AsyncCountingReader::new_with_bytes_read(
                                match tokio::fs::File::open(&file_name).await {
                                    Ok(file) => file,
                                    Err(err) => {
                                        tracing::error!(
                                            server = %server.uuid,
                                            "failed to open backup file {}: {}",
                                            file_name.display(),
                                            err
                                        );
                                        continue;
                                    }
                                },
                                Arc::clone(&bytes_archived),
                            );
                            let reader = AsyncCountingReader::new_with_bytes_read(
                                reader,
                                Arc::clone(&bytes_sent),
                            );
                            let reader = AsyncHashReader::new_with_hasher(reader, Arc::clone(&hasher)).await;

                            let (checksum_sender, checksum_receiver) = tokio::sync::oneshot::channel();
                            tokio::spawn(async move {
                                checksum_sender.send(format!("{:x}", hasher.lock().await.finalize_reset())).ok();
                            });

                            total_bytes += tokio::fs::metadata(&file_name)
                                .await
                                .map(|m| m.len())
                                .unwrap_or(0);

                            form = form
                                .part(
                                    format!("backup-{}", backup.uuid()),
                                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                                        tokio_util::io::ReaderStream::with_capacity(reader, crate::BUFFER_SIZE),
                                    ))
                                    .file_name(file_name.file_name().unwrap_or_default().to_string_lossy().to_string())
                                    .mime_str("backup/wings")
                                    .unwrap(),
                                )
                                .part(
                                    format!("backup-checksum-{}", backup.uuid()),
                                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                                        checksum_receiver.into_stream()
                                    ))
                                    .file_name(format!("backup-checksum-{}", backup.uuid()))
                                    .mime_str("text/plain")
                                    .unwrap(),
                                );
                        }
                        _ => {
                            tracing::warn!(
                                server = %server.uuid,
                                "backup {} is not a Wings backup and cannot be transferred, skipping",
                                backup.uuid()
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        server = %server.uuid,
                        "requested backup {} does not exist",
                        backup
                    );
                }
            }

            let progress_task = Box::pin({
                let bytes_archived = Arc::clone(&bytes_archived);
                let bytes_sent = Arc::clone(&bytes_sent);
                let server = server.clone();

                async move {
                    let mut last_bytes_archived = 0;
                    let mut last_bytes_sent = 0;
                    let mut last_update_time = Instant::now();
                    let start_time = Instant::now();

                    loop {
                        let now = Instant::now();
                        let elapsed_secs = now.duration_since(last_update_time).as_secs_f64();
                        let total_elapsed_secs = now.duration_since(start_time).as_secs_f64();
                        last_update_time = now;

                        let current_bytes_archived = bytes_archived.load(Ordering::SeqCst);
                        let current_bytes_sent = bytes_sent.load(Ordering::SeqCst);

                        let archive_rate = if elapsed_secs > 0.0 {
                            (current_bytes_archived - last_bytes_archived) as f64 / elapsed_secs
                        } else {
                            0.0
                        };

                        let network_rate = if elapsed_secs > 0.0 {
                            (current_bytes_sent - last_bytes_sent) as f64 / elapsed_secs
                        } else {
                            0.0
                        };

                        last_bytes_archived = current_bytes_archived;
                        last_bytes_sent = current_bytes_sent;

                        let total_bytes = total_bytes.max(current_bytes_archived);

                        let formatted_bytes_archived = human_bytes(current_bytes_archived as f64);
                        let formatted_total_bytes = human_bytes(total_bytes as f64);
                        let formatted_archive_rate = human_bytes(archive_rate);
                        let formatted_bytes_sent = human_bytes(current_bytes_sent as f64);
                        let formatted_network_rate = human_bytes(network_rate);

                        let archive_percentage = (current_bytes_archived as f64 / total_bytes as f64) * 100.0;
                        let formatted_archive_percentage = format!("{:.2}%", archive_percentage);

                        let time_estimate = if archive_rate > 0.0 {
                            let remaining_bytes = total_bytes as f64 - current_bytes_archived as f64;
                            let remaining_seconds = remaining_bytes / archive_rate;

                            &if remaining_seconds < 60.0 {
                                format!("{:.0}s", remaining_seconds)
                            } else if remaining_seconds < 3600.0 {
                                format!("{:.0}m {:.0}s", remaining_seconds / 60.0, remaining_seconds % 60.0)
                            } else {
                                format!("{:.1}h {:.0}m", 
                                    remaining_seconds / 3600.0,
                                    (remaining_seconds % 3600.0) / 60.0
                                )
                            }
                        } else {
                            "unknown"
                        };

                        let elapsed_time = if total_elapsed_secs < 60.0 {
                            format!("{:.0}s", total_elapsed_secs)
                        } else if total_elapsed_secs < 3600.0 {
                            format!("{:.0}m {:.0}s",
                                total_elapsed_secs / 60.0,
                                total_elapsed_secs % 60.0
                            )
                        } else {
                            format!("{:.0}h {:.0}m",
                                total_elapsed_secs / 3600.0,
                                (total_elapsed_secs % 3600.0) / 60.0
                            )
                        };

                        let progress_log = format!(
                            "{} - ETA: {}\r\nArchive: {} of {} ({}/s) - Elapsed: {}\r\nNetwork: {} sent ({}/s)",
                            crate::utils::draw_progress_bar(30, current_bytes_archived as f64, total_bytes as f64),
                            time_estimate,
                            formatted_bytes_archived,
                            formatted_total_bytes,
                            formatted_archive_rate,
                            elapsed_time,
                            formatted_bytes_sent,
                            formatted_network_rate
                        );

                        Self::log(&server, &progress_log);

                        tracing::debug!(
                            server = %server.uuid,
                            "Progress: {}, Archive: {} of {} ({}/s), Network: {} ({}/s), ETA: {}",
                            formatted_archive_percentage,
                            formatted_bytes_archived,
                            formatted_total_bytes,
                            formatted_archive_rate,
                            formatted_bytes_sent,
                            formatted_network_rate,
                            time_estimate
                        );

                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            });

            let storage_pool = &server.app_state.config.system.transfers.storage_pool;
            let include_storage_pool =
                storage_pool.enabled && !storage_pool.pool_name.is_empty();

            let mut response = reqwest::Client::new()
                .post(&url)
                .header("Authorization", &token)
                .header("Multiplex-Stream-Count", multiplex_streams)
                .multipart(form);
            if include_storage_pool {
                response = response.header("X-Storage-Pool", storage_pool.pool_name.as_str());
            }
            let response = response.send();
            let mut multiplex_responses = Vec::new();
            multiplex_responses.reserve_exact(multiplex_streams);

            type MultiplexTaskResult = Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>;
            let mut multiplex_tasks: Vec<Pin<MultiplexTaskResult>> = Vec::new();
            multiplex_tasks.reserve_exact(multiplex_streams * 2);

            for i in 0..multiplex_streams {
                let (checksum_sender, checksum_receiver) = tokio::sync::oneshot::channel();
                let (mut checksummed_reader, checksummed_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
                let (reader, mut writer) = tokio::io::simplex(crate::BUFFER_SIZE);

                let archive_task = get_archive_task(
                    files_receiver.clone(),
                    Arc::clone(&bytes_archived),
                    server.clone(),
                    tokio_util::io::SyncIoBridge::new(checksummed_writer),
                    crate::server::filesystem::archive::create::CreateTarOptions {
                        compression_type: archive_format.compression_format(),
                        compression_level,
                        threads: server.app_state.config.api.file_compression_threads,
                    },
                );

                let checksum_task = Box::pin({
                    let bytes_sent = Arc::clone(&bytes_sent);

                    async move {
                        let mut hasher = sha2::Sha256::new();

                        let mut buffer = vec![0; crate::BUFFER_SIZE];
                        loop {
                            let bytes_read = checksummed_reader.read(&mut buffer).await?;
                            if crate::unlikely(bytes_read == 0) {
                                break;
                            }

                            hasher.update(&buffer[..bytes_read]);
                            writer.write_all(&buffer[..bytes_read]).await?;
                            bytes_sent.fetch_add(bytes_read as u64, Ordering::Relaxed);
                        }

                        checksum_sender.send(format!("{:x}", hasher.finalize())).ok();
                        writer.flush().await?;
                        writer.shutdown().await?;

                        Ok::<_, anyhow::Error>(())
                    }
                });

                let form = reqwest::multipart::Form::new()
                    .part(
                        "archive",
                        reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                            tokio_util::io::ReaderStream::with_capacity(reader, crate::BUFFER_SIZE),
                        ))
                        .file_name(format!("archive.{}", archive_format.extension()))
                        .mime_str("application/x-tar")
                        .unwrap(),
                    )
                    .part(
                        "checksum",
                        reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                            checksum_receiver.into_stream()
                        ))
                        .file_name("checksum")
                        .mime_str("text/plain")
                        .unwrap(),
                    );

                let mut request = reqwest::Client::new()
                    .post(&url)
                    .header("Authorization", &token)
                    .header("Multiplex-Stream", i)
                    .multipart(form);
                if include_storage_pool {
                    request = request.header("X-Storage-Pool", storage_pool.pool_name.as_str());
                }
                multiplex_responses.push(request.send());
                multiplex_tasks.push(archive_task);
                multiplex_tasks.push(checksum_task);
            }

            Self::log(&server, "Streaming archive to destination...");

            tokio::select! {
                result = async {
                    tokio::try_join!(
                        archive_task,
                        checksum_task,
                        file_collector_task,
                        futures_util::future::try_join_all(multiplex_tasks),
                        async { Ok(response.await?) },
                        async { Ok(futures_util::future::try_join_all(multiplex_responses).await?) }
                    )
                } => {
                    if let Err(err) = result {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to transfer server: {}",
                            err
                        );

                        Self::transfer_failure(&server).await;
                        return;
                    }
                }
                _ = progress_task => {}
            };

            Self::log(&server, "Finished streaming archive to destination.");

            if delete_backups {
                for backup in backups {
                    match backup_manager.find(backup).await {
                        Ok(Some(backup)) => {
                            if let Err(err) = backup.delete(&server.app_state.config).await {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to delete backup {}: {}",
                                    backup.uuid(),
                                    err
                                );
                            } else {
                                tracing::info!(
                                    server = %server.uuid,
                                    "deleted backup {} after transfer",
                                    backup.uuid()
                                );
                            }
                        }
                        Ok(None) => {
                            tracing::warn!(
                                server = %server.uuid,
                                "requested backup {} does not exist",
                                backup
                            );
                        }
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to find backup {}: {:#?}",
                                backup,
                                err
                            );
                        }
                    }
                }
            }

            server.transferring.store(false, Ordering::SeqCst);

            tracing::info!(
                server = %server.uuid,
                "finished outgoing server transfer"
            );

            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                server
                    .websocket
                    .send(super::websocket::WebsocketMessage::new(
                        super::websocket::WebsocketEvent::ServerTransferStatus,
                        ["completed".into()].into(),
                    ))
                    .ok();
            });
        }));

        if let Some(old_task) = old_task {
            old_task.abort();
        }

        Ok(())
    }
}

impl Drop for OutgoingServerTransfer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub struct IncomingServerTransfer {
    pub main_handle: AbortHandle,

    pub multiplex_handles: Vec<(
        AbortHandle,
        tokio::sync::oneshot::Receiver<Result<(), anyhow::Error>>,
    )>,
}

impl IncomingServerTransfer {
    pub async fn try_join_handles(
        &mut self,
        main: JoinHandle<Result<Vec<uuid::Uuid>, anyhow::Error>>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        let (backups, _) = tokio::try_join!(async { main.await? }, async {
            Ok(futures_util::future::try_join_all(
                self.multiplex_handles.drain(..).map(|h| h.1),
            ))
        })?;

        Ok(backups)
    }
}

impl Drop for IncomingServerTransfer {
    fn drop(&mut self) {
        self.main_handle.abort();

        for handle in self.multiplex_handles.iter() {
            handle.0.abort();
        }
    }
}
