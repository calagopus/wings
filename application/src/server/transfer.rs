use crate::{
    io::{
        SafeAsyncWriteExt, SafeDigestExt,
        compression::{CompressionLevel, CompressionType},
        counting_reader::AsyncCountingReader,
    },
    server::filesystem::archive::StreamableArchiveFormat,
};
use futures::FutureExt;
use human_bytes::human_bytes;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    borrow::Cow,
    collections::VecDeque,
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

    Itaf,
    ItafGz,
    ItafXz,
    ItafLzip,
    ItafBz2,
    ItafLz4,
    ItafZstd,
}

impl TransferArchiveFormat {
    #[inline]
    pub fn compression_format(self) -> CompressionType {
        match self {
            TransferArchiveFormat::Tar | TransferArchiveFormat::Itaf => CompressionType::None,
            TransferArchiveFormat::TarGz | TransferArchiveFormat::ItafGz => CompressionType::Gz,
            TransferArchiveFormat::TarXz | TransferArchiveFormat::ItafXz => CompressionType::Xz,
            TransferArchiveFormat::TarLzip | TransferArchiveFormat::ItafLzip => {
                CompressionType::Lzip
            }
            TransferArchiveFormat::TarBz2 | TransferArchiveFormat::ItafBz2 => CompressionType::Bz2,
            TransferArchiveFormat::TarLz4 | TransferArchiveFormat::ItafLz4 => CompressionType::Lz4,
            TransferArchiveFormat::TarZstd | TransferArchiveFormat::ItafZstd => {
                CompressionType::Zstd
            }
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
            TransferArchiveFormat::Itaf => "itaf",
            TransferArchiveFormat::ItafGz => "itaf.gz",
            TransferArchiveFormat::ItafXz => "itaf.xz",
            TransferArchiveFormat::ItafLzip => "itaf.lz",
            TransferArchiveFormat::ItafBz2 => "itaf.bz2",
            TransferArchiveFormat::ItafLz4 => "itaf.lz4",
            TransferArchiveFormat::ItafZstd => "itaf.zst",
        }
    }

    #[inline]
    pub const fn is_tar(self) -> bool {
        matches!(
            self,
            TransferArchiveFormat::Tar
                | TransferArchiveFormat::TarGz
                | TransferArchiveFormat::TarXz
                | TransferArchiveFormat::TarLzip
                | TransferArchiveFormat::TarBz2
                | TransferArchiveFormat::TarLz4
                | TransferArchiveFormat::TarZstd
        )
    }

    #[inline]
    pub const fn is_itaf(self) -> bool {
        matches!(
            self,
            TransferArchiveFormat::Itaf
                | TransferArchiveFormat::ItafGz
                | TransferArchiveFormat::ItafXz
                | TransferArchiveFormat::ItafLzip
                | TransferArchiveFormat::ItafBz2
                | TransferArchiveFormat::ItafLz4
                | TransferArchiveFormat::ItafZstd
        )
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
            TransferArchiveFormat::Itaf => StreamableArchiveFormat::Itaf,
            TransferArchiveFormat::ItafGz => StreamableArchiveFormat::ItafGz,
            TransferArchiveFormat::ItafXz => StreamableArchiveFormat::ItafXz,
            TransferArchiveFormat::ItafLzip => StreamableArchiveFormat::ItafLzip,
            TransferArchiveFormat::ItafBz2 => StreamableArchiveFormat::ItafBz2,
            TransferArchiveFormat::ItafLz4 => StreamableArchiveFormat::ItafLz4,
            TransferArchiveFormat::ItafZstd => StreamableArchiveFormat::ItafZstd,
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
        } else if s.ends_with(".itaf") {
            Ok(TransferArchiveFormat::Itaf)
        } else if s.ends_with(".itaf.gz") {
            Ok(TransferArchiveFormat::ItafGz)
        } else if s.ends_with(".itaf.xz") {
            Ok(TransferArchiveFormat::ItafXz)
        } else if s.ends_with(".itaf.lz") {
            Ok(TransferArchiveFormat::ItafLzip)
        } else if s.ends_with(".itaf.bz2") {
            Ok(TransferArchiveFormat::ItafBz2)
        } else if s.ends_with(".itaf.lz4") {
            Ok(TransferArchiveFormat::ItafLz4)
        } else if s.ends_with(".itaf.zst") {
            Ok(TransferArchiveFormat::ItafZstd)
        } else {
            Err("Invalid archive format")
        }
    }
}

#[derive(ToSchema, Deserialize, Serialize, Clone, Copy)]
pub struct TransferCapabilities {
    pub wings_archive_format: super::filesystem::archive::ArchiveFormat,
    pub wings_archive_compression_level: CompressionLevel,
    pub disk_limiter_mode: super::filesystem::limiter::DiskLimiterMode,
}

impl TransferCapabilities {
    pub fn from_config(config: &crate::config::InnerConfig) -> Self {
        Self {
            wings_archive_format: config.system.backups.wings.archive_format,
            wings_archive_compression_level: config.system.backups.compression_level,
            disk_limiter_mode: config.system.disk_limiter_mode,
        }
    }
}

pub struct OutgoingServerTransfer {
    pub bytes_archived: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_total: Arc<AtomicU64>,

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
            bytes_total: Arc::new(AtomicU64::new(0)),
            server: server.clone(),
            archive_format,
            compression_level,
            task: None,
        }
    }

    fn log(server: &super::Server, message: &str) {
        let prelude = nu_ansi_term::Color::Yellow.bold().paint(format!(
            "{} [Transfer System] [Source Node]:",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));

        server
            .websocket
            .send(
                super::websocket::WebsocketMessage::builder(
                    super::websocket::WebsocketEvent::ServerTransferLogs,
                )
                .arg(compact_str::format_compact!("{prelude} {message}"))
                .build(),
            )
            .ok();
    }

    async fn transfer_failure(server: &super::Server) {
        server
            .app_state
            .config
            .client
            .set_server_transfer(server.uuid, false, &Default::default())
            .await
            .ok();
        server.outgoing_transfer.write().await.take();

        server.transferring.store(false, Ordering::SeqCst);
        server
            .websocket
            .send(
                super::websocket::WebsocketMessage::builder(
                    super::websocket::WebsocketEvent::ServerTransferStatus,
                )
                .arg("failure")
                .build(),
            )
            .ok();
    }

    async fn query_destination_capabilities(
        url: &str,
        token: &str,
    ) -> Result<TransferCapabilities, anyhow::Error> {
        let mut query_url = reqwest::Url::parse(url)?;
        query_url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("transfer url cannot be a base"))?
            .pop_if_empty()
            .push("query");

        let capabilities = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?
            .get(query_url)
            .header("Authorization", token)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(capabilities)
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
        let bytes_total = Arc::clone(&self.bytes_total);
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
                .send(
                    super::websocket::WebsocketMessage::builder(
                        super::websocket::WebsocketEvent::ServerTransferStatus,
                    )
                    .arg("processing")
                    .build(),
                )
                .ok();

            let (files_sender, files_receiver) = async_channel::bounded(512 * (1 + multiplex_streams));

            let (checksum_sender, checksum_receiver) = tokio::sync::oneshot::channel();
            let (mut checksummed_reader, checksummed_writer) = tokio::io::simplex(crate::TRANSFER_BUFFER_SIZE);
            let (reader, mut writer) = tokio::io::simplex(crate::TRANSFER_BUFFER_SIZE);

            fn get_tar_archive_task(
                files_receiver: async_channel::Receiver<PathBuf>,
                bytes_archived: Arc<AtomicU64>,
                server: super::Server,
                writer: tokio_util::io::SyncIoBridge<tokio::io::WriteHalf<tokio::io::SimplexStream>>,
                options: crate::server::filesystem::archive::create::CreateTarOptions
            ) -> Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>> {
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

            fn get_itaf_archive_task(
                files_receiver: async_channel::Receiver<PathBuf>,
                bytes_archived: Arc<AtomicU64>,
                server: super::Server,
                writer: tokio_util::io::SyncIoBridge<tokio::io::WriteHalf<tokio::io::SimplexStream>>,
                options: crate::server::filesystem::archive::create::CreateItafOptions
            ) -> Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>> {
                Box::pin(async move {
                    let writer = crate::server::filesystem::archive::create::create_itaf_distributed(
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

            let get_archive_task = |writer: tokio_util::io::SyncIoBridge<tokio::io::WriteHalf<tokio::io::SimplexStream>>| {
                if archive_format.is_tar() {
                    get_tar_archive_task(
                        files_receiver.clone(),
                        Arc::clone(&bytes_archived),
                        server.clone(),
                        writer,
                        crate::server::filesystem::archive::create::CreateTarOptions {
                            compression_type: archive_format.compression_format(),
                            compression_level,
                            threads: server.app_state.config.load().api.file_compression_threads,
                        },
                    )
                } else {
                    get_itaf_archive_task(
                        files_receiver.clone(),
                        Arc::clone(&bytes_archived),
                        server.clone(),
                        writer,
                        crate::server::filesystem::archive::create::CreateItafOptions {
                            compression_type: archive_format.compression_format(),
                            compression_level,
                            threads: server.app_state.config.load().api.file_compression_threads,
                            crc_enabled: false,
                        },
                    )
                }
            };

            let archive_task = get_archive_task(tokio_util::io::SyncIoBridge::new(checksummed_writer));

            let checksum_task = Box::pin({
                let bytes_sent = Arc::clone(&bytes_sent);

                async move {
                    let mut hasher = sha2::Sha256::new();

                    let mut buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
                    loop {
                        let bytes_read = checksummed_reader.read(&mut buffer).await?;
                        if crate::unlikely(bytes_read == 0) {
                            break;
                        }

                        hasher.safe_update(&buffer, bytes_read)?;
                        writer.safe_write_all(&buffer, bytes_read).await?;
                        bytes_sent.fetch_add(bytes_read as u64, Ordering::Relaxed);
                    }

                    checksum_sender
                        .send(hex::encode(hasher.finalize()))
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
                        tokio_util::io::ReaderStream::with_capacity(reader, crate::TRANSFER_BUFFER_SIZE),
                    ))
                    .file_name(format!("archive.{}", archive_format.extension()))
                    .mime_str("application/x-tar")
                    .expect("failed to set mime type for archive"),
                )
                .part(
                    "checksum",
                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                        checksum_receiver.into_stream()
                    ))
                    .file_name("checksum")
                    .mime_str("text/plain")
                    .expect("failed to set mime type for checksum"),
                );

            bytes_total.store(server.filesystem.get_logical_cached_size(), Ordering::Relaxed);

            if let Ok(install_logs) = crate::server::installation::ServerInstaller::get_install_logs(&server).await {
                bytes_total.fetch_add(install_logs.metadata().await.map(|m| m.len()).unwrap_or(0), Ordering::Relaxed);

                form = form.part(
                    "install-logs",
                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                        tokio_util::io::ReaderStream::with_capacity(
                            AsyncCountingReader::new_with_bytes_read(
                                install_logs,
                                Arc::clone(&bytes_archived),
                            ),
                            crate::TRANSFER_BUFFER_SIZE,
                        ),
                    ))
                    .file_name("install.log")
                    .mime_str("text/plain")
                    .expect("failed to set mime type for install logs"),
                );
            }

            let destination_capabilities = if backups.is_empty() {
                None
            } else {
                match Self::query_destination_capabilities(&url, &token).await {
                    Ok(capabilities) => Some(capabilities),
                    Err(err) => {
                        tracing::warn!(
                            server = %server.uuid,
                            "failed to query destination transfer capabilities, falling back to local config: {err:#}"
                        );
                        Self::log(
                            &server,
                            "Could not query destination capabilities, using local backup format for conversions.",
                        );

                        Some(TransferCapabilities::from_config(
                            &server.app_state.config.load(),
                        ))
                    }
                }
            };

            let mut backup_sender = crate::server::backup::transfer::BackupSender::new(
                &server.app_state,
                destination_capabilities.as_ref(),
                &bytes_archived,
                &bytes_sent,
                &bytes_total,
            );
            for backup in &backups {
                form = backup_sender.append_part(form, *backup).await;
            }

            let progress_task = Box::pin({
                let bytes_archived = Arc::clone(&bytes_archived);
                let bytes_sent = Arc::clone(&bytes_sent);
                let bytes_total = bytes_total.load(Ordering::Relaxed);
                let server = server.clone();

                async move {
                    let mut last_bytes_archived = 0;
                    let mut last_bytes_sent = 0;
                    let mut last_update_time = Instant::now();
                    let start_time = Instant::now();
                    let mut history = VecDeque::new();

                    loop {
                        let now = Instant::now();
                        let elapsed_secs = now.duration_since(last_update_time).as_secs_f64();
                        let total_elapsed_secs = now.duration_since(start_time).as_secs_f64();
                        last_update_time = now;

                        let current_bytes_archived = bytes_archived.load(Ordering::SeqCst);
                        let current_bytes_sent = bytes_sent.load(Ordering::SeqCst);

                        history.push_back((now, current_bytes_archived));
                        while let Some(&(t, _)) = history.front() {
                            if now.duration_since(t).as_secs_f64() > 30.0 {
                                history.pop_front();
                            } else {
                                break;
                            }
                        }

                        let archive_rate = if elapsed_secs > 0.0 {
                            (current_bytes_archived.saturating_sub(last_bytes_archived)) as f64 / elapsed_secs
                        } else {
                            0.0
                        };

                        let network_rate = if elapsed_secs > 0.0 {
                            (current_bytes_sent.saturating_sub(last_bytes_sent)) as f64 / elapsed_secs
                        } else {
                            0.0
                        };

                        last_bytes_archived = current_bytes_archived;
                        last_bytes_sent = current_bytes_sent;

                        let bytes_total = bytes_total.max(current_bytes_archived);

                        let formatted_bytes_archived = human_bytes(current_bytes_archived as f64);
                        let formatted_bytes_total = human_bytes(bytes_total as f64);
                        let formatted_archive_rate = human_bytes(archive_rate);
                        let formatted_bytes_sent = human_bytes(current_bytes_sent as f64);
                        let formatted_network_rate = human_bytes(network_rate);

                        let archive_percentage = (current_bytes_archived as f64 / bytes_total as f64) * 100.0;
                        let formatted_archive_percentage = format!("{:.2}%", archive_percentage);

                        let time_estimate = if history.len() > 1 && current_bytes_archived < bytes_total {
                            let Some(&(oldest_time, oldest_progress)) = history.front() else {
                                return Cow::Borrowed("unknown");
                            };
                            let Some(&(newest_time, newest_progress)) = history.back() else {
                                return Cow::Borrowed("unknown");
                            };

                            let delta_progress = newest_progress.saturating_sub(oldest_progress) as f64;
                            let delta_time = newest_time.duration_since(oldest_time).as_secs_f64();

                            if delta_progress > 0.0 && delta_time > 0.0 {
                                let rate_30s = delta_progress / delta_time;
                                let remaining_bytes = bytes_total.saturating_sub(newest_progress) as f64;
                                let remaining_seconds = remaining_bytes / rate_30s;

                                Cow::Owned(if remaining_seconds < 60.0 {
                                    format!("{:.0}s", remaining_seconds)
                                } else if remaining_seconds < 3600.0 {
                                    format!("{:.0}m {:.0}s", remaining_seconds / 60.0, remaining_seconds % 60.0)
                                } else {
                                    format!("{:.1}h {:.0}m", 
                                        remaining_seconds / 3600.0,
                                        (remaining_seconds % 3600.0) / 60.0
                                    )
                                })
                            } else {
                                Cow::Borrowed("calculating...")
                            }
                        } else if current_bytes_archived >= bytes_total {
                            Cow::Borrowed("0s")
                        } else {
                            Cow::Borrowed("unknown")
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
                            crate::utils::draw_progress_bar(30, current_bytes_archived as f64, bytes_total as f64),
                            time_estimate,
                            formatted_bytes_archived,
                            formatted_bytes_total,
                            formatted_archive_rate,
                            elapsed_time,
                            formatted_bytes_sent,
                            formatted_network_rate
                        );

                        Self::log(&server, &progress_log);

                        server
                            .websocket
                            .send(
                                super::websocket::WebsocketMessage::builder(
                                    super::websocket::WebsocketEvent::ServerTransferProgress,
                                )
                                .structured_arg(crate::models::TransferProgress {
                                    archive_progress: current_bytes_archived,
                                    network_progress: current_bytes_sent,
                                    total: bytes_total,
                                })
                                .build(),
                            )
                            .ok();

                        tracing::debug!(
                            server = %server.uuid,
                            "Progress: {}, Archive: {} of {} ({}/s), Network: {} ({}/s), ETA: {}",
                            formatted_archive_percentage,
                            formatted_bytes_archived,
                            formatted_bytes_total,
                            formatted_archive_rate,
                            formatted_bytes_sent,
                            formatted_network_rate,
                            time_estimate
                        );

                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            });

            let response = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(15))
                .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
                .build()
                .expect("failed to build HTTP client")
                .post(&url)
                .header("Authorization", &token)
                .header("Multiplex-Stream-Count", multiplex_streams)
                .multipart(form)
                .send();
            let mut multiplex_responses = Vec::new();
            multiplex_responses.reserve_exact(multiplex_streams);

            type MultiplexTaskResult = Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>;
            let mut multiplex_tasks: Vec<Pin<MultiplexTaskResult>> = Vec::new();
            multiplex_tasks.reserve_exact(multiplex_streams * 2);

            for i in 0..multiplex_streams {
                let (checksum_sender, checksum_receiver) = tokio::sync::oneshot::channel();
                let (mut checksummed_reader, checksummed_writer) = tokio::io::simplex(crate::TRANSFER_BUFFER_SIZE);
                let (reader, mut writer) = tokio::io::simplex(crate::TRANSFER_BUFFER_SIZE);

                let archive_task = get_archive_task(tokio_util::io::SyncIoBridge::new(checksummed_writer));

                let checksum_task = Box::pin({
                    let bytes_sent = Arc::clone(&bytes_sent);

                    async move {
                        let mut hasher = sha2::Sha256::new();

                        let mut buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
                        loop {
                            let bytes_read = checksummed_reader.read(&mut buffer).await?;
                            if crate::unlikely(bytes_read == 0) {
                                break;
                            }

                            hasher.safe_update(&buffer, bytes_read)?;
                            writer.safe_write_all(&buffer, bytes_read).await?;
                            bytes_sent.fetch_add(bytes_read as u64, Ordering::Relaxed);
                        }

                        checksum_sender.send(hex::encode(hasher.finalize())).ok();
                        writer.flush().await?;
                        writer.shutdown().await?;

                        Ok::<_, anyhow::Error>(())
                    }
                });

                let form = reqwest::multipart::Form::new()
                    .part(
                        "archive",
                        reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                            tokio_util::io::ReaderStream::with_capacity(reader, crate::TRANSFER_BUFFER_SIZE),
                        ))
                        .file_name(format!("archive.{}", archive_format.extension()))
                        .mime_str("application/x-tar")
                        .expect("failed to set mime type for archive"),
                    )
                    .part(
                        "checksum",
                        reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                            checksum_receiver.into_stream()
                        ))
                        .file_name("checksum")
                        .mime_str("text/plain")
                        .expect("failed to set mime type for checksum"),
                    );

                multiplex_responses.push(
                    reqwest::Client::builder()
                        .connect_timeout(std::time::Duration::from_secs(15))
                        .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
                        .build()
                        .expect("failed to build HTTP client")
                        .post(&url)
                        .header("Authorization", &token)
                        .header("Multiplex-Stream", i)
                        .multipart(form)
                        .send()
                );
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
                        futures::future::try_join_all(multiplex_tasks),
                        async { Ok(response.await?) },
                        async { Ok(futures::future::try_join_all(multiplex_responses).await?) }
                    )
                } => {
                    if let Err(err) = result {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to transfer server: {}",
                            err
                        );

                        backup_sender.finish().await;
                        Self::transfer_failure(&server).await;
                        return;
                    }
                }
                _ = progress_task => {}
            };

            backup_sender.finish().await;

            Self::log(&server, "Finished streaming archive to destination.");

            if delete_backups {
                for backup in backups {
                    match backup_manager.find(&server.app_state, backup).await {
                        Ok(Some(backup)) => {
                            if let Err(err) = backup.delete(&server.app_state).await {
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

            server
                .websocket
                .send(
                    super::websocket::WebsocketMessage::builder(
                        super::websocket::WebsocketEvent::ServerTransferStatus,
                    )
                    .arg("completed")
                    .build(),
                )
                .ok();

            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                server.user_permissions.clear_permissions();
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
        main: JoinHandle<Result<super::backup::transfer::ReceivedBackups, anyhow::Error>>,
    ) -> Result<super::backup::transfer::ReceivedBackups, anyhow::Error> {
        let (backups, _) = tokio::try_join!(async { main.await? }, async {
            Ok(futures::future::try_join_all(
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
