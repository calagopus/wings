use crate::{
    io::{
        abort::{AbortListener, AbortReader},
        counting_reader::AsyncCountingReader,
        hash_reader::{AsyncHashReader, HashReader},
        limited_reader::LimitedReader,
    },
    server::filesystem::archive::{ArchiveFormat, StreamableArchiveFormat},
};
use futures::{FutureExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha1::Digest;
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;

pub struct BackupSender {
    state: crate::routes::State,
    capabilities: Option<crate::server::transfer::TransferCapabilities>,
    bytes_archived: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    bytes_total: Arc<AtomicU64>,

    btrfs_parent: Option<std::path::PathBuf>,
    btrfs_cleanup_dirs: Vec<std::path::PathBuf>,
}

impl BackupSender {
    pub fn new(
        state: &crate::routes::State,
        capabilities: Option<&crate::server::transfer::TransferCapabilities>,
        bytes_archived: &Arc<AtomicU64>,
        bytes_sent: &Arc<AtomicU64>,
        bytes_total: &Arc<AtomicU64>,
    ) -> Self {
        Self {
            state: Arc::clone(state),
            capabilities: capabilities.copied(),
            bytes_archived: Arc::clone(bytes_archived),
            bytes_sent: Arc::clone(bytes_sent),
            bytes_total: Arc::clone(bytes_total),
            btrfs_parent: None,
            btrfs_cleanup_dirs: Vec::new(),
        }
    }

    pub async fn finish(self) {
        for dir in self.btrfs_cleanup_dirs {
            crate::server::backup::adapters::btrfs::BtrfsBackup::cleanup_send_dir(&dir).await;
        }
    }

    pub async fn append_part(
        &mut self,
        form: reqwest::multipart::Form,
        uuid: uuid::Uuid,
    ) -> reqwest::multipart::Form {
        let backup = match self.state.backup_manager.find(&self.state, uuid).await {
            Ok(Some(backup)) => backup,
            Ok(None) => {
                tracing::warn!(backup = %uuid, "requested backup does not exist");
                return form;
            }
            Err(err) => {
                tracing::error!(backup = %uuid, "failed to find backup: {err:#?}");
                return form;
            }
        };

        struct TransferPart {
            reader: Pin<Box<dyn tokio::io::AsyncRead + Send>>,
            file_name: String,
            content_type: &'static str,
            ignore: Option<String>,
        }

        let part = match &*backup {
            super::Backup::Wings(backup) => {
                let file = match tokio::fs::File::open(&backup.path).await {
                    Ok(file) => file,
                    Err(err) => {
                        tracing::error!(
                            backup = %uuid,
                            "failed to open backup file {}: {err}",
                            backup.path.display()
                        );
                        return form;
                    }
                };

                self.bytes_total.fetch_add(
                    file.metadata().await.map(|m| m.len()).unwrap_or(0),
                    Ordering::Relaxed,
                );

                TransferPart {
                    reader: Box::pin(file),
                    file_name: format!("{}.{}", uuid, backup.format.extension()),
                    content_type: "backup/wings",
                    ignore: None,
                }
            }
            super::Backup::Btrfs(backup) => {
                let Some(capabilities) = self.capabilities else {
                    tracing::warn!(
                        backup = %uuid,
                        "destination capabilities unknown, cannot convert btrfs backup, skipping"
                    );
                    return form;
                };

                let native_stream = if capabilities.disk_limiter_mode
                    == crate::server::filesystem::limiter::DiskLimiterMode::BtrfsSubvolume
                {
                    match backup
                        .open_send_stream(&self.state, self.btrfs_parent.as_deref())
                        .await
                    {
                        Ok(stream) => Some(stream),
                        Err(err) => {
                            tracing::warn!(
                                backup = %uuid,
                                "native btrfs send unavailable, falling back to archive conversion: {err}"
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                if let Some(stream) = native_stream {
                    self.btrfs_parent = Some(stream.snapshot_path);
                    self.btrfs_cleanup_dirs.push(stream.send_dir);

                    let ignore = tokio::fs::read_to_string(
                        super::adapters::btrfs::BtrfsBackup::get_ignore_path(
                            &self.state.config,
                            uuid,
                        ),
                    )
                    .await
                    .unwrap_or_default();

                    TransferPart {
                        reader: Box::pin(stream.stdout),
                        file_name: format!("{uuid}.btrfs"),
                        content_type: "backup/btrfs",
                        ignore: Some(ignore),
                    }
                } else {
                    let archive_format = match capabilities.wings_archive_format {
                        ArchiveFormat::Tar => StreamableArchiveFormat::Tar,
                        ArchiveFormat::TarGz => StreamableArchiveFormat::TarGz,
                        ArchiveFormat::TarXz => StreamableArchiveFormat::TarXz,
                        ArchiveFormat::TarLzip => StreamableArchiveFormat::TarLzip,
                        ArchiveFormat::TarBz2 => StreamableArchiveFormat::TarBz2,
                        ArchiveFormat::TarLz4 => StreamableArchiveFormat::TarLz4,
                        ArchiveFormat::TarZstd => StreamableArchiveFormat::TarZstd,
                        ArchiveFormat::Zip => StreamableArchiveFormat::Zip,
                        ArchiveFormat::SevenZip => {
                            tracing::warn!(
                                backup = %uuid,
                                "cannot convert btrfs backup to 7z format as it is not streamable, skipping"
                            );
                            return form;
                        }
                    };

                    let reader = match backup
                        .open_archive_stream(
                            &self.state,
                            archive_format,
                            capabilities.wings_archive_compression_level,
                        )
                        .await
                    {
                        Ok(reader) => reader,
                        Err(err) => {
                            tracing::error!(
                                backup = %uuid,
                                "failed to convert btrfs backup for transfer: {err}"
                            );
                            return form;
                        }
                    };

                    TransferPart {
                        reader: Box::pin(reader),
                        file_name: format!("{uuid}.{}", archive_format.extension()),
                        content_type: "backup/wings",
                        ignore: None,
                    }
                }
            }
            _ => {
                tracing::warn!(
                    backup = %uuid,
                    "backup uses an adapter that cannot be transferred, skipping"
                );
                return form;
            }
        };

        let hasher = Arc::new(Mutex::new(sha2::Sha256::new()));
        let reader =
            AsyncCountingReader::new_with_bytes_read(part.reader, Arc::clone(&self.bytes_archived));
        let reader = AsyncCountingReader::new_with_bytes_read(reader, Arc::clone(&self.bytes_sent));
        let reader = AsyncHashReader::new_with_hasher(reader, Arc::clone(&hasher)).await;

        let (checksum_sender, checksum_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            checksum_sender
                .send(hex::encode(hasher.lock().await.finalize_reset()))
                .ok();
        });

        let mut form = form
            .part(
                format!("backup-{uuid}"),
                reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                    tokio_util::io::ReaderStream::with_capacity(
                        reader,
                        crate::TRANSFER_BUFFER_SIZE,
                    ),
                ))
                .file_name(part.file_name)
                .mime_str(part.content_type)
                .expect("failed to set mime type for archive"),
            )
            .part(
                format!("backup-checksum-{uuid}"),
                reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                    checksum_receiver.into_stream(),
                ))
                .file_name(format!("backup-checksum-{uuid}"))
                .mime_str("text/plain")
                .expect("failed to set mime type for checksum"),
            );
        if let Some(ignore) = part.ignore {
            form = form.part(
                format!("backup-ignore-{uuid}"),
                reqwest::multipart::Part::text(ignore)
                    .file_name(format!("backup-ignore-{uuid}"))
                    .mime_str("text/plain")
                    .expect("failed to set mime type for ignore"),
            );
        }

        form
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMigration {
    pub checksum: String,
    pub checksum_type: compact_str::CompactString,
    pub browsable: bool,
    pub streaming: bool,
}

#[derive(Debug, Default)]
pub struct ReceivedBackups {
    pub uuids: Vec<uuid::Uuid>,
    pub migrations: BTreeMap<uuid::Uuid, BackupMigration>,
}

pub struct BackupReceiver {
    state: crate::routes::State,
    listener: AbortListener,

    received: ReceivedBackups,
    checksum: Option<String>,
}

impl BackupReceiver {
    #[inline]
    pub fn new(state: crate::routes::State, listener: AbortListener) -> Self {
        Self {
            state,
            listener,
            received: ReceivedBackups::default(),
            checksum: None,
        }
    }

    #[inline]
    pub fn into_received(self) -> ReceivedBackups {
        self.received
    }

    pub fn handle_field(
        &mut self,
        runtime: &tokio::runtime::Handle,
        field: axum::extract::multipart::Field<'_>,
    ) -> Result<(), anyhow::Error> {
        tracing::debug!(
            "processing backup field: {}",
            field.name().unwrap_or("unknown")
        );

        let uuid = field
            .name()
            .and_then(|n| n.strip_prefix("backup-"))
            .and_then(|n| uuid::Uuid::from_str(n).ok());

        let uuid = match uuid {
            Some(uuid) => uuid,
            None => {
                let name = field.name().unwrap_or("");

                if name.contains("checksum") {
                    let checksum = match self.checksum.take() {
                        Some(checksum) => checksum,
                        None => {
                            return Err(anyhow::anyhow!(
                                "backup checksum does not match multipart checksum, None to be found"
                            ));
                        }
                    };
                    let expected = runtime.block_on(field.text())?;

                    if checksum != expected {
                        return Err(anyhow::anyhow!(
                            "backup checksum does not match multipart checksum, {expected} != {checksum}"
                        ));
                    }

                    return Ok(());
                }

                if let Some(uuid) = name
                    .strip_prefix("backup-ignore-")
                    .and_then(|n| uuid::Uuid::from_str(n).ok())
                {
                    let backup_path =
                        crate::server::backup::adapters::btrfs::BtrfsBackup::get_backup_path(
                            &self.state.config,
                            uuid,
                        );
                    let ignore_path =
                        crate::server::backup::adapters::btrfs::BtrfsBackup::get_ignore_path(
                            &self.state.config,
                            uuid,
                        );
                    let contents = runtime.block_on(field.text())?;

                    if let Err(err) = std::fs::create_dir_all(&backup_path)
                        .and_then(|_| std::fs::write(&ignore_path, contents))
                    {
                        tracing::error!(
                            "failed to write ignore file {}: {err:#?}",
                            ignore_path.display()
                        );
                    }

                    return Ok(());
                }

                tracing::warn!("invalid backup field name: {name}");
                return Ok(());
            }
        };

        let file_name = match field.file_name() {
            Some(name) => name.to_string(),
            None => {
                tracing::warn!("backup field without file name found in transfer archive");
                return Ok(());
            }
        };

        match field.content_type() {
            Some("backup/wings") => {
                if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
                    tracing::warn!("invalid backup file name: {file_name}");
                    return Ok(());
                }

                let Ok(archive_format) = ArchiveFormat::from_str(&file_name) else {
                    tracing::warn!("invalid backup file format: {file_name}");
                    return Ok(());
                };

                let file_name =
                    Path::new(&self.state.config.load().system.backup_directory).join(file_name);
                let reader =
                    tokio_util::io::StreamReader::new(field.into_stream().map_err(|err| {
                        std::io::Error::other(format!("failed to read multipart field: {err}"))
                    }));
                let reader = tokio_util::io::SyncIoBridge::new(reader);
                let reader = AbortReader::new(reader, self.listener.clone());
                let reader = LimitedReader::new_with_bytes_per_second(
                    reader,
                    self.state
                        .config
                        .load()
                        .system
                        .transfers
                        .download_limit
                        .as_bytes(),
                );
                let mut reader = HashReader::new_with_hasher(reader, sha2::Sha256::new());

                let mut file = match std::fs::File::create(&file_name) {
                    Ok(file) => file,
                    Err(err) => {
                        tracing::error!(
                            "failed to create backup file {}: {err:#?}",
                            file_name.display()
                        );
                        return Ok(());
                    }
                };

                if let Err(err) = crate::io::copy(&mut reader, &mut file) {
                    tracing::error!(
                        "failed to copy backup file {}: {err:#?}",
                        file_name.display()
                    );
                    return Ok(());
                }

                if let Err(err) = file.flush() {
                    tracing::error!(
                        "failed to flush backup file {}: {err:#?}",
                        file_name.display()
                    );
                    return Ok(());
                }

                let checksum = hex::encode(reader.finish());

                self.received.uuids.push(uuid);
                self.received.migrations.insert(
                    uuid,
                    BackupMigration {
                        checksum: checksum.clone(),
                        checksum_type: "sha256".into(),
                        browsable: matches!(
                            archive_format,
                            ArchiveFormat::Zip | ArchiveFormat::SevenZip
                        ),
                        streaming: false,
                    },
                );
                self.checksum = Some(checksum);

                tracing::debug!(
                    "backup file {} transferred successfully",
                    file_name.display()
                );
            }
            Some("backup/btrfs") => {
                use crate::server::backup::adapters::btrfs::BtrfsBackup;

                let backup_path = BtrfsBackup::get_backup_path(&self.state.config, uuid);
                let subvolume_path = BtrfsBackup::get_subvolume_path(&self.state.config, uuid);

                if std::fs::metadata(&subvolume_path).is_ok() {
                    std::process::Command::new("btrfs")
                        .args(["subvolume", "delete"])
                        .arg(&subvolume_path)
                        .output()
                        .ok();
                }

                if let Err(err) = std::fs::create_dir_all(&backup_path) {
                    tracing::error!(
                        "failed to create btrfs backup directory {}: {err:#?}",
                        backup_path.display()
                    );
                    return Ok(());
                }

                let reader =
                    tokio_util::io::StreamReader::new(field.into_stream().map_err(|err| {
                        std::io::Error::other(format!("failed to read multipart field: {err}"))
                    }));
                let reader = tokio_util::io::SyncIoBridge::new(reader);
                let reader = AbortReader::new(reader, self.listener.clone());
                let reader = LimitedReader::new_with_bytes_per_second(
                    reader,
                    self.state
                        .config
                        .load()
                        .system
                        .transfers
                        .download_limit
                        .as_bytes(),
                );
                let mut reader = HashReader::new_with_hasher(reader, sha2::Sha256::new());

                let mut command = std::process::Command::new("btrfs");
                command.arg("receive");
                if let Some(mount_point) = BtrfsBackup::filesystem_mount_point(&backup_path) {
                    command.arg("-m").arg(mount_point);
                }

                let mut child = match command
                    .arg(&backup_path)
                    .stdin(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(child) => child,
                    Err(err) => {
                        tracing::error!("failed to spawn btrfs receive: {err:#?}");
                        return Ok(());
                    }
                };

                let mut stdin = child.stdin.take().expect("btrfs receive stdin");
                let stderr = child.stderr.take().expect("btrfs receive stderr");
                let stderr_handle = std::thread::spawn(move || {
                    let mut buffer = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr), &mut buffer)
                        .ok();
                    buffer
                });

                let copy_result = crate::io::copy(&mut reader, &mut stdin);
                drop(stdin);

                if copy_result.is_err() {
                    child.kill().ok();
                }

                let status = child.wait();
                let stderr =
                    String::from_utf8_lossy(&stderr_handle.join().unwrap_or_default()).into_owned();

                if copy_result.is_ok() && status.as_ref().is_ok_and(|s| s.success()) {
                    self.received.uuids.push(uuid);
                    self.checksum = Some(hex::encode(reader.finish()));

                    let mut generation = None;
                    let mut subvolume_uuid = None;
                    if let Ok(output) = std::process::Command::new("btrfs")
                        .args(["subvolume", "show"])
                        .arg(&subvolume_path)
                        .output()
                        && output.status.success()
                    {
                        let output = String::from_utf8_lossy(&output.stdout);
                        for line in output.lines() {
                            let mut whitespace = line.split_whitespace();
                            match whitespace.next() {
                                Some("Generation:") => {
                                    generation =
                                        whitespace.next().and_then(|v| v.parse::<u64>().ok())
                                }
                                Some("UUID:") => {
                                    subvolume_uuid = whitespace
                                        .next()
                                        .and_then(|v| uuid::Uuid::parse_str(v).ok())
                                }
                                _ => {}
                            }
                        }
                    }

                    self.received.migrations.insert(
                        uuid,
                        BackupMigration {
                            checksum: format!(
                                "{}-{}",
                                generation.unwrap_or_default(),
                                subvolume_uuid.unwrap_or_default()
                            ),
                            checksum_type: "btrfs-subvolume".into(),
                            browsable: true,
                            streaming: true,
                        },
                    );

                    tracing::debug!("btrfs backup {uuid} received successfully");
                } else {
                    tracing::error!(
                        "failed to receive btrfs backup {uuid}: copy={copy_result:?}, status={status:?}, stderr={stderr}"
                    );

                    if std::fs::metadata(&subvolume_path).is_ok() {
                        std::process::Command::new("btrfs")
                            .args(["subvolume", "delete"])
                            .arg(&subvolume_path)
                            .output()
                            .ok();
                    }
                    std::fs::remove_dir_all(&backup_path).ok();
                }
            }
            _ => {
                tracing::warn!(
                    "invalid content type for backup field: {:?}",
                    field.content_type()
                );
            }
        }

        Ok(())
    }
}
