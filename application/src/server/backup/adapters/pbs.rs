use crate::{
    io::{
        compression::{CompressionType, writer::CompressionWriter},
        copy_shared,
        limited_reader::LimitedReader,
        limited_writer::LimitedWriter,
    },
    remote::backups::{PbsBackupConfiguration, RawServerBackup},
    response::ApiResponse,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::{
                StreamableArchiveFormat,
                create::{CreateTarOptions, create_tar},
            },
            file::ServerFile,
            virtualfs::{ByteRange, VirtualReadableFilesystem},
        },
    },
    utils::PortablePermissions,
};
use compact_str::CompactString;
use pbs_client::{
    config::PbsConfig,
    manifest::{BackupManifest, MANIFEST_BLOB_NAME},
    naming,
    reader::PbsBackupReader,
    rest::PbsClient,
    writer::{ARCHIVE_NAME, META_BLOB_NAME, PbsBackupWriter},
};
use std::{
    io::Write,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncWriteExt;
use tokio_util::io::SyncIoBridge;

pub struct PbsBackup {
    uuid: uuid::Uuid,
    config: PbsConfig,
    backup_id: CompactString,
    backup_time: i64,
}

fn build_config(remote: PbsBackupConfiguration) -> PbsConfig {
    PbsConfig {
        url: remote.url.into(),
        datastore: remote.datastore.into(),
        namespace: remote.namespace.map(Into::into),
        username: remote.username.into(),
        token_name: remote.token_name.into(),
        token_secret: remote.token_secret.into(),
        fingerprint: remote.fingerprint.into(),
        backup_id_prefix: remote.backup_id_prefix.map(Into::into),
    }
}

#[async_trait::async_trait]
impl BackupFindExt for PbsBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        match state.config.client.backup_pbs_configuration(uuid).await {
            Ok(remote) => Ok(remote.server_uuid.is_some()),
            Err(_) => Ok(false),
        }
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        let remote = match state.config.client.backup_pbs_configuration(uuid).await {
            Ok(remote) => remote,
            Err(_) => return Ok(None),
        };

        let Some(server_uuid) = remote.server_uuid else {
            return Ok(None);
        };
        let backup_time = remote.backup_created.timestamp();

        let config = build_config(remote);
        let backup_id = naming::backup_id(config.id_prefix(), server_uuid);

        Ok(Some(Backup::ProxmoxBackupServer(PbsBackup {
            uuid,
            config,
            backup_id,
            backup_time,
        })))
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for PbsBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        _ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let remote = server
            .app_state
            .config
            .client
            .backup_pbs_configuration(uuid)
            .await?;
        let backup_time = remote.backup_created.timestamp();
        let config = build_config(remote);
        config.validate().map_err(|err| anyhow::anyhow!("{err}"))?;

        let backup_id = naming::backup_id(config.id_prefix(), server.uuid);

        let (archive_reader, archive_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

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
                let mut total_files = 0u64;
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
                let writer = SyncIoBridge::new(archive_writer);
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

                let file = create_tar(
                    server.filesystem.clone(),
                    writer,
                    Path::new(""),
                    sources,
                    Some(Arc::clone(&progress)),
                    ignore.into(),
                    CreateTarOptions {
                        compression_type: CompressionType::None,
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

        let pbs_task = {
            let config = config.clone();
            let backup_id = backup_id.clone();
            let server_uuid = server.uuid;

            async move {
                let reader = SyncIoBridge::new(archive_reader);
                let mut writer = PbsBackupWriter::connect(&config, &backup_id, backup_time).await?;

                let archive = writer.upload_archive(reader).await?;

                let metadata = serde_json::json!({
                    "backup_uuid": uuid,
                    "server_uuid": server_uuid,
                    "backup_id": backup_id,
                    "backup_time": backup_time,
                    "archive": ARCHIVE_NAME,
                    "wings_version": env!("CARGO_PKG_VERSION"),
                });
                let meta_file = writer
                    .upload_blob(META_BLOB_NAME, &serde_json::to_vec(&metadata)?)
                    .await?;

                let mut manifest =
                    BackupManifest::new(naming::BACKUP_TYPE, backup_id.as_str(), backup_time);
                let checksum = archive.file.csum.clone();
                manifest.add_file(archive.file);
                manifest.add_file(meta_file);
                writer.finish(&manifest).await?;

                Ok::<_, anyhow::Error>((archive.size, checksum))
            }
        };

        let (total_files, _, (size, checksum)) =
            tokio::try_join!(total_task, archive_task, pbs_task)?;

        Ok(RawServerBackup {
            checksum,
            checksum_type: "sha256".into(),
            size,
            files: total_files,
            successful: true,
            browsable: false,
            streaming: false,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for PbsBackup {
    #[inline]
    fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    async fn download(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        _range: Option<ByteRange>,
    ) -> Result<ApiResponse, anyhow::Error> {
        if !archive_format.is_tar() {
            return Err(anyhow::anyhow!(
                "Proxmox Backup Server downloads currently support only tar-based formats, not {}",
                archive_format.extension()
            ));
        }

        let reader =
            PbsBackupReader::connect(&self.config, &self.backup_id, self.backup_time).await?;

        let (tar_reader, tar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (out_reader, out_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        tokio::spawn(async move {
            let mut tar_writer = tar_writer;
            if let Err(err) = reader.reassemble_archive(&mut tar_writer, None).await {
                tracing::error!("failed to reassemble PBS archive for download: {:?}", err);
            }
            let _ = tar_writer.shutdown().await;
        });

        let compression_type = archive_format.compression_format();
        let compression_level = state.config.load().system.backups.compression_level;
        let threads = state.config.load().api.file_compression_threads;

        crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
            let mut input = SyncIoBridge::new(tar_reader);
            let mut writer = CompressionWriter::new(
                SyncIoBridge::new(out_writer),
                compression_type,
                compression_level,
                threads,
            )?;

            std::io::copy(&mut input, &mut writer)?;

            let mut inner = writer.finish()?;
            inner.flush()?;
            inner.shutdown()?;

            Ok(())
        });

        Ok(ApiResponse::new_stream(out_reader)
            .with_header(
                "Content-Disposition",
                &format!(
                    "attachment; filename={}.{}",
                    self.uuid,
                    archive_format.extension()
                ),
            )
            .with_header("Content-Type", archive_format.mime_type()))
    }

    async fn restore(
        &self,
        server: &crate::server::Server,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let mut reader =
            PbsBackupReader::connect(&self.config, &self.backup_id, self.backup_time).await?;

        if let Ok(manifest_raw) = reader.download_file(MANIFEST_BLOB_NAME).await
            && let Ok(json) = pbs_client::datablob::decode_blob(&manifest_raw)
            && let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&json)
            && let Some(files) = manifest.get("files").and_then(|files| files.as_array())
        {
            for file in files {
                if file.get("filename").and_then(|name| name.as_str()) == Some(ARCHIVE_NAME)
                    && let Some(size) = file.get("size").and_then(|size| size.as_u64())
                {
                    total.store(size, Ordering::SeqCst);
                }
            }
        }

        let (pipe_reader, pipe_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let fetch_task = {
            let progress = Arc::clone(&progress);
            async move {
                let mut pipe_writer = pipe_writer;
                reader
                    .reassemble_archive(&mut pipe_writer, Some(progress))
                    .await?;
                pipe_writer.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            }
        };

        let extract_task = {
            let server = server.clone();
            async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = SyncIoBridge::new(pipe_reader);
                    let reader = LimitedReader::new_with_bytes_per_second(
                        reader,
                        server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .read_limit
                            .as_bytes(),
                    );
                    let reader =
                        std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

                    let mut archive = tar::Archive::new(reader);
                    let mut directory_entries = Vec::new();
                    let entries = archive.entries()?;

                    let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
                    for entry in entries {
                        let mut entry = entry?;
                        let path = entry.path()?.to_path_buf();

                        if path.is_absolute() {
                            continue;
                        }

                        let header = entry.header().clone();
                        match header.entry_type() {
                            tar::EntryType::Directory => {
                                server.filesystem.create_chowned_dir_all(path.as_path())?;
                                server.filesystem.set_permissions(
                                    path.as_path(),
                                    PortablePermissions::from_mode(header.mode().unwrap_or(0o755)),
                                )?;

                                if let Ok(modified_time) = header.mtime() {
                                    directory_entries.push((path.clone(), modified_time));
                                }
                            }
                            tar::EntryType::Regular => {
                                server.log_daemon(compact_str::format_compact!(
                                    "(restoring): {}",
                                    path.display()
                                ));

                                if let Some(parent) = path.parent() {
                                    server.filesystem.create_chowned_dir_all(parent)?;
                                }

                                let mut writer = ServerFile::new(
                                    server.clone(),
                                    &path,
                                    Some(PortablePermissions::from_mode(
                                        header.mode().unwrap_or(0o644),
                                    )),
                                    header
                                        .mtime()
                                        .map(|t| {
                                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(t)
                                        })
                                        .ok(),
                                )?;

                                copy_shared(&mut read_buffer, &mut entry, &mut writer)?;
                                writer.flush()?;
                            }
                            tar::EntryType::Symlink => {
                                let link =
                                    entry.link_name().unwrap_or_default().unwrap_or_default();

                                if let Err(err) = server.filesystem.symlink(link, path.as_path()) {
                                    tracing::debug!(path = %path.display(), "failed to create symlink from PBS backup: {:?}", err);
                                } else if let Ok(modified_time) = header.mtime() {
                                    server.filesystem.set_times(
                                        path.as_path(),
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
                .await?
            }
        };

        tokio::try_join!(fetch_task, extract_task)?;

        server.filesystem.rerun_disk_checker().await;

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        if !naming::is_calagopus_id(self.config.id_prefix(), &self.backup_id) {
            return Err(anyhow::anyhow!(
                "refusing to delete PBS snapshot with non-Calagopus backup-id '{}'",
                self.backup_id
            ));
        }

        let client = PbsClient::new(self.config.clone())?;
        client
            .delete_snapshot(naming::BACKUP_TYPE, &self.backup_id, self.backup_time)
            .await?;

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
impl BackupCleanExt for PbsBackup {
    async fn clean(
        _server: &crate::server::Server,
        _uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
