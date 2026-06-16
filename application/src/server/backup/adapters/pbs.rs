use crate::{
    io::{
        compression::{CompressionType, writer::CompressionWriter},
        copy_shared,
        limited_reader::LimitedReader,
        limited_writer::LimitedWriter,
    },
    models::DirectoryEntry,
    remote::backups::{PbsBackupConfiguration, RawServerBackup},
    response::ApiResponse,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::{
                StreamableArchiveFormat,
                create::{CreateTarOptions, create_tar},
            },
            cap::CapFilesystem,
            file::ServerFile,
            virtualfs::{
                AsyncFileRead, ByteRange, DirectoryListing, DirectoryStreamWalk, DirectoryWalk,
                FileMetadata, FileRead, IsIgnoredFn, VirtualReadableFilesystem,
                cap::VirtualCapFilesystem,
            },
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

        let (tar_reader, tar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
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

                let file = create_tar(
                    server.filesystem.clone(),
                    SyncIoBridge::new(tar_writer),
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

                file.into_inner().shutdown().await?;

                Ok::<_, anyhow::Error>(())
            }
        };

        let pxar_task = {
            let server = server.clone();

            async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let mut writer = LimitedWriter::new_with_bytes_per_second(
                        SyncIoBridge::new(archive_writer),
                        server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .write_limit
                            .as_bytes(),
                    );

                    pbs_client::pxar_archive::tar_to_pxar(SyncIoBridge::new(tar_reader), &mut writer)?;
                    writer.flush()?;
                    writer.into_inner().shutdown()?;

                    Ok(())
                })
                .await?
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

        let (total_files, _, _, (size, checksum)) =
            tokio::try_join!(total_task, archive_task, pxar_task, pbs_task)?;

        Ok(RawServerBackup {
            checksum,
            checksum_type: "sha256".into(),
            size,
            files: total_files,
            successful: true,
            browsable: true,
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

        let (pxar_reader, pxar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (tar_reader, tar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (out_reader, out_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        tokio::spawn(async move {
            let mut pxar_writer = pxar_writer;
            if let Err(err) = reader.reassemble_archive(&mut pxar_writer, None).await {
                tracing::error!("failed to reassemble PBS archive for download: {:?}", err);
            }
            let _ = pxar_writer.shutdown().await;
        });

        crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
            let mut tar_writer = SyncIoBridge::new(tar_writer);
            pbs_client::pxar_archive::pxar_to_tar(SyncIoBridge::new(pxar_reader), &mut tar_writer)?;
            tar_writer.shutdown()?;

            Ok(())
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

        let (pxar_reader, pxar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (tar_reader, tar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let fetch_task = {
            let progress = Arc::clone(&progress);
            async move {
                let mut pxar_writer = pxar_writer;
                reader
                    .reassemble_archive(&mut pxar_writer, Some(progress))
                    .await?;
                pxar_writer.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            }
        };

        let pxar_task = async move {
            tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                let mut tar_writer = SyncIoBridge::new(tar_writer);
                pbs_client::pxar_archive::pxar_to_tar(SyncIoBridge::new(pxar_reader), &mut tar_writer)?;
                tar_writer.shutdown()?;
                Ok(())
            })
            .await?
        };

        let extract_task = {
            let server = server.clone();
            async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = SyncIoBridge::new(tar_reader);
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

        tokio::try_join!(fetch_task, pxar_task, extract_task)?;

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
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        let reader =
            PbsBackupReader::connect(&self.config, &self.backup_id, self.backup_time).await?;

        let temp_dir = std::env::temp_dir().join(format!("calagopus-pbs-browse-{}", self.uuid));
        tokio::fs::remove_dir_all(&temp_dir).await.ok();
        tokio::fs::create_dir_all(&temp_dir).await?;
        let guard = BrowseTempDir(temp_dir.clone());

        let (pxar_reader, pxar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (tar_reader, tar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let fetch_task = async move {
            let mut pxar_writer = pxar_writer;
            reader.reassemble_archive(&mut pxar_writer, None).await?;
            pxar_writer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };

        let pxar_task = async move {
            tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                let mut tar_writer = SyncIoBridge::new(tar_writer);
                pbs_client::pxar_archive::pxar_to_tar(SyncIoBridge::new(pxar_reader), &mut tar_writer)?;
                tar_writer.shutdown()?;

                Ok(())
            })
            .await?
        };

        let extract_task = {
            let temp_dir = temp_dir.clone();

            async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    tar::Archive::new(SyncIoBridge::new(tar_reader)).unpack(&temp_dir)?;

                    Ok(())
                })
                .await?
            }
        };

        tokio::try_join!(fetch_task, pxar_task, extract_task)?;

        let inner = CapFilesystem::new(temp_dir).await?.get_virtual(server.clone());

        Ok(Arc::new(ExtractedBackup {
            inner,
            _guard: guard,
        }))
    }
}

/// Removes the backup's extracted temp directory once the cached browse
/// filesystem is dropped (covers both explicit invalidation and TTL eviction,
/// the latter of which never calls `close`).
struct BrowseTempDir(std::path::PathBuf);

impl Drop for BrowseTempDir {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.0)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.0.display(), "failed to remove PBS browse temp dir: {:?}", err);
        }
    }
}

/// A PBS snapshot extracted to a temp directory and served through the standard
/// directory-backed virtual filesystem.
struct ExtractedBackup {
    inner: VirtualCapFilesystem,
    _guard: BrowseTempDir,
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for ExtractedBackup {
    fn is_fast(&self) -> bool {
        self.inner.is_fast()
    }

    fn backing_server(&self) -> &crate::server::Server {
        self.inner.backing_server()
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.inner.metadata(path)
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.inner.async_metadata(path).await
    }

    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.inner.symlink_metadata(path)
    }
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.inner.async_symlink_metadata(path).await
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        self.inner.async_directory_entry(path).await
    }
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        self.inner.async_directory_entry_buffer(path, buffer).await
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        self.inner
            .async_read_dir(path, per_page, page, is_ignored, sort)
            .await
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        self.inner.async_walk_dir(path, is_ignored).await
    }
    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        self.inner.async_walk_dir_stream(path, is_ignored).await
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        self.inner.read_file(path, range)
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        self.inner.async_read_file(path, range).await
    }
    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<std::path::PathBuf, anyhow::Error> {
        self.inner.read_symlink(path)
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<std::path::PathBuf, anyhow::Error> {
        self.inner.async_read_symlink(path).await
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: crate::io::compression::CompressionLevel,
        bytes_archived: Option<Arc<AtomicU64>>,
        is_ignored: IsIgnoredFn,
    ) -> Result<tokio::io::ReadHalf<tokio::io::SimplexStream>, anyhow::Error> {
        self.inner
            .async_read_dir_archive(
                path,
                archive_format,
                compression_level,
                bytes_archived,
                is_ignored,
            )
            .await
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        self.inner.close().await
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
