use crate::{
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::StreamableArchiveFormat,
            virtualfs::{ByteRange, VirtualReadableFilesystem},
        },
    },
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{io::AsyncWriteExt, process::Command};

pub struct ZfsBackup {
    server_uuid: uuid::Uuid,
    uuid: uuid::Uuid,
}

impl ZfsBackup {
    #[inline]
    fn get_backup_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Path::new(&config.system.backup_directory)
            .join("zfs")
            .join(uuid.to_string())
    }

    #[inline]
    fn get_snapshot_name(uuid: uuid::Uuid) -> String {
        format!("backup-{uuid}")
    }

    #[inline]
    pub fn get_snapshot_path(
        config: &crate::config::Config,
        server_uuid: uuid::Uuid,
        uuid: uuid::Uuid,
    ) -> PathBuf {
        Path::new(&config.system.data_directory)
            .join(server_uuid.to_string())
            .join(".zfs")
            .join("snapshot")
            .join(Self::get_snapshot_name(uuid))
    }

    #[inline]
    pub fn get_dataset_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Self::get_backup_path(config, uuid).join("dataset")
    }

    #[inline]
    pub fn get_ignore_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Self::get_backup_path(config, uuid).join("ignored")
    }

    pub async fn get_ignore(
        config: &crate::config::Config,
        uuid: uuid::Uuid,
    ) -> Result<ignore::gitignore::Gitignore, anyhow::Error> {
        let ignored_path = Self::get_ignore_path(config, uuid);
        let mut ignore_builder = ignore::gitignore::GitignoreBuilder::new("");

        if let Ok(ignore_content) = tokio::fs::read_to_string(&ignored_path).await {
            for line in ignore_content.lines() {
                ignore_builder.add_line(None, line).ok();
            }
        }

        Ok(ignore_builder.build()?)
    }

    async fn destroy_snapshot(target: &str) -> Result<(), anyhow::Error> {
        let backoffs_ms = [100u64, 200, 400, 800, 1600, 3200];

        for backoff_ms in backoffs_ms {
            let output = Command::new("zfs")
                .arg("destroy")
                .arg("-f")
                .arg(target)
                .env("LC_ALL", "C")
                .output()
                .await?;

            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            if stderr.contains("could not find any snapshots to destroy") {
                return Ok(());
            }

            if !stderr.contains("dataset is busy") {
                return Err(anyhow::anyhow!("failed to delete zfs snapshot: {}", stderr));
            }

            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
        }

        // Deferred destroy so the user-visible delete completes even if a kernel reference lingers.
        let output = Command::new("zfs")
            .arg("destroy")
            .arg("-d")
            .arg(target)
            .env("LC_ALL", "C")
            .output()
            .await?;

        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && !stderr.contains("could not find any snapshots to destroy") {
            return Err(anyhow::anyhow!("failed to delete zfs snapshot: {}", stderr));
        }

        tracing::warn!(
            snapshot = %target,
            "zfs snapshot still busy after retries; marked for deferred destroy"
        );

        Ok(())
    }
}

#[async_trait::async_trait]
impl BackupFindExt for ZfsBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        let path = Self::get_backup_path(&state.config, uuid);
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        if Self::exists(state, uuid).await? {
            let dataset_path = Self::get_dataset_path(&state.config, uuid);
            let dataset = tokio::fs::read_to_string(&dataset_path).await?;
            let server_uuid = dataset
                .split_once("server-")
                .map(|(_, uuid)| uuid::Uuid::parse_str(uuid.trim()))
                .ok_or_else(|| anyhow::anyhow!("failed to parse dataset name: {}", dataset))??;

            Ok(Some(Backup::Zfs(Self { server_uuid, uuid })))
        } else {
            Ok(None)
        }
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for ZfsBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        _progress: Arc<AtomicU64>,
        _total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let backup_path = Self::get_backup_path(&server.app_state.config, uuid);
        let snapshot_name = Self::get_snapshot_name(uuid);
        let ignored_path = Self::get_ignore_path(&server.app_state.config, uuid);

        tokio::fs::create_dir_all(Self::get_backup_path(&server.app_state.config, uuid)).await?;

        let total_task = {
            let server = server.clone();
            let ignore = ignore.clone();

            async move {
                let mut walker = server
                    .filesystem
                    .async_walk_dir(&PathBuf::from(""))
                    .await?
                    .with_is_ignored(ignore.into());
                let mut total_size = 0;
                let mut total_files = 0;
                while let Some(Ok((_, path))) = walker.next_entry().await {
                    let metadata = match server.filesystem.async_symlink_metadata(&path).await {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };

                    total_size += metadata.len();
                    if !metadata.is_dir() {
                        total_files += 1;
                    }
                }

                Ok::<_, anyhow::Error>((total_size, total_files))
            }
        };

        let dataset_task = async {
            let output = Command::new("zfs")
                .arg("list")
                .arg("-o")
                .arg("name")
                .arg("-H")
                .arg(&server.filesystem.base_path)
                .output()
                .await?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to get ZFS dataset name for {}: {}",
                    server.filesystem.base_path.display(),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            let dataset_name = String::from_utf8_lossy(&output.stdout).trim().to_string();

            tokio::fs::write(&ignored_path, ignore_raw).await?;
            tokio::fs::write(backup_path.join("dataset"), &dataset_name).await?;

            let output = Command::new("zfs")
                .arg("snapshot")
                .arg(format!("{dataset_name}@{snapshot_name}"))
                .output()
                .await?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to create ZFS snapshot for {}: {}",
                    server.filesystem.base_path.display(),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            Ok::<_, anyhow::Error>(dataset_name)
        };

        let ((total_size, total_files), dataset_name) = tokio::try_join!(total_task, dataset_task)?;

        Ok(RawServerBackup {
            checksum: dataset_name,
            checksum_type: "zfs-snapshot".into(),
            size: total_size,
            files: total_files,
            successful: true,
            browsable: true,
            streaming: true,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for ZfsBackup {
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
        let snapshot_path = Self::get_snapshot_path(&state.config, self.server_uuid, self.uuid);

        if tokio::fs::metadata(&snapshot_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "zfs backup snapshot does not exist: {}",
                snapshot_path.display()
            ));
        }

        let filesystem = crate::server::filesystem::cap::CapFilesystem::new(snapshot_path).await?;
        let names = filesystem.async_read_dir_all(Path::new("")).await?;
        let ignore = Self::get_ignore(&state.config, self.uuid).await?;

        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        tokio::spawn({
            let config = Arc::clone(&state.config);

            async move {
                let writer = tokio_util::io::SyncIoBridge::new(writer);

                match archive_format {
                    StreamableArchiveFormat::Zip => {
                        match crate::server::filesystem::archive::create::create_zip_streaming(
                            filesystem,
                            writer,
                            Path::new(""),
                            names,
                            None,
                            ignore.into(),
                            crate::server::filesystem::archive::create::CreateZipOptions {
                                compression_level: config.system.backups.compression_level,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create zip archive for zfs backup: {}",
                                    err
                                );
                            }
                        }
                    }
                    _ => {
                        match crate::server::filesystem::archive::create::create_tar(
                            filesystem,
                            writer,
                            Path::new(""),
                            names,
                            None,
                            ignore.into(),
                            crate::server::filesystem::archive::create::CreateTarOptions {
                                compression_type: archive_format.compression_format(),
                                compression_level: config.system.backups.compression_level,
                                threads: config.api.file_compression_threads,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create tar archive for zfs backup: {}",
                                    err
                                );
                            }
                        }
                    }
                }
            }
        });

        Ok(ApiResponse::new_stream(reader)
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
        let snapshot_path =
            Self::get_snapshot_path(&server.app_state.config, self.server_uuid, self.uuid);

        if tokio::fs::metadata(&snapshot_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "zfs backup snapshot does not exist: {}",
                snapshot_path.display()
            ));
        }

        let filesystem = crate::server::filesystem::cap::CapFilesystem::new(snapshot_path).await?;
        let ignore = Self::get_ignore(&server.app_state.config, self.uuid).await?;

        let total_task = {
            let filesystem = filesystem.clone();
            let ignore = ignore.clone();

            async move {
                let mut walker = filesystem
                    .async_walk_dir(&PathBuf::from(""))
                    .await?
                    .with_is_ignored(ignore.into());
                while let Some(Ok((_, path))) = walker.next_entry().await {
                    let metadata = match filesystem.async_symlink_metadata(&path).await {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };

                    total.fetch_add(metadata.len(), Ordering::Relaxed);
                }

                Ok::<(), anyhow::Error>(())
            }
        };

        let server = server.clone();
        let restore_task = async move {
            filesystem
                .async_walk_dir(Path::new(""))
                .await?
                .with_is_ignored(ignore.into())
                .run_multithreaded(
                    server.app_state.config.system.backups.zfs.restore_threads,
                    Arc::new({
                        let server = server.clone();
                        let filesystem = filesystem.clone();
                        let progress = Arc::clone(&progress);

                        move |_, path: PathBuf| {
                            let server = server.clone();
                            let filesystem = filesystem.clone();
                            let progress = Arc::clone(&progress);

                            async move {
                                let metadata =
                                    match filesystem.async_symlink_metadata(&path).await {
                                        Ok(metadata) => metadata,
                                        Err(_) => return Ok(()),
                                    };

                                if metadata.is_file() {
                                    server.log_daemon(compact_str::format_compact!("(restoring): {}", path.display()));

                                    if let Some(parent) = path.parent() {
                                        server.filesystem.async_create_dir_all(parent).await?;
                                    }

                                    filesystem.async_quota_copy(&path, &path, &server, Some(&progress)).await?;
                                } else if metadata.is_dir() {
                                    server.filesystem.async_create_dir_all(&path).await?;
                                    server
                                        .filesystem
                                        .async_set_permissions(&path, metadata.permissions())
                                        .await?;
                                    if let Ok(modified_time) = metadata.modified() {
                                        server.filesystem.async_set_times(
                                            &path,
                                            modified_time.into_std(),
                                            None,
                                        ).await?;
                                    }
                                } else if metadata.is_symlink() && let Ok(target) = filesystem.async_read_link(&path).await {
                                    if let Err(err) = server.filesystem.async_symlink(&target, &path).await {
                                        tracing::debug!(path = %path.display(), "failed to create symlink from backup: {:?}", err);
                                    } else if let Ok(modified_time) = metadata.modified() {
                                        server.filesystem.async_set_times(
                                            &path,
                                            modified_time.into_std(),
                                            None,
                                        ).await?;
                                    }
                                }

                                Ok(())
                            }
                        }
                    }),
                ).await?;

            Ok::<(), anyhow::Error>(())
        };

        let (_, _) = tokio::try_join!(total_task, restore_task)?;

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        let backup_path = Self::get_backup_path(&state.config, self.uuid);
        let dataset_path = Self::get_dataset_path(&state.config, self.uuid);
        let snapshot_name = Self::get_snapshot_name(self.uuid);

        if tokio::fs::metadata(&backup_path).await.is_err() {
            return Ok(());
        }

        state
            .backup_manager
            .invalidate_cached_browse(self.uuid)
            .await;

        if let Ok(dataset_name) = tokio::fs::read_to_string(dataset_path).await {
            Self::destroy_snapshot(&format!("{}@{}", dataset_name.trim(), snapshot_name)).await?;
        }

        tokio::fs::remove_dir_all(backup_path).await?;

        Ok(())
    }

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        let snapshot_path =
            Self::get_snapshot_path(&server.app_state.config, self.server_uuid, self.uuid);

        if tokio::fs::metadata(&snapshot_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "zfs backup snapshot does not exist: {}",
                snapshot_path.display()
            ));
        }

        let filesystem = crate::server::filesystem::cap::CapFilesystem::new(snapshot_path).await?;
        let ignore = Self::get_ignore(&server.app_state.config, self.uuid).await?;

        Ok(Arc::new(
            filesystem
                .get_virtual(server.clone())
                .with_is_ignored(ignore.into()),
        ))
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for ZfsBackup {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let backup_path = Self::get_backup_path(&server.app_state.config, uuid);
        let dataset_path = Self::get_dataset_path(&server.app_state.config, uuid);
        let snapshot_name = Self::get_snapshot_name(uuid);

        if tokio::fs::metadata(&backup_path).await.is_err() {
            return Ok(());
        }

        server
            .app_state
            .backup_manager
            .invalidate_cached_browse(uuid)
            .await;

        if let Ok(dataset_name) = tokio::fs::read_to_string(dataset_path).await {
            Self::destroy_snapshot(&format!("{}@{}", dataset_name.trim(), snapshot_name)).await?;
        }

        tokio::fs::remove_dir_all(backup_path).await?;

        Ok(())
    }
}
