use super::snapshot_dir::SnapshotDir;
use crate::{
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::{
        backup::{
            Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt, BackupStream,
            BackupStreamCreateExt, BackupStreamExt, BackupTestExt, DumpSource,
        },
        filesystem::{
            archive::StreamableArchiveFormat,
            virtualfs::{ByteRange, VirtualReadableFilesystem},
        },
    },
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
};
use tokio::process::Command;

pub struct ZfsBackup {
    server_uuid: uuid::Uuid,
    uuid: uuid::Uuid,
}

impl ZfsBackup {
    #[inline]
    fn get_backup_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        config
            .resolve_as_path(|cfg| &cfg.system.backup_directory)
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
        config
            .data_path(server_uuid)
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

    fn snapshot_dir(&self, config: &crate::config::Config) -> SnapshotDir {
        SnapshotDir {
            root: Self::get_snapshot_path(config, self.server_uuid, self.uuid),
            ignore_path: Self::get_ignore_path(config, self.uuid),
            what: "zfs backup snapshot",
        }
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
    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        if tokio::fs::metadata(Self::get_backup_path(&state.config, uuid))
            .await
            .is_ok()
        {
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
        _progress: crate::server::filesystem::archive::create::ArchiveProgress,
        _total: Arc<AtomicU64>,
        ignore: crate::server::filesystem::ignore_list::IgnoreList,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let backup_path = Self::get_backup_path(&server.app_state.config, uuid);
        let snapshot_name = Self::get_snapshot_name(uuid);
        let ignored_path = Self::get_ignore_path(&server.app_state.config, uuid);

        tokio::fs::create_dir_all(Self::get_backup_path(&server.app_state.config, uuid)).await?;

        let total_task = {
            let filesystem = server.filesystem.clone();
            let ignore = ignore.clone();

            async move {
                tokio::task::spawn_blocking(move || {
                    let mut walker = filesystem
                        .walk_dir(Path::new(""))?
                        .with_is_ignored(ignore.into());
                    let mut total_size = 0;
                    let mut total_files = 0;
                    while let Some(Ok(entry)) = walker.next_entry() {
                        let metadata = match entry.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => continue,
                        };

                        total_size += metadata.len();
                        if !metadata.is_dir() {
                            total_files += 1;
                        }
                    }

                    Ok::<_, anyhow::Error>((total_size, total_files))
                })
                .await?
            }
        };

        let dataset_task = async {
            let output = Command::new("zfs")
                .arg("list")
                .arg("-o")
                .arg("name,mountpoint")
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

            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut columns = stdout.trim().split('\t');
            let dataset_name = columns.next().unwrap_or_default().to_string();
            let mountpoint = columns.next().unwrap_or_default();

            if Path::new(mountpoint) != server.filesystem.base_path {
                return Err(anyhow::anyhow!(
                    "server volume {} is not its own ZFS dataset (found {} mounted at {}); \
                     enable the zfs_dataset disk limiter and migrate the server first",
                    server.filesystem.base_path.display(),
                    dataset_name,
                    mountpoint
                ));
            }

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
        let reader = self
            .snapshot_dir(&state.config)
            .archive_stream(
                &state.config,
                archive_format,
                state.config.load().system.backups.compression_level,
            )
            .await?;

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
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        self.snapshot_dir(&server.app_state.config)
            .restore(
                server,
                progress,
                total,
                server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .zfs
                    .restore_threads,
            )
            .await
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
        self.snapshot_dir(&server.app_state.config)
            .browse(server)
            .await
    }
}

#[async_trait::async_trait]
impl BackupStreamCreateExt for ZfsBackup {
    async fn create_from_stream(
        _state: &crate::routes::State,
        _uuid: uuid::Uuid,
        _extension: &str,
        _compression: crate::io::compression::CompressionType,
        _source: DumpSource,
    ) -> Result<RawServerBackup, anyhow::Error> {
        Err(anyhow::anyhow!(
            "zfs backups snapshot the server dataset and cannot store database dumps"
        ))
    }
}

#[async_trait::async_trait]
impl BackupStreamExt for ZfsBackup {
    async fn read_stream(
        &self,
        _state: &crate::routes::State,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<BackupStream, anyhow::Error> {
        Err(anyhow::anyhow!("zfs backups do not store database dumps"))
    }
}

#[async_trait::async_trait]
impl BackupTestExt for ZfsBackup {
    type Configuration = ();

    async fn test(
        state: &crate::routes::State,
        _configuration: Option<Self::Configuration>,
    ) -> Result<(), anyhow::Error> {
        super::probe_backup_directory(&state.config).await?;

        let mut command = Command::new("zfs");
        command.arg("list").arg("-H").arg("-o").arg("name").arg(
            state
                .config
                .resolve_as_path(|cfg| &cfg.system.data_directory),
        );

        super::probe_command(command).await
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
