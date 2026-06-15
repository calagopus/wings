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

pub struct BtrfsBackup {
    uuid: uuid::Uuid,
}

pub struct BtrfsSendStream {
    pub stdout: tokio::process::ChildStdout,
    pub snapshot_path: PathBuf,
    pub send_dir: PathBuf,
}

impl BtrfsBackup {
    #[inline]
    pub fn get_backup_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Path::new(&config.load().system.backup_directory)
            .join("btrfs")
            .join(uuid.to_string())
    }

    #[inline]
    pub fn get_subvolume_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Self::get_backup_path(config, uuid).join("subvolume")
    }

    #[inline]
    pub fn get_ignore_path(config: &crate::config::Config, uuid: uuid::Uuid) -> PathBuf {
        Self::get_backup_path(config, uuid).join("ignored")
    }

    pub async fn open_send_stream(
        &self,
        state: &crate::routes::State,
        parent: Option<&Path>,
    ) -> Result<BtrfsSendStream, anyhow::Error> {
        let subvolume_path = Self::get_subvolume_path(&state.config, self.uuid);

        if tokio::fs::metadata(&subvolume_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "btrfs backup subvolume does not exist: {}",
                subvolume_path.display()
            ));
        }

        let send_dir = Self::get_backup_path(&state.config, self.uuid)
            .join(format!(".send-{}", uuid::Uuid::new_v4()));
        let send_path = send_dir.join("subvolume");

        tokio::fs::create_dir_all(&send_dir).await?;

        let output = Command::new("btrfs")
            .args(["subvolume", "snapshot", "-r"])
            .arg(&subvolume_path)
            .arg(&send_path)
            .output()
            .await?;

        if !output.status.success() {
            tokio::fs::remove_dir_all(&send_dir).await.ok();

            return Err(anyhow::anyhow!(
                "failed to create read-only snapshot for btrfs send: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut command = Command::new("btrfs");
        command.arg("send");
        if let Some(parent) = parent {
            command.arg("-p").arg(parent);
        }

        let mut child = command
            .arg(&send_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture btrfs send stdout"))?;

        tokio::spawn(async move {
            match child.wait_with_output().await {
                Ok(output) if !output.status.success() => {
                    tracing::error!(
                        "btrfs send failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Err(err) => tracing::error!("failed to wait for btrfs send: {err}"),
                _ => {}
            }
        });

        Ok(BtrfsSendStream {
            stdout,
            snapshot_path: send_path,
            send_dir,
        })
    }

    pub async fn cleanup_stale_btrfs_send_snapshots(config: &crate::config::Config) {
        let btrfs_dir = Path::new(&config.load().system.backup_directory).join("btrfs");

        let mut backups = match tokio::fs::read_dir(&btrfs_dir).await {
            Ok(backups) => backups,
            Err(_) => return,
        };

        while let Ok(Some(backup)) = backups.next_entry().await {
            let mut entries = match tokio::fs::read_dir(backup.path()).await {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();

                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".send-"))
                {
                    tracing::warn!("removing stale btrfs send snapshot {}", path.display());
                    Self::cleanup_send_dir(&path).await;
                }
            }
        }
    }

    pub fn filesystem_mount_point(path: &Path) -> Option<PathBuf> {
        let target = std::fs::canonicalize(path).ok()?;
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;

        let mut best: Option<PathBuf> = None;
        for line in mountinfo.lines() {
            if let Some(mount_point) = line.split(' ').nth(4) {
                let mount_point = PathBuf::from(mount_point);

                if target.starts_with(&mount_point)
                    && best
                        .as_ref()
                        .is_none_or(|best| mount_point.as_os_str().len() > best.as_os_str().len())
                {
                    best = Some(mount_point);
                }
            }
        }

        best
    }

    pub async fn cleanup_send_dir(send_dir: &Path) {
        let send_path = send_dir.join("subvolume");

        if tokio::fs::metadata(&send_path).await.is_ok() {
            let output = Command::new("btrfs")
                .args(["subvolume", "delete"])
                .arg(&send_path)
                .output()
                .await;
            if let Ok(output) = output
                && !output.status.success()
            {
                tracing::warn!(
                    "failed to delete temporary btrfs send snapshot {}: {}",
                    send_path.display(),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        tokio::fs::remove_dir_all(send_dir).await.ok();
    }

    pub async fn open_archive_stream(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        compression_level: crate::io::compression::CompressionLevel,
    ) -> Result<tokio::io::ReadHalf<tokio::io::SimplexStream>, anyhow::Error> {
        let subvolume_path = Self::get_subvolume_path(&state.config, self.uuid);

        if tokio::fs::metadata(&subvolume_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "btrfs backup subvolume does not exist: {}",
                subvolume_path.display()
            ));
        }

        let filesystem = crate::server::filesystem::cap::CapFilesystem::new(subvolume_path).await?;
        let names = filesystem.async_read_dir_all(Path::new("")).await?;
        let ignore = Self::get_ignore(&state.config, self.uuid).await?;
        let threads = state.config.load().api.file_compression_threads;

        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        tokio::spawn(async move {
            let writer = tokio_util::io::SyncIoBridge::new(writer);

            let result = match archive_format {
                StreamableArchiveFormat::Zip => {
                    crate::server::filesystem::archive::create::create_zip_streaming(
                        filesystem,
                        writer,
                        Path::new(""),
                        names,
                        None,
                        ignore.into(),
                        crate::server::filesystem::archive::create::CreateZipOptions {
                            compression_level,
                        },
                    )
                    .await
                    .map(|inner| inner.into_inner())
                }
                f if f.is_itaf() => crate::server::filesystem::archive::create::create_itaf(
                    filesystem,
                    writer,
                    Path::new(""),
                    names,
                    None,
                    ignore.into(),
                    crate::server::filesystem::archive::create::CreateItafOptions {
                        compression_type: f.compression_format(),
                        compression_level,
                        threads,
                        crc_enabled: true,
                    },
                )
                .await
                .map(|inner| inner.into_inner()),
                f => crate::server::filesystem::archive::create::create_tar(
                    filesystem,
                    writer,
                    Path::new(""),
                    names,
                    None,
                    ignore.into(),
                    crate::server::filesystem::archive::create::CreateTarOptions {
                        compression_type: f.compression_format(),
                        compression_level,
                        threads,
                    },
                )
                .await
                .map(|inner| inner.into_inner()),
            };

            match result {
                Ok(mut inner) => {
                    inner.shutdown().await.ok();
                }
                Err(err) => {
                    tracing::error!("failed to create archive for btrfs backup: {err}");
                }
            }
        });

        Ok(reader)
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
}

#[async_trait::async_trait]
impl BackupFindExt for BtrfsBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        let path = Self::get_backup_path(&state.config, uuid);
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        if Self::exists(state, uuid).await? {
            Ok(Some(Backup::Btrfs(Self { uuid })))
        } else {
            Ok(None)
        }
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for BtrfsBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        _progress: Arc<AtomicU64>,
        _total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let subvolume_path = Self::get_subvolume_path(&server.app_state.config, uuid);
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

        let snapshot_task = async {
            let output = Command::new("btrfs")
                .arg("subvolume")
                .arg("snapshot")
                .args(
                    if server
                        .app_state
                        .config
                        .load()
                        .system
                        .backups
                        .btrfs
                        .create_read_only
                    {
                        &["-r"]
                    } else {
                        &[] as &[&str]
                    },
                )
                .arg(&server.filesystem.base_path)
                .arg(&subvolume_path)
                .output()
                .await?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to create Btrfs subvolume snapshot for {}: {}",
                    server.filesystem.base_path.display(),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            let output = Command::new("btrfs")
                .arg("subvolume")
                .arg("show")
                .arg(&subvolume_path)
                .output()
                .await?;

            let mut generation = None;
            let mut uuid = None;
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let mut whitespace = line.split_whitespace();

                    if let Some(label) = whitespace.next() {
                        match label {
                            "Generation:" => {
                                if let Some(parsed_generation) = whitespace.next() {
                                    if let Ok(parsed_generation) = parsed_generation.parse::<u64>()
                                    {
                                        generation = Some(parsed_generation);
                                    }

                                    break;
                                }
                            }
                            "UUID:" => {
                                if let Some(parsed_uuid) = whitespace.next()
                                    && let Ok(parsed_uuid) = uuid::Uuid::parse_str(parsed_uuid)
                                {
                                    uuid = Some(parsed_uuid);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            tokio::fs::write(&ignored_path, ignore_raw).await?;

            Ok::<_, anyhow::Error>((generation, uuid))
        };

        let ((total_size, total_files), (generation, uuid)) =
            tokio::try_join!(total_task, snapshot_task)?;

        Ok(RawServerBackup {
            checksum: format!(
                "{}-{}",
                generation.unwrap_or_default(),
                uuid.unwrap_or_default()
            ),
            checksum_type: "btrfs-subvolume".into(),
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
impl BackupExt for BtrfsBackup {
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
            .open_archive_stream(
                state,
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
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let subvolume_path = Self::get_subvolume_path(&server.app_state.config, self.uuid);

        if tokio::fs::metadata(&subvolume_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "btrfs backup subvolume does not exist: {}",
                subvolume_path.display()
            ));
        }

        let filesystem = crate::server::filesystem::cap::CapFilesystem::new(subvolume_path).await?;
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
                    server.app_state.config.load().system.backups.btrfs.restore_threads,
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
                                        .async_set_permissions(&path, metadata.permissions().into())
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
        let subvolume_path = Self::get_subvolume_path(&state.config, self.uuid);

        if tokio::fs::metadata(&subvolume_path).await.is_err() {
            return Ok(());
        }

        let output = Command::new("btrfs")
            .arg("qgroup")
            .arg("show")
            .arg(&subvolume_path)
            .output()
            .await?;

        if output.status.success() {
            let uuid_str = self.uuid.to_string();
            let output_str = String::from_utf8_lossy(&output.stdout);

            for line in output_str.lines() {
                if line.ends_with(&uuid_str)
                    && let Some(qgroup_id) = line.split_whitespace().next()
                {
                    let output = Command::new("btrfs")
                        .arg("qgroup")
                        .arg("destroy")
                        .arg(qgroup_id)
                        .arg(&subvolume_path)
                        .output()
                        .await?;

                    if !output.status.success() {
                        tracing::warn!(
                            "failed to destroy btrfs qgroup: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }
        }

        let output = Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(&subvolume_path)
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to delete btrfs subvolume: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

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
        let subvolume_path = Self::get_subvolume_path(&server.app_state.config, self.uuid);

        if tokio::fs::metadata(&subvolume_path).await.is_err() {
            return Err(anyhow::anyhow!(
                "btrfs backup subvolume does not exist: {}",
                subvolume_path.display()
            ));
        }

        let filesystem = crate::server::filesystem::cap::CapFilesystem::new(subvolume_path).await?;
        let ignore = Self::get_ignore(&server.app_state.config, self.uuid).await?;

        Ok(Arc::new(
            filesystem
                .get_virtual(server.clone())
                .with_is_ignored(ignore.into()),
        ))
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for BtrfsBackup {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let subvolume_path = Self::get_subvolume_path(&server.app_state.config, uuid);

        if tokio::fs::metadata(&subvolume_path).await.is_err() {
            return Ok(());
        }

        let output = Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(&subvolume_path)
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to delete btrfs subvolume: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }
}
