use crate::{
    remote::backups::RawServerBackup,
    server::{backup::adapters::BackupAdapter, filesystem::virtualfs::VirtualReadableFilesystem},
};
use compact_str::ToCompactString;
use ignore::gitignore::GitignoreBuilder;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

pub struct BackupManager {
    cached_backups: moka::future::Cache<uuid::Uuid, Arc<super::Backup>>,
    cached_browse_backups: moka::future::Cache<uuid::Uuid, Arc<dyn VirtualReadableFilesystem>>,
    cached_browse_backup_locks: moka::future::Cache<uuid::Uuid, Arc<tokio::sync::Mutex<()>>>,
    cached_backup_adapters: moka::future::Cache<uuid::Uuid, BackupAdapter>,
}

impl Default for BackupManager {
    fn default() -> Self {
        Self {
            cached_backups: moka::future::CacheBuilder::new(128)
                .time_to_live(std::time::Duration::from_mins(10))
                .build(),
            cached_browse_backups: moka::future::CacheBuilder::new(64)
                .time_to_live(std::time::Duration::from_mins(5))
                .build(),
            cached_backup_adapters: moka::future::Cache::new(1024),
            cached_browse_backup_locks: moka::future::Cache::new(10240),
        }
    }
}

impl BackupManager {
    pub async fn fast_contains(&self, server: &crate::server::Server, uuid: uuid::Uuid) -> bool {
        self.cached_backups.contains_key(&uuid)
            || server.configuration.read().await.backups.contains(&uuid)
    }

    pub async fn adapter_contains(&self, state: &crate::routes::State, uuid: uuid::Uuid) -> bool {
        if let Some(adapter) = self.cached_backup_adapters.get(&uuid).await {
            match adapter.exists(state, uuid).await {
                Ok(exists) => exists,
                Err(err) => {
                    tracing::error!(adapter = ?adapter, "failed to check if backup {} exists: {:#?}", uuid, err);
                    false
                }
            }
        } else {
            match BackupAdapter::exists_any(state, uuid).await {
                Ok(exists) => exists,
                Err(err) => {
                    tracing::error!("failed to check if backup {} exists: {:#?}", uuid, err);
                    false
                }
            }
        }
    }

    pub async fn create(
        &self,
        adapter: BackupAdapter,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        ignore: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        tracing::info!(
            server = %server.uuid,
            backup = %uuid,
            adapter = ?adapter,
            "creating backup",
        );

        let mut ignore_builder = GitignoreBuilder::new("");
        let mut ignore_raw = compact_str::CompactString::default();

        for line in ignore.lines() {
            if ignore_builder.add_line(None, line).is_ok() {
                ignore_raw.push_str(line);
                ignore_raw.push('\n');
            }
        }

        if let Ok(pteroignore) = server
            .filesystem
            .async_read_to_string(".pteroignore", 1024 * 1024)
            .await
        {
            for line in pteroignore.lines() {
                if ignore_builder.add_line(None, line).is_ok() {
                    ignore_raw.push_str(line);
                    ignore_raw.push('\n');
                }
            }
        }

        for line in server.configuration.read().await.egg.file_denylist.iter() {
            if ignore_builder.add_line(None, line).is_ok() {
                ignore_raw.push_str(line);
                ignore_raw.push('\n');
            }
        }

        ignore_raw.shrink_to_fit();

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));

        let progress_task = tokio::spawn({
            let progress = Arc::clone(&progress);
            let total = Arc::clone(&total);
            let server = server.clone();

            async move {
                loop {
                    let progress = progress.load(Ordering::SeqCst);
                    let total = total.load(Ordering::SeqCst);

                    server
                        .websocket
                        .send(crate::server::websocket::WebsocketMessage::new(
                            crate::server::websocket::WebsocketEvent::ServerBackupProgress,
                            [
                                uuid.to_compact_string(),
                                serde_json::to_string(&crate::models::Progress { progress, total })
                                    .unwrap()
                                    .into(),
                            ]
                            .into(),
                        ))
                        .ok();

                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        });

        server
            .websocket
            .send(crate::server::websocket::WebsocketMessage::new(
                crate::server::websocket::WebsocketEvent::ServerBackupStarted,
                [uuid.to_compact_string()].into(),
            ))?;
        server
            .schedules
            .execute_backup_status_trigger(crate::models::ServerBackupStatus::Starting)
            .await;

        let backup = match adapter
            .create(
                server,
                uuid,
                Arc::clone(&progress),
                Arc::clone(&total),
                ignore_builder.build()?,
                ignore_raw,
            )
            .await
        {
            Ok(backup) => {
                progress_task.abort();

                backup
            }
            Err(err) => {
                progress_task.abort();

                if let Err(err) = adapter.clean(server, uuid).await {
                    tracing::error!(server = %server.uuid, adapter = ?adapter, "failed to clean up backup {} after error: {:#?}", uuid, err);
                }

                server
                    .schedules
                    .execute_backup_status_trigger(crate::models::ServerBackupStatus::Failed)
                    .await;
                server
                    .app_state
                    .config
                    .client
                    .set_backup_status(uuid, &RawServerBackup::default())
                    .await?;
                server
                    .websocket
                    .send(crate::server::websocket::WebsocketMessage::new(
                        crate::server::websocket::WebsocketEvent::ServerBackupCompleted,
                        [
                            uuid.to_compact_string(),
                            serde_json::json!({
                                "checksum_type": "",
                                "checksum": "",
                                "size": 0,
                                "files": 0,
                                "successful": false,
                                "browsable": false,
                                "streaming": false,
                            })
                            .to_compact_string(),
                        ]
                        .into(),
                    ))?;
                self.cached_backup_adapters.insert(uuid, adapter).await;

                return Err(err);
            }
        };

        server
            .schedules
            .execute_backup_status_trigger(crate::models::ServerBackupStatus::Finished)
            .await;
        server
            .app_state
            .config
            .client
            .set_backup_status(uuid, &backup)
            .await?;
        server
            .websocket
            .send(crate::server::websocket::WebsocketMessage::new(
                crate::server::websocket::WebsocketEvent::ServerBackupCompleted,
                [
                    uuid.to_compact_string(),
                    serde_json::json!({
                        "checksum_type": backup.checksum_type,
                        "checksum": backup.checksum,
                        "size": backup.size,
                        "files": backup.files,
                        "successful": backup.successful,
                        "browsable": backup.browsable,
                        "streaming": backup.streaming,
                    })
                    .to_compact_string(),
                ]
                .into(),
            ))?;
        server.configuration.write().await.backups.push(uuid);
        self.cached_backup_adapters.insert(uuid, adapter).await;

        tracing::info!(
            server = %server.uuid,
            adapter = ?adapter,
            "completed backup {}",
            uuid,
        );

        Ok(backup)
    }

    pub async fn restore(
        &self,
        backup: &super::Backup,
        server: &crate::server::Server,
        truncate_directory: bool,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        if server.is_locked_state() {
            return Err(anyhow::anyhow!("Server is in a locked state"));
        }

        server.restoring.store(true, Ordering::SeqCst);
        if let Err(err) = server
            .stop_with_kill_timeout(std::time::Duration::from_secs(30), false)
            .await
        {
            tracing::error!(
                server = %server.uuid,
                "failed to stop server before restoring backup: {:#?}",
                err
            );

            server.restoring.store(false, Ordering::SeqCst);
            server
                .app_state
                .config
                .client
                .set_backup_restore_status(server.uuid, backup.uuid(), false)
                .await?;

            return Err(err);
        }

        tracing::info!(
            server = %server.uuid,
            backup = %backup.uuid(),
            adapter = ?backup.adapter(),
            "restoring backup",
        );

        if truncate_directory && let Err(err) = server.filesystem.truncate_root().await {
            server.restoring.store(false, Ordering::SeqCst);
            server
                .app_state
                .config
                .client
                .set_backup_restore_status(server.uuid, backup.uuid(), false)
                .await?;

            return Err(err.context("failed to truncate root directory before restoring backup"));
        }

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(1));

        let progress_task = tokio::spawn({
            let progress = Arc::clone(&progress);
            let total = Arc::clone(&total);
            let server = server.clone();

            async move {
                loop {
                    let progress_value = progress.load(Ordering::SeqCst);
                    let total_value = total.load(Ordering::SeqCst);

                    server
                        .websocket
                        .send(crate::server::websocket::WebsocketMessage::new(
                            crate::server::websocket::WebsocketEvent::ServerBackupRestoreProgress,
                            [serde_json::to_string(&crate::models::Progress {
                                progress: progress_value,
                                total: total_value,
                            })
                            .unwrap()
                            .into()]
                            .into(),
                        ))
                        .ok();

                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        });

        server
            .websocket
            .send(crate::server::websocket::WebsocketMessage::new(
                crate::server::websocket::WebsocketEvent::ServerBackupRestoreStarted,
                [].into(),
            ))?;

        match backup
            .restore(
                server,
                Arc::clone(&progress),
                Arc::clone(&total),
                download_url,
            )
            .await
        {
            Ok(_) => {
                progress_task.abort();

                server.restoring.store(false, Ordering::SeqCst);
                server.log_daemon(
                    format!(
                        "Completed server restoration from {} backup.",
                        backup.adapter().to_str()
                    )
                    .into(),
                );
                server
                    .app_state
                    .config
                    .client
                    .set_backup_restore_status(server.uuid, backup.uuid(), true)
                    .await?;
                server
                    .websocket
                    .send(crate::server::websocket::WebsocketMessage::new(
                        crate::server::websocket::WebsocketEvent::ServerBackupRestoreCompleted,
                        [].into(),
                    ))?;

                tracing::info!(
                    server = %server.uuid,
                    backup = %backup.uuid(),
                    adapter = ?backup.adapter(),
                    "completed restore of backup",
                );

                Ok(())
            }
            Err(err) => {
                progress_task.abort();

                server.restoring.store(false, Ordering::SeqCst);
                server
                    .app_state
                    .config
                    .client
                    .set_backup_restore_status(server.uuid, backup.uuid(), false)
                    .await?;
                server
                    .websocket
                    .send(crate::server::websocket::WebsocketMessage::new(
                        crate::server::websocket::WebsocketEvent::ServerBackupRestoreCompleted,
                        [].into(),
                    ))?;

                Err(err)
            }
        }
    }

    pub async fn find(
        &self,
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Arc<super::Backup>>, anyhow::Error> {
        if let Some(backup) = self.cached_backups.get(&uuid).await {
            return Ok(Some(backup));
        }

        if let Some(adapter) = self.cached_backup_adapters.get(&uuid).await
            && let Some(backup) = adapter.find(state, uuid).await?
        {
            let backup = Arc::new(backup);
            self.cached_backups.insert(uuid, Arc::clone(&backup)).await;

            return Ok(Some(backup));
        }

        if let Some((adapter, backup)) = BackupAdapter::find_all(state, uuid).await? {
            let backup = Arc::new(backup);
            self.cached_backups.insert(uuid, Arc::clone(&backup)).await;
            self.cached_backup_adapters.insert(uuid, adapter).await;

            return Ok(Some(backup));
        }

        Ok(None)
    }

    pub async fn find_adapter(
        &self,
        state: &crate::routes::State,
        adapter: BackupAdapter,
        uuid: uuid::Uuid,
    ) -> Result<Option<Arc<super::Backup>>, anyhow::Error> {
        if let Some(backup) = self.cached_backups.get(&uuid).await {
            return Ok(Some(backup));
        }

        if let Some(backup) = adapter.find(state, uuid).await? {
            let backup = Arc::new(backup);
            self.cached_backups.insert(uuid, Arc::clone(&backup)).await;

            return Ok(Some(backup));
        }

        Ok(None)
    }

    pub async fn browse(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
    ) -> Result<Option<Arc<dyn VirtualReadableFilesystem>>, anyhow::Error> {
        if let Some(browse_backup) = self.cached_browse_backups.get(&uuid).await {
            return Ok(Some(browse_backup));
        }

        if let Some(backup) = self.find(&server.app_state, uuid).await? {
            let server = server.clone();
            let cached_browse_backup_locks = self.cached_browse_backup_locks.clone();
            let cached_browse_backups = self.cached_browse_backups.clone();

            return tokio::spawn(async move {
                let _guard = if let Some(lock) = cached_browse_backup_locks.get(&uuid).await {
                    lock
                } else {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    cached_browse_backup_locks
                        .insert(uuid, Arc::clone(&lock))
                        .await;

                    lock
                };
                let _guard = _guard.lock().await;

                if let Some(browse_backup) = cached_browse_backups.get(&uuid).await {
                    return Ok(Some(browse_backup));
                }

                let browse_backup = backup.browse(&server).await?;

                cached_browse_backups
                    .insert(uuid, Arc::clone(&browse_backup))
                    .await;

                Ok(Some(browse_backup))
            })
            .await?;
        }

        Ok(None)
    }

    pub async fn invalidate_cached_browse(&self, uuid: uuid::Uuid) {
        self.cached_browse_backups.invalidate(&uuid).await;
        self.cached_browse_backup_locks.invalidate(&uuid).await;
        self.cached_browse_backups.run_pending_tasks().await;
        self.cached_browse_backup_locks.run_pending_tasks().await;
    }
}
