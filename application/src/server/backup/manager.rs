use crate::{
    remote::backups::RawServerBackup,
    server::{backup::adapters::BackupAdapter, filesystem::virtualfs::VirtualReadableFilesystem},
};
use compact_str::ToCompactString;
use futures::TryStreamExt;
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
    database_backup_restores: tokio::sync::broadcast::Sender<DatabaseBackupRestore>,
}

#[derive(Clone)]
struct DatabaseBackupRestore {
    request_uuid: uuid::Uuid,
    completion: tokio::sync::watch::Receiver<Option<bool>>,
}

pub struct DatabaseBackupRestoreWaiter {
    receiver: tokio::sync::broadcast::Receiver<DatabaseBackupRestore>,
}

impl DatabaseBackupRestoreWaiter {
    pub async fn wait(
        mut self,
        request_uuid: uuid::Uuid,
        start_timeout: std::time::Duration,
    ) -> Result<(), anyhow::Error> {
        let mut completion = tokio::time::timeout(start_timeout, async {
            loop {
                let restore = self.receiver.recv().await?;
                if restore.request_uuid == request_uuid {
                    return Ok::<_, anyhow::Error>(restore.completion);
                }
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("database backup restore did not start before the timeout")
        })??;

        loop {
            if let Some(successful) = *completion.borrow_and_update() {
                return if successful {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("database backup restore failed"))
                };
            }

            completion
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("database backup restore ended without a result"))?;
        }
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self {
            database_backup_restores: tokio::sync::broadcast::channel(128).0,
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
    pub fn subscribe_database_backup_restores(&self) -> DatabaseBackupRestoreWaiter {
        DatabaseBackupRestoreWaiter {
            receiver: self.database_backup_restores.subscribe(),
        }
    }

    fn start_database_backup_restore(
        &self,
        request_uuid: uuid::Uuid,
    ) -> tokio::sync::watch::Sender<Option<bool>> {
        let (sender, completion) = tokio::sync::watch::channel(None);
        self.database_backup_restores
            .send(DatabaseBackupRestore {
                request_uuid,
                completion,
            })
            .ok();

        sender
    }

    pub async fn fast_contains(&self, server: &crate::server::Server, uuid: uuid::Uuid) -> bool {
        self.cached_backups.contains_key(&uuid)
            || server.configuration.read().await.backups.contains(&uuid)
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
        let files = Arc::new(AtomicU64::new(0));

        let progress_task = tokio::spawn({
            let progress = Arc::clone(&progress);
            let total = Arc::clone(&total);
            let files = Arc::clone(&files);
            let server = server.clone();

            async move {
                loop {
                    let progress = progress.load(Ordering::SeqCst);
                    let total = total.load(Ordering::SeqCst);
                    let files = files.load(Ordering::SeqCst);

                    server
                        .websocket
                        .send(
                            crate::server::websocket::WebsocketMessage::builder(
                                crate::server::websocket::WebsocketEvent::ServerBackupProgress,
                            )
                            .arg(uuid.to_compact_string())
                            .structured_arg(crate::models::BackupProgress {
                                bytes_processed: progress,
                                bytes_total: total,
                                files_processed: files,
                            })
                            .build(),
                        )
                        .ok();

                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        });

        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerBackupStarted,
            )
            .arg(uuid.to_compact_string())
            .build(),
        )?;
        server
            .schedules
            .execute_backup_status_trigger(crate::models::ServerBackupStatus::Starting)
            .await;

        let backup = match adapter
            .create(
                server,
                uuid,
                crate::server::filesystem::archive::create::ArchiveProgress::new(
                    Arc::clone(&progress),
                    Arc::clone(&files),
                ),
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
                server.websocket.send(
                    crate::server::websocket::WebsocketMessage::builder(
                        crate::server::websocket::WebsocketEvent::ServerBackupCompleted,
                    )
                    .arg(uuid.to_compact_string())
                    .structured_arg(serde_json::json!({
                        "checksum_type": "",
                        "checksum": "",
                        "size": 0,
                        "files": 0,
                        "successful": false,
                        "browsable": false,
                        "streaming": false,
                    }))
                    .build(),
                )?;
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
        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerBackupCompleted,
            )
            .arg(uuid.to_compact_string())
            .structured_arg(serde_json::json!({
                "checksum_type": backup.checksum_type,
                "checksum": backup.checksum,
                "size": backup.size,
                "files": backup.files,
                "successful": backup.successful,
                "browsable": backup.browsable,
                "streaming": backup.streaming,
            }))
            .build(),
        )?;
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

    fn spawn_backup_progress_task(
        server: &crate::server::Server,
        event: crate::server::websocket::WebsocketEvent,
        uuid: uuid::Uuid,
        database_instance: Option<uuid::Uuid>,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
    ) -> tokio::task::JoinHandle<()> {
        let server = server.clone();

        tokio::spawn(async move {
            loop {
                let mut builder = crate::server::websocket::WebsocketMessage::builder(event)
                    .arg(uuid.to_compact_string());
                if let Some(database_instance) = database_instance {
                    builder = builder.arg(database_instance.to_compact_string());
                }

                server
                    .websocket
                    .send(
                        builder
                            .structured_arg(crate::models::BackupProgress {
                                bytes_processed: progress.load(Ordering::SeqCst),
                                bytes_total: total.load(Ordering::SeqCst),
                                files_processed: 0,
                            })
                            .build(),
                    )
                    .ok();

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
    }

    async fn finish_database_backup(
        &self,
        server: &crate::server::Server,
        adapter: BackupAdapter,
        uuid: uuid::Uuid,
        result: Result<RawServerBackup, anyhow::Error>,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let backup = match result {
            Ok(backup) => backup,
            Err(err) => {
                if let Err(err) = adapter.clean(server, uuid).await {
                    tracing::error!(server = %server.uuid, adapter = ?adapter, "failed to clean up backup {} after error: {:#?}", uuid, err);
                }

                server
                    .schedules
                    .execute_database_backup_status_trigger(
                        crate::models::ServerBackupStatus::Failed,
                    )
                    .await;
                server
                    .app_state
                    .config
                    .client
                    .set_backup_status(uuid, &RawServerBackup::default())
                    .await?;
                server.websocket.send(
                    crate::server::websocket::WebsocketMessage::builder(
                        crate::server::websocket::WebsocketEvent::ServerBackupCompleted,
                    )
                    .arg(uuid.to_compact_string())
                    .structured_arg(serde_json::json!({
                        "checksum_type": "",
                        "checksum": "",
                        "size": 0,
                        "files": 0,
                        "successful": false,
                        "browsable": false,
                        "streaming": false,
                    }))
                    .build(),
                )?;
                self.cached_backup_adapters.insert(uuid, adapter).await;

                return Err(err);
            }
        };

        server
            .schedules
            .execute_database_backup_status_trigger(crate::models::ServerBackupStatus::Finished)
            .await;
        server
            .app_state
            .config
            .client
            .set_backup_status(uuid, &backup)
            .await?;
        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerBackupCompleted,
            )
            .arg(uuid.to_compact_string())
            .structured_arg(serde_json::json!({
                "checksum_type": backup.checksum_type,
                "checksum": backup.checksum,
                "size": backup.size,
                "files": backup.files,
                "successful": backup.successful,
                "browsable": backup.browsable,
                "streaming": backup.streaming,
            }))
            .build(),
        )?;
        server.configuration.write().await.backups.push(uuid);
        self.cached_backup_adapters.insert(uuid, adapter).await;

        Ok(backup)
    }

    pub async fn create_database(
        &self,
        adapter: BackupAdapter,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        database_instance: uuid::Uuid,
        extension: &str,
    ) -> Result<RawServerBackup, anyhow::Error> {
        tracing::info!(
            server = %server.uuid,
            backup = %uuid,
            database_instance = %database_instance,
            adapter = ?adapter,
            "creating database backup",
        );

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));

        let progress_task = Self::spawn_backup_progress_task(
            server,
            crate::server::websocket::WebsocketEvent::ServerBackupProgress,
            uuid,
            None,
            Arc::clone(&progress),
            Arc::clone(&total),
        );

        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerBackupStarted,
            )
            .arg(uuid.to_compact_string())
            .build(),
        )?;
        server
            .schedules
            .execute_database_backup_status_trigger(crate::models::ServerBackupStatus::Starting)
            .await;

        let result = async {
            super::validate_dump_extension(extension)?;

            let response = server
                .app_state
                .config
                .client
                .database_backup_source(uuid, database_instance)
                .await?;
            if let Some(length) = response.content_length() {
                total.store(length, Ordering::SeqCst);
            }

            let reader = tokio_util::io::StreamReader::new(
                response.bytes_stream().map_err(std::io::Error::other),
            );
            let reader = crate::io::counting_reader::AsyncCountingReader::new_with_bytes_read(
                reader,
                Arc::clone(&progress),
            );

            adapter
                .create_from_stream(&server.app_state, uuid, extension, Box::new(reader))
                .await
        }
        .await;

        progress_task.abort();

        let backup = self
            .finish_database_backup(server, adapter, uuid, result)
            .await?;

        tracing::info!(
            server = %server.uuid,
            adapter = ?adapter,
            "completed database backup {}",
            uuid,
        );

        Ok(backup)
    }

    pub async fn restore_database(
        &self,
        backup: &super::Backup,
        server: &crate::server::Server,
        database_instance: uuid::Uuid,
        download_url: Option<compact_str::CompactString>,
        request_uuid: Option<uuid::Uuid>,
    ) -> Result<(), anyhow::Error> {
        let completion = request_uuid.map(|uuid| self.start_database_backup_restore(uuid));
        let uuid = backup.uuid();

        tracing::info!(
            server = %server.uuid,
            backup = %uuid,
            database_instance = %database_instance,
            adapter = ?backup.adapter(),
            "restoring database backup",
        );

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));

        let progress_task = Self::spawn_backup_progress_task(
            server,
            crate::server::websocket::WebsocketEvent::ServerDatabaseBackupRestoreProgress,
            uuid,
            Some(database_instance),
            Arc::clone(&progress),
            Arc::clone(&total),
        );

        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerDatabaseBackupRestoreStarted,
            )
            .arg(uuid.to_compact_string())
            .arg(database_instance.to_compact_string())
            .build(),
        )?;

        let import_result = async {
            let stream = backup.read_stream(&server.app_state, download_url).await?;
            if let Some(size) = stream.size {
                total.store(size, Ordering::SeqCst);
            }

            let reader = crate::io::counting_reader::AsyncCountingReader::new_with_bytes_read(
                stream.reader,
                Arc::clone(&progress),
            );
            let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(
                reader,
                crate::BUFFER_SIZE,
            ));

            server
                .app_state
                .config
                .client
                .database_backup_restore_target(uuid, database_instance, body)
                .await
        }
        .await;

        progress_task.abort();

        let import_successful = import_result.is_ok();
        let status_result = server
            .app_state
            .config
            .client
            .set_database_backup_restore_status(uuid, database_instance, import_successful)
            .await;
        if import_result.is_err()
            && let Err(err) = &status_result
        {
            tracing::error!(
                server = %server.uuid,
                backup = %uuid,
                database_instance = %database_instance,
                "failed to report database backup restore status: {:#?}",
                err
            );
        }

        let successful = import_successful && status_result.is_ok();

        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerDatabaseBackupRestoreCompleted,
            )
            .arg(uuid.to_compact_string())
            .arg(database_instance.to_compact_string())
            .arg(if successful { "true" } else { "false" })
            .build(),
        )?;

        if successful {
            tracing::info!(
                server = %server.uuid,
                backup = %uuid,
                adapter = ?backup.adapter(),
                "completed restore of database backup",
            );
        }

        if let Some(completion) = completion {
            completion.send_replace(Some(successful));
        }

        import_result?;

        status_result.map_err(|err| err.context("failed to report database backup restore status"))
    }

    pub async fn restore(
        &self,
        backup: &super::Backup,
        server: &crate::server::Server,
        truncate_directory: bool,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        if let Some(state) = server.locked_state() {
            return Err(anyhow::anyhow!(
                "server is in a locked state ({state}), cannot restore backup"
            ));
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

            return Err(anyhow::anyhow!(err)
                .context("failed to truncate root directory before restoring backup"));
        }

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(1));
        let files = Arc::new(AtomicU64::new(0));

        let progress_task = tokio::spawn({
            let progress = Arc::clone(&progress);
            let total = Arc::clone(&total);
            let files = Arc::clone(&files);
            let server = server.clone();

            async move {
                loop {
                    let progress_value = progress.load(Ordering::SeqCst);
                    let total_value = total.load(Ordering::SeqCst);
                    let files_value = files.load(Ordering::SeqCst);

                    server
                        .websocket
                        .send(
                            crate::server::websocket::WebsocketMessage::builder(
                                crate::server::websocket::WebsocketEvent::ServerBackupRestoreProgress,
                            )
                            .structured_arg(crate::models::BackupProgress {
                                bytes_processed: progress_value,
                                bytes_total: total_value,
                                files_processed: files_value,
                            })
                            .build(),
                        )
                        .ok();

                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        });

        server.websocket.send(
            crate::server::websocket::WebsocketMessage::builder(
                crate::server::websocket::WebsocketEvent::ServerBackupRestoreStarted,
            )
            .build(),
        )?;

        match backup
            .restore(
                server,
                crate::server::filesystem::archive::create::ArchiveProgress::new(
                    Arc::clone(&progress),
                    Arc::clone(&files),
                ),
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
                if let Err(err) = server.diff.clear().await {
                    tracing::warn!(server = %server.uuid, "failed to clear file history: {:?}", err);
                }

                server
                    .app_state
                    .config
                    .client
                    .set_backup_restore_status(server.uuid, backup.uuid(), true)
                    .await?;
                server.websocket.send(
                    crate::server::websocket::WebsocketMessage::builder(
                        crate::server::websocket::WebsocketEvent::ServerBackupRestoreCompleted,
                    )
                    .arg("true")
                    .build(),
                )?;

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
                server.websocket.send(
                    crate::server::websocket::WebsocketMessage::builder(
                        crate::server::websocket::WebsocketEvent::ServerBackupRestoreCompleted,
                    )
                    .arg("false")
                    .build(),
                )?;

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
        self.cached_browse_backup_locks.invalidate(&uuid).await;

        if let Some(browse) = self.cached_browse_backups.remove(&uuid).await
            && let Err(err) = browse.close().await
        {
            tracing::error!(backup = %uuid, "failed to close cached browse backup: {:#?}", err);
        }

        self.cached_browse_backups.run_pending_tasks().await;
        self.cached_browse_backup_locks.run_pending_tasks().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn database_restore_completion_before_wait_is_preserved() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let request_uuid = uuid::Uuid::new_v4();
            let completion = manager.start_database_backup_restore(request_uuid);
            completion.send_replace(Some(true));
            drop(completion);

            waiter.wait(request_uuid, Duration::from_secs(1)).await
        })
    }

    #[test]
    fn database_restore_waits_for_its_own_completion() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let old = manager.start_database_backup_restore(uuid::Uuid::new_v4());
            let request_uuid = uuid::Uuid::new_v4();
            let completion = manager.start_database_backup_restore(request_uuid);
            old.send_replace(Some(true));

            let wait = waiter.wait(request_uuid, Duration::from_secs(1));
            tokio::pin!(wait);
            assert!(futures::poll!(&mut wait).is_pending());
            completion.send_replace(Some(true));
            wait.await
        })
    }

    #[test]
    fn database_restore_failure_reaches_waiter() {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let request_uuid = uuid::Uuid::new_v4();
            let completion = manager.start_database_backup_restore(request_uuid);
            completion.send_replace(Some(false));

            assert!(
                waiter
                    .wait(request_uuid, Duration::from_secs(1))
                    .await
                    .is_err_and(|err| err.to_string().contains("restore failed"))
            );
        });
    }

    #[test]
    fn database_restore_missing_start_times_out() {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let unrelated = manager.start_database_backup_restore(uuid::Uuid::new_v4());
            unrelated.send_replace(Some(true));

            assert!(
                waiter
                    .wait(uuid::Uuid::new_v4(), Duration::from_millis(5))
                    .await
                    .is_err_and(|err| err.to_string().contains("did not start"))
            );
        });
    }

    #[test]
    fn database_restore_dropped_task_fails_waiter() {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let request_uuid = uuid::Uuid::new_v4();
            drop(manager.start_database_backup_restore(request_uuid));

            assert!(
                waiter
                    .wait(request_uuid, Duration::from_secs(1))
                    .await
                    .is_err_and(|err| err.to_string().contains("without a result"))
            );
        });
    }

    #[test]
    fn database_restore_lagged_or_closed_notifications_fail_waiter() {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let request_uuid = uuid::Uuid::new_v4();
            let completion = manager.start_database_backup_restore(request_uuid);
            completion.send_replace(Some(true));
            for _ in 0..128 {
                manager.start_database_backup_restore(uuid::Uuid::new_v4());
            }

            assert!(
                waiter
                    .wait(request_uuid, Duration::from_secs(1))
                    .await
                    .is_err()
            );

            let waiter = manager.subscribe_database_backup_restores();
            drop(manager);
            assert!(
                waiter
                    .wait(request_uuid, Duration::from_secs(1))
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn database_restore_completion_has_no_start_deadline() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let manager = BackupManager::default();
            let waiter = manager.subscribe_database_backup_restores();
            let request_uuid = uuid::Uuid::new_v4();
            let completion = manager.start_database_backup_restore(request_uuid);
            let wait = waiter.wait(request_uuid, Duration::from_millis(1));
            tokio::pin!(wait);
            assert!(futures::poll!(&mut wait).is_pending());
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(futures::poll!(&mut wait).is_pending());
            completion.send_replace(Some(true));

            wait.await
        })
    }
}
