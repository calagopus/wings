use super::{RevisionInfo, storage::Storage};
use compact_str::ToCompactString;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;

const FORGET_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

struct PendingForget {
    id: u64,
    handle: tokio::task::AbortHandle,
    before: Option<Vec<u8>>,
}

pub struct DiffManager {
    server: uuid::Uuid,
    config: Arc<crate::config::Config>,
    storage: Arc<Mutex<Option<Storage>>>,
    db_path: PathBuf,

    pending_forgets: Arc<Mutex<HashMap<compact_str::CompactString, PendingForget>>>,
    forget_seq: AtomicU64,

    task: tokio::task::JoinHandle<()>,
}

impl DiffManager {
    pub fn new(server: uuid::Uuid, config: &Arc<crate::config::Config>) -> Self {
        let diffs_directory = config.resolve_as_path(|cfg| &cfg.system.diffs_directory);
        let db_path = diffs_directory.join(format!("{server}.db"));

        let storage: Arc<Mutex<Option<Storage>>> = Arc::new(Mutex::new(None));
        let pending_forgets: Arc<Mutex<HashMap<compact_str::CompactString, PendingForget>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let task = tokio::spawn({
            let config = Arc::clone(config);
            let storage = Arc::clone(&storage);
            let pending_forgets = Arc::clone(&pending_forgets);

            async move {
                loop {
                    let interval = std::time::Duration::from_secs(
                        config.load().system.file_history.maintenance_interval,
                    );
                    tokio::time::sleep(interval).await;

                    pending_forgets
                        .lock()
                        .await
                        .retain(|_, p| !p.handle.is_finished());

                    let storage = Arc::clone(&storage);
                    match tokio::task::spawn_blocking(move || {
                        let mut guard = storage.blocking_lock();
                        if let Some(s) = guard.as_mut() {
                            s.vacuum()
                        } else {
                            Ok(())
                        }
                    })
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => tracing::warn!(
                            server = %server,
                            "diff db maintenance failed: {err:#}",
                        ),
                        Err(err) => tracing::warn!(
                            server = %server,
                            "diff db maintenance join error: {err}"
                        ),
                    }
                }
            }
        });

        Self {
            server,
            config: Arc::clone(config),
            storage,
            db_path,
            task,
            pending_forgets,
            forget_seq: AtomicU64::new(0),
        }
    }

    async fn ensure_open(&self) -> bool {
        if !self.config.load().system.file_history.enabled {
            return false;
        }
        if self.storage.lock().await.is_some() {
            return true;
        }

        let zstd_level = self.config.load().system.file_history.zstd_level;
        let db_path = self.db_path.clone();
        let storage = Arc::clone(&self.storage);
        let server = self.server;
        let path_display = db_path.display().to_string();

        match tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut guard = storage.blocking_lock();
            if guard.is_some() {
                return Ok(());
            }

            let s = Storage::open(&db_path, zstd_level)?;
            *guard = Some(s);

            Ok(())
        })
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                tracing::error!(
                    server = %server,
                    "failed to open diff db at {path_display}: {err:#}",
                );
                false
            }
            Err(err) => {
                tracing::error!(
                    server = %server,
                    "diff db open join error: {err}"
                );
                false
            }
        }
    }

    pub async fn record_edit(
        &self,
        path: &str,
        before: Option<Vec<u8>>,
        after: Vec<u8>,
        user: Option<uuid::Uuid>,
    ) -> Result<i64, anyhow::Error> {
        if !self.ensure_open().await {
            return Ok(0);
        }
        let config = self.config.load();

        let anchor_interval = config.system.file_history.anchor_interval.max(1);
        let keep_chains = config.system.file_history.keep_chains.max(1);
        let per_file_budget = config.system.file_history.per_file_disk_budget;
        let per_server_budget = config.system.file_history.per_server_disk_budget;
        drop(config);

        let path = path.to_string();
        let server = self.server;
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || -> Result<i64, anyhow::Error> {
            let mut guard = storage.blocking_lock();
            let Some(storage) = guard.as_mut() else {
                return Ok(0);
            };

            let now_ms = chrono::Utc::now().timestamp_millis();
            let file_id = storage.upsert_file(&path)?;

            let latest = storage.latest_revision(file_id)?;
            let revision_id = match latest {
                None => match before {
                    Some(before) if before != after => {
                        let baseline =
                            storage.insert_snapshot(file_id, None, &before, now_ms - 1)?;
                        storage.insert_delta(
                            file_id, baseline, baseline, &before, user, &after, now_ms,
                        )?
                    }
                    _ => storage.insert_snapshot(file_id, user, &after, now_ms)?,
                },
                Some(prev) => {
                    let prev_hash = prev.content_hash;
                    let after_hash = blake3::hash(&after);
                    if &prev_hash == after_hash.as_bytes() {
                        return Ok(prev.id);
                    }

                    let chain_len = storage.current_chain_length(file_id)?;
                    let should_anchor = chain_len >= anchor_interval;
                    if should_anchor {
                        storage.insert_snapshot(file_id, user, &after, now_ms)?
                    } else {
                        let prev_content = storage.reconstruct(prev.id)?;

                        storage.insert_successor(
                            file_id,
                            &prev,
                            &prev_content,
                            user,
                            &after,
                            now_ms,
                        )?
                    }
                }
            };

            let protected_chain = storage.latest_chain_id(file_id)?;
            storage.prune_old_chains(file_id, keep_chains)?;

            while storage.file_payload_bytes(file_id)? > per_file_budget {
                let freed = storage.drop_oldest_chain(file_id, protected_chain, 1)?;
                if freed == 0 {
                    break;
                }
            }

            let server_protect = protected_chain.map(|cid| (file_id, cid));
            let mut total = storage.total_payload_bytes()?;
            while total > per_server_budget {
                let freed = storage.drop_globally_oldest_chain(server_protect)?;
                if freed == 0 {
                    break;
                }
                total = total.saturating_sub(freed);
            }

            tracing::debug!(server = %server, path = %path, "recorded file edit");

            Ok(revision_id)
        })
        .await?
    }

    pub async fn list(&self, path: &str) -> Result<Vec<RevisionInfo>, anyhow::Error> {
        if !self.ensure_open().await {
            return Ok(Vec::new());
        }

        let path = path.to_string();
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || -> Result<Vec<RevisionInfo>, anyhow::Error> {
            let guard = storage.blocking_lock();
            let Some(storage) = guard.as_ref() else {
                return Ok(Vec::new());
            };
            let Some(file_id) = storage.find_file(&path)? else {
                return Ok(Vec::new());
            };
            let rows = storage.list_for_file(file_id)?;
            Ok(rows.into_iter().map(RevisionInfo::from).collect())
        })
        .await?
    }

    pub async fn revision_path(&self, revision_id: i64) -> Result<Option<String>, anyhow::Error> {
        if !self.ensure_open().await {
            return Ok(None);
        }

        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || -> Result<Option<String>, anyhow::Error> {
            let guard = storage.blocking_lock();
            let Some(storage) = guard.as_ref() else {
                return Ok(None);
            };

            storage.revision_path(revision_id)
        })
        .await?
    }

    pub async fn get_content(&self, revision_id: i64) -> Result<Option<Vec<u8>>, anyhow::Error> {
        if !self.ensure_open().await {
            return Ok(None);
        }

        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>, anyhow::Error> {
            let guard = storage.blocking_lock();
            let Some(storage) = guard.as_ref() else {
                return Ok(None);
            };
            match storage.reconstruct(revision_id) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(err) => {
                    tracing::warn!("failed to reconstruct revision {revision_id}: {err:#}");
                    Ok(None)
                }
            }
        })
        .await?
    }

    pub async fn forget_file(
        &self,
        path: &str,
        before: Option<Vec<u8>>,
    ) -> Result<(), anyhow::Error> {
        if !self.ensure_open().await {
            return Ok(());
        }

        let path = path.to_compact_string();
        let id = self.forget_seq.fetch_add(1, Ordering::Relaxed);
        let storage = Arc::clone(&self.storage);
        let pending_forgets = Arc::clone(&self.pending_forgets);
        let server = self.server;

        let task = tokio::spawn({
            let path = path.clone();
            let pending_forgets = Arc::clone(&pending_forgets);

            async move {
                tokio::time::sleep(FORGET_GRACE).await;

                let result = tokio::task::spawn_blocking({
                    let storage = Arc::clone(&storage);
                    let path = path.clone();

                    move || -> Result<(), anyhow::Error> {
                        let mut guard = storage.blocking_lock();
                        if let Some(s) = guard.as_mut() {
                            s.delete_file(&path)?;
                        }
                        Ok(())
                    }
                })
                .await;

                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::error!(server = %server, path = %path, "failed to forget file from diff storage: {err:#}");
                    }
                    Err(err) => {
                        tracing::error!(server = %server, path = %path, "diff forget join error: {err}");
                    }
                }

                let mut map = pending_forgets.lock().await;
                if map.get(&*path).is_some_and(|p| p.id == id) {
                    map.remove(&*path);
                }
            }
        });

        let mut map = pending_forgets.lock().await;
        if let Some(old) = map.insert(
            path,
            PendingForget {
                id,
                handle: task.abort_handle(),
                before,
            },
        ) {
            old.handle.abort();
        }

        Ok(())
    }

    pub async fn cancel_pending_forget(&self, path: &str) -> Option<Option<Vec<u8>>> {
        let mut map = self.pending_forgets.lock().await;
        map.remove(path).map(|p| {
            p.handle.abort();
            p.before
        })
    }

    pub async fn rename_file(
        &self,
        old: &str,
        new: &str,
    ) -> Result<Option<Option<Vec<u8>>>, anyhow::Error> {
        let replaced = self.cancel_pending_forget(new).await;

        if !self.ensure_open().await {
            return Ok(replaced);
        }

        let old = old.to_string();
        let new = new.to_string();
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut guard = storage.blocking_lock();
            if let Some(s) = guard.as_mut() {
                s.rename_file(&old, &new)?;
            }
            Ok(())
        })
        .await??;

        Ok(replaced)
    }

    pub async fn clear(&self) -> Result<(), anyhow::Error> {
        if !self.ensure_open().await {
            return Ok(());
        }

        let storage = Arc::clone(&self.storage);
        let server = self.server;
        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut guard = storage.blocking_lock();
            if let Some(s) = guard.as_mut() {
                s.clear()?;
                tracing::debug!(server = %server, "cleared all file history");
            }
            Ok(())
        })
        .await?
    }

    pub async fn export_snapshot(&self) -> Result<Option<tokio::fs::File>, anyhow::Error> {
        let db_path = self.db_path.clone();
        let zstd_level = self.config.load().system.file_history.zstd_level;
        let storage = Arc::clone(&self.storage);

        let temp_path =
            tokio::task::spawn_blocking(move || -> Result<Option<PathBuf>, anyhow::Error> {
                let guard = storage.blocking_lock();

                let mut temp = db_path.clone().into_os_string();
                temp.push(".transfer");
                let temp_path = PathBuf::from(temp);
                std::fs::remove_file(&temp_path).ok();

                match guard.as_ref() {
                    Some(s) => s.vacuum_into(&temp_path)?,
                    None => {
                        if !db_path.exists() {
                            return Ok(None);
                        }

                        Storage::open(&db_path, zstd_level)?.vacuum_into(&temp_path)?;
                    }
                }

                Ok(Some(temp_path))
            })
            .await??;

        match temp_path {
            Some(path) => {
                let file = tokio::fs::File::open(&path).await?;
                tokio::fs::remove_file(&path).await.ok();

                Ok(Some(file))
            }
            None => Ok(None),
        }
    }

    pub async fn prepare_import(&self) -> Result<tokio::fs::File, anyhow::Error> {
        let mut guard = self.storage.lock().await;
        *guard = None;

        if let Some(parent) = self.db_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        for ext in ["-wal", "-shm"] {
            let mut s = self.db_path.clone().into_os_string();
            s.push(ext);
            tokio::fs::remove_file(PathBuf::from(s)).await.ok();
        }

        Ok(tokio::fs::File::create(&self.db_path).await?)
    }

    pub async fn close(&self) {
        let mut guard = self.storage.lock().await;
        *guard = None;
    }

    pub async fn destroy(&self) {
        self.close().await;
        let path = self.db_path.clone();

        tokio::task::spawn_blocking(move || {
            for ext in ["", "-wal", "-shm"] {
                let p = if ext.is_empty() {
                    path.clone()
                } else {
                    let mut s = path.clone().into_os_string();
                    s.push(ext);
                    PathBuf::from(s)
                };

                std::fs::remove_file(p).ok();
            }
        })
        .await
        .ok();
    }
}

impl Drop for DiffManager {
    fn drop(&mut self) {
        self.task.abort();

        tokio::spawn({
            let pending_forgets = Arc::clone(&self.pending_forgets);
            async move {
                let mut map = pending_forgets.lock().await;
                for (_, pending) in map.drain() {
                    pending.handle.abort();
                }
            }
        });
    }
}
