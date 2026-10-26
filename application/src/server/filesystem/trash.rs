use super::cap::{CapFilesystem, FileType};
use crate::server::resources::{ResourceUsage, ResourceUsageWatchExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::sync::RwLock;
use utoipa::ToSchema;

pub const TRASH_DIRECTORY: &str = ".trash";
pub const PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_mins(5);

const META_FILE: &str = "meta.json";
const META_SIZE_CAP: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrashSource {
    Api,
    Schedule,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrashMeta {
    pub path: compact_str::CompactString,
    pub name: compact_str::CompactString,
    pub directory: bool,
    pub size: u64,
    pub deleted_at: chrono::DateTime<chrono::Utc>,
    pub source: TrashSource,
}

impl TrashMeta {
    #[inline]
    pub fn file_type(&self) -> FileType {
        FileType::from_is_dir(self.directory)
    }

    #[inline]
    pub fn entry(&self, uuid: uuid::Uuid) -> TrashEntry {
        TrashEntry {
            uuid,
            name: self.name.clone(),
            path: self.path.clone(),
            directory: self.directory,
            size: self.size,
            deleted_at: self.deleted_at,
        }
    }
}

#[derive(ToSchema, Serialize, Clone)]
pub struct TrashEntry {
    pub uuid: uuid::Uuid,
    pub name: compact_str::CompactString,
    pub path: compact_str::CompactString,
    pub directory: bool,
    pub size: u64,
    pub deleted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy)]
enum PurgeUntil {
    Expired(chrono::DateTime<chrono::Utc>),
    Headroom(i64),
    NotFull,
    BelowUsageThreshold,
}

pub enum RestoreOutcome {
    Restored(TrashEntry),
    Conflict,
    Missing,
}

pub fn ignore_line() -> String {
    format!("/{TRASH_DIRECTORY}")
}

fn entry_directory(uuid: uuid::Uuid) -> PathBuf {
    Path::new(TRASH_DIRECTORY).join(uuid.to_string())
}

fn payload_path(uuid: uuid::Uuid, name: &str) -> PathBuf {
    entry_directory(uuid).join(name)
}

pub struct TrashManager {
    entries: RwLock<HashMap<uuid::Uuid, TrashMeta>>,
    retention: AtomicU64,
    usage_threshold: AtomicU64,
    purge_task: std::sync::OnceLock<tokio::task::AbortHandle>,
    resource_usage: tokio::sync::watch::Sender<ResourceUsage>,
}

impl TrashManager {
    pub fn new(resource_usage: tokio::sync::watch::Sender<ResourceUsage>) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            retention: AtomicU64::new(0),
            usage_threshold: AtomicU64::new(0),
            purge_task: std::sync::OnceLock::new(),
            resource_usage,
        }
    }

    fn publish_usage(&self, entries: &HashMap<uuid::Uuid, TrashMeta>) {
        self.resource_usage
            .publish_trash_usage(entries.values().map(|meta| meta.size).sum());
    }

    /// Retention `0` and thresholds outside `1..=100` disable their purge.
    pub fn update(&self, config: Option<crate::server::configuration::ServerConfigurationTrash>) {
        self.set_retention(config.map(|config| config.retention));
        self.set_usage_threshold(
            config
                .and_then(|config| config.usage_threshold)
                .filter(|threshold| (1..=100).contains(threshold)),
        );
    }

    #[inline]
    fn set_retention(&self, retention: Option<u64>) {
        self.retention
            .store(retention.unwrap_or(0), Ordering::Relaxed);
    }

    #[inline]
    fn retention(&self) -> Option<u64> {
        match self.retention.load(Ordering::Relaxed) {
            0 => None,
            retention => Some(retention),
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.retention().is_some()
    }

    #[inline]
    fn set_usage_threshold(&self, threshold: Option<u64>) {
        self.usage_threshold
            .store(threshold.unwrap_or(0), Ordering::Relaxed);
    }

    #[inline]
    fn usage_threshold(&self) -> Option<u64> {
        match self.usage_threshold.load(Ordering::Relaxed) {
            0 => None,
            threshold => Some(threshold),
        }
    }

    async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    async fn get(&self, uuid: uuid::Uuid) -> Option<TrashMeta> {
        self.entries.read().await.get(&uuid).cloned()
    }

    pub async fn get_visible(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        ignored: &super::RequestIgnored,
    ) -> Option<TrashMeta> {
        let meta = self.get(uuid).await?;
        if ignored
            .is_ignored(server, Path::new(&meta.path), meta.file_type())
            .await
        {
            return None;
        }

        Some(meta)
    }

    async fn entries(&self) -> Vec<(uuid::Uuid, TrashMeta)> {
        let mut entries: Vec<_> = self
            .entries
            .read()
            .await
            .iter()
            .map(|(uuid, meta)| (*uuid, meta.clone()))
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.1.deleted_at));

        entries
    }

    pub async fn visible_entries(
        &self,
        server: &crate::server::Server,
        ignored: &super::RequestIgnored,
    ) -> Vec<TrashEntry> {
        let mut entries = Vec::new();
        for (uuid, meta) in self.entries().await {
            if ignored
                .is_ignored(server, Path::new(&meta.path), meta.file_type())
                .await
            {
                continue;
            }

            entries.push(meta.entry(uuid));
        }

        entries
    }

    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        self.publish_usage(&entries);
    }

    /// Rebuilds the index from `.trash/*/meta.json`, dropping entry directories whose
    /// payload never arrived.
    pub async fn load(&self, filesystem: &CapFilesystem) {
        let mut read_dir = match filesystem.async_read_dir(TRASH_DIRECTORY).await {
            Ok(read_dir) => read_dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.clear().await;
                return;
            }
            Err(err) => {
                tracing::warn!(
                    path = %filesystem.base_path.display(),
                    "failed to read trash directory: {}",
                    err
                );
                return;
            }
        };

        let mut entries = HashMap::new();
        while let Some(Ok((file_type, name))) = read_dir.next_entry().await {
            if !file_type.is_dir() {
                continue;
            }

            let Ok(uuid) = name.parse::<uuid::Uuid>() else {
                continue;
            };

            let entry_directory = entry_directory(uuid);
            let meta = match filesystem
                .async_read_to_string(entry_directory.join(META_FILE), META_SIZE_CAP)
                .await
                .map_err(anyhow::Error::from)
                .and_then(|content| serde_json::from_str::<TrashMeta>(&content).map_err(Into::into))
            {
                Ok(meta) => meta,
                Err(err) => {
                    tracing::warn!(
                        path = %filesystem.base_path.display(),
                        entry = %uuid,
                        "skipping trash entry with unreadable metadata: {:#?}",
                        err
                    );
                    continue;
                }
            };

            if filesystem
                .async_symlink_metadata(payload_path(uuid, &meta.name))
                .await
                .is_err()
            {
                tracing::debug!(
                    path = %filesystem.base_path.display(),
                    entry = %uuid,
                    "removing trash entry without payload"
                );

                if let Err(err) = filesystem.async_remove_dir_all(&entry_directory, 1).await {
                    tracing::warn!(
                        path = %filesystem.base_path.display(),
                        entry = %uuid,
                        "failed to remove orphaned trash entry: {}",
                        err
                    );
                }

                continue;
            }

            entries.insert(uuid, meta);
        }

        self.publish_usage(&entries);
        *self.entries.write().await = entries;
    }

    /// Moves `path` into the trash. The metadata file is written before the payload is
    /// renamed, so a crash in between leaves an orphan that [`Self::load`] drops.
    pub async fn trash(
        &self,
        server: &crate::server::Server,
        path: &Path,
        source: TrashSource,
    ) -> Result<TrashEntry, anyhow::Error> {
        let filesystem = &server.filesystem;
        let path = filesystem.relative_path(path);
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("path has no file name"))?
            .to_string_lossy()
            .into_owned();

        let metadata = filesystem.async_symlink_metadata(&path).await?;
        let file_type: FileType = metadata.file_type().into();

        let size = if file_type.is_dir() {
            filesystem
                .directory_entry_space(&path, super::DirectoryEntryOptions::server_fs(true))
                .await
                .0
        } else {
            metadata.len()
        };

        let from_key = if file_type.is_file() {
            Some(filesystem.diff_key(&path).await)
        } else {
            None
        };

        let uuid = uuid::Uuid::new_v4();
        let entry_directory = entry_directory(uuid);
        let meta = TrashMeta {
            path: path.to_string_lossy().as_ref().into(),
            name: name.as_str().into(),
            directory: file_type.is_dir(),
            size,
            deleted_at: chrono::Utc::now(),
            source,
        };

        filesystem
            .async_create_chowned_dir_all(&entry_directory)
            .await?;

        let result = async {
            let content = serde_json::to_vec(&meta)?;
            let meta_path = entry_directory.join(META_FILE);
            filesystem.async_write(&meta_path, &content).await?;
            filesystem
                .async_allocate_in_path(&entry_directory, content.len() as i64, true)
                .await;

            if let Err(err) = filesystem.async_clear_inode_flags(&path, file_type).await {
                tracing::debug!(
                    server = %server.uuid,
                    path = %path.display(),
                    "failed to clear inode flags before trashing: {}",
                    err
                );
            }

            filesystem
                .rename_path(
                    &path,
                    payload_path(uuid, &name),
                    super::RenameParents::Require,
                )
                .await?;

            Ok::<_, anyhow::Error>(())
        }
        .await;

        if let Err(err) = result {
            if let Err(err) = filesystem.truncate_path(&entry_directory).await {
                tracing::warn!(
                    server = %server.uuid,
                    entry = %uuid,
                    "failed to remove incomplete trash entry: {:#?}",
                    err
                );
            }

            return Err(err);
        }

        if let Some(from_key) = from_key
            && let Err(err) = server
                .diff
                .rename_file(
                    &from_key.to_string_lossy(),
                    &payload_path(uuid, &name).to_string_lossy(),
                )
                .await
        {
            tracing::error!("failed to rename file in diff storage: {:?}", err);
        }

        let mut entries = self.entries.write().await;
        entries.insert(uuid, meta.clone());
        self.publish_usage(&entries);

        Ok(meta.entry(uuid))
    }

    /// Moves an entry back to `target`. The restored path gets a fresh mtime so
    /// collaboration sessions that watched it notice the file is back. The returned
    /// entry carries `target`, not the original path.
    pub async fn restore(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        target: &Path,
        overwrite: bool,
    ) -> Result<RestoreOutcome, anyhow::Error> {
        let Some(meta) = self.get(uuid).await else {
            return Ok(RestoreOutcome::Missing);
        };

        let filesystem = &server.filesystem;
        let target = filesystem.relative_path(target);
        if target.as_os_str().is_empty() {
            return Ok(RestoreOutcome::Conflict);
        }

        if filesystem.async_symlink_metadata(&target).await.is_ok() {
            if !overwrite {
                return Ok(RestoreOutcome::Conflict);
            }

            filesystem.truncate_path(&target).await?;
        }

        let payload_path = payload_path(uuid, &meta.name);
        filesystem
            .rename_path(&payload_path, &target, super::RenameParents::Create)
            .await?;

        if let Err(err) = server
            .diff
            .rename_file(&payload_path.to_string_lossy(), &target.to_string_lossy())
            .await
        {
            tracing::error!("failed to rename file in diff storage: {:?}", err);
        }

        if let Err(err) = filesystem
            .async_set_times(&target, std::time::SystemTime::now(), None)
            .await
        {
            tracing::debug!(
                server = %server.uuid,
                path = %target.display(),
                "failed to touch restored path: {}",
                err
            );
        }

        let mut entries = self.entries.write().await;
        entries.remove(&uuid);
        self.publish_usage(&entries);
        drop(entries);

        if let Err(err) = filesystem.truncate_path(entry_directory(uuid)).await {
            tracing::warn!(
                server = %server.uuid,
                entry = %uuid,
                "failed to remove restored trash entry directory: {:#?}",
                err
            );
        }

        let mut entry = meta.entry(uuid);
        entry.path = target.to_string_lossy().as_ref().into();
        entry.name = target
            .file_name()
            .map(|name| name.to_string_lossy().as_ref().into())
            .unwrap_or(entry.name);

        Ok(RestoreOutcome::Restored(entry))
    }

    async fn purge(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
    ) -> Result<bool, anyhow::Error> {
        let mut entries = self.entries.write().await;
        let Some(meta) = entries.remove(&uuid) else {
            return Ok(false);
        };
        self.publish_usage(&entries);
        drop(entries);

        if !meta.directory {
            let path = payload_path(uuid, &meta.name);

            if let Err(err) = server.diff.forget_file(&path.to_string_lossy(), None).await {
                tracing::error!("failed to forget file from diff storage: {:?}", err);
            }
        }

        if let Err(err) = server.filesystem.truncate_path(entry_directory(uuid)).await {
            let mut entries = self.entries.write().await;
            entries.insert(uuid, meta);
            self.publish_usage(&entries);

            return Err(err);
        }

        Ok(true)
    }

    async fn should_purge(
        &self,
        server: &crate::server::Server,
        until: PurgeUntil,
        meta: &TrashMeta,
    ) -> bool {
        match until {
            PurgeUntil::Expired(cutoff) => meta.deleted_at < cutoff,
            PurgeUntil::Headroom(delta) => !server.filesystem.has_headroom(delta),
            PurgeUntil::NotFull => server.filesystem.is_full().await,
            PurgeUntil::BelowUsageThreshold => self.over_usage_threshold(server).await,
        }
    }

    async fn purge_oldest_while(&self, server: &crate::server::Server, until: PurgeUntil) -> usize {
        let mut entries = self.entries().await;
        entries.reverse();

        let mut purged = 0;
        for (uuid, meta) in entries {
            if !self.should_purge(server, until, &meta).await {
                break;
            }

            if self.purge_logged(server, uuid).await {
                purged += 1;
            }
        }

        purged
    }

    pub async fn purge_many(
        &self,
        server: &crate::server::Server,
        entries: impl IntoIterator<Item = uuid::Uuid>,
    ) -> usize {
        let mut purged = 0;
        for uuid in entries {
            if self.purge_logged(server, uuid).await {
                purged += 1;
            }
        }

        purged
    }

    async fn purge_logged(&self, server: &crate::server::Server, uuid: uuid::Uuid) -> bool {
        match self.purge(server, uuid).await {
            Ok(purged) => purged,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    entry = %uuid,
                    "failed to purge trash entry: {:#?}",
                    err
                );

                false
            }
        }
    }

    async fn purge_expired(&self, server: &crate::server::Server) -> usize {
        let Some(retention) = self.retention() else {
            return 0;
        };

        let cutoff = chrono::Utc::now()
            - chrono::Duration::seconds(i64::try_from(retention).unwrap_or(i64::MAX));

        self.purge_oldest_while(server, PurgeUntil::Expired(cutoff))
            .await
    }

    async fn over_usage_threshold(&self, server: &crate::server::Server) -> bool {
        let Some(threshold) = self.usage_threshold() else {
            return false;
        };

        let limit = server.filesystem.disk_limit();
        if limit <= 0 {
            return false;
        }

        let usage = server.filesystem.limiter_usage().await;

        (usage as u128) * 100 >= (limit as u128) * (threshold as u128)
    }

    async fn purge_over_threshold(&self, server: &crate::server::Server) -> usize {
        if !self.over_usage_threshold(server).await {
            return 0;
        }

        self.purge_oldest_while(server, PurgeUntil::BelowUsageThreshold)
            .await
    }

    pub async fn run_maintenance(&self, server: &crate::server::Server) -> usize {
        let purged = self.purge_expired(server).await + self.purge_over_threshold(server).await;
        self.log_purge(server, purged);

        purged
    }

    pub async fn ensure_headroom(&self, server: &crate::server::Server, delta: i64) -> bool {
        let mut purged = 0;
        if !server.filesystem.has_headroom(delta) {
            if self.is_empty().await {
                return false;
            }

            purged += self
                .purge_oldest_while(server, PurgeUntil::Headroom(delta))
                .await;
        }

        let fits = server.filesystem.has_headroom(delta);
        if fits {
            purged += self.purge_over_threshold(server).await;
        }

        self.log_purge(server, purged);

        fits
    }

    pub async fn ensure_not_full(&self, server: &crate::server::Server) -> bool {
        let mut purged = 0;
        if server.filesystem.is_full().await {
            if self.is_empty().await {
                return false;
            }

            purged += self.purge_oldest_while(server, PurgeUntil::NotFull).await;
        }

        let not_full = !server.filesystem.is_full().await;
        if not_full {
            purged += self.purge_over_threshold(server).await;
        }

        self.log_purge(server, purged);

        not_full
    }

    fn log_purge(&self, server: &crate::server::Server, count: usize) {
        if count == 0 {
            return;
        }

        server
            .activity
            .log_activity(crate::server::activity::Activity {
                event: crate::server::activity::ActivityEvent::FileTrashPurge,
                user: None,
                ip: None,
                metadata: Some(serde_json::json!({ "count": count })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
    }

    pub fn set_purge_task(&self, task: tokio::task::AbortHandle) {
        let _ = self.purge_task.set(task);
    }

    pub fn abort_purge_task(&self) {
        if let Some(task) = self.purge_task.get() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Server;

    fn root(server: &Server) -> PathBuf {
        server.filesystem.base_path.to_path_buf()
    }

    // TrashManager
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn trash_then_restore_round_trips_a_directory() {
        Server::with_mock(|server| async move {
            server.filesystem.trash.set_retention(Some(60));
            let root = root(&server);
            std::fs::create_dir_all(root.join("world/region")).unwrap();
            std::fs::write(root.join("world/level.dat"), b"level").unwrap();
            server
                .filesystem
                .async_allocate_in_path(Path::new("world"), 5, true)
                .await;
            server
                .filesystem
                .async_allocate_in_path(Path::new("world/region"), 10, true)
                .await;

            let entry = server
                .filesystem
                .trash
                .trash(&server, Path::new("world"), TrashSource::Api)
                .await
                .unwrap();

            assert_eq!(entry.name, "world");
            assert_eq!(entry.path, "world");
            assert!(entry.directory);
            assert_eq!(entry.size, 15);
            assert!(!root.join("world").exists());
            assert!(
                root.join(".trash")
                    .join(entry.uuid.to_string())
                    .join("world/level.dat")
                    .is_file()
            );
            assert!(
                root.join(".trash")
                    .join(entry.uuid.to_string())
                    .join("meta.json")
                    .is_file()
            );

            let listed = server.filesystem.trash.entries().await;
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].0, entry.uuid);

            let outcome = server
                .filesystem
                .trash
                .restore(&server, entry.uuid, Path::new("world"), false)
                .await
                .unwrap();
            let RestoreOutcome::Restored(restored) = outcome else {
                panic!("expected restore");
            };
            assert_eq!(restored.uuid, entry.uuid);
            assert_eq!(restored.path, "world");
            assert_eq!(
                std::fs::read(root.join("world/level.dat")).unwrap(),
                b"level"
            );
            assert!(!root.join(".trash").join(entry.uuid.to_string()).exists());
            assert!(server.filesystem.trash.is_empty().await);
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn restore_reports_conflict_unless_overwrite() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            std::fs::write(root.join("a.txt"), b"old").unwrap();

            let entry = server
                .filesystem
                .trash
                .trash(&server, Path::new("a.txt"), TrashSource::Api)
                .await
                .unwrap();
            std::fs::write(root.join("a.txt"), b"new").unwrap();

            let outcome = server
                .filesystem
                .trash
                .restore(&server, entry.uuid, Path::new("a.txt"), false)
                .await
                .unwrap();
            assert!(matches!(outcome, RestoreOutcome::Conflict));
            assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"new");

            let outcome = server
                .filesystem
                .trash
                .restore(&server, entry.uuid, Path::new("a.txt"), true)
                .await
                .unwrap();
            assert!(matches!(outcome, RestoreOutcome::Restored(_)));
            assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"old");
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn restore_to_another_directory_creates_parents() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            std::fs::write(root.join("a.txt"), b"x").unwrap();

            let entry = server
                .filesystem
                .trash
                .trash(&server, Path::new("a.txt"), TrashSource::Api)
                .await
                .unwrap();

            let outcome = server
                .filesystem
                .trash
                .restore(
                    &server,
                    entry.uuid,
                    Path::new("elsewhere/deep/a.txt"),
                    false,
                )
                .await
                .unwrap();
            let RestoreOutcome::Restored(restored) = outcome else {
                panic!("expected restore");
            };
            assert_eq!(restored.path, "elsewhere/deep/a.txt");
            assert_eq!(restored.name, "a.txt");
            assert!(root.join("elsewhere/deep/a.txt").is_file());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn load_rebuilds_index_and_drops_orphans() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            std::fs::write(root.join("a.txt"), b"x").unwrap();

            let entry = server
                .filesystem
                .trash
                .trash(&server, Path::new("a.txt"), TrashSource::Schedule)
                .await
                .unwrap();

            let orphan = uuid::Uuid::new_v4();
            let orphan_dir = root.join(".trash").join(orphan.to_string());
            std::fs::create_dir_all(&orphan_dir).unwrap();
            std::fs::write(
                orphan_dir.join("meta.json"),
                serde_json::to_vec(&TrashMeta {
                    path: "gone.txt".into(),
                    name: "gone.txt".into(),
                    directory: false,
                    size: 0,
                    deleted_at: chrono::Utc::now(),
                    source: TrashSource::Api,
                })
                .unwrap(),
            )
            .unwrap();
            std::fs::create_dir_all(root.join(".trash/not-a-uuid")).unwrap();

            server.filesystem.trash.clear().await;
            server.filesystem.trash.load(&server.filesystem).await;

            let entries = server.filesystem.trash.entries().await;
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0, entry.uuid);
            assert_eq!(entries[0].1.source, TrashSource::Schedule);
            assert!(!orphan_dir.exists());
            assert!(root.join(".trash/not-a-uuid").exists());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn purge_expired_respects_retention_and_disabled_state() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            std::fs::write(root.join("old.txt"), b"x").unwrap();
            std::fs::write(root.join("new.txt"), b"y").unwrap();

            let old = server
                .filesystem
                .trash
                .trash(&server, Path::new("old.txt"), TrashSource::Api)
                .await
                .unwrap();
            server
                .filesystem
                .trash
                .entries
                .write()
                .await
                .get_mut(&old.uuid)
                .unwrap()
                .deleted_at = chrono::Utc::now() - chrono::Duration::hours(2);
            let new = server
                .filesystem
                .trash
                .trash(&server, Path::new("new.txt"), TrashSource::Api)
                .await
                .unwrap();

            server.filesystem.trash.set_retention(None);
            assert_eq!(server.filesystem.trash.purge_expired(&server).await, 0);
            assert_eq!(server.filesystem.trash.entries().await.len(), 2);

            server.filesystem.trash.set_retention(Some(3600));
            assert_eq!(server.filesystem.trash.purge_expired(&server).await, 1);

            let entries = server.filesystem.trash.entries().await;
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0, new.uuid);
            assert!(!root.join(".trash").join(old.uuid.to_string()).exists());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn ensure_headroom_purges_oldest_first() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            std::fs::write(root.join("old.bin"), vec![0u8; 4096]).unwrap();
            std::fs::write(root.join("new.bin"), vec![0u8; 4096]).unwrap();
            server.filesystem.rerun_disk_checker();

            let old = server
                .filesystem
                .trash
                .trash(&server, Path::new("old.bin"), TrashSource::Api)
                .await
                .unwrap();
            server
                .filesystem
                .trash
                .entries
                .write()
                .await
                .get_mut(&old.uuid)
                .unwrap()
                .deleted_at = chrono::Utc::now() - chrono::Duration::hours(1);
            let new = server
                .filesystem
                .trash
                .trash(&server, Path::new("new.bin"), TrashSource::Api)
                .await
                .unwrap();

            let used = server.filesystem.get_physical_cached_size();
            server.filesystem.update_disk_limit(used + 1024).await;
            assert!(!server.filesystem.has_headroom(2048));

            assert!(server.filesystem.trash.ensure_headroom(&server, 2048).await);

            let entries = server.filesystem.trash.entries().await;
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0, new.uuid);
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn usage_threshold_purges_oldest_until_below() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            std::fs::write(root.join("old.bin"), vec![0u8; 4096]).unwrap();
            std::fs::write(root.join("new.bin"), vec![0u8; 4096]).unwrap();
            server
                .filesystem
                .async_allocate_in_path(Path::new(""), 8192, true)
                .await;

            let old = server
                .filesystem
                .trash
                .trash(&server, Path::new("old.bin"), TrashSource::Api)
                .await
                .unwrap();
            server
                .filesystem
                .trash
                .entries
                .write()
                .await
                .get_mut(&old.uuid)
                .unwrap()
                .deleted_at = chrono::Utc::now() - chrono::Duration::hours(1);
            let new = server
                .filesystem
                .trash
                .trash(&server, Path::new("new.bin"), TrashSource::Api)
                .await
                .unwrap();

            let usage = server.filesystem.limiter_usage().await;
            assert!(usage >= 8192);
            server.filesystem.update_disk_limit(usage + 1500).await;

            assert_eq!(
                server.filesystem.trash.purge_over_threshold(&server).await,
                0
            );
            assert_eq!(server.filesystem.trash.entries().await.len(), 2);

            server.filesystem.trash.set_usage_threshold(Some(50));
            server.filesystem.update_disk_limit(0).await;
            assert_eq!(
                server.filesystem.trash.purge_over_threshold(&server).await,
                0
            );
            assert_eq!(server.filesystem.trash.entries().await.len(), 2);

            server.filesystem.update_disk_limit(usage + 1500).await;
            assert_eq!(
                server.filesystem.trash.purge_over_threshold(&server).await,
                1
            );

            let entries = server.filesystem.trash.entries().await;
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0, new.uuid);
            assert!(server.filesystem.limiter_usage().await * 100 < (usage + 1500) * 50);
        });
    }

    // Filesystem
    #[test]
    fn trash_directory_is_denied_and_hidden() {
        Server::with_mock(|server| async move {
            assert!(
                server
                    .filesystem
                    .is_ignored(Path::new(".trash"), FileType::Dir)
            );
            assert!(
                server
                    .filesystem
                    .is_ignored(Path::new(".trash/abc/file.txt"), FileType::File)
            );

            server.filesystem.update_ignored(&["!.trash"]).await;
            assert!(
                server
                    .filesystem
                    .is_ignored(Path::new(".trash"), FileType::Dir)
            );
        });
    }
}
