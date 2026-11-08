use super::{
    RequestIgnored,
    cap::{CapFilesystem, FileType},
    usage::DiskUsage,
    virtualfs::{IgnoreVerdict, IsIgnoredFn, VirtualReadableFilesystem},
};
use crate::server::resources::{ResourceUsage, ResourceUsageWatchExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use utoipa::ToSchema;

pub const TRASH_DIRECTORY: &str = ".trash";
pub const PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_mins(5);

const META_FILE: &str = "meta.json";
const META_TEMPORARY_FILE: &str = "meta.json.tmp";
const META_SIZE_CAP: usize = 64 * 1024;
const MAX_RESTORATIONS: usize = 64;
const RESTORATION_LIFETIME: chrono::Duration = chrono::Duration::hours(1);

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
    #[serde(alias = "deleted_at")]
    pub deleted: chrono::DateTime<chrono::Utc>,
    pub source: TrashSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restorations: Vec<TrashRestoration>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrashRestoration {
    pub id: uuid::Uuid,
    pub inner: compact_str::CompactString,
    pub destination: compact_str::CompactString,
    pub directory: bool,
    pub restored_at: chrono::DateTime<chrono::Utc>,
    pub dev: u64,
    pub ino: u64,
}

impl TrashMeta {
    #[inline]
    pub fn file_type(&self) -> FileType {
        FileType::from_is_dir(self.directory)
    }

    pub fn entry(&self, uuid: uuid::Uuid, disk_usage: &DiskUsage) -> TrashEntry {
        let size = if self.directory {
            disk_usage
                .get_size(&payload_path(uuid, &self.name))
                .map_or(self.size, |space| space.get_logical())
        } else {
            self.size
        };

        TrashEntry {
            uuid,
            name: self.name.clone(),
            path: self.path.clone(),
            directory: self.directory,
            file: !self.directory,
            size,
            deleted: self.deleted,
        }
    }
}

impl TrashRestoration {
    #[inline]
    pub fn file_type(&self) -> FileType {
        FileType::from_is_dir(self.directory)
    }
}

#[derive(ToSchema, Serialize, Clone)]
pub struct TrashEntry {
    pub uuid: uuid::Uuid,
    pub name: compact_str::CompactString,
    pub path: compact_str::CompactString,
    pub directory: bool,
    pub file: bool,
    pub size: u64,
    pub deleted: chrono::DateTime<chrono::Utc>,
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

pub enum InnerRestoreOutcome {
    Restored(Option<TrashRestoration>),
    Conflict,
    Missing,
}

pub enum ReturnOutcome {
    Returned,
    Unavailable,
}

pub fn ignore_line() -> String {
    format!("/{TRASH_DIRECTORY}")
}

pub(super) fn physical_usage(disk_usage: &DiskUsage) -> u64 {
    disk_usage
        .get_size(Path::new(TRASH_DIRECTORY))
        .map_or(0, |space| space.get_physical())
}

pub fn inner_path(path: &str) -> Option<PathBuf> {
    let mut inner = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(component) => inner.push(component),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }

    Some(inner)
}

fn entry_directory(uuid: uuid::Uuid) -> PathBuf {
    Path::new(TRASH_DIRECTORY).join(uuid.to_string())
}

fn payload_path(uuid: uuid::Uuid, name: &str) -> PathBuf {
    entry_directory(uuid).join(name)
}

#[inline]
fn file_id(metadata: &cap_std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;

        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;

        (0, 0)
    }
}

pub struct TrashManager {
    entries: RwLock<HashMap<uuid::Uuid, TrashMeta>>,
    entry_locks: moka::future::Cache<uuid::Uuid, Arc<Mutex<()>>>,
    disk_usage: Arc<RwLock<DiskUsage>>,
    retention: AtomicU64,
    usage_threshold: AtomicU64,
    purge_task: std::sync::OnceLock<tokio::task::AbortHandle>,
    resource_usage: tokio::sync::watch::Sender<ResourceUsage>,
}

impl TrashManager {
    pub fn new(
        resource_usage: tokio::sync::watch::Sender<ResourceUsage>,
        disk_usage: Arc<RwLock<DiskUsage>>,
    ) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            entry_locks: moka::future::Cache::new(10240),
            disk_usage,
            retention: AtomicU64::new(0),
            usage_threshold: AtomicU64::new(0),
            purge_task: std::sync::OnceLock::new(),
            resource_usage,
        }
    }

    async fn lock_entry(&self, uuid: uuid::Uuid) -> OwnedMutexGuard<()> {
        self.entry_locks
            .get_with(uuid, async { Arc::new(Mutex::new(())) })
            .await
            .lock_owned()
            .await
    }

    async fn publish_usage(&self) {
        let trash_bytes = physical_usage(&*self.disk_usage.read().await);
        self.resource_usage.publish_trash_usage(trash_bytes);
    }

    pub async fn entry(&self, uuid: uuid::Uuid, meta: &TrashMeta) -> TrashEntry {
        meta.entry(uuid, &*self.disk_usage.read().await)
    }

    async fn tree_size(&self, path: &Path) -> Option<u64> {
        self.disk_usage
            .read()
            .await
            .get_size(path)
            .map(|space| space.get_logical())
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
        ignored: &RequestIgnored,
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

    pub async fn visible_entry(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        ignored: &RequestIgnored,
    ) -> Option<TrashEntry> {
        let meta = self.get_visible(server, uuid, ignored).await?;

        Some(self.entry(uuid, &meta).await)
    }

    async fn entries(&self) -> Vec<(uuid::Uuid, TrashMeta)> {
        let mut entries: Vec<_> = self
            .entries
            .read()
            .await
            .iter()
            .map(|(uuid, meta)| (*uuid, meta.clone()))
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.1.deleted));

        entries
    }

    pub async fn visible_entries(
        &self,
        server: &crate::server::Server,
        ignored: &RequestIgnored,
    ) -> Vec<TrashEntry> {
        let mut entries = Vec::new();
        for (uuid, meta) in self.entries().await {
            if ignored
                .is_ignored(server, Path::new(&meta.path), meta.file_type())
                .await
            {
                continue;
            }

            entries.push(self.entry(uuid, &meta).await);
        }

        entries
    }

    pub async fn is_inner_ignored(
        &self,
        server: &crate::server::Server,
        meta: &TrashMeta,
        inner: &Path,
        file_type: FileType,
        ignored: &RequestIgnored,
    ) -> bool {
        let mut original = PathBuf::from(meta.path.as_str());
        let mut components = inner.components().peekable();
        while let Some(component) = components.next() {
            original.push(component);

            let file_type = match components.peek() {
                Some(_) => FileType::Dir,
                None => FileType::from_is_dir(file_type.is_dir()),
            };
            if ignored.is_ignored(server, &original, file_type).await {
                return true;
            }
        }

        false
    }

    pub async fn inner_file_type(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        meta: &TrashMeta,
        inner: &Path,
    ) -> Option<FileType> {
        server
            .filesystem
            .async_symlink_metadata(payload_path(uuid, &meta.name).join(inner))
            .await
            .ok()
            .map(|metadata| metadata.file_type().into())
    }

    fn inner_filter(
        server: &crate::server::Server,
        meta: &TrashMeta,
        payload: PathBuf,
        ignored: &RequestIgnored,
    ) -> IsIgnoredFn {
        let server = server.clone();
        let ignored = ignored.clone();
        let original = PathBuf::from(meta.path.as_str());
        let entry_directory = payload.parent().map(Path::to_path_buf);

        IsIgnoredFn::from(move |file_type: FileType, path: PathBuf| {
            if entry_directory.as_deref() == Some(path.as_path()) {
                return IgnoreVerdict::Keep(path);
            }

            let Ok(inner) = path.strip_prefix(&payload) else {
                return IgnoreVerdict::Skip;
            };

            ignored.verdict_as(&server, file_type, &original.join(inner), path)
        })
    }

    async fn resolve_inner(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        inner: &Path,
        ignored: &RequestIgnored,
    ) -> Option<(PathBuf, Arc<dyn VirtualReadableFilesystem>)> {
        let meta = self.get_visible(server, uuid, ignored).await?;
        let file_type = self
            .inner_file_type(server, uuid, &meta, inner)
            .await
            .unwrap_or(FileType::File);
        if self
            .is_inner_ignored(server, &meta, inner, file_type, ignored)
            .await
        {
            return None;
        }

        let payload = payload_path(uuid, &meta.name);
        let filesystem = Self::payload_filesystem(server, &meta, payload.clone(), ignored);

        let path = if inner.as_os_str().is_empty() {
            payload
        } else {
            payload.join(inner)
        };

        Some((path, filesystem))
    }

    fn payload_filesystem(
        server: &crate::server::Server,
        meta: &TrashMeta,
        payload: PathBuf,
        ignored: &RequestIgnored,
    ) -> Arc<dyn VirtualReadableFilesystem> {
        let mut fs = server.filesystem.cap_filesystem.get_virtual(server.clone());
        fs.check_links = true;
        fs.directory_size = true;

        Arc::new(fs.with_is_ignored(Self::inner_filter(server, meta, payload, ignored)))
    }

    pub async fn resolve_virtual(
        &self,
        server: &crate::server::Server,
        path: &Path,
        ignored: &RequestIgnored,
    ) -> Option<(PathBuf, Arc<dyn VirtualReadableFilesystem>)> {
        let mut components = path.components();
        let uuid: uuid::Uuid = components.next()?.as_os_str().to_str()?.parse().ok()?;
        let meta = self.get_visible(server, uuid, ignored).await?;

        let Some(name) = components.next() else {
            let filesystem =
                Self::payload_filesystem(server, &meta, payload_path(uuid, &meta.name), ignored);

            return Some((entry_directory(uuid), filesystem));
        };

        if name.as_os_str() != meta.name.as_str() {
            return None;
        }

        self.resolve_inner(server, uuid, components.as_path(), ignored)
            .await
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
        self.publish_usage().await;
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

        *self.entries.write().await = entries;
        self.publish_usage().await;
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
            self.tree_size(&path).await.unwrap_or(0)
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
            deleted: chrono::Utc::now(),
            source,
            restorations: Vec::new(),
        };

        filesystem
            .async_create_chowned_dir_all(&entry_directory, None)
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

        self.entries.write().await.insert(uuid, meta.clone());
        self.publish_usage().await;

        Ok(self.entry(uuid, &meta).await)
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
        let _guard = self.lock_entry(uuid).await;
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

        self.entries.write().await.remove(&uuid);
        self.entry_locks.invalidate(&uuid).await;

        if let Err(err) = filesystem.truncate_path(entry_directory(uuid)).await {
            tracing::warn!(
                server = %server.uuid,
                entry = %uuid,
                "failed to remove restored trash entry directory: {:#?}",
                err
            );
        }
        self.publish_usage().await;

        let mut entry = self.entry(uuid, &meta).await;
        entry.path = target.to_string_lossy().as_ref().into();
        entry.name = target
            .file_name()
            .map(|name| name.to_string_lossy().as_ref().into())
            .unwrap_or(entry.name);

        Ok(RestoreOutcome::Restored(entry))
    }

    pub async fn restore_inner(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        inner: &Path,
        target: &Path,
        overwrite: bool,
    ) -> Result<InnerRestoreOutcome, anyhow::Error> {
        let _guard = self.lock_entry(uuid).await;
        let Some(mut meta) = self.get(uuid).await else {
            return Ok(InnerRestoreOutcome::Missing);
        };

        if !meta.directory {
            return Ok(InnerRestoreOutcome::Missing);
        }

        let filesystem = &server.filesystem;
        let source = payload_path(uuid, &meta.name).join(inner);
        let Ok(metadata) = filesystem.async_symlink_metadata(&source).await else {
            return Ok(InnerRestoreOutcome::Missing);
        };
        let file_type: FileType = metadata.file_type().into();

        let target = filesystem.relative_path(target);
        if target.as_os_str().is_empty() {
            return Ok(InnerRestoreOutcome::Conflict);
        }

        if filesystem.async_symlink_metadata(&target).await.is_ok() {
            if !overwrite {
                return Ok(InnerRestoreOutcome::Conflict);
            }

            filesystem.truncate_path(&target).await?;
        }

        filesystem
            .rename_path(&source, &target, super::RenameParents::Create)
            .await?;

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

        let restoration = filesystem
            .async_symlink_metadata(&target)
            .await
            .ok()
            .map(|metadata| {
                let (dev, ino) = file_id(&metadata);

                TrashRestoration {
                    id: uuid::Uuid::new_v4(),
                    inner: inner.to_string_lossy().as_ref().into(),
                    destination: target.to_string_lossy().as_ref().into(),
                    directory: metadata.is_dir(),
                    restored_at: chrono::Utc::now(),
                    dev,
                    ino,
                }
            });

        meta.restorations
            .retain(|restoration| !Path::new(restoration.inner.as_str()).starts_with(inner));
        if let Some(restoration) = &restoration {
            meta.restorations.push(restoration.clone());
        }

        let original = Path::new(meta.path.as_str()).join(inner);
        self.finish_inner_move(server, uuid, meta, file_type, &original, &target)
            .await;
        self.purge_if_spent(server, uuid).await;

        Ok(InnerRestoreOutcome::Restored(restoration))
    }

    async fn is_spent(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        meta: &TrashMeta,
    ) -> bool {
        if !meta.directory {
            return false;
        }

        let cutoff = chrono::Utc::now() - RESTORATION_LIFETIME;
        if meta
            .restorations
            .iter()
            .any(|restoration| restoration.restored_at >= cutoff)
        {
            return false;
        }

        match server
            .filesystem
            .async_read_dir(payload_path(uuid, &meta.name))
            .await
        {
            Ok(mut read_dir) => read_dir.next_entry().await.is_none(),
            Err(_) => false,
        }
    }

    /// [`Self::purge_locked`] for entries [`Self::is_spent`] reports.
    async fn purge_if_spent(&self, server: &crate::server::Server, uuid: uuid::Uuid) -> bool {
        let Some(meta) = self.get(uuid).await else {
            return false;
        };
        if !self.is_spent(server, uuid, &meta).await {
            return false;
        }

        match self.purge_locked(server, uuid).await {
            Ok(purged) => purged,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    entry = %uuid,
                    "failed to purge emptied trash entry: {:#?}",
                    err
                );

                false
            }
        }
    }

    async fn purge_spent(&self, server: &crate::server::Server) -> usize {
        let mut purged = 0;
        for (uuid, _) in self.entries().await {
            let _guard = self.lock_entry(uuid).await;
            if self.purge_if_spent(server, uuid).await {
                purged += 1;
            }
        }

        purged
    }

    pub async fn return_restoration(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Result<ReturnOutcome, anyhow::Error> {
        let _guard = self.lock_entry(uuid).await;
        let Some(mut meta) = self.get(uuid).await else {
            return Ok(ReturnOutcome::Unavailable);
        };

        let Some(restoration) = meta
            .restorations
            .iter()
            .find(|restoration| restoration.id == id)
            .cloned()
        else {
            return Ok(ReturnOutcome::Unavailable);
        };

        let filesystem = &server.filesystem;
        let destination = Path::new(restoration.destination.as_str());
        let Ok(metadata) = filesystem.async_symlink_metadata(destination).await else {
            return Ok(ReturnOutcome::Unavailable);
        };

        if file_id(&metadata) != (restoration.dev, restoration.ino)
            || metadata.is_dir() != restoration.directory
        {
            return Ok(ReturnOutcome::Unavailable);
        }

        let slot = payload_path(uuid, &meta.name).join(restoration.inner.as_str());
        if filesystem.async_symlink_metadata(&slot).await.is_ok() {
            return Ok(ReturnOutcome::Unavailable);
        }

        let file_type: FileType = metadata.file_type().into();
        if let Err(err) = filesystem
            .async_clear_inode_flags(destination, file_type)
            .await
        {
            tracing::debug!(
                server = %server.uuid,
                path = %destination.display(),
                "failed to clear inode flags before returning to trash: {}",
                err
            );
        }

        filesystem
            .rename_path(destination, &slot, super::RenameParents::Require)
            .await?;

        meta.restorations.retain(|restoration| restoration.id != id);

        let original = Path::new(meta.path.as_str()).join(restoration.inner.as_str());
        self.finish_inner_move(server, uuid, meta, file_type, destination, &original)
            .await;

        Ok(ReturnOutcome::Returned)
    }

    async fn finish_inner_move(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        mut meta: TrashMeta,
        file_type: FileType,
        from: &Path,
        to: &Path,
    ) {
        if file_type.is_file()
            && from != to
            && let Err(err) = server
                .diff
                .rename_file(&from.to_string_lossy(), &to.to_string_lossy())
                .await
        {
            tracing::error!("failed to rename file in diff storage: {:?}", err);
        }

        if let Some(size) = self.tree_size(&payload_path(uuid, &meta.name)).await {
            meta.size = size;
        }
        if let Err(err) = Self::write_meta(&server.filesystem, uuid, &mut meta).await {
            tracing::error!(
                server = %server.uuid,
                entry = %uuid,
                "failed to write trash entry metadata: {:#?}",
                err
            );
        }

        self.entries.write().await.insert(uuid, meta);
        self.publish_usage().await;
    }

    async fn write_meta(
        filesystem: &super::Filesystem,
        uuid: uuid::Uuid,
        meta: &mut TrashMeta,
    ) -> Result<(), anyhow::Error> {
        let cutoff = chrono::Utc::now() - RESTORATION_LIFETIME;
        meta.restorations
            .retain(|restoration| restoration.restored_at >= cutoff);
        let excess = meta.restorations.len().saturating_sub(MAX_RESTORATIONS);
        meta.restorations.drain(..excess);

        let content = loop {
            let content = serde_json::to_vec(meta)?;
            if content.len() <= META_SIZE_CAP || meta.restorations.is_empty() {
                break content;
            }

            meta.restorations.remove(0);
        };

        let entry_directory = entry_directory(uuid);
        let meta_path = entry_directory.join(META_FILE);
        let temporary_path = entry_directory.join(META_TEMPORARY_FILE);
        let previous_size = filesystem
            .async_symlink_metadata(&meta_path)
            .await
            .map_or(0, |metadata| metadata.len());

        filesystem.async_write(&temporary_path, &content).await?;
        filesystem
            .async_rename(&temporary_path, filesystem, &meta_path)
            .await?;
        filesystem
            .async_allocate_in_path(
                &entry_directory,
                content.len() as i64 - previous_size as i64,
                true,
            )
            .await;

        Ok(())
    }

    async fn purge(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
    ) -> Result<bool, anyhow::Error> {
        let _guard = self.lock_entry(uuid).await;

        self.purge_locked(server, uuid).await
    }

    /// [`Self::purge`] for callers already holding the entry lock.
    async fn purge_locked(
        &self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
    ) -> Result<bool, anyhow::Error> {
        let Some(meta) = self.entries.write().await.remove(&uuid) else {
            return Ok(false);
        };

        if !meta.directory {
            let path = payload_path(uuid, &meta.name);

            if let Err(err) = server.diff.forget_file(&path.to_string_lossy(), None).await {
                tracing::error!("failed to forget file from diff storage: {:?}", err);
            }
        }

        let result = server.filesystem.truncate_path(entry_directory(uuid)).await;
        self.publish_usage().await;

        if let Err(err) = result {
            self.entries.write().await.insert(uuid, meta);

            return Err(err);
        }
        self.entry_locks.invalidate(&uuid).await;

        Ok(true)
    }

    async fn should_purge(
        &self,
        server: &crate::server::Server,
        until: PurgeUntil,
        meta: &TrashMeta,
    ) -> bool {
        match until {
            PurgeUntil::Expired(cutoff) => meta.deleted < cutoff,
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
        let purged = self.purge_expired(server).await
            + self.purge_over_threshold(server).await
            + self.purge_spent(server).await;
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
    use crate::server::{Server, filesystem::virtualfs::CheckedDirectoryListing};

    fn root(server: &Server) -> PathBuf {
        server.filesystem.base_path.to_path_buf()
    }

    async fn trash_world(server: &Server) -> TrashEntry {
        let root = root(server);
        std::fs::create_dir_all(root.join("world/region")).unwrap();
        std::fs::write(root.join("world/level.dat"), b"level").unwrap();
        std::fs::write(root.join("world/region/r.mca"), b"0123456789").unwrap();
        server
            .filesystem
            .async_allocate_in_path(Path::new("world"), 5, true)
            .await;
        server
            .filesystem
            .async_allocate_in_path(Path::new("world/region"), 10, true)
            .await;

        server
            .filesystem
            .trash
            .trash(server, Path::new("world"), TrashSource::Api)
            .await
            .unwrap()
    }

    fn payload(server: &Server, entry: &TrashEntry) -> PathBuf {
        root(server)
            .join(".trash")
            .join(entry.uuid.to_string())
            .join("world")
    }

    async fn restore_region(server: &Server, entry: &TrashEntry, target: &str) -> TrashRestoration {
        let outcome = server
            .filesystem
            .trash
            .restore_inner(
                server,
                entry.uuid,
                Path::new("region"),
                Path::new(target),
                false,
            )
            .await
            .unwrap();
        let InnerRestoreOutcome::Restored(Some(restoration)) = outcome else {
            panic!("expected restore with restoration");
        };

        restoration
    }

    async fn read_through(fs: &Arc<dyn VirtualReadableFilesystem>, path: &Path) -> Option<Vec<u8>> {
        let mut file = fs.async_read_file(&path, None).await.ok()?;
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file.reader, &mut buf)
            .await
            .ok()?;

        Some(buf)
    }

    async fn empty_world(server: &Server) -> (TrashEntry, TrashRestoration) {
        let entry = trash_world(server).await;
        let region = restore_region(server, &entry, "region").await;
        let outcome = server
            .filesystem
            .trash
            .restore_inner(
                server,
                entry.uuid,
                Path::new("level.dat"),
                Path::new("level.dat"),
                false,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, InnerRestoreOutcome::Restored(_)));

        (entry, region)
    }

    async fn age_restorations(server: &Server, uuid: uuid::Uuid) {
        let mut entries = server.filesystem.trash.entries.write().await;
        for restoration in &mut entries.get_mut(&uuid).unwrap().restorations {
            restoration.restored_at = chrono::Utc::now() - chrono::Duration::hours(2);
        }
    }

    // TrashManager
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn trash_then_restore_round_trips_a_directory() {
        Server::with_mock(|server| async move {
            server.filesystem.trash.set_retention(Some(60));
            let root = root(&server);
            let entry = trash_world(&server).await;

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
                    deleted: chrono::Utc::now(),
                    source: TrashSource::Api,
                    restorations: Vec::new(),
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
                .deleted = chrono::Utc::now() - chrono::Duration::hours(2);
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
                .deleted = chrono::Utc::now() - chrono::Duration::hours(1);
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
                .deleted = chrono::Utc::now() - chrono::Duration::hours(1);
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

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn restore_inner_moves_one_child_and_persists_size() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            let entry = trash_world(&server).await;
            assert_eq!(entry.size, 15);

            let restoration = restore_region(&server, &entry, "restored/region").await;
            assert_eq!(restoration.inner, "region");
            assert_eq!(restoration.destination, "restored/region");
            assert!(restoration.directory);

            assert_eq!(
                std::fs::read(root.join("restored/region/r.mca")).unwrap(),
                b"0123456789"
            );
            assert!(!payload(&server, &entry).join("region").exists());
            assert!(payload(&server, &entry).join("level.dat").is_file());

            let meta = server.filesystem.trash.get(entry.uuid).await.unwrap();
            assert_eq!(meta.size, 5);
            assert_eq!(meta.restorations.len(), 1);

            server.filesystem.trash.clear().await;
            server.filesystem.trash.load(&server.filesystem).await;

            let meta = server.filesystem.trash.get(entry.uuid).await.unwrap();
            assert_eq!(meta.size, 5);
            assert_eq!(meta.restorations.len(), 1);
            assert_eq!(meta.restorations[0].id, restoration.id);
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn restore_inner_conflicts_on_occupied_or_empty_target() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            let entry = trash_world(&server).await;
            std::fs::write(root.join("taken"), b"mine").unwrap();

            for target in ["taken", ""] {
                let outcome = server
                    .filesystem
                    .trash
                    .restore_inner(
                        &server,
                        entry.uuid,
                        Path::new("region"),
                        Path::new(target),
                        false,
                    )
                    .await
                    .unwrap();
                assert!(matches!(outcome, InnerRestoreOutcome::Conflict));
            }

            assert_eq!(std::fs::read(root.join("taken")).unwrap(), b"mine");
            assert!(payload(&server, &entry).join("region/r.mca").is_file());
            assert_eq!(
                server.filesystem.trash.get(entry.uuid).await.unwrap().size,
                15
            );
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn return_restoration_puts_item_back_into_its_slot() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            let entry = trash_world(&server).await;
            let restoration = restore_region(&server, &entry, "restored/region").await;

            let outcome = server
                .filesystem
                .trash
                .return_restoration(&server, entry.uuid, restoration.id)
                .await
                .unwrap();
            assert!(matches!(outcome, ReturnOutcome::Returned));
            assert!(!root.join("restored/region").exists());

            let meta = server.filesystem.trash.get(entry.uuid).await.unwrap();
            assert_eq!(meta.size, 15);
            assert!(meta.restorations.is_empty());

            let outcome = server
                .filesystem
                .trash
                .restore(&server, entry.uuid, Path::new("world"), false)
                .await
                .unwrap();
            assert!(matches!(outcome, RestoreOutcome::Restored(_)));
            assert_eq!(
                std::fs::read(root.join("world/region/r.mca")).unwrap(),
                b"0123456789"
            );
            assert!(root.join("world/level.dat").is_file());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn return_restoration_refuses_a_replaced_destination() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            let entry = trash_world(&server).await;
            let outcome = server
                .filesystem
                .trash
                .restore_inner(
                    &server,
                    entry.uuid,
                    Path::new("level.dat"),
                    Path::new("level.dat"),
                    false,
                )
                .await
                .unwrap();
            let InnerRestoreOutcome::Restored(Some(restoration)) = outcome else {
                panic!("expected restore with restoration");
            };

            // rename over the original so the replacement cannot reuse its inode
            std::fs::write(root.join("replacement"), b"other").unwrap();
            std::fs::rename(root.join("replacement"), root.join("level.dat")).unwrap();

            let outcome = server
                .filesystem
                .trash
                .return_restoration(&server, entry.uuid, restoration.id)
                .await
                .unwrap();
            assert!(matches!(outcome, ReturnOutcome::Unavailable));
            assert_eq!(std::fs::read(root.join("level.dat")).unwrap(), b"other");
            assert!(!payload(&server, &entry).join("level.dat").exists());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn return_restoration_refuses_an_occupied_slot() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            let entry = trash_world(&server).await;
            let restoration = restore_region(&server, &entry, "restored/region").await;
            std::fs::write(payload(&server, &entry).join("region"), b"squatter").unwrap();

            let outcome = server
                .filesystem
                .trash
                .return_restoration(&server, entry.uuid, restoration.id)
                .await
                .unwrap();
            assert!(matches!(outcome, ReturnOutcome::Unavailable));
            assert!(root.join("restored/region/r.mca").is_file());
            assert_eq!(
                std::fs::read(payload(&server, &entry).join("region")).unwrap(),
                b"squatter"
            );
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn return_restoration_is_unavailable_once_the_entry_is_restored() {
        Server::with_mock(|server| async move {
            let root = root(&server);
            let entry = trash_world(&server).await;
            let restoration = restore_region(&server, &entry, "restored/region").await;

            let outcome = server
                .filesystem
                .trash
                .restore(&server, entry.uuid, Path::new("world"), false)
                .await
                .unwrap();
            assert!(matches!(outcome, RestoreOutcome::Restored(_)));

            let outcome = server
                .filesystem
                .trash
                .return_restoration(&server, entry.uuid, restoration.id)
                .await
                .unwrap();
            assert!(matches!(outcome, ReturnOutcome::Unavailable));
            assert!(root.join("restored/region/r.mca").is_file());
            assert!(!root.join("world/region").exists());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn is_inner_ignored_matches_rules_against_the_original_path() {
        Server::with_mock(|server| async move {
            let entry = trash_world(&server).await;
            let meta = server.filesystem.trash.get(entry.uuid).await.unwrap();
            let ignored = RequestIgnored::compile(&["world/region"]).unwrap();
            let trash = &server.filesystem.trash;

            assert!(
                trash
                    .is_inner_ignored(&server, &meta, Path::new("region"), FileType::Dir, &ignored)
                    .await
            );
            assert!(
                trash
                    .is_inner_ignored(
                        &server,
                        &meta,
                        Path::new("region/r.mca"),
                        FileType::File,
                        &ignored
                    )
                    .await
            );
            assert!(
                !trash
                    .is_inner_ignored(
                        &server,
                        &meta,
                        Path::new("level.dat"),
                        FileType::File,
                        &ignored
                    )
                    .await
            );
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn virtual_listing_hides_ignored_children() {
        Server::with_mock(|server| async move {
            let entry = trash_world(&server).await;
            let ignored = RequestIgnored::compile(&["world/region"]).unwrap();

            let (path, fs) = server
                .filesystem
                .resolve_readable_fs_ignoring(
                    &server,
                    &entry_directory(entry.uuid).join("world"),
                    &ignored,
                )
                .await;
            let listing = fs
                .async_read_dir_checked(
                    &path,
                    None,
                    1,
                    IsIgnoredFn::default(),
                    crate::models::DirectorySortingMode::default(),
                )
                .await
                .unwrap();
            let CheckedDirectoryListing::Listing(listing) = listing else {
                panic!("expected listing");
            };
            let names: Vec<_> = listing
                .entries
                .iter()
                .map(|entry| entry.name.to_string())
                .collect();
            assert_eq!(names, ["level.dat"]);
            assert_eq!(listing.total_entries, 1);
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn resolve_inner_reads_a_file_inside_a_directory_entry() {
        Server::with_mock(|server| async move {
            let entry = trash_world(&server).await;

            let (path, fs) = server
                .filesystem
                .trash
                .resolve_inner(
                    &server,
                    entry.uuid,
                    Path::new("level.dat"),
                    &RequestIgnored::default(),
                )
                .await
                .unwrap();
            assert_eq!(read_through(&fs, &path).await.unwrap(), b"level");
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn resolve_inner_reads_a_file_entry_with_an_empty_inner_path() {
        Server::with_mock(|server| async move {
            std::fs::write(root(&server).join("a.txt"), b"alpha").unwrap();
            let entry = server
                .filesystem
                .trash
                .trash(&server, Path::new("a.txt"), TrashSource::Api)
                .await
                .unwrap();

            let (path, fs) = server
                .filesystem
                .trash
                .resolve_inner(
                    &server,
                    entry.uuid,
                    Path::new(""),
                    &RequestIgnored::default(),
                )
                .await
                .unwrap();
            assert_eq!(read_through(&fs, &path).await.unwrap(), b"alpha");
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn resolve_inner_filesystem_denies_paths_outside_the_payload() {
        Server::with_mock(|server| async move {
            std::fs::write(root(&server).join("secret.txt"), b"secret").unwrap();
            let entry = trash_world(&server).await;

            let (_, fs) = server
                .filesystem
                .trash
                .resolve_inner(
                    &server,
                    entry.uuid,
                    Path::new(""),
                    &RequestIgnored::default(),
                )
                .await
                .unwrap();

            let meta = Path::new(".trash")
                .join(entry.uuid.to_string())
                .join("meta.json");
            assert!(fs.async_metadata(&meta).await.is_err());
            assert!(read_through(&fs, &meta).await.is_none());
            assert!(read_through(&fs, Path::new("secret.txt")).await.is_none());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn resolve_inner_does_not_follow_symlinks_out_of_the_payload() {
        Server::with_mock(|server| async move {
            std::fs::write(root(&server).join("secret.txt"), b"secret").unwrap();
            let entry = trash_world(&server).await;
            let payload = payload(&server, &entry);
            std::os::unix::fs::symlink("../../../secret.txt", payload.join("escape")).unwrap();
            std::os::unix::fs::symlink("../meta.json", payload.join("meta")).unwrap();
            assert!(payload.join("escape").is_file());
            assert!(payload.join("meta").is_file());

            let trash = &server.filesystem.trash;
            for link in ["escape", "meta"] {
                let (path, fs) = trash
                    .resolve_inner(
                        &server,
                        entry.uuid,
                        Path::new(link),
                        &RequestIgnored::default(),
                    )
                    .await
                    .unwrap();
                assert!(read_through(&fs, &path).await.is_none(), "{link}");
            }
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn resolve_inner_does_not_follow_symlinks_to_ignored_files() {
        Server::with_mock(|server| async move {
            let entry = trash_world(&server).await;
            let payload = payload(&server, &entry);
            std::fs::write(payload.join("hidden.txt"), b"hidden").unwrap();
            std::os::unix::fs::symlink("hidden.txt", payload.join("link")).unwrap();

            let trash = &server.filesystem.trash;
            let (path, fs) = trash
                .resolve_inner(
                    &server,
                    entry.uuid,
                    Path::new("link"),
                    &RequestIgnored::default(),
                )
                .await
                .unwrap();
            assert_eq!(read_through(&fs, &path).await.unwrap(), b"hidden");

            let ignored = RequestIgnored::compile(&["world/hidden.txt"]).unwrap();
            let (path, fs) = trash
                .resolve_inner(&server, entry.uuid, Path::new("link"), &ignored)
                .await
                .unwrap();
            assert!(read_through(&fs, &path).await.is_none());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn resolve_inner_rejects_ignored_paths_and_ancestors() {
        Server::with_mock(|server| async move {
            let entry = trash_world(&server).await;
            let trash = &server.filesystem.trash;
            let ignored = RequestIgnored::compile(&["world/region"]).unwrap();

            assert!(
                trash
                    .resolve_inner(&server, entry.uuid, Path::new("region"), &ignored)
                    .await
                    .is_none()
            );
            assert!(
                trash
                    .resolve_inner(&server, entry.uuid, Path::new("region/r.mca"), &ignored)
                    .await
                    .is_none()
            );
            assert!(
                trash
                    .resolve_inner(&server, entry.uuid, Path::new("level.dat"), &ignored)
                    .await
                    .is_some()
            );
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn emptied_entry_survives_while_a_restoration_can_be_undone() {
        Server::with_mock(|server| async move {
            let (entry, region) = empty_world(&server).await;

            assert!(server.filesystem.trash.get(entry.uuid).await.is_some());
            assert_eq!(server.filesystem.trash.run_maintenance(&server).await, 0);
            assert!(server.filesystem.trash.get(entry.uuid).await.is_some());

            let outcome = server
                .filesystem
                .trash
                .return_restoration(&server, entry.uuid, region.id)
                .await
                .unwrap();
            assert!(matches!(outcome, ReturnOutcome::Returned));
            assert!(payload(&server, &entry).join("region/r.mca").is_file());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn emptied_entry_is_purged_once_restorations_expire() {
        Server::with_mock(|server| async move {
            let (entry, _) = empty_world(&server).await;
            age_restorations(&server, entry.uuid).await;

            assert_eq!(server.filesystem.trash.run_maintenance(&server).await, 1);
            assert!(server.filesystem.trash.get(entry.uuid).await.is_none());
            assert!(
                !root(&server)
                    .join(".trash")
                    .join(entry.uuid.to_string())
                    .exists()
            );
            assert!(root(&server).join("region/r.mca").is_file());
            assert!(root(&server).join("level.dat").is_file());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn non_empty_entry_is_never_spent() {
        Server::with_mock(|server| async move {
            let entry = trash_world(&server).await;
            restore_region(&server, &entry, "region").await;
            age_restorations(&server, entry.uuid).await;

            assert_eq!(server.filesystem.trash.run_maintenance(&server).await, 0);
            assert!(server.filesystem.trash.get(entry.uuid).await.is_some());
            assert!(payload(&server, &entry).join("level.dat").is_file());
        });
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn file_entry_is_never_spent() {
        Server::with_mock(|server| async move {
            std::fs::write(root(&server).join("a.txt"), b"").unwrap();
            let entry = server
                .filesystem
                .trash
                .trash(&server, Path::new("a.txt"), TrashSource::Api)
                .await
                .unwrap();

            assert_eq!(server.filesystem.trash.run_maintenance(&server).await, 0);
            assert!(server.filesystem.trash.get(entry.uuid).await.is_some());
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

    // inner_path
    #[test]
    fn inner_path_normalizes_and_rejects_parent_components() {
        assert_eq!(inner_path(""), Some(PathBuf::new()));
        assert_eq!(inner_path("/"), Some(PathBuf::new()));
        assert_eq!(inner_path("/a/./b/"), Some(PathBuf::from("a/b")));
        assert_eq!(inner_path("a/../b"), None);
        assert_eq!(inner_path("../a"), None);
        assert_eq!(inner_path("/.."), None);
    }
}
