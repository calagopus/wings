use crate::{
    routes::MimeCacheValue,
    server::{
        filesystem::virtualfs::{
            AsyncDirectoryStreamWalkFn, IsIgnoredFn, VirtualReadableFilesystem,
            VirtualWritableFilesystem,
        },
        resources::ResourceUsageWatchExt,
    },
    utils::{PortablePermissions, PortableSizeExt},
};
use cap_std::fs::Metadata;
use compact_str::ToCompactString;
use std::{
    collections::HashMap,
    fmt::Debug,
    hint::unreachable_unchecked,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{RwLock, RwLockReadGuard},
};

pub mod archive;
pub mod cap;
pub mod disk_checker;
pub mod file;
pub mod inotify;
pub mod limiter;
pub mod operations;
pub mod pull;
pub mod sqlite;
pub mod usage;
pub mod virtualfs;

pub fn build_gitignore_matcher<S: AsRef<str>>(
    lines: impl Iterator<Item = S>,
) -> Result<ignore::gitignore::Gitignore, ignore::Error> {
    let mut builder = ignore::gitignore::GitignoreBuilder::new("");
    for line in lines {
        builder.add_line(None, line.as_ref()).ok();
    }

    builder.build()
}

#[inline]
pub fn encode_mode(mode: u32) -> compact_str::CompactString {
    let mut mode_str = compact_str::CompactString::default();

    #[cfg(unix)]
    mode_str.push(match rustix::fs::FileType::from_raw_mode(mode) {
        rustix::fs::FileType::RegularFile => '-',
        rustix::fs::FileType::Directory => 'd',
        rustix::fs::FileType::Symlink => 'l',
        rustix::fs::FileType::BlockDevice => 'b',
        rustix::fs::FileType::CharacterDevice => 'c',
        rustix::fs::FileType::Socket => 's',
        rustix::fs::FileType::Fifo => 'p',
        rustix::fs::FileType::Unknown => '?',
    });
    #[cfg(not(unix))]
    mode_str.push('?');

    for i in 0u8..9 {
        if mode & (1 << (8 - i)) != 0 {
            mode_str.push(match i.rem_euclid(3) {
                0 => 'r',
                1 => 'w',
                2 => 'x',
                _ => unsafe { unreachable_unchecked() },
            });
        } else {
            mode_str.push('-');
        }
    }

    mode_str
}

pub struct Filesystem {
    uuid: uuid::Uuid,
    app_state: crate::routes::State,

    disk_checker_rescan: Arc<tokio::sync::Notify>,
    pub disk_checker_state_dirty: Arc<AtomicBool>,
    pub chown_state_dirty: Arc<AtomicBool>,
    chown_refused: Arc<AtomicBool>,
    pub disk_checker: tokio::task::JoinHandle<()>,
    config: Arc<crate::config::Config>,

    pub base_path: PathBuf,
    base_fs_mount_path: RwLock<PathBuf>,
    cap_filesystem: cap::CapFilesystem,
    server_notifier: inotify::InotifyServerNotifier,
    use_server_notifier: Arc<AtomicBool>,

    resource_usage: tokio::sync::watch::Sender<crate::server::resources::ResourceUsage>,
    disk_limit: AtomicI64,
    disk_usage_delta_cached: Arc<AtomicI64>,
    disk_usage_cached_logical: Arc<AtomicU64>,
    disk_usage_cached_physical: Arc<AtomicU64>,
    pub disk_usage: Arc<RwLock<usage::DiskUsage>>,
    pub last_disk_check: Arc<AtomicU64>,
    pub disk_check_completed: Arc<tokio::sync::Notify>,
    disk_ignored: arc_swap::ArcSwap<ignore::gitignore::Gitignore>,

    pub archive_fs_cache: moka::future::Cache<PathBuf, Arc<dyn VirtualReadableFilesystem>>,
    pub pulls: RwLock<HashMap<uuid::Uuid, Arc<RwLock<pull::Download>>>>,
    pub operations: operations::OperationManager,
}

impl Filesystem {
    pub fn new(
        uuid: uuid::Uuid,
        app_state: crate::routes::State,
        disk_limit: u64,
        sender: tokio::sync::broadcast::Sender<crate::server::websocket::WebsocketMessage>,
        resource_usage: tokio::sync::watch::Sender<crate::server::resources::ResourceUsage>,
        config: Arc<crate::config::Config>,
        deny_list: &[compact_str::CompactString],
    ) -> Self {
        let base_path = config.data_path(uuid);

        let disk_checker_state_dirty = Arc::new(AtomicBool::new(true));
        let chown_state_dirty = Arc::new(AtomicBool::new(true));

        let disk_usage = Arc::new(RwLock::new(usage::DiskUsage::default()));
        let disk_usage_cached_logical = Arc::new(AtomicU64::new(0));
        let disk_usage_cached_physical = Arc::new(AtomicU64::new(0));
        let disk_ignored = build_gitignore_matcher(deny_list.iter())
            .unwrap_or_else(|_| ignore::gitignore::Gitignore::empty());

        let cap_filesystem = cap::CapFilesystem::new_uninitialized(&base_path);
        let server_notifier = inotify::InotifyServerNotifier::new(
            base_path.clone(),
            [
                Arc::clone(&disk_checker_state_dirty),
                Arc::clone(&chown_state_dirty),
            ],
        );
        let use_server_notifier = Arc::new(AtomicBool::new(false));
        let disk_checker_rescan = Arc::new(tokio::sync::Notify::new());
        let disk_check_completed = Arc::new(tokio::sync::Notify::new());
        let last_disk_check = Arc::new(AtomicU64::new(0));

        Self {
            uuid,
            app_state,
            disk_checker_rescan: Arc::clone(&disk_checker_rescan),
            disk_checker_state_dirty: Arc::clone(&disk_checker_state_dirty),
            chown_state_dirty,
            chown_refused: Arc::new(AtomicBool::new(false)),
            disk_checker: tokio::spawn(disk_checker::run(disk_checker::DiskCheckerContext {
                config: Arc::clone(&config),
                disk_usage: Arc::clone(&disk_usage),
                disk_usage_cached_logical: Arc::clone(&disk_usage_cached_logical),
                disk_usage_cached_physical: Arc::clone(&disk_usage_cached_physical),
                disk_checker_state_dirty: Arc::clone(&disk_checker_state_dirty),
                disk_checker_rescan: Arc::clone(&disk_checker_rescan),
                disk_check_completed: Arc::clone(&disk_check_completed),
                cap_filesystem: cap_filesystem.clone(),
                server_notifier: server_notifier.clone(),
                use_server_notifier: Arc::clone(&use_server_notifier),
                last_disk_check: Arc::clone(&last_disk_check),
                resource_usage: resource_usage.clone(),
            })),
            config: Arc::clone(&config),

            base_path: base_path.clone(),
            base_fs_mount_path: RwLock::new(base_path),
            cap_filesystem,
            server_notifier,
            use_server_notifier,

            resource_usage,
            disk_limit: AtomicI64::new(disk_limit as i64),
            disk_usage_delta_cached: Arc::new(AtomicI64::new(0)),
            disk_usage_cached_logical,
            disk_usage_cached_physical,
            disk_usage,
            last_disk_check,
            disk_check_completed,
            disk_ignored: arc_swap::ArcSwap::from_pointee(disk_ignored),

            archive_fs_cache: moka::future::CacheBuilder::new(8)
                .time_to_idle(std::time::Duration::from_mins(1))
                .build(),
            pulls: RwLock::new(HashMap::new()),
            operations: operations::OperationManager::new(sender),
        }
    }

    #[inline]
    pub fn get_logical_cached_size(&self) -> u64 {
        self.disk_usage_cached_logical.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn get_physical_cached_size(&self) -> u64 {
        self.disk_usage_cached_physical.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn rerun_disk_checker(&self) {
        self.server_notifier.clear_modified_paths();
        self.disk_checker_rescan.notify_one();
    }

    #[inline]
    pub fn write_tracking_active(&self) -> bool {
        self.use_server_notifier.load(Ordering::Relaxed) && self.server_notifier.is_trusted()
    }

    pub async fn update_ignored(&self, deny_list: &[impl AsRef<str>]) {
        if let Ok(disk_ignored) = build_gitignore_matcher(deny_list.iter()) {
            self.disk_ignored.store(Arc::new(disk_ignored));
        }
    }

    fn deny_filter(server: &crate::server::Server) -> IsIgnoredFn {
        let (sync_server, async_server) = (server.clone(), server.clone());

        IsIgnoredFn::new(
            move |file_type, path: PathBuf| {
                if sync_server.filesystem.is_ignored(&path, file_type) {
                    None
                } else {
                    Some(path)
                }
            },
            move |file_type, path: PathBuf| {
                let server = async_server.clone();

                async move {
                    if server.filesystem.async_is_ignored(&path, file_type).await {
                        None
                    } else {
                        Some(path)
                    }
                }
            },
        )
    }

    pub async fn probe_file_type(&self, path: impl AsRef<Path>) -> cap::FileType {
        self.async_symlink_metadata(path)
            .await
            .map(|metadata| metadata.file_type().into())
            .unwrap_or(cap::FileType::File)
    }

    pub fn is_ignored(&self, path: &Path, file_type: cap::FileType) -> bool {
        let path = if file_type.is_symlink() {
            self.canonicalize(path)
                .unwrap_or_else(|_| self.relative_path(path))
        } else {
            self.relative_path(path)
        };

        if path.as_os_str().is_empty() {
            return false;
        }

        self.disk_ignored
            .load()
            .matched(path, file_type.is_dir())
            .is_ignore()
    }

    pub async fn async_is_ignored(&self, path: &Path, file_type: cap::FileType) -> bool {
        let path = if file_type.is_symlink() {
            self.async_canonicalize(path)
                .await
                .unwrap_or_else(|_| self.relative_path(path))
        } else {
            self.relative_path(path)
        };

        if path.as_os_str().is_empty() {
            return false;
        }

        self.disk_ignored
            .load()
            .matched(path, file_type.is_dir())
            .is_ignore()
    }

    pub fn get_ignored(&self) -> ignore::gitignore::Gitignore {
        (**self.disk_ignored.load()).clone()
    }

    pub async fn diff_key(&self, path: &Path) -> PathBuf {
        self.async_canonicalize(path)
            .await
            .unwrap_or_else(|_| self.relative_path(path))
    }

    pub async fn pulls(
        &self,
    ) -> RwLockReadGuard<'_, HashMap<uuid::Uuid, Arc<RwLock<pull::Download>>>> {
        if let Ok(mut pulls) = self.pulls.try_write() {
            let operations = self.operations.operations().await;

            for key in pulls.keys().copied().collect::<Vec<_>>() {
                if !operations.contains_key(&key) {
                    pulls.remove(&key);
                }
            }
        }

        self.pulls.read().await
    }

    #[inline]
    pub fn get_disk_limiter<'a>(&'a self) -> Box<dyn limiter::DiskLimiterExt + 'a> {
        self.config
            .load()
            .system
            .disk_limiter_mode
            .get_limiter(self)
    }

    #[inline]
    pub async fn limiter_usage(&self) -> u64 {
        self.get_disk_limiter()
            .disk_usage()
            .await
            .unwrap_or_else(|_| self.get_physical_cached_size())
    }

    #[inline]
    pub async fn update_disk_limit(&self, limit: u64) {
        self.disk_limit.store(limit as i64, Ordering::Relaxed);

        if let Err(err) = self.get_disk_limiter().update_disk_limit(limit).await {
            tracing::warn!("failed to update disk limit: {:?}", err);
        }
    }

    /// Sets the base fs path, this is the path used by the container filesystem
    /// It may differ from the base_path for some disk limiters.
    ///
    /// DO NOT CALL THIS FUNCTION UNLESS YOU KNOW WHAT YOU ARE DOING
    pub async fn set_base_fs_mount_path(&self, path: PathBuf) -> Result<(), std::io::Error> {
        let mut base_fs_path = self.base_fs_mount_path.write().await;
        if *base_fs_path == path {
            return Ok(());
        }
        *base_fs_path = path;

        Ok(())
    }

    /// Returns the base fs path, this is the path used by the container filesystem
    /// It may differ from the base_path for some disk limiters
    pub async fn get_base_fs_mount_path(&self) -> PathBuf {
        self.base_fs_mount_path.read().await.clone()
    }

    #[inline]
    pub fn disk_limit(&self) -> i64 {
        self.disk_limit.load(Ordering::Relaxed)
    }

    #[inline]
    pub async fn is_full(&self) -> bool {
        self.disk_limit() != 0 && self.limiter_usage().await >= self.disk_limit() as u64
    }

    /// Checks whether `delta` additional bytes would still fit within the disk limit,
    /// without reserving them. Writers that go through [`file::ServerFile`] account for
    /// their own bytes, so callers that only want to fail early must not allocate here.
    #[inline]
    pub fn has_headroom(&self, delta: i64) -> bool {
        let limit = self.disk_limit();
        if limit <= 0 || delta <= 0 {
            return true;
        }

        delta as u64 <= (limit as u64).saturating_sub(self.get_physical_cached_size())
    }

    #[inline]
    pub fn base(&self) -> compact_str::CompactString {
        self.base_path.to_string_lossy().to_compact_string()
    }

    #[inline]
    pub fn path_to_components(&self, path: &Path) -> Vec<String> {
        self.relative_path(path)
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect()
    }

    pub async fn resolve_readable_fs(
        &self,
        server: &crate::server::Server,
        path: &Path,
    ) -> (PathBuf, Arc<dyn VirtualReadableFilesystem>) {
        let path = self.relative_path(path);

        'backupfs: {
            if !self.config.load().system.backups.mounting.enabled {
                break 'backupfs;
            }

            if !path.starts_with(&self.config.load().system.backups.mounting.path) {
                break 'backupfs;
            }

            let backup_path =
                match path.strip_prefix(&self.config.load().system.backups.mounting.path) {
                    Ok(p) => p,
                    Err(_) => break 'backupfs,
                };
            let uuid: uuid::Uuid = match backup_path
                .components()
                .next()
                .and_then(|c| c.as_os_str().to_string_lossy().parse().ok())
            {
                Some(u) => u,
                None => break 'backupfs,
            };

            if !server.configuration.read().await.backups.contains(&uuid) {
                break 'backupfs;
            }

            match self.app_state.backup_manager.browse(server, uuid).await {
                Ok(Some(backup)) => {
                    let path = match backup_path.strip_prefix(uuid.to_string()) {
                        Ok(p) => p.to_path_buf(),
                        Err(_) => PathBuf::new(),
                    };

                    return (path, backup);
                }
                Ok(None) => break 'backupfs,
                Err(err) => {
                    tracing::error!(server = %server.uuid, backup = %uuid, "failed to find backup: {:?}", err);
                    break 'backupfs;
                }
            }
        }

        'archivefs: {
            let mut archive_path = PathBuf::new();
            let mut found = false;
            for component in path.components() {
                let Some(component_str) = component.as_os_str().to_str() else {
                    break 'archivefs;
                };

                archive_path.push(component);

                if component_str.ends_with(".zip")
                    || component_str.ends_with(".7z")
                    || component_str.ends_with(".ddup")
                {
                    found = true;
                    break;
                }
            }

            if !found || archive_path == PathBuf::new() {
                break 'archivefs;
            }

            if self
                .async_is_ignored(&archive_path, cap::FileType::File)
                .await
            {
                break 'archivefs;
            }

            let inner_path = match path.strip_prefix(&archive_path) {
                Ok(p) => p,
                Err(_) => break 'archivefs,
            };

            if self
                .async_metadata(&archive_path)
                .await
                .ok()
                .is_none_or(|m| !m.is_file())
            {
                break 'archivefs;
            }

            if let Some(archive_fs) = self.archive_fs_cache.get(&archive_path).await {
                return (inner_path.to_path_buf(), archive_fs);
            }

            let archive_fs: Arc<dyn VirtualReadableFilesystem> =
                match archive_path.extension().and_then(|ext| ext.to_str()) {
                    Some("zip") => {
                        match virtualfs::archive::zip::VirtualZipArchive::open(
                            server.clone(),
                            &archive_path,
                        )
                        .await
                        {
                            Ok(archive) => Arc::new(archive),
                            Err(err) => {
                                tracing::error!(
                                    "failed to open archivefs zip archive {}: {:?}",
                                    archive_path.display(),
                                    err
                                );
                                break 'archivefs;
                            }
                        }
                    }
                    Some("7z") => {
                        match virtualfs::archive::seven_zip::VirtualSevenZipArchive::open(
                            server.clone(),
                            &archive_path,
                        )
                        .await
                        {
                            Ok(archive) => Arc::new(archive),
                            Err(err) => {
                                tracing::error!(
                                    "failed to open archivefs 7z archive {}: {:?}",
                                    archive_path.display(),
                                    err
                                );
                                break 'archivefs;
                            }
                        }
                    }
                    Some("ddup") => {
                        match virtualfs::archive::ddup_bak::VirtualDdupBakArchive::open(
                            server.clone(),
                            &archive_path,
                        )
                        .await
                        {
                            Ok(archive) => Arc::new(archive),
                            Err(err) => {
                                tracing::error!(
                                    "failed to open archivefs ddup archive {}: {:?}",
                                    archive_path.display(),
                                    err
                                );
                                break 'archivefs;
                            }
                        }
                    }
                    _ => break 'archivefs,
                };

            self.archive_fs_cache
                .insert(archive_path, archive_fs.clone())
                .await;

            return (inner_path.to_path_buf(), archive_fs);
        }

        let (mount_match, mount_infos) = {
            let server_config = server.configuration.read().await;
            let allowed = if server_config.mounts.is_empty() {
                crate::server::configuration::AllowedMounts::default()
            } else {
                crate::server::configuration::AllowedMounts::load(&server.app_state.config).await
            };

            let mut match_result = None;
            let mut infos = Vec::new();

            for mount in &server_config.mounts {
                let Some(relative_target) = mount.target.strip_prefix("/home/container/") else {
                    continue;
                };
                if relative_target.is_empty() {
                    continue;
                }
                let Ok(source_path) = mount.resolve_allowed_source(&allowed).await else {
                    continue;
                };

                infos.push(virtualfs::mount::MountInfo {
                    relative_target: PathBuf::from(relative_target),
                });

                if match_result.is_none() {
                    let relative_target_path = Path::new(relative_target);
                    if path.starts_with(relative_target_path)
                        && let Ok(inner_path) = path.strip_prefix(relative_target_path)
                    {
                        match_result =
                            Some((inner_path.to_path_buf(), source_path, mount.read_only));
                    }
                }
            }

            (match_result, infos)
        };

        if let Some((inner_path, source_path, read_only)) = mount_match {
            match cap::CapFilesystem::new(&source_path).await {
                Ok(cap_fs) => {
                    let mut fs = cap_fs.get_virtual(server.clone());
                    fs.is_primary_server_fs = false;
                    fs.is_writable = !read_only;

                    return (inner_path, Arc::new(fs));
                }
                Err(err) => {
                    tracing::warn!(
                        server = %server.uuid,
                        "failed to open mount source for browsing: {:?}",
                        err
                    );
                }
            }
        }

        let mut fs = self.cap_filesystem.get_virtual(server.clone());
        fs.is_primary_server_fs = true;
        fs.is_writable = true;
        let fs = fs.with_is_ignored(Self::deny_filter(server));

        (
            path,
            Arc::new(virtualfs::mount::VirtualMountFilesystem {
                inner: fs,
                mounts: mount_infos,
            }),
        )
    }

    pub async fn resolve_writable_fs(
        &self,
        server: &crate::server::Server,
        path: impl AsRef<Path>,
    ) -> (PathBuf, Arc<dyn VirtualWritableFilesystem>) {
        let path = self.relative_path(path.as_ref());

        let mount_match = {
            let server_config = server.configuration.read().await;
            let allowed = if server_config.mounts.is_empty() {
                crate::server::configuration::AllowedMounts::default()
            } else {
                crate::server::configuration::AllowedMounts::load(&server.app_state.config).await
            };

            let mut result: Option<(PathBuf, PathBuf, bool)> = None;
            for mount in &server_config.mounts {
                let Some(relative_target) = mount.target.strip_prefix("/home/container/") else {
                    continue;
                };
                if relative_target.is_empty() {
                    continue;
                }

                let relative_target_path = Path::new(relative_target);
                if !path.starts_with(relative_target_path) {
                    continue;
                }

                let Ok(source_path) = mount.resolve_allowed_source(&allowed).await else {
                    continue;
                };

                if let Ok(inner_path) = path.strip_prefix(relative_target_path) {
                    result = Some((inner_path.to_path_buf(), source_path, mount.read_only));
                    break;
                }
            }
            result
        };

        if let Some((inner_path, source_path, read_only)) = mount_match {
            match cap::CapFilesystem::new(&source_path).await {
                Ok(cap_fs) => {
                    let mut fs = cap_fs.get_virtual(server.clone());
                    fs.is_primary_server_fs = false;
                    fs.is_writable = !read_only;

                    return (inner_path, Arc::new(fs));
                }
                Err(err) => {
                    tracing::warn!(
                        server = %server.uuid,
                        "failed to open mount source for writable fs: {:?}",
                        err
                    );
                    if read_only {
                        let mut fs = self.cap_filesystem.get_virtual(server.clone());
                        fs.is_primary_server_fs = true;
                        fs.is_writable = false;
                        let fs = fs.with_is_ignored(Self::deny_filter(server));

                        return (inner_path, Arc::new(fs));
                    }
                }
            }
        }

        let mut fs = self.cap_filesystem.get_virtual(server.clone());
        fs.is_primary_server_fs = true;
        fs.is_writable = true;
        let fs = fs.with_is_ignored(Self::deny_filter(server));

        (path, Arc::new(fs))
    }

    pub async fn truncate_path(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = self.async_symlink_metadata(&path).await?;

        if metadata.is_dir() {
            self.async_remove_dir_all(&path).await?;

            let mut disk_usage = self.disk_usage.write().await;
            if let Some(removed) = disk_usage.remove_path(&path) {
                drop(disk_usage);
                self.try_update_atomics(
                    usage::SpaceDelta::new(
                        -(removed.space.get_logical() as i64),
                        -(removed.space.get_physical() as i64),
                    ),
                    false,
                );
            }
        } else {
            let size = metadata.len() as i64;
            self.async_remove_file(&path).await?;

            if let Some(parent) = path.parent() {
                self.async_allocate_in_path(parent, -size, false).await;
            }
        }

        Ok(())
    }

    pub async fn rename_path(
        &self,
        old_path: impl AsRef<Path>,
        new_path: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
        let old_path = self.relative_path(old_path.as_ref());
        let new_path = self.relative_path(new_path.as_ref());

        if let Some(parent) = new_path.parent() {
            self.async_create_dir_all(parent).await?;
        }

        let old_metadata = self.async_metadata(&old_path).await?;
        let new_metadata = self.async_metadata(&new_path).await.ok();
        let is_dir = old_metadata.is_dir();

        let old_parent = self
            .async_canonicalize(match old_path.parent() {
                Some(parent) => parent,
                None => return Err(anyhow::anyhow!("failed to get old path parent")),
            })
            .await
            .unwrap_or_default();
        let new_parent = self
            .async_canonicalize(match new_path.parent() {
                Some(parent) => parent,
                None => return Err(anyhow::anyhow!("failed to get new path parent")),
            })
            .await
            .unwrap_or_default();

        let abs_new_path = new_parent.join(match new_path.file_name() {
            Some(name) => name,
            None => return Err(anyhow::anyhow!("failed to get new path file name")),
        });

        self.async_rename(&old_path, &self.cap_filesystem, &new_path)
            .await?;

        if is_dir {
            let mut disk_usage = self.disk_usage.write().await;

            let path = disk_usage.remove_path(&old_path);
            if let Some(path) = path {
                disk_usage.add_directory(
                    &abs_new_path
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().to_string())
                        .collect::<Vec<_>>(),
                    path,
                );
            }
        } else {
            let size = old_metadata.len() as i64;

            if let Some(new_metadata) = new_metadata {
                let new_size = new_metadata.len() as i64;
                let size_delta = new_size - size;

                self.async_allocate_in_path(&old_parent, -size, true).await;
                self.async_allocate_in_path(&new_parent, size_delta, true)
                    .await;
            } else {
                self.async_allocate_in_path(&old_parent, -size, true).await;
                self.async_allocate_in_path(&new_parent, size, true).await;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn copy_path(
        &self,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        server: &crate::server::Server,
        metadata: virtualfs::FileMetadata,
        path: PathBuf,
        filesystem: Arc<dyn VirtualReadableFilesystem>,
        destination_path: PathBuf,
        destination_filesystem: Arc<dyn VirtualWritableFilesystem>,
    ) -> Result<(), anyhow::Error> {
        if metadata.file_type.is_file() {
            if filesystem.is_primary_server_fs() && destination_filesystem.is_primary_server_fs() {
                server
                    .filesystem
                    .async_quota_copy(
                        &path,
                        &destination_path,
                        server,
                        progress.clone_bytes().as_ref(),
                    )
                    .await?;
                destination_filesystem
                    .async_set_permissions(
                        &destination_path,
                        metadata.file_type,
                        metadata.permissions,
                    )
                    .await?;
            } else {
                let file_read = filesystem.async_read_file(&path, None).await?;
                let mut reader = progress.async_counting_reader(file_read.reader);

                if let Some(parent) = destination_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    destination_filesystem.async_create_dir_all(&parent).await?;
                }

                let mut writer = destination_filesystem
                    .async_create_file(&destination_path)
                    .await?;
                destination_filesystem
                    .async_set_permissions(
                        &destination_path,
                        metadata.file_type,
                        metadata.permissions,
                    )
                    .await?;

                tokio::io::copy(&mut reader, &mut writer).await?;
                writer.shutdown().await?;
            }

            progress.increment_files();
        } else {
            destination_filesystem
                .async_create_dir_all(&destination_path)
                .await?;
            destination_filesystem
                .async_set_permissions(&destination_path, metadata.file_type, metadata.permissions)
                .await?;

            let ignored = if filesystem.is_primary_server_fs() {
                server.filesystem.get_ignored().into()
            } else {
                Default::default()
            };
            let mut walker = filesystem.async_walk_dir_stream(&path, ignored).await?;

            walker
                .run_multithreaded(
                    server.app_state.config.load().api.file_copy_threads,
                    AsyncDirectoryStreamWalkFn::from({
                        let server = server.clone();
                        let filesystem = filesystem.clone();
                        let source_path = Arc::new(path);
                        let destination_path = Arc::new(destination_path);
                        let destination_filesystem = destination_filesystem.clone();
                        let progress = progress.clone();

                        move |entry: virtualfs::VirtualWalkEntry, stream| {
                            let path = entry.path;

                            let server = server.clone();
                            let filesystem = filesystem.clone();
                            let source_path = Arc::clone(&source_path);
                            let destination_path = Arc::clone(&destination_path);
                            let destination_filesystem = destination_filesystem.clone();
                            let progress = progress.clone();

                            async move {
                                let metadata =
                                    match filesystem.async_symlink_metadata(&path).await {
                                        Ok(metadata) => metadata,
                                        Err(err) => {
                                            tracing::debug!(
                                                path = %path.display(),
                                                "skipping copy entry, failed to stat: {:?}",
                                                err,
                                            );
                                            return Ok(());
                                        }
                                    };

                                let relative_path = match path.strip_prefix(&*source_path) {
                                    Ok(p) => p,
                                    Err(_) => {
                                        tracing::debug!(
                                            path = %path.display(),
                                            source = %source_path.display(),
                                            "skipping copy entry, not under source path",
                                        );
                                        return Ok(());
                                    }
                                };
                                let destination_path = destination_path.join(relative_path);

                                if metadata.file_type.is_file() {
                                    if let Some(parent) = destination_path.parent() {
                                        destination_filesystem.async_create_dir_all(&parent).await?;
                                    }

                                    if filesystem.is_primary_server_fs()
                                        && destination_filesystem.is_primary_server_fs()
                                        && filesystem.backing_server().uuid == destination_filesystem.backing_server().uuid
                                    {
                                        server
                                            .filesystem
                                            .async_quota_copy(
                                                &path,
                                                &destination_path,
                                                &server,
                                                progress.clone_bytes().as_ref(),
                                            )
                                            .await?;
                                        destination_filesystem
                                            .async_set_permissions(&destination_path, metadata.file_type, metadata.permissions)
                                            .await?;
                                    } else {
                                        let mut reader = progress.async_counting_reader(stream);

                                        let mut writer = destination_filesystem
                                            .async_create_file(&destination_path)
                                            .await?;
                                        destination_filesystem
                                            .async_set_permissions(&destination_path, metadata.file_type, metadata.permissions)
                                            .await?;

                                        tokio::io::copy(&mut reader, &mut writer).await?;
                                        writer.shutdown().await?;
                                    }

                                    progress.increment_files();
                                } else if metadata.file_type.is_dir() {
                                    destination_filesystem.async_create_dir_all(&destination_path).await?;
                                    destination_filesystem
                                        .async_set_permissions(&destination_path, metadata.file_type, metadata.permissions)
                                        .await?;

                                    progress.increment_bytes(metadata.size);
                                } else if metadata.file_type.is_symlink() && let Ok(target) = filesystem.async_read_symlink(&path).await {
                                    if let Err(err) = destination_filesystem.async_create_symlink(&target, &destination_path).await {
                                        tracing::debug!(path = %destination_path.display(), "failed to create symlink from copy: {:?}", err);
                                    } else {
                                        progress.increment_files();
                                    }
                                }

                                Ok(())
                            }
                        }
                    }),
                )
                .await?;
        }

        Ok(())
    }

    fn try_update_atomics(&self, delta: impl Into<usage::SpaceDelta>, ignorant: bool) -> bool {
        let delta: usage::SpaceDelta = delta.into();

        if delta.logical == 0 && delta.physical == 0 {
            return true;
        }

        if delta.physical > 0 {
            let delta_u64 = delta.physical as u64;

            if !ignorant && self.disk_limit() != 0 {
                let limit = self.disk_limit() as u64;

                let result = self.disk_usage_cached_physical.fetch_update(
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    |current| {
                        if current + delta_u64 > limit {
                            None
                        } else {
                            Some(current + delta_u64)
                        }
                    },
                );

                if result.is_err() {
                    tracing::debug!(
                        "failed to allocate {} bytes: disk limit of {} bytes would be exceeded",
                        delta_u64,
                        limit
                    );
                    return false;
                }
            } else {
                self.disk_usage_cached_physical
                    .fetch_add(delta_u64, Ordering::Relaxed);
            }
        } else if delta.physical < 0 {
            let abs = delta.physical.unsigned_abs();
            self.disk_usage_cached_physical
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(abs))
                })
                .ok();
        }

        if delta.logical > 0 {
            self.disk_usage_cached_logical
                .fetch_add(delta.logical as u64, Ordering::Relaxed);
        } else if delta.logical < 0 {
            let abs = delta.logical.unsigned_abs();
            self.disk_usage_cached_logical
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(abs))
                })
                .ok();
        }

        self.disk_usage_delta_cached
            .fetch_add(delta.physical, Ordering::Relaxed);
        self.resource_usage
            .publish_disk_usage(self.get_physical_cached_size());

        true
    }

    /// Allocates (or deallocates) space for a path in the filesystem.
    /// Updates both the disk_usage map for directories and the cached total.
    ///
    /// - `path`: The path to allocate space for
    /// - `size`: The amount of space to allocate (positive) or deallocate (negative)
    /// - `ignorant`: If `true`, ignores disk limit checks
    ///
    /// Returns `true` if allocation was successful, `false` if it would exceed disk limit
    pub async fn async_allocate_in_path(&self, path: &Path, delta: i64, ignorant: bool) -> bool {
        if !self.try_update_atomics(delta, ignorant) {
            return false;
        }

        self.disk_usage
            .write()
            .await
            .update_size(path, delta.into());

        true
    }

    /// Allocates (or deallocates) space for a path in the filesystem.
    /// Updates both the disk_usage map for directories and the cached total.
    ///
    /// - `path`: The path to allocate space for
    /// - `size`: The amount of space to allocate (positive) or deallocate (negative)
    /// - `ignorant`: If `true`, ignores disk limit checks
    ///
    /// Returns `true` if allocation was successful, `false` if it would exceed disk limit
    pub async fn async_allocate_in_path_iterator(
        &self,
        path: impl IntoIterator<Item = impl AsRef<str> + Debug> + Debug,
        delta: i64,
        ignorant: bool,
    ) -> bool {
        if !self.try_update_atomics(delta, ignorant) {
            return false;
        }

        self.disk_usage
            .write()
            .await
            .update_size_iterator(path, delta.into());

        true
    }

    /// Allocates (or deallocates) space for a path in the filesystem.
    /// Updates both the disk_usage map for directories and the cached total.
    ///
    /// - `path`: The path to allocate space for
    /// - `size`: The amount of space to allocate (positive) or deallocate (negative)
    /// - `ignorant`: If `true`, ignores disk limit checks
    ///
    /// Returns `true` if allocation was successful, `false` if it would exceed disk limit
    pub fn allocate_in_path(&self, path: &Path, delta: i64, ignorant: bool) -> bool {
        if !self.try_update_atomics(delta, ignorant) {
            return false;
        }

        self.disk_usage
            .blocking_write()
            .update_size(path, delta.into());

        true
    }

    /// Allocates (or deallocates) space for a path in the filesystem.
    /// Updates both the disk_usage map for directories and the cached total.
    ///
    /// - `path`: The path to allocate space for
    /// - `size`: The amount of space to allocate (positive) or deallocate (negative)
    /// - `ignorant`: If `true`, ignores disk limit checks
    ///
    /// Returns `true` if allocation was successful, `false` if it would exceed disk limit
    pub fn allocate_in_path_iterator(
        &self,
        path: impl IntoIterator<Item = impl AsRef<str> + Debug> + Debug,
        delta: i64,
        ignorant: bool,
    ) -> bool {
        if !self.try_update_atomics(delta, ignorant) {
            return false;
        }

        self.disk_usage
            .blocking_write()
            .update_size_iterator(path, delta.into());

        true
    }

    pub async fn truncate_root(&self) -> Result<(), std::io::Error> {
        self.disk_usage.write().await.truncate();
        self.disk_usage_cached_logical.store(0, Ordering::Relaxed);
        self.disk_usage_cached_physical.store(0, Ordering::Relaxed);
        self.resource_usage.publish_disk_usage(0);

        self.async_remove_dir_all(Path::new("")).await
    }

    fn chown_impl(
        config: &crate::config::Config,
        cap_filesystem: &cap::CapFilesystem,
        path: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;

            let cfg = config.load();
            let owner_uid = rustix::fs::Uid::from_raw_unchecked(cfg.system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(cfg.system.user.gid);
            drop(cfg);

            if path.as_ref() == Path::new("")
                || path.as_ref() == Path::new(".")
                || path.as_ref() == Path::new("/")
            {
                std::os::unix::fs::chown(
                    &cap_filesystem.base_path,
                    Some(owner_uid.as_raw()),
                    Some(owner_gid.as_raw()),
                )?;
            } else {
                rustix::fs::chownat(
                    cap_filesystem.get_inner()?.as_fd(),
                    cap_filesystem.relative_path(path.as_ref()),
                    Some(owner_uid),
                    Some(owner_gid),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )?;
            }

            Ok(())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    fn absorb_chown_refusal(
        &self,
        result: Result<(), std::io::Error>,
    ) -> Result<(), std::io::Error> {
        let Err(err) = result else {
            return Ok(());
        };

        if !self.config.load().system.user.rootless.enabled {
            return Err(err);
        }

        if !self.chown_refused.swap(true, Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "chown refused under a rootless engine, leaving ownership as written: {}",
                err
            );
        }

        Ok(())
    }

    pub fn chown_path(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        if self.chown_refused.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.absorb_chown_refusal(Self::chown_impl(&self.config, &self.cap_filesystem, path))
    }
    pub async fn async_chown_path(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        if self.chown_refused.load(Ordering::Relaxed) {
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsFd;

            let owner_uid = rustix::fs::Uid::from_raw_unchecked(self.config.load().system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(self.config.load().system.user.gid);

            tokio::task::spawn_blocking({
                let cap_filesystem = self.cap_filesystem.clone();
                let path = self.relative_path(path.as_ref());
                let base_path = self.base_path.clone();

                move || {
                    if path == Path::new("") || path == Path::new(".") || path == Path::new("/") {
                        std::os::unix::fs::chown(
                            &base_path,
                            Some(owner_uid.as_raw()),
                            Some(owner_gid.as_raw()),
                        )
                    } else {
                        Ok(rustix::fs::chownat(
                            cap_filesystem.get_inner()?.as_fd(),
                            path,
                            Some(owner_uid),
                            Some(owner_gid),
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )?)
                    }
                }
            })
            .await
            .map_err(std::io::Error::other)
            .and_then(|result| self.absorb_chown_refusal(result))
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    pub async fn async_chown_path_recursive(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
        if self.chown_refused.load(Ordering::Relaxed) {
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsFd;

            let metadata = self.async_metadata(path.as_ref()).await?;
            let owner_uid = rustix::fs::Uid::from_raw_unchecked(self.config.load().system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(self.config.load().system.user.gid);
            let root_rel = self.relative_path(path.as_ref());

            tokio::task::spawn_blocking({
                let cap_filesystem = self.cap_filesystem.clone();
                let base_path = self.base_path.clone();
                let root_rel = root_rel.clone();

                move || -> Result<(), std::io::Error> {
                    if root_rel.as_os_str().is_empty()
                        || root_rel == Path::new(".")
                        || root_rel == Path::new("/")
                    {
                        std::os::unix::fs::chown(
                            &base_path,
                            Some(owner_uid.as_raw()),
                            Some(owner_gid.as_raw()),
                        )?;
                    } else {
                        rustix::fs::chownat(
                            cap_filesystem.get_inner()?.as_fd(),
                            &root_rel,
                            Some(owner_uid),
                            Some(owner_gid),
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )?;
                    }

                    Ok(())
                }
            })
            .await
            .map(|result| self.absorb_chown_refusal(result))??;

            if !metadata.is_dir() || self.chown_refused.load(Ordering::Relaxed) {
                return Ok(());
            }

            let threads = self.config.load().system.check_permissions_on_boot_threads;

            tokio::task::spawn_blocking({
                let cap_filesystem = self.cap_filesystem.clone();

                move || -> Result<(), anyhow::Error> {
                    let inner = cap_filesystem.get_inner()?;

                    let func = std::sync::Arc::new(
                        move |entry: crate::server::filesystem::cap::WalkEntry| {
                            let fd = inner.as_fd();
                            let path = entry.path;

                            let Ok(stat) = rustix::fs::statx(
                                fd,
                                &path,
                                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                                rustix::fs::StatxFlags::UID | rustix::fs::StatxFlags::GID,
                            ) else {
                                return Ok(());
                            };

                            if stat.stx_uid == owner_uid.as_raw()
                                && stat.stx_gid == owner_gid.as_raw()
                            {
                                return Ok(());
                            }

                            rustix::fs::chownat(
                                fd,
                                &path,
                                Some(owner_uid),
                                Some(owner_gid),
                                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                            )
                            .ok();

                            Ok(())
                        },
                    );

                    cap_filesystem
                        .walk_dir(&root_rel)?
                        .run_multithreaded(threads, func)
                }
            })
            .await??;

            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    pub fn create_chowned_dir_all(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());
        if path.as_os_str().is_empty() {
            return Ok(());
        }

        match self.create_dir(&path) {
            Ok(_) => {
                self.chown_path(&path)?;
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
            Err(_) => {}
        }

        let mut progress = PathBuf::new();
        for component in path.components() {
            progress.push(component);

            match self.create_dir(&progress) {
                Ok(_) => self.chown_path(&progress)?,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    pub async fn async_create_chowned_dir_all(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());
        if path.as_os_str().is_empty() {
            return Ok(());
        }

        let config = self.config.clone();
        let cap_filesystem = self.cap_filesystem.clone();

        tokio::task::spawn_blocking(move || {
            match cap_filesystem.create_dir(&path) {
                Ok(_) => {
                    Self::chown_impl(&config, &cap_filesystem, &path)?;
                    return Ok(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
                Err(_) => {}
            }

            let mut progress = PathBuf::new();
            for component in path.components() {
                progress.push(component);

                match cap_filesystem.create_dir(&progress) {
                    Ok(_) => Self::chown_impl(&config, &cap_filesystem, &progress)?,
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err),
                }
            }

            Ok(())
        })
        .await?
    }

    pub async fn setup(&self) {
        let limiter = self.get_disk_limiter();

        if let Err(err) = limiter.setup().await {
            tracing::error!(
                path = %self.base_path.display(),
                "failed to create server base directory: {}",
                err
            );

            return;
        }

        if let Err(err) = limiter
            .update_disk_limit(self.disk_limit.load(Ordering::Relaxed) as u64)
            .await
        {
            tracing::error!(
                path = %self.base_path.display(),
                "failed to update disk limit for server: {}",
                err
            );
        }

        if self.cap_filesystem.is_uninitialized() {
            let base_path = self.base_path.clone();
            match tokio::task::spawn_blocking(move || {
                cap_std::fs::Dir::open_ambient_dir(&base_path, cap_std::ambient_authority())
            })
            .await
            {
                Ok(Ok(dir)) => {
                    self.cap_filesystem.inner.store(Some(Arc::new(dir)));
                    if self.app_state.config.load().system.disk_check_use_inotify {
                        tokio::spawn({
                            let state = self.app_state.clone();
                            let server_notifier = self.server_notifier.clone();
                            let server_use_server_notifier = self.use_server_notifier.clone();
                            let server_uuid = self.uuid;

                            async move {
                                match state
                                    .inotify_manager
                                    .register_server_with_notifier(
                                        server_notifier.clone(),
                                        server_uuid,
                                    )
                                    .await
                                {
                                    Ok(watching) => {
                                        server_use_server_notifier
                                            .store(watching, Ordering::Relaxed);
                                    }
                                    Err(err) => {
                                        tracing::error!(
                                            "error while trying to attach server inotify listener, falling back to regular scans: {}",
                                            err
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
                Ok(Err(err)) => {
                    tracing::error!(
                        path = %self.base_path.display(),
                        "failed to open server base directory: {:?}",
                        err
                    );
                }
                Err(err) => {
                    tracing::error!(
                        path = %self.base_path.display(),
                        "failed to open server base directory: {:?}",
                        err
                    );
                }
            }
        }
    }

    pub async fn attach(&self) {
        if let Err(err) = self.get_disk_limiter().attach().await {
            tracing::error!(
                path = %self.base_path.display(),
                "failed to attach server base directory: {}",
                err
            );
        }

        if self.cap_filesystem.is_uninitialized() {
            let base_path = self.base_path.clone();
            match tokio::task::spawn_blocking(move || {
                cap_std::fs::Dir::open_ambient_dir(&base_path, cap_std::ambient_authority())
            })
            .await
            {
                Ok(Ok(dir)) => {
                    self.cap_filesystem.inner.store(Some(Arc::new(dir)));
                    if self.app_state.config.load().system.disk_check_use_inotify {
                        tokio::spawn({
                            let state = self.app_state.clone();
                            let server_notifier = self.server_notifier.clone();
                            let server_use_server_notifier = self.use_server_notifier.clone();
                            let server_uuid = self.uuid;

                            async move {
                                match state
                                    .inotify_manager
                                    .register_server_with_notifier(
                                        server_notifier.clone(),
                                        server_uuid,
                                    )
                                    .await
                                {
                                    Ok(watching) => {
                                        server_use_server_notifier
                                            .store(watching, Ordering::Relaxed);
                                    }
                                    Err(err) => {
                                        tracing::error!(
                                            "error while trying to attach server inotify listener, falling back to regular scans: {}",
                                            err
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
                Ok(Err(err)) => {
                    tracing::error!(
                        path = %self.base_path.display(),
                        "failed to open server base directory: {}",
                        err
                    );
                }
                Err(err) => {
                    tracing::error!(
                        path = %self.base_path.display(),
                        "failed to open server base directory: {}",
                        err
                    );
                }
            }
        }
    }

    pub async fn destroy(&self) {
        self.disk_checker.abort();
        self.app_state
            .inotify_manager
            .unregister_server(self.uuid)
            .await;

        if let Err(err) = self.get_disk_limiter().destroy().await {
            tracing::error!(
                path = %self.base_path.display(),
                "failed to delete server base directory for: {}",
                err
            );
        }
    }

    pub async fn directory_entry_space(
        &self,
        real_path: &Path,
        options: DirectoryEntryOptions,
    ) -> (u64, u64) {
        if !options.directory_size || self.config.load().api.disable_directory_size {
            return (0, 0);
        }

        if let Some(space) = self.disk_usage.read().await.get_size(real_path) {
            return (space.get_logical(), space.get_physical());
        }

        let canonical = match self.async_canonicalize(real_path).await {
            Ok(canonical) if canonical != real_path => canonical,
            _ => return (0, 0),
        };

        self.disk_usage
            .read()
            .await
            .get_size(&canonical)
            .map_or((0, 0), |space| (space.get_logical(), space.get_physical()))
    }

    pub async fn to_api_entry_buffer(
        &self,
        path: PathBuf,
        metadata: &Metadata,
        options: DirectoryEntryOptions,
        buffer: Option<&[u8]>,
        symlink_destination: Option<PathBuf>,
        symlink_destination_metadata: Option<Metadata>,
    ) -> crate::models::DirectoryEntry {
        let real_metadata = symlink_destination_metadata.as_ref().unwrap_or(metadata);
        let real_path = symlink_destination.as_ref().unwrap_or(&path);

        let (size, size_physical) = if real_metadata.is_dir() {
            self.directory_entry_space(real_path, options).await
        } else {
            (real_metadata.size_logical(), real_metadata.size_physical())
        };

        let detected_mime = if real_metadata.is_dir() {
            MimeCacheValue::directory()
        } else if real_metadata.is_symlink() {
            MimeCacheValue::symlink()
        } else {
            crate::utils::detect_mime_type(real_path, buffer)
        };

        crate::models::DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(PortablePermissions::from(metadata.permissions()).mode() as u32),
            mode_bits: compact_str::format_compact!(
                "{:o}",
                PortablePermissions::from(metadata.permissions()).mode()
            ),
            size,
            size_physical,
            editable: real_metadata.is_file() && detected_mime.valid_utf8,
            inner_editable: real_metadata.is_file() && detected_mime.valid_inner_utf8,
            directory: real_metadata.is_dir(),
            file: real_metadata.is_file(),
            symlink: metadata.is_symlink(),
            r#virtual: options.r#virtual,
            mime: detected_mime.mime,
            modified: chrono::DateTime::from_timestamp(
                metadata
                    .modified()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs() as i64,
                0,
            )
            .unwrap_or_default(),
            created: chrono::DateTime::from_timestamp(
                metadata
                    .created()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs() as i64,
                0,
            )
            .unwrap_or_default(),
        }
    }

    pub async fn to_api_entry_mime_type(
        &self,
        path: PathBuf,
        metadata: &Metadata,
        options: DirectoryEntryOptions,
        mime_type: Option<MimeCacheValue>,
        symlink_destination: Option<PathBuf>,
        symlink_destination_metadata: Option<Metadata>,
    ) -> crate::models::DirectoryEntry {
        let real_metadata = symlink_destination_metadata.as_ref().unwrap_or(metadata);
        let real_path = symlink_destination.as_ref().unwrap_or(&path);

        let (size, size_physical) = if real_metadata.is_dir() {
            self.directory_entry_space(real_path, options).await
        } else {
            (real_metadata.size_logical(), real_metadata.size_physical())
        };

        let detected_mime = if real_metadata.is_dir() {
            MimeCacheValue::directory()
        } else if real_metadata.is_symlink() {
            MimeCacheValue::symlink()
        } else {
            mime_type.unwrap_or_default()
        };

        crate::models::DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(PortablePermissions::from(metadata.permissions()).mode() as u32),
            mode_bits: compact_str::format_compact!(
                "{:o}",
                PortablePermissions::from(metadata.permissions()).mode()
            ),
            size,
            size_physical,
            editable: real_metadata.is_file() && detected_mime.valid_utf8,
            inner_editable: real_metadata.is_file() && detected_mime.valid_inner_utf8,
            directory: real_metadata.is_dir(),
            file: real_metadata.is_file(),
            symlink: metadata.is_symlink(),
            r#virtual: options.r#virtual,
            mime: detected_mime.mime,
            modified: chrono::DateTime::from_timestamp(
                metadata
                    .modified()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs() as i64,
                0,
            )
            .unwrap_or_default(),
            created: chrono::DateTime::from_timestamp(
                metadata
                    .created()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs() as i64,
                0,
            )
            .unwrap_or_default(),
        }
    }

    pub async fn to_api_entry_cap(
        &self,
        filesystem: &cap::CapFilesystem,
        path: PathBuf,
        metadata: Metadata,
        options: DirectoryEntryOptions,
    ) -> crate::models::DirectoryEntry {
        let prepared = self.prepare_api_entry_cap(filesystem, path, metadata).await;
        self.finish_api_entry_cap(filesystem, prepared, options)
            .await
    }

    pub async fn prepare_api_entry_cap(
        &self,
        filesystem: &cap::CapFilesystem,
        path: PathBuf,
        metadata: Metadata,
    ) -> PreparedDirectoryEntry {
        let symlink_destination = if metadata.is_symlink() {
            match filesystem.async_read_link(&path).await {
                Ok(link) => filesystem.async_canonicalize(link).await.ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let symlink_destination_metadata =
            if let Some(symlink_destination) = symlink_destination.clone() {
                filesystem
                    .async_symlink_metadata(&symlink_destination)
                    .await
                    .ok()
            } else {
                None
            };

        PreparedDirectoryEntry {
            path,
            metadata,
            symlink_destination,
            symlink_destination_metadata,
        }
    }

    pub async fn prepared_entry_sort_size(
        &self,
        prepared: &PreparedDirectoryEntry,
        options: DirectoryEntryOptions,
    ) -> (u64, u64) {
        let real_metadata = prepared
            .symlink_destination_metadata
            .as_ref()
            .unwrap_or(&prepared.metadata);
        let real_path = prepared
            .symlink_destination
            .as_ref()
            .unwrap_or(&prepared.path);

        if real_metadata.is_dir() {
            self.directory_entry_space(real_path, options).await
        } else {
            (real_metadata.size_logical(), real_metadata.size_physical())
        }
    }

    pub async fn finish_api_entry_cap(
        &self,
        filesystem: &cap::CapFilesystem,
        prepared: PreparedDirectoryEntry,
        options: DirectoryEntryOptions,
    ) -> crate::models::DirectoryEntry {
        let PreparedDirectoryEntry {
            path,
            metadata,
            symlink_destination,
            symlink_destination_metadata,
        } = prepared;

        let mime_key = crate::routes::MimeCacheKey::from(&metadata);
        let detected_mime =
            if let Some(detected_mime) = self.app_state.mime_cache.get(&mime_key).await {
                detected_mime
            } else if (metadata.is_file() && metadata.len() == 0)
                || (symlink_destination.is_some()
                    && symlink_destination_metadata
                        .as_ref()
                        .is_some_and(|m| m.is_file() && m.len() == 0))
            {
                crate::routes::MimeCacheValue::text()
            } else {
                let mut buffer = [0; 64];
                let buffer = if metadata.is_file()
                    || (symlink_destination.is_some()
                        && symlink_destination_metadata
                            .as_ref()
                            .is_some_and(|m| m.is_file()))
                {
                    match filesystem
                        .async_open(symlink_destination.as_ref().unwrap_or(&path))
                        .await
                    {
                        Ok(mut file) => {
                            let bytes_read = file.read(&mut buffer).await.unwrap_or(0);

                            buffer.get(..bytes_read)
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                };

                let detected_mime = crate::utils::detect_mime_type(
                    symlink_destination.as_ref().unwrap_or(&path),
                    buffer,
                );

                self.app_state
                    .mime_cache
                    .insert(mime_key, detected_mime)
                    .await;

                detected_mime
            };

        self.to_api_entry_mime_type(
            path,
            &metadata,
            options,
            Some(detected_mime),
            symlink_destination,
            symlink_destination_metadata,
        )
        .await
    }
}

#[derive(Clone, Copy, Default)]
pub struct DirectoryEntryOptions {
    pub directory_size: bool,
    pub r#virtual: bool,
}

impl DirectoryEntryOptions {
    pub fn server_fs(is_primary_server_fs: bool) -> Self {
        Self {
            directory_size: is_primary_server_fs,
            r#virtual: !is_primary_server_fs,
        }
    }
}

pub struct PreparedDirectoryEntry {
    pub path: PathBuf,
    pub metadata: Metadata,
    pub symlink_destination: Option<PathBuf>,
    pub symlink_destination_metadata: Option<Metadata>,
}

impl PreparedDirectoryEntry {
    pub fn modified_secs(&self) -> i64 {
        self.metadata
            .modified()
            .map(|t| {
                t.into_std()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
            })
            .unwrap_or_default()
            .as_secs() as i64
    }

    pub fn created_secs(&self) -> i64 {
        self.metadata
            .created()
            .map(|t| {
                t.into_std()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
            })
            .unwrap_or_default()
            .as_secs() as i64
    }
}

impl Deref for Filesystem {
    type Target = cap::CapFilesystem;

    fn deref(&self) -> &Self::Target {
        &self.cap_filesystem
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap::FileType;

    #[test]
    fn root_is_never_ignored() {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);

            server.filesystem.update_ignored(&["*"]).await;

            for root in ["/", ".", ""] {
                assert!(!server.filesystem.is_ignored(Path::new(root), FileType::Dir));
                assert!(
                    !server
                        .filesystem
                        .async_is_ignored(Path::new(root), FileType::Dir)
                        .await
                );
            }

            assert!(
                server
                    .filesystem
                    .is_ignored(Path::new("server.log"), FileType::File)
            );
        });
    }

    #[test]
    fn has_headroom_checks_the_limit_without_reserving() {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);

            server.filesystem.update_disk_limit(0).await;
            assert!(server.filesystem.has_headroom(i64::MAX));

            server.filesystem.update_disk_limit(1024).await;
            assert!(server.filesystem.has_headroom(1024));
            assert!(!server.filesystem.has_headroom(1025));

            assert_eq!(server.filesystem.get_physical_cached_size(), 0);

            server
                .filesystem
                .async_allocate_in_path(Path::new(""), 512, true)
                .await;

            assert!(server.filesystem.has_headroom(512));
            assert!(!server.filesystem.has_headroom(513));
            assert!(server.filesystem.has_headroom(-4096));
        });
    }
}
