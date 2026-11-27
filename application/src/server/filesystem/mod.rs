use crate::{
    routes::{MimeCacheKey, MimeCacheValue},
    server::{
        filesystem::{
            ignore_list::IgnoreList,
            virtualfs::{
                AsyncDirectoryStreamWalkFn, AsyncDirectoryWalkFn, IgnoreVerdict, IsIgnoredFn,
                VirtualReadableFilesystem, VirtualWritableFilesystem,
            },
        },
        resources::ResourceUsageWatchExt,
    },
    utils::{PortablePermissions, PortableSizeExt},
};
use cap_std::fs::Metadata;
use compact_str::ToCompactString;
use std::{
    borrow::Cow,
    fmt::Debug,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
};
use tokio::{io::AsyncWriteExt, sync::RwLock};

pub mod archive;
pub mod cap;
pub mod disk_checker;
pub mod file;
pub mod ignore_list;
pub mod inotify;
pub mod limiter;
pub mod listing;
pub mod operations;
pub mod patch;
pub mod pull;
pub mod sqlite;
pub mod trash;
pub mod uploads;
pub mod usage;
pub mod virtualfs;

/// A subuser deny-list carried on a single panel request.
///
/// The panel checks the paths it was handed before calling, but it cannot see file
/// types, symlink targets, or the entries inside a directory it names, so the list is
/// applied again here. The predicates also apply the server's own deny-list, so a
/// route needs one check per path.
#[derive(Default, Clone)]
pub struct RequestIgnored(Option<IgnoreList>);

impl RequestIgnored {
    /// Unlike [`IgnoreList::from_lines`], an unusable pattern is an error rather than
    /// a dropped line: a deny-list that compiles to nothing hides nothing.
    pub fn compile<S: AsRef<str>>(patterns: &[S]) -> Result<Self, ignore::Error> {
        if patterns.is_empty() {
            return Ok(Self(None));
        }

        Ok(Self(Some(IgnoreList::try_from_lines(patterns)?)))
    }

    pub fn from_list(list: IgnoreList) -> Self {
        Self((!list.is_empty()).then_some(list))
    }

    pub async fn is_ignored(
        &self,
        server: &crate::server::Server,
        path: &Path,
        file_type: cap::FileType,
    ) -> bool {
        if server.filesystem.async_is_ignored(path, file_type).await {
            return true;
        }

        match &self.0 {
            Some(matcher) => matcher.is_ignored(
                &server.filesystem.async_ignore_path(path, file_type).await,
                file_type,
            ),
            None => false,
        }
    }

    /// Like [`Self::is_ignored`], but also checks the canonical
    /// [`Filesystem::diff_key`], so a denied path cannot be reached through a
    /// symlinked parent directory.
    pub async fn is_ignored_resolved(
        &self,
        server: &crate::server::Server,
        path: &Path,
        file_type: cap::FileType,
    ) -> bool {
        if !self.applies(server) {
            return false;
        }

        self.is_ignored(server, path, file_type).await
            || self
                .is_ignored(
                    server,
                    &server.filesystem.diff_key(path).await,
                    cap::FileType::from_is_dir(file_type.is_dir()),
                )
                .await
    }

    /// Like [`Self::is_ignored_subtree`], but also checks the canonical
    /// [`Filesystem::diff_key`].
    pub async fn is_ignored_subtree_resolved(
        &self,
        server: &crate::server::Server,
        path: &Path,
    ) -> bool {
        if !self.applies(server) {
            return false;
        }

        self.is_ignored_subtree(server, path).await
            || self
                .is_ignored_subtree(server, &server.filesystem.diff_key(path).await)
                .await
    }

    /// Like [`Self::is_ignored_resolved`], but resolves only the parent directories,
    /// for operations that act on the entry rather than on what it links to.
    pub async fn is_ignored_resolved_parent(
        &self,
        server: &crate::server::Server,
        path: &Path,
        file_type: cap::FileType,
    ) -> bool {
        if !self.applies(server) {
            return false;
        }

        let file_type = cap::FileType::from_is_dir(file_type.is_dir());

        self.is_ignored(server, path, file_type).await
            || self
                .is_ignored(
                    server,
                    &server.filesystem.async_canonicalize_parent(path).await,
                    file_type,
                )
                .await
    }

    /// Whether moving or removing the directory at `directory` would carry along an
    /// entry that is hidden at its current location or would be at any of `roots`,
    /// the places its contents are judged at. Point checks on the directory itself
    /// cannot see a pattern that names something deeper inside it.
    pub async fn contains_ignored(
        &self,
        server: &crate::server::Server,
        file_type: cap::FileType,
        directory: &Path,
        roots: &[&Path],
    ) -> bool {
        if !file_type.is_dir() || !self.applies(server) {
            return false;
        }

        server
            .filesystem
            .async_contains_ignored(directory, roots, self.0.as_ref())
            .await
    }

    fn applies(&self, server: &crate::server::Server) -> bool {
        self.0.is_some() || !server.filesystem.disk_ignored.load().is_empty()
    }

    /// Like [`Self::is_ignored`] for a directory, but false when the list only
    /// excludes it while re-including something beneath it.
    async fn is_ignored_subtree(&self, server: &crate::server::Server, path: &Path) -> bool {
        if server
            .filesystem
            .async_is_ignored_subtree(path, cap::FileType::Dir)
            .await
        {
            return true;
        }

        match &self.0 {
            Some(matcher) => matcher.is_ignored_subtree(
                &server
                    .filesystem
                    .async_ignore_path(path, cap::FileType::Dir)
                    .await,
                cap::FileType::Dir,
            ),
            None => false,
        }
    }

    pub fn filter(&self, server: &crate::server::Server) -> Option<IsIgnoredFn> {
        self.0
            .as_ref()
            .map(|matcher| Filesystem::subuser_deny_filter(server, matcher.clone()))
    }

    /// A filter judging each entry by its own path placed under `root`, without
    /// resolving links against the live filesystem, for filesystems whose entries
    /// stand for server paths: a backup mirrors the server root, a mount sits at its
    /// target.
    fn lexical_filter(&self, server: &crate::server::Server, root: &Path) -> IsIgnoredFn {
        let server = server.clone();
        let ignored = self.clone();
        let root = root.to_path_buf();

        IsIgnoredFn::from(move |file_type, path: PathBuf| {
            let mut match_path = root.clone();
            match_path.extend(
                path.components()
                    .filter(|component| matches!(component, std::path::Component::Normal(_))),
            );

            ignored.verdict_as(&server, file_type, &match_path, path)
        })
    }

    /// [`IgnoreList::verdict_as`] over the server's deny-list and this request's,
    /// for filters that judge an entry by a path other than the one it sits at.
    pub fn verdict_as(
        &self,
        server: &crate::server::Server,
        file_type: cap::FileType,
        match_path: &Path,
        path: PathBuf,
    ) -> IgnoreVerdict {
        let verdict = server
            .filesystem
            .disk_ignored
            .load()
            .verdict_as(file_type, match_path, path);

        match &self.0 {
            Some(matcher) => verdict.then(|path| matcher.verdict_as(file_type, match_path, path)),
            None => verdict,
        }
    }
}

/// Whether a rename may materialise the destination's parent directories.
///
/// Renaming `f.txt` to `newdir/f.txt` creates `newdir`, so a caller acting for a user may
/// only pass [`RenameParents::Create`] once that user has been checked for the create
/// permission, not merely the update permission the rename itself needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameParents {
    Create,
    Require,
}

#[inline]
fn raw_mode(metadata: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;

        metadata.mode()
    }
    #[cfg(not(unix))]
    {
        PortablePermissions::from(metadata.permissions()).mode() as u32
    }
}

#[inline]
pub fn encode_mode(mode: u32) -> compact_str::CompactString {
    #[cfg(unix)]
    let file_type = match rustix::fs::FileType::from_raw_mode(mode) {
        rustix::fs::FileType::RegularFile => b'-',
        rustix::fs::FileType::Directory => b'd',
        rustix::fs::FileType::Symlink => b'l',
        rustix::fs::FileType::BlockDevice => b'b',
        rustix::fs::FileType::CharacterDevice => b'c',
        rustix::fs::FileType::Socket => b's',
        rustix::fs::FileType::Fifo => b'p',
        rustix::fs::FileType::Unknown => b'?',
    };
    #[cfg(not(unix))]
    let file_type = b'?';

    let mut buffer = [
        file_type, b'-', b'-', b'-', b'-', b'-', b'-', b'-', b'-', b'-',
    ];
    for (i, slot) in buffer.iter_mut().skip(1).enumerate() {
        if mode & (1 << (8 - i)) != 0 {
            *slot = match i % 3 {
                0 => b'r',
                1 => b'w',
                _ => b'x',
            };
        }
    }

    match std::str::from_utf8(&buffer) {
        Ok(mode_str) => compact_str::CompactString::from(mode_str),
        Err(_) => compact_str::CompactString::const_new("?---------"),
    }
}

#[cfg(target_os = "linux")]
const ZFS_SUPER_MAGIC: u64 = 0x2fc12fc1;

pub const VIRTUAL_PATH_MESSAGE: &str = "path is a mount point or virtual directory";
pub const IGNORED_CONTENTS_MESSAGE: &str =
    "a directory contains files you cannot access, so it was left in place";

struct MountMatch {
    inner_path: PathBuf,
    source_path: PathBuf,
    read_only: bool,
    target: PathBuf,
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
    limiter_usage_known: Arc<AtomicBool>,
    disk_limit: AtomicI64,
    disk_usage_delta_cached: Arc<AtomicI64>,
    disk_usage_cached_logical: Arc<AtomicU64>,
    disk_usage_cached_physical: Arc<AtomicU64>,
    pub disk_usage: Arc<RwLock<usage::DiskUsage>>,
    pub last_disk_check: Arc<AtomicU64>,
    pub disk_check_completed: Arc<tokio::sync::Notify>,
    disk_ignored: arc_swap::ArcSwap<IgnoreList>,
    mount_gateways: arc_swap::ArcSwap<Vec<PathBuf>>,
    zfs_dataset_root: AtomicBool,

    pub archive_fs_cache:
        moka::future::Cache<(PathBuf, MimeCacheKey), Arc<dyn VirtualReadableFilesystem>>,
    pub operations: operations::OperationManager,
    pub uploads: uploads::UploadManager,
    pub trash: trash::TrashManager,
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
        let disk_ignored = Self::build_deny_list(deny_list).unwrap_or_else(|_| IgnoreList::empty());

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
        let limiter_usage_known = Arc::new(AtomicBool::new(false));

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
                limiter_usage_known: Arc::clone(&limiter_usage_known),
            })),
            config: Arc::clone(&config),

            base_path: base_path.clone(),
            base_fs_mount_path: RwLock::new(base_path),
            cap_filesystem,
            server_notifier,
            use_server_notifier,

            trash: trash::TrashManager::new(resource_usage.clone(), Arc::clone(&disk_usage)),
            resource_usage,
            limiter_usage_known,
            disk_limit: AtomicI64::new(disk_limit as i64),
            disk_usage_delta_cached: Arc::new(AtomicI64::new(0)),
            disk_usage_cached_logical,
            disk_usage_cached_physical,
            disk_usage,
            last_disk_check,
            disk_check_completed,
            disk_ignored: arc_swap::ArcSwap::from_pointee(disk_ignored),
            mount_gateways: arc_swap::ArcSwap::from_pointee(Vec::new()),
            zfs_dataset_root: AtomicBool::new(false),

            archive_fs_cache: moka::future::CacheBuilder::new(8)
                .time_to_idle(std::time::Duration::from_mins(1))
                .build(),
            operations: operations::OperationManager::new(sender.clone(), Arc::clone(&config)),
            uploads: uploads::UploadManager::new(sender),
        }
    }

    /// The egg deny-list with the trash directory appended last, so no egg rule can
    /// re-include it.
    fn build_deny_list(deny_list: &[impl AsRef<str>]) -> Result<IgnoreList, ignore::Error> {
        let trash_line = trash::ignore_line();

        IgnoreList::from_lines(
            deny_list
                .iter()
                .map(AsRef::as_ref)
                .chain([trash_line.as_str()]),
        )
    }

    pub async fn ensure_trash_directory(&self) {
        if let Err(err) = self
            .async_create_chowned_dir_all(trash::TRASH_DIRECTORY, None)
            .await
        {
            tracing::warn!(
                path = %self.base_path.display(),
                "failed to create trash directory: {}",
                err
            );
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

    /// Remembers the container-relative mount targets so the mount points and the
    /// virtual directories leading to them cannot be replaced or removed.
    pub fn update_mounts(&self, mounts: &[crate::server::configuration::Mount]) {
        let gateways = mounts
            .iter()
            .filter_map(|mount| mount.container_relative_target())
            .map(|target| cap::CapFilesystem::resolve_path(Path::new(target)))
            .collect();

        self.mount_gateways.store(Arc::new(gateways));
    }

    /// A mount point itself, or a directory that only exists to lead to one.
    pub fn is_mount_gateway(&self, path: &Path) -> bool {
        let gateways = self.mount_gateways.load();
        if gateways.is_empty() {
            return false;
        }

        let path = self.relative_path_cow(path);
        if path.as_os_str().is_empty() {
            return false;
        }

        gateways.iter().any(|gateway| gateway.starts_with(&*path))
    }

    fn is_backups_virtual(&self, path: &Path) -> bool {
        let config = self.config.load();
        if !config.system.backups.mounting.enabled {
            return false;
        }

        let path = self.relative_path_cow(path);
        if path.as_os_str().is_empty() {
            return false;
        }

        path.starts_with(&config.system.backups.mounting.path)
    }

    /// Whether writing an entry of `file_type` at `path` would clobber a virtual
    /// entry: anything under the backup browsing directory, or a non-directory where
    /// a mount point or one of its parents belongs. Directories stay allowed there,
    /// which is what the container runtime creates itself.
    pub fn is_virtual_write_target(&self, path: &Path, file_type: cap::FileType) -> bool {
        self.is_backups_virtual(path)
            || self.is_zfs_control_path(path)
            || (!file_type.is_dir() && self.is_mount_gateway(path))
    }

    /// Whether `path` lies in the control directory a ZFS dataset root exposes its
    /// snapshots under, which hold copies no deny-list or backup mount check sees.
    fn is_zfs_control_path(&self, path: &Path) -> bool {
        self.zfs_dataset_root.load(Ordering::Relaxed)
            && self
                .relative_path_cow(path)
                .components()
                .next()
                .is_some_and(|component| component.as_os_str() == ".zfs")
    }

    /// Whether a symlink still has to be resolved to tell if it leads somewhere
    /// virtual, when no deny-list would resolve it anyway.
    fn resolves_virtual_links(&self, file_type: cap::FileType) -> bool {
        file_type.is_symlink() && self.zfs_dataset_root.load(Ordering::Relaxed)
    }

    /// Whether [`Self::is_ignored`] can return true for any path at all.
    pub fn may_ignore(&self) -> bool {
        self.config.load().system.backups.mounting.enabled
            || self.zfs_dataset_root.load(Ordering::Relaxed)
            || !self.mount_gateways.load().is_empty()
            || !self.disk_ignored.load().is_empty()
    }

    /// Whether `path` may not be removed, renamed or replaced at all, also when it is
    /// a directory. Resolves the parent chain so a symlink cannot reach around it.
    pub async fn async_is_protected_path(&self, path: &Path) -> bool {
        if self.is_backups_virtual(path)
            || self.is_zfs_control_path(path)
            || self.is_mount_gateway(path)
        {
            return true;
        }

        if self.zfs_dataset_root.load(Ordering::Relaxed)
            && self.is_zfs_control_path(&self.diff_key(path).await)
        {
            return true;
        }

        if self.mount_gateways.load().is_empty() {
            return false;
        }

        self.is_mount_gateway(&self.diff_key(path).await)
    }

    fn virtual_path_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, VIRTUAL_PATH_MESSAGE)
    }

    pub async fn update_ignored(&self, deny_list: &[impl AsRef<str>]) {
        if let Ok(disk_ignored) = Self::build_deny_list(deny_list) {
            self.disk_ignored.store(Arc::new(disk_ignored));
        }
    }

    fn subuser_deny_filter(server: &crate::server::Server, matcher: IgnoreList) -> IsIgnoredFn {
        let (sync_server, async_server) = (server.clone(), server.clone());
        let async_matcher = matcher.clone();

        IsIgnoredFn::new(
            move |file_type, path: PathBuf| {
                let match_path = sync_server.filesystem.rematched(&path, file_type);

                Self::judge(&matcher, file_type, match_path, path)
            },
            move |file_type, path: PathBuf| {
                let server = async_server.clone();
                let matcher = async_matcher.clone();

                async move {
                    let match_path = server.filesystem.async_rematched(&path, file_type).await;

                    Self::judge(&matcher, file_type, match_path, path)
                }
            },
        )
    }

    fn deny_filter(server: &crate::server::Server) -> IsIgnoredFn {
        let (sync_server, async_server) = (server.clone(), server.clone());

        IsIgnoredFn::new(
            move |file_type, path: PathBuf| {
                if sync_server
                    .filesystem
                    .is_virtual_write_target(&path, file_type)
                {
                    return IgnoreVerdict::Skip;
                }

                let matcher = sync_server.filesystem.disk_ignored.load();
                if matcher.is_empty() {
                    return IgnoreVerdict::Keep(path);
                }

                let match_path = sync_server.filesystem.rematched(&path, file_type);

                Self::judge(&matcher, file_type, match_path, path)
            },
            move |file_type, path: PathBuf| {
                let server = async_server.clone();

                async move {
                    if server.filesystem.is_virtual_write_target(&path, file_type) {
                        return IgnoreVerdict::Skip;
                    }

                    let matcher = server.filesystem.disk_ignored.load();
                    if matcher.is_empty() {
                        return IgnoreVerdict::Keep(path);
                    }

                    let match_path = server.filesystem.async_rematched(&path, file_type).await;

                    Self::judge(&matcher, file_type, match_path, path)
                }
            },
        )
    }

    /// The path an entry is matched as when that differs from the path itself: made
    /// relative, or a symlink's resolved target.
    fn rematched(&self, path: &Path, file_type: cap::FileType) -> Option<PathBuf> {
        match self.ignore_path(path, file_type) {
            Cow::Borrowed(same) if same == path => None,
            Cow::Borrowed(other) => Some(other.to_path_buf()),
            Cow::Owned(other) => Some(other),
        }
    }

    async fn async_rematched(&self, path: &Path, file_type: cap::FileType) -> Option<PathBuf> {
        match self.async_ignore_path(path, file_type).await {
            Cow::Borrowed(same) if same == path => None,
            Cow::Borrowed(other) => Some(other.to_path_buf()),
            Cow::Owned(other) => Some(other),
        }
    }

    fn judge(
        matcher: &IgnoreList,
        file_type: cap::FileType,
        match_path: Option<PathBuf>,
        path: PathBuf,
    ) -> IgnoreVerdict {
        match match_path {
            Some(match_path) => matcher.verdict_as(file_type, &match_path, path),
            None => matcher.verdict(file_type, path),
        }
    }

    pub async fn probe_file_type(&self, path: impl AsRef<Path>) -> cap::FileType {
        self.async_symlink_metadata(path)
            .await
            .map(|metadata| metadata.file_type().into())
            .unwrap_or(cap::FileType::File)
    }

    pub fn is_ignored(&self, path: &Path, file_type: cap::FileType) -> bool {
        if self.is_virtual_write_target(path, file_type) {
            return true;
        }

        let disk_ignored = self.disk_ignored.load();
        if disk_ignored.is_empty() && !self.resolves_virtual_links(file_type) {
            return false;
        }

        let path = self.ignore_path(path, file_type);

        self.is_zfs_control_path(&path) || disk_ignored.is_ignored(&path, file_type)
    }

    pub async fn async_is_ignored(&self, path: &Path, file_type: cap::FileType) -> bool {
        if self.is_virtual_write_target(path, file_type) {
            return true;
        }

        if self.disk_ignored.load().is_empty() && !self.resolves_virtual_links(file_type) {
            return false;
        }

        let path = self.async_ignore_path(path, file_type).await;

        self.is_zfs_control_path(&path) || self.disk_ignored.load().is_ignored(&path, file_type)
    }

    /// Like [`Self::async_is_ignored`], but false for a directory the denylist only
    /// excludes while re-including something beneath it, so that a re-included
    /// entry can still be created or reached through it.
    pub async fn async_is_ignored_subtree(&self, path: &Path, file_type: cap::FileType) -> bool {
        if self.is_virtual_write_target(path, file_type) {
            return true;
        }

        if self.disk_ignored.load().is_empty() && !self.resolves_virtual_links(file_type) {
            return false;
        }

        let path = self.async_ignore_path(path, file_type).await;

        self.is_zfs_control_path(&path)
            || self
                .disk_ignored
                .load()
                .is_ignored_subtree(&path, file_type)
    }

    /// Walks the real directory `directory` and reports whether any entry beneath it,
    /// re-rooted onto any of `roots` (each also taken with its parents resolved), is
    /// excluded by the deny-list or `list`. Entries are judged by their own path, not
    /// what they link to, since the caller acts on the links themselves. Anything that
    /// cannot be read counts as hidden.
    pub async fn async_contains_ignored(
        &self,
        directory: &Path,
        roots: &[&Path],
        list: Option<&IgnoreList>,
    ) -> bool {
        let denylist = self.disk_ignored.load_full();
        if denylist.is_empty() && list.is_none() {
            return false;
        }

        let mut match_roots = Vec::with_capacity(roots.len() * 2);
        for root in roots {
            for root in [
                self.relative_path(root),
                self.async_canonicalize_parent(root).await,
            ] {
                if !match_roots.contains(&root) {
                    match_roots.push(root);
                }
            }
        }

        let directory = self.relative_path(directory);
        let cap_filesystem = self.cap_filesystem.clone();
        let list = list.cloned();

        tokio::task::spawn_blocking(move || {
            Self::contains_ignored_impl(
                &cap_filesystem,
                &directory,
                &match_roots,
                &denylist,
                list.as_ref(),
            )
        })
        .await
        .unwrap_or(true)
    }

    fn contains_ignored_impl(
        cap_filesystem: &cap::CapFilesystem,
        directory: &Path,
        roots: &[PathBuf],
        denylist: &IgnoreList,
        list: Option<&IgnoreList>,
    ) -> bool {
        let Ok(mut walk) = cap_filesystem.walk_dir(directory) else {
            return true;
        };

        while let Some(entry) = walk.next_entry() {
            let Ok(entry) = entry else {
                return true;
            };

            let file_type = entry.file_type();
            if matches!(file_type, cap::FileType::Unknown) {
                return true;
            }

            let Ok(inner) = entry.path.strip_prefix(directory) else {
                return true;
            };

            for root in roots {
                let path = root.join(inner);
                if denylist.is_ignored(&path, file_type)
                    || list.is_some_and(|list| list.is_ignored(&path, file_type))
                {
                    return true;
                }
            }
        }

        false
    }

    fn ignore_path<'a>(&self, path: &'a Path, file_type: cap::FileType) -> Cow<'a, Path> {
        if file_type.is_symlink() {
            Cow::Owned(
                self.canonicalize(path)
                    .unwrap_or_else(|_| self.relative_path(path)),
            )
        } else {
            self.relative_path_cow(path)
        }
    }

    async fn async_ignore_path<'a>(
        &self,
        path: &'a Path,
        file_type: cap::FileType,
    ) -> Cow<'a, Path> {
        if file_type.is_symlink() {
            Cow::Owned(
                self.async_canonicalize(path)
                    .await
                    .unwrap_or_else(|_| self.relative_path(path)),
            )
        } else {
            self.relative_path_cow(path)
        }
    }

    pub fn get_ignored(&self) -> IgnoreList {
        (**self.disk_ignored.load()).clone()
    }

    pub fn symlink_name_filter(&self) -> IsIgnoredFn {
        let matcher = self.disk_ignored.load_full();

        IsIgnoredFn::from(move |file_type: cap::FileType, path: PathBuf| {
            if !file_type.is_symlink() {
                return IgnoreVerdict::Keep(path);
            }

            matcher.verdict(file_type, path)
        })
    }

    pub async fn diff_key(&self, path: &Path) -> PathBuf {
        match self.async_canonicalize(path).await {
            Ok(path) => path,
            Err(_) => self.async_canonicalize_parent(path).await,
        }
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
    #[cfg(unix)]
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
    pub fn server_notifier(&self) -> &inotify::InotifyServerNotifier {
        &self.server_notifier
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
        self.resolve_readable_fs_ignoring(server, path, &RequestIgnored::default())
            .await
    }

    pub async fn resolve_readable_fs_ignoring(
        &self,
        server: &crate::server::Server,
        path: &Path,
        ignored: &RequestIgnored,
    ) -> (PathBuf, Arc<dyn VirtualReadableFilesystem>) {
        let path = self.relative_path(path);

        if let Ok(trash_path) = path.strip_prefix(trash::TRASH_DIRECTORY)
            && let Some(resolved) = self
                .trash
                .resolve_virtual(server, trash_path, ignored)
                .await
        {
            return resolved;
        }

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

            {
                let configuration = server.configuration.read().await;
                if !configuration.backups.contains(&uuid)
                    || configuration.database_backups.contains(&uuid)
                {
                    break 'backupfs;
                }
            }

            match self.app_state.backup_manager.browse(server, uuid).await {
                Ok(Some(backup)) => {
                    let path = match backup_path.strip_prefix(uuid.to_string()) {
                        Ok(p) => p.to_path_buf(),
                        Err(_) => PathBuf::new(),
                    };

                    if !ignored.applies(server) {
                        return (path, backup);
                    }

                    let is_ignored = ignored.lexical_filter(server, Path::new(""));
                    if let Some(filesystem) = backup.as_virtual_cap() {
                        let mut filesystem = filesystem.clone();
                        filesystem.check_links = true;

                        return (path, Arc::new(filesystem.with_is_ignored(is_ignored)));
                    }

                    return (
                        path,
                        Arc::new(virtualfs::filtered::VirtualFilteredFilesystem {
                            inner: backup,
                            is_ignored,
                        }),
                    );
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

            if ignored
                .is_ignored_resolved(server, &archive_path, cap::FileType::File)
                .await
            {
                break 'archivefs;
            }

            let inner_path = match path.strip_prefix(&archive_path) {
                Ok(p) => p,
                Err(_) => break 'archivefs,
            };
            let archive_path = self.diff_key(&archive_path).await;

            let archive_key = match self.async_metadata(&archive_path).await {
                Ok(metadata) if metadata.is_file() => MimeCacheKey::from(&metadata),
                _ => break 'archivefs,
            };
            let cache_key = (archive_path, archive_key);

            if let Some(archive_fs) = self.archive_fs_cache.get(&cache_key).await {
                return (inner_path.to_path_buf(), archive_fs);
            }
            let archive_path = &cache_key.0;

            let archive_fs: Arc<dyn VirtualReadableFilesystem> =
                match archive_path.extension().and_then(|ext| ext.to_str()) {
                    Some("zip") => {
                        match virtualfs::archive::zip::VirtualZipArchive::open(
                            server.clone(),
                            archive_path,
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
                            archive_path,
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
                            archive_path,
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
                .insert(cache_key, archive_fs.clone())
                .await;

            return (inner_path.to_path_buf(), archive_fs);
        }

        let (mount_match, mounts, mut allowed) = {
            let server_config = server.configuration.read().await;
            if server_config.mounts.is_empty() {
                (None, Vec::new(), None)
            } else {
                let mounts = server_config.mounts.clone();
                let config = Arc::clone(&server.app_state.config);
                let path = path.clone();

                tokio::task::spawn_blocking(move || {
                    let mut allowed = None;
                    let mount_match = Self::match_mount(&config, &mounts, &path, &mut allowed);

                    (mount_match, mounts, allowed)
                })
                .await
                .unwrap_or_default()
            }
        };

        if let Some(MountMatch {
            inner_path,
            source_path,
            read_only,
            target,
        }) = mount_match
        {
            match cap::CapFilesystem::new(&source_path).await {
                Ok(cap_fs) => {
                    let fs = Self::mount_virtual_fs(server, cap_fs, read_only, &target, ignored);

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

        let mount_infos = if mounts.is_empty() {
            Vec::new()
        } else {
            let config = Arc::clone(&server.app_state.config);

            tokio::task::spawn_blocking(move || Self::mount_infos(&config, &mounts, &mut allowed))
                .await
                .unwrap_or_default()
        };

        let mut fs = self.cap_filesystem.get_virtual(server.clone());
        fs.is_primary_server_fs = true;
        fs.is_writable = true;
        let mut fs = fs.with_is_ignored(Self::deny_filter(server));
        if let Some(ignored) = ignored.filter(server) {
            fs = fs.with_is_ignored(ignored);
        }

        (
            path,
            Arc::new(virtualfs::mount::VirtualMountFilesystem {
                inner: fs,
                mounts: mount_infos,
            }),
        )
    }

    /// The deepest mount holding `path` whose source resolves inside `allowed_mounts`, the
    /// first in config order on equal depth. `allowed` is loaded on first use. Blocking.
    fn match_mount(
        config: &crate::config::Config,
        mounts: &[crate::server::configuration::Mount],
        path: &Path,
        allowed: &mut Option<crate::server::configuration::AllowedMounts>,
    ) -> Option<MountMatch> {
        let mut candidates: Vec<(usize, &crate::server::configuration::Mount, &Path)> = mounts
            .iter()
            .filter_map(|mount| {
                let target = Path::new(mount.container_relative_target()?);

                path.starts_with(target)
                    .then(|| (target.components().count(), mount, target))
            })
            .collect();
        candidates.sort_by_key(|(depth, _, _)| std::cmp::Reverse(*depth));

        for (_, mount, target) in candidates {
            let allowed = allowed.get_or_insert_with(|| {
                crate::server::configuration::AllowedMounts::load_blocking(config)
            });
            let Ok(source_path) = mount.resolve_allowed_source_blocking(allowed) else {
                continue;
            };
            let Ok(inner_path) = path.strip_prefix(target) else {
                continue;
            };

            return Some(MountMatch {
                inner_path: inner_path.to_path_buf(),
                source_path,
                read_only: mount.read_only,
                target: target.to_path_buf(),
            });
        }

        None
    }

    /// Every mount with a target inside the container root whose source resolves. Blocking.
    fn mount_infos(
        config: &crate::config::Config,
        mounts: &[crate::server::configuration::Mount],
        allowed: &mut Option<crate::server::configuration::AllowedMounts>,
    ) -> Vec<virtualfs::mount::MountInfo> {
        let mut infos = Vec::new();

        for mount in mounts {
            let Some(relative_target) = mount.container_relative_target() else {
                continue;
            };
            let allowed = allowed.get_or_insert_with(|| {
                crate::server::configuration::AllowedMounts::load_blocking(config)
            });
            if mount.resolve_allowed_source_blocking(allowed).is_err() {
                continue;
            }

            infos.push(virtualfs::mount::MountInfo {
                relative_target: PathBuf::from(relative_target),
            });
        }

        infos
    }

    /// A mount source as a filesystem whose entries are judged by the denylist and
    /// `ignored` at the server path they appear under, `target` joined with their own.
    fn mount_virtual_fs(
        server: &crate::server::Server,
        cap_fs: cap::CapFilesystem,
        read_only: bool,
        target: &Path,
        ignored: &RequestIgnored,
    ) -> virtualfs::cap::VirtualCapFilesystem {
        let mut fs = cap_fs.get_virtual(server.clone());
        fs.is_primary_server_fs = false;
        fs.is_writable = !read_only;

        if !ignored.applies(server) {
            return fs;
        }

        fs.check_links = true;
        fs.with_is_ignored(ignored.lexical_filter(server, target))
    }

    pub async fn resolve_writable_fs(
        &self,
        server: &crate::server::Server,
        path: impl AsRef<Path>,
    ) -> (PathBuf, Arc<dyn VirtualWritableFilesystem>) {
        self.resolve_writable_fs_ignoring(server, path, &RequestIgnored::default())
            .await
    }

    pub async fn resolve_writable_fs_ignoring(
        &self,
        server: &crate::server::Server,
        path: impl AsRef<Path>,
        ignored: &RequestIgnored,
    ) -> (PathBuf, Arc<dyn VirtualWritableFilesystem>) {
        let request_ignored = ignored;
        let ignored = ignored.filter(server);
        let path = self.relative_path(path.as_ref());

        let mount_match = {
            let server_config = server.configuration.read().await;
            if server_config.mounts.is_empty() {
                None
            } else {
                let mounts = server_config.mounts.clone();
                let config = Arc::clone(&server.app_state.config);
                let path = path.clone();

                tokio::task::spawn_blocking(move || {
                    Self::match_mount(&config, &mounts, &path, &mut None)
                })
                .await
                .unwrap_or_default()
            }
        };

        if let Some(MountMatch {
            inner_path,
            source_path,
            read_only,
            target,
        }) = mount_match
        {
            match cap::CapFilesystem::new(&source_path).await {
                Ok(cap_fs) => {
                    let fs =
                        Self::mount_virtual_fs(server, cap_fs, read_only, &target, request_ignored);

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
                        let mut fs = fs.with_is_ignored(Self::deny_filter(server));
                        if let Some(ignored) = ignored.clone() {
                            fs = fs.with_is_ignored(ignored);
                        }

                        return (path, Arc::new(fs));
                    }
                }
            }
        }

        let mut fs = self.cap_filesystem.get_virtual(server.clone());
        fs.is_primary_server_fs = true;
        fs.is_writable = true;
        let mut fs = fs.with_is_ignored(Self::deny_filter(server));
        if let Some(ignored) = ignored.clone() {
            fs = fs.with_is_ignored(ignored);
        }

        (path, Arc::new(fs))
    }

    /// The primary filesystem without ignore rules or disk quota, for restoring a
    /// server's files exactly as they were sent.
    pub fn transfer_writable_fs(
        &self,
        server: &crate::server::Server,
    ) -> Arc<dyn virtualfs::VirtualWritableFilesystem> {
        let mut fs = self.cap_filesystem.get_virtual(server.clone());
        fs.is_primary_server_fs = true;
        fs.is_writable = true;
        fs.ignore_quota = true;

        Arc::new(fs)
    }

    pub async fn truncate_path(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        if self.async_is_protected_path(&path).await {
            return Err(Self::virtual_path_error().into());
        }

        let metadata = self.async_symlink_metadata(&path).await?;

        if metadata.is_dir() {
            let key = self.diff_key(&path).await;
            let threads = self.config.load().api.file_delete_threads;
            let result = self.async_remove_dir_all(&path, threads).await;

            let delta = if result.is_ok() || self.async_symlink_metadata(&key).await.is_err() {
                self.disk_usage
                    .write()
                    .await
                    .remove_path(&key)
                    .map(|removed| {
                        usage::SpaceDelta::new(
                            -(removed.space.get_logical() as i64),
                            -(removed.space.get_physical() as i64),
                        )
                    })
            } else {
                match disk_checker::rescan_tree(
                    self.cap_filesystem.clone(),
                    Arc::clone(&self.disk_usage),
                    key,
                )
                .await
                {
                    Ok(delta) => Some(delta),
                    Err(err) => {
                        tracing::warn!(
                            path = %path.display(),
                            "failed to rescan partially removed directory: {}",
                            err
                        );
                        None
                    }
                }
            };

            if let Some(delta) = delta {
                self.try_update_atomics(delta, true);
            }
            result?;
        } else {
            let removed = disk_checker::space_delta(&metadata);
            self.async_remove_file(&path).await?;

            if let Some(parent) = path.parent() {
                self.async_allocate_in_path(
                    parent,
                    usage::SpaceDelta::new(-removed.logical, -removed.physical),
                    false,
                )
                .await;
            }
        }

        self.uploads.forget(&path, &self.cap_filesystem).await;

        Ok(())
    }

    pub async fn remove_empty_dir(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        if path.as_os_str().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cannot remove the server root directory",
            ));
        }

        if self.async_is_protected_path(&path).await {
            return Err(Self::virtual_path_error());
        }

        self.async_remove_dir(&path).await?;

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

        Ok(())
    }

    pub async fn rename_path(
        &self,
        old_path: impl AsRef<Path>,
        new_path: impl AsRef<Path>,
        parents: RenameParents,
    ) -> Result<(), anyhow::Error> {
        let old_path = self.relative_path(old_path.as_ref());
        let new_path = self.relative_path(new_path.as_ref());

        if self.async_is_protected_path(&old_path).await
            || self.async_is_protected_path(&new_path).await
        {
            return Err(Self::virtual_path_error().into());
        }

        if parents == RenameParents::Create
            && let Some(parent) = new_path.parent()
        {
            self.async_create_chowned_dir_all(parent, None).await?;
        }

        let old_metadata = self.async_symlink_metadata(&old_path).await?;
        let new_metadata = self.async_symlink_metadata(&new_path).await.ok();
        let is_dir = old_metadata.is_dir();

        #[cfg(unix)]
        let same_file = new_metadata.as_ref().is_some_and(|new_metadata| {
            use cap_std::fs::MetadataExt;

            new_metadata.dev() == old_metadata.dev() && new_metadata.ino() == old_metadata.ino()
        });
        #[cfg(not(unix))]
        let same_file = false;

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

        let abs_old_path = old_parent.join(match old_path.file_name() {
            Some(name) => name,
            None => return Err(anyhow::anyhow!("failed to get old path file name")),
        });
        let abs_new_path = new_parent.join(match new_path.file_name() {
            Some(name) => name,
            None => return Err(anyhow::anyhow!("failed to get new path file name")),
        });

        self.async_rename(&old_path, &self.cap_filesystem, &new_path)
            .await?;

        if same_file {
            return Ok(());
        }

        if is_dir {
            let mut disk_usage = self.disk_usage.write().await;

            let path = disk_usage.remove_path(&abs_old_path);
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
            let moved = disk_checker::space_delta(&old_metadata);
            let added = match new_metadata {
                Some(new_metadata) => {
                    let replaced = disk_checker::space_delta(&new_metadata);

                    usage::SpaceDelta::new(
                        moved.logical - replaced.logical,
                        moved.physical - replaced.physical,
                    )
                }
                None => moved,
            };

            self.async_allocate_in_path(
                &old_parent,
                usage::SpaceDelta::new(-moved.logical, -moved.physical),
                true,
            )
            .await;
            self.async_allocate_in_path(&new_parent, added, true).await;
        }

        self.uploads.forget(&old_path, &self.cap_filesystem).await;

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
                destination_filesystem
                    .async_quota_copy_from(
                        filesystem.backing_server(),
                        &path,
                        &destination_path,
                        Some(metadata.permissions),
                        progress.clone_bytes().as_ref(),
                    )
                    .await?;
            } else {
                let file_read = filesystem.async_read_file(&path, None).await?;
                let mut reader = progress.async_counting_reader(file_read.reader);

                if let Some(parent) = destination_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    destination_filesystem
                        .async_create_dir_all(&parent, None)
                        .await?;
                }

                if destination_filesystem.is_primary_server_fs() {
                    let mut writer = destination_filesystem
                        .async_create_file_with_permissions(
                            &destination_path,
                            Some(metadata.permissions),
                        )
                        .await?;

                    crate::io::async_copy(&mut reader, &mut writer).await?;
                    writer.shutdown().await?;
                } else {
                    // Both sides may be the same file on one mount, which creating the
                    // destination in place would truncate before it is read.
                    let staging = destination_path
                        .with_file_name(format!(".calagopus-copy-{}", uuid::Uuid::new_v4()));

                    let result = async {
                        let mut writer = destination_filesystem
                            .async_create_file_with_permissions(
                                &staging,
                                Some(metadata.permissions),
                            )
                            .await?;

                        crate::io::async_copy(&mut reader, &mut writer).await?;
                        writer.shutdown().await?;

                        destination_filesystem
                            .async_rename(&staging, &destination_path, cap::FileType::File)
                            .await
                    }
                    .await;

                    if result.is_err() {
                        destination_filesystem
                            .async_remove_file(&staging)
                            .await
                            .ok();
                    }
                    result?;
                }
            }

            progress.increment_files();
        } else {
            destination_filesystem
                .async_create_dir_all(&destination_path, Some(metadata.permissions))
                .await?;

            let ignored = if filesystem.is_primary_server_fs() {
                server.filesystem.get_ignored().into()
            } else {
                Default::default()
            };
            let threads = server.app_state.config.load().api.file_copy_threads;
            let quota_copy = filesystem.is_primary_server_fs()
                && destination_filesystem.is_primary_server_fs()
                && filesystem.backing_server().uuid == destination_filesystem.backing_server().uuid;

            let copy_entry = {
                let server = server.clone();
                let filesystem = filesystem.clone();
                let source_path = Arc::new(path.clone());
                let destination_path = Arc::new(destination_path);
                let destination_filesystem = destination_filesystem.clone();
                let progress = progress.clone();

                move |entry: virtualfs::VirtualWalkEntry,
                      stream: Option<virtualfs::AsyncReadableFileStream>| {
                    let path = entry.path;

                    let server = server.clone();
                    let filesystem = filesystem.clone();
                    let source_path = Arc::clone(&source_path);
                    let destination_path = Arc::clone(&destination_path);
                    let destination_filesystem = destination_filesystem.clone();
                    let progress = progress.clone();

                    async move {
                        let metadata = match filesystem.async_symlink_metadata(&path).await {
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
                                destination_filesystem
                                    .async_create_dir_all(&parent, None)
                                    .await?;
                            }

                            if let Some(stream) = stream {
                                let mut reader = progress.async_counting_reader(stream);

                                let mut writer = destination_filesystem
                                    .async_create_file_with_permissions(
                                        &destination_path,
                                        Some(metadata.permissions),
                                    )
                                    .await?;

                                crate::io::async_copy(&mut reader, &mut writer).await?;
                                writer.shutdown().await?;
                            } else {
                                destination_filesystem
                                    .async_quota_copy_from(
                                        &server,
                                        &path,
                                        &destination_path,
                                        Some(metadata.permissions),
                                        progress.clone_bytes().as_ref(),
                                    )
                                    .await?;
                            }

                            progress.increment_files();
                        } else if metadata.file_type.is_dir() {
                            destination_filesystem
                                .async_create_dir_all(&destination_path, Some(metadata.permissions))
                                .await?;

                            progress.increment_bytes(metadata.size);
                        } else if metadata.file_type.is_symlink()
                            && let Ok(target) = filesystem.async_read_symlink(&path).await
                        {
                            if let Err(err) = destination_filesystem
                                .async_create_symlink(&target, &destination_path)
                                .await
                            {
                                tracing::debug!(path = %destination_path.display(), "failed to create symlink from copy: {:?}", err);
                            } else {
                                progress.increment_files();
                            }
                        }

                        Ok(())
                    }
                }
            };

            if quota_copy {
                filesystem
                    .async_walk_dir(&path, ignored)
                    .await?
                    .run_multithreaded(
                        threads,
                        AsyncDirectoryWalkFn::from(move |entry| copy_entry(entry, None)),
                    )
                    .await?;
            } else {
                filesystem
                    .async_walk_dir_stream(&path, ignored)
                    .await?
                    .run_multithreaded(
                        threads,
                        AsyncDirectoryStreamWalkFn::from(move |entry, stream| {
                            copy_entry(entry, Some(stream))
                        }),
                    )
                    .await?;
            }
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

                let result = self.disk_usage_cached_physical.try_update(
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
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
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
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(abs))
                })
                .ok();
        }

        self.disk_usage_delta_cached
            .fetch_add(delta.physical, Ordering::Relaxed);
        if self
            .config
            .load()
            .system
            .disk_limiter_mode
            .usage_is_scanned()
            || !self.limiter_usage_known.load(Ordering::Relaxed)
        {
            self.resource_usage
                .publish_disk_usage(self.get_physical_cached_size());
        }

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
    pub async fn async_allocate_in_path(
        &self,
        path: &Path,
        delta: impl Into<usage::SpaceDelta>,
        ignorant: bool,
    ) -> bool {
        let delta: usage::SpaceDelta = delta.into();
        if !self.try_update_atomics(delta, ignorant) {
            return false;
        }

        self.disk_usage.write().await.update_size(path, delta);

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

        self.trash.clear().await;

        let threads = self.config.load().api.file_delete_threads;
        self.async_remove_dir_all(Path::new(""), threads).await
    }

    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    fn chown_impl(
        config: &crate::config::Config,
        cap_filesystem: &cap::CapFilesystem,
        path: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            let cfg = config.load();
            let owner_uid = rustix::fs::Uid::from_raw_unchecked(cfg.system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(cfg.system.user.gid);
            drop(cfg);

            cap_filesystem.lchown(path, owner_uid, owner_gid)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    fn absorb_chown_refusal(
        &self,
        result: Result<(), std::io::Error>,
    ) -> Result<(), std::io::Error> {
        Self::absorb_chown_refusal_impl(&self.config, &self.chown_refused, self.uuid, result)
    }

    fn absorb_chown_refusal_impl(
        config: &crate::config::Config,
        chown_refused: &AtomicBool,
        uuid: uuid::Uuid,
        result: Result<(), std::io::Error>,
    ) -> Result<(), std::io::Error> {
        let Err(err) = result else {
            return Ok(());
        };

        if !config.load().system.user.rootless.enabled {
            return Err(err);
        }

        if !chown_refused.swap(true, Ordering::Relaxed) {
            tracing::debug!(
                server = %uuid,
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

    /// Whether `metadata` already carries the configured owner, so a chown would be a no-op.
    pub fn is_owned(&self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let cfg = self.config.load();
            metadata.uid() == cfg.system.user.uid && metadata.gid() == cfg.system.user.gid
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            true
        }
    }

    pub fn chown_file(&self, file: &std::fs::File) -> Result<(), std::io::Error> {
        if self.chown_refused.load(Ordering::Relaxed) {
            return Ok(());
        }

        #[cfg(unix)]
        {
            let cfg = self.config.load();
            let owner_uid = rustix::fs::Uid::from_raw_unchecked(cfg.system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(cfg.system.user.gid);
            drop(cfg);

            self.absorb_chown_refusal(
                rustix::fs::fchown(file, Some(owner_uid), Some(owner_gid)).map_err(Into::into),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Ok(())
        }
    }
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub async fn async_chown_path(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        if self.chown_refused.load(Ordering::Relaxed) {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            let owner_uid = rustix::fs::Uid::from_raw_unchecked(self.config.load().system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(self.config.load().system.user.gid);

            self.absorb_chown_refusal(
                self.cap_filesystem
                    .async_lchown(path, owner_uid, owner_gid)
                    .await,
            )
        }
        #[cfg(not(target_os = "linux"))]
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

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;

            let metadata = self.async_metadata(path.as_ref()).await?;
            let owner_uid = rustix::fs::Uid::from_raw_unchecked(self.config.load().system.user.uid);
            let owner_gid = rustix::fs::Gid::from_raw_unchecked(self.config.load().system.user.gid);
            let root_rel = self.relative_path(path.as_ref());

            self.absorb_chown_refusal(
                self.cap_filesystem
                    .async_lchown(&root_rel, owner_uid, owner_gid)
                    .await,
            )?;

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
                            let Ok(stat) = rustix::fs::statx(
                                inner.as_fd(),
                                &entry.path,
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

                            entry.lchown(owner_uid, owner_gid).ok();

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
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Ok(())
        }
    }

    pub fn create_chowned_dir_all(
        &self,
        path: impl AsRef<Path>,
        permissions: Option<PortablePermissions>,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());
        if path.as_os_str().is_empty() {
            if let Some(permissions) = permissions {
                self.set_permissions(&path, permissions)?;
            }

            return Ok(());
        }

        Self::create_chowned_dir_all_impl(
            &self.config,
            &self.chown_refused,
            self.uuid,
            &self.cap_filesystem,
            &path,
            permissions,
        )
    }

    /// `permissions` only apply to the leaf directory, and are also applied when it already exists.
    pub async fn async_create_chowned_dir_all(
        &self,
        path: impl AsRef<Path>,
        permissions: Option<PortablePermissions>,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());
        if path.as_os_str().is_empty() {
            if let Some(permissions) = permissions {
                self.async_set_permissions(&path, permissions).await?;
            }

            return Ok(());
        }

        let config = self.config.clone();
        let chown_refused = Arc::clone(&self.chown_refused);
        let uuid = self.uuid;
        let cap_filesystem = self.cap_filesystem.clone();

        tokio::task::spawn_blocking(move || {
            Self::create_chowned_dir_all_impl(
                &config,
                &chown_refused,
                uuid,
                &cap_filesystem,
                &path,
                permissions,
            )
        })
        .await?
    }

    fn create_chowned_dir_all_impl(
        config: &crate::config::Config,
        chown_refused: &AtomicBool,
        uuid: uuid::Uuid,
        cap_filesystem: &cap::CapFilesystem,
        path: &Path,
        permissions: Option<PortablePermissions>,
    ) -> Result<(), std::io::Error> {
        match Self::create_chowned_dir(
            config,
            chown_refused,
            uuid,
            cap_filesystem,
            path,
            permissions,
        ) {
            Ok(chowned) => return chowned,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Some(permissions) = permissions {
                    cap_filesystem.set_permissions(path, permissions)?;
                }

                return Ok(());
            }
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
            Err(_) => {}
        }

        let mut progress = PathBuf::new();
        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            progress.push(component);
            let permissions = permissions.filter(|_| components.peek().is_none());

            match Self::create_chowned_dir(
                config,
                chown_refused,
                uuid,
                cap_filesystem,
                &progress,
                permissions,
            ) {
                Ok(chowned) => chowned?,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Some(permissions) = permissions {
                        cap_filesystem.set_permissions(&progress, permissions)?;
                    }
                }
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    /// Creates a single directory and chowns it through the same parent directory fd.
    /// The outer error is the creation's, the inner one the chown's.
    fn create_chowned_dir(
        config: &crate::config::Config,
        chown_refused: &AtomicBool,
        uuid: uuid::Uuid,
        cap_filesystem: &cap::CapFilesystem,
        path: &Path,
        permissions: Option<PortablePermissions>,
    ) -> Result<Result<(), std::io::Error>, std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            cap_filesystem.create_dir_then(path, permissions, |fd, name| {
                Self::chown_at(config, chown_refused, uuid, fd, name)
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, chown_refused, uuid);
            cap_filesystem.create_dir(path, permissions).map(Ok)
        }
    }

    /// Creates a symlink like [`cap::CapFilesystem::symlink`], then chowns it and sets
    /// its modification time through the same parent directory fd.
    pub fn create_chowned_symlink(
        &self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
        modified: Option<std::time::SystemTime>,
    ) -> Result<(), std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            Self::create_chowned_symlink_impl(
                &self.config,
                &self.chown_refused,
                self.uuid,
                &self.cap_filesystem,
                target.as_ref(),
                link.as_ref(),
                false,
                modified,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.cap_filesystem.symlink(&target, &link)?;
            self.chown_path(&link)?;
            if let Some(modified) = modified {
                self.cap_filesystem.set_times(&link, modified, None)?;
            }

            Ok(())
        }
    }

    /// Like [`Self::create_chowned_symlink`], writing `target` verbatim when `verbatim` is set
    /// (see [`cap::CapFilesystem::async_symlink_contents`]).
    pub async fn async_create_chowned_symlink(
        &self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
        verbatim: bool,
    ) -> Result<(), std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            let config = self.config.clone();
            let chown_refused = Arc::clone(&self.chown_refused);
            let uuid = self.uuid;
            let cap_filesystem = self.cap_filesystem.clone();
            let target = target.as_ref().to_path_buf();
            let link = link.as_ref().to_path_buf();

            tokio::task::spawn_blocking(move || {
                Self::create_chowned_symlink_impl(
                    &config,
                    &chown_refused,
                    uuid,
                    &cap_filesystem,
                    &target,
                    &link,
                    verbatim,
                    None,
                )
            })
            .await?
        }
        #[cfg(not(target_os = "linux"))]
        {
            if verbatim {
                self.cap_filesystem
                    .async_symlink_contents(&target, &link)
                    .await?;
            } else {
                self.cap_filesystem.async_symlink(&target, &link).await?;
            }

            self.async_chown_path(&link).await
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn create_chowned_symlink_impl(
        config: &crate::config::Config,
        chown_refused: &AtomicBool,
        uuid: uuid::Uuid,
        cap_filesystem: &cap::CapFilesystem,
        target: &Path,
        link: &Path,
        verbatim: bool,
        modified: Option<std::time::SystemTime>,
    ) -> Result<(), std::io::Error> {
        cap_filesystem.create_symlink_then(target, link, verbatim, |fd, name| {
            Self::chown_at(config, chown_refused, uuid, fd, name)?;
            if let Some(modified) = modified {
                cap::CapFilesystem::set_times_at(fd, name, modified, None)?;
            }

            Ok(())
        })?
    }

    #[cfg(target_os = "linux")]
    fn chown_at(
        config: &crate::config::Config,
        chown_refused: &AtomicBool,
        uuid: uuid::Uuid,
        fd: std::os::fd::BorrowedFd<'_>,
        name: &Path,
    ) -> Result<(), std::io::Error> {
        if chown_refused.load(Ordering::Relaxed) {
            return Ok(());
        }

        let cfg = config.load();
        let owner_uid = rustix::fs::Uid::from_raw_unchecked(cfg.system.user.uid);
        let owner_gid = rustix::fs::Gid::from_raw_unchecked(cfg.system.user.gid);
        drop(cfg);

        Self::absorb_chown_refusal_impl(
            config,
            chown_refused,
            uuid,
            rustix::fs::chownat(
                fd,
                name,
                Some(owner_uid),
                Some(owner_gid),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(Into::into),
        )
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

        self.open_cap_filesystem().await;
    }

    pub async fn attach(&self) {
        if let Err(err) = self.get_disk_limiter().attach().await {
            tracing::error!(
                path = %self.base_path.display(),
                "failed to attach server base directory: {}",
                err
            );
        }

        self.open_cap_filesystem().await;
    }

    async fn open_cap_filesystem(&self) {
        if !self.cap_filesystem.is_uninitialized() {
            return;
        }

        let base_path = self.base_path.clone();
        let dir = match tokio::task::spawn_blocking(move || {
            cap_std::fs::Dir::open_ambient_dir(&base_path, cap_std::ambient_authority())
        })
        .await
        {
            Ok(Ok(dir)) => dir,
            Ok(Err(err)) => {
                tracing::error!(
                    path = %self.base_path.display(),
                    "failed to open server base directory: {:?}",
                    err
                );

                return;
            }
            Err(err) => {
                tracing::error!(
                    path = %self.base_path.display(),
                    "failed to open server base directory: {:?}",
                    err
                );

                return;
            }
        };

        #[cfg(target_os = "linux")]
        self.zfs_dataset_root.store(
            rustix::fs::fstatfs(&dir).is_ok_and(|stat| stat.f_type as u64 == ZFS_SUPER_MAGIC),
            Ordering::Relaxed,
        );
        self.cap_filesystem.inner.store(Some(Arc::new(dir)));

        self.ensure_trash_directory().await;
        self.trash.load(&self.cap_filesystem).await;

        if self.app_state.config.load().system.disk_check_use_inotify {
            tokio::spawn({
                let state = self.app_state.clone();
                let server_notifier = self.server_notifier.clone();
                let server_use_server_notifier = self.use_server_notifier.clone();
                let server_uuid = self.uuid;

                async move {
                    match state
                        .inotify_manager
                        .register_server_with_notifier(server_notifier, server_uuid)
                        .await
                    {
                        Ok(watching) => {
                            server_use_server_notifier.store(watching, Ordering::Relaxed);
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

    pub async fn destroy(&self) -> Result<(), std::io::Error> {
        self.disk_checker.abort();
        self.trash.abort_purge_task();
        self.app_state
            .inotify_manager
            .unregister_server(self.uuid)
            .await;

        if let Err(err) = self.get_disk_limiter().destroy().await {
            tracing::debug!(
                path = %self.base_path.display(),
                "disk limiter destroy failed, retrying without an open handle: {}",
                err
            );
            self.close();

            self.get_disk_limiter().destroy().await?;
        }

        Ok(())
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

    fn directory_entry_space_blocking(
        &self,
        real_path: &Path,
        options: DirectoryEntryOptions,
    ) -> (u64, u64) {
        if !options.directory_size || self.config.load().api.disable_directory_size {
            return (0, 0);
        }

        if let Some(space) = self.disk_usage.blocking_read().get_size(real_path) {
            return (space.get_logical(), space.get_physical());
        }

        let canonical = match self.canonicalize(real_path) {
            Ok(canonical) if canonical != real_path => canonical,
            _ => return (0, 0),
        };

        self.disk_usage
            .blocking_read()
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

        Self::assemble_api_entry(
            path,
            metadata,
            real_metadata,
            options,
            (size, size_physical),
            detected_mime,
        )
    }

    pub fn to_api_entry_buffer_blocking(
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
            self.directory_entry_space_blocking(real_path, options)
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

        Self::assemble_api_entry(
            path,
            metadata,
            real_metadata,
            options,
            (size, size_physical),
            detected_mime,
        )
    }

    /// Synchronous counterpart of [`Self::to_api_entry_buffer`] for entries that are
    /// not directories, whose size never needs a walk.
    pub fn to_api_file_entry_buffer(
        &self,
        path: PathBuf,
        metadata: &Metadata,
        options: DirectoryEntryOptions,
        buffer: Option<&[u8]>,
    ) -> crate::models::DirectoryEntry {
        let detected_mime = if metadata.is_symlink() {
            MimeCacheValue::symlink()
        } else {
            crate::utils::detect_mime_type(&path, buffer)
        };

        Self::assemble_api_entry(
            path,
            metadata,
            metadata,
            options,
            (metadata.size_logical(), metadata.size_physical()),
            detected_mime,
        )
    }

    fn assemble_api_entry(
        path: PathBuf,
        metadata: &Metadata,
        real_metadata: &Metadata,
        options: DirectoryEntryOptions,
        (size, size_physical): (u64, u64),
        detected_mime: MimeCacheValue,
    ) -> crate::models::DirectoryEntry {
        crate::models::DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(raw_mode(metadata)),
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

        Self::assemble_api_entry(
            path,
            metadata,
            real_metadata,
            options,
            (size, size_physical),
            detected_mime,
        )
    }

    pub async fn to_api_entry_cap(
        &self,
        filesystem: &cap::CapFilesystem,
        path: PathBuf,
        metadata: Metadata,
        options: DirectoryEntryOptions,
    ) -> Result<crate::models::DirectoryEntry, anyhow::Error> {
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
            filesystem.async_canonicalize(&path).await.ok()
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
            parent: None,
        }
    }

    pub fn prepare_api_entry_cap_blocking(
        &self,
        filesystem: &cap::CapFilesystem,
        path: PathBuf,
        metadata: Metadata,
    ) -> PreparedDirectoryEntry {
        let symlink_destination = if metadata.is_symlink() {
            filesystem.canonicalize(&path).ok()
        } else {
            None
        };

        let symlink_destination_metadata =
            if let Some(symlink_destination) = symlink_destination.clone() {
                filesystem.symlink_metadata(&symlink_destination).ok()
            } else {
                None
            };

        PreparedDirectoryEntry {
            path,
            metadata,
            symlink_destination,
            symlink_destination_metadata,
            parent: None,
        }
    }

    pub fn prepared_entry_sort_size_blocking(
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
            self.directory_entry_space_blocking(real_path, options)
        } else {
            (real_metadata.size_logical(), real_metadata.size_physical())
        }
    }

    pub async fn finish_api_entry_cap(
        &self,
        filesystem: &cap::CapFilesystem,
        prepared: PreparedDirectoryEntry,
        options: DirectoryEntryOptions,
    ) -> Result<crate::models::DirectoryEntry, anyhow::Error> {
        let mime_key = MimeCacheKey::from(&prepared.metadata);

        let (prepared, detected_mime) =
            if let Some(detected_mime) = self.app_state.mime_cache.get(&mime_key) {
                (prepared, detected_mime)
            } else if prepared.is_empty_file() {
                (prepared, MimeCacheValue::text())
            } else {
                tokio::task::spawn_blocking({
                    let filesystem = filesystem.clone();
                    let mime_cache = self.app_state.mime_cache.clone();

                    move || {
                        let detected_mime = prepared
                            .cached_mime_type_blocking(&mime_cache, || prepared.open(&filesystem));

                        (prepared, detected_mime)
                    }
                })
                .await?
            };

        let PreparedDirectoryEntry {
            path,
            metadata,
            symlink_destination,
            symlink_destination_metadata,
            ..
        } = prepared;

        Ok(self
            .to_api_entry_mime_type(
                path,
                &metadata,
                options,
                Some(detected_mime),
                symlink_destination,
                symlink_destination_metadata,
            )
            .await)
    }

    pub fn finish_api_entry_cap_blocking(
        &self,
        filesystem: &cap::CapFilesystem,
        prepared: PreparedDirectoryEntry,
        options: DirectoryEntryOptions,
    ) -> crate::models::DirectoryEntry {
        let detected_mime = prepared
            .cached_mime_type_blocking(&self.app_state.mime_cache, || prepared.open(filesystem));

        let PreparedDirectoryEntry {
            path,
            metadata,
            symlink_destination,
            symlink_destination_metadata,
            ..
        } = prepared;

        let real_metadata = symlink_destination_metadata.as_ref().unwrap_or(&metadata);
        let real_path = symlink_destination.as_ref().unwrap_or(&path);

        let (size, size_physical) = if real_metadata.is_dir() {
            self.directory_entry_space_blocking(real_path, options)
        } else {
            (real_metadata.size_logical(), real_metadata.size_physical())
        };

        let detected_mime = if real_metadata.is_dir() {
            MimeCacheValue::directory()
        } else if real_metadata.is_symlink() {
            MimeCacheValue::symlink()
        } else {
            detected_mime
        };

        Self::assemble_api_entry(
            path,
            &metadata,
            real_metadata,
            options,
            (size, size_physical),
            detected_mime,
        )
    }
}

#[derive(Clone, Copy, Default)]
pub struct DirectoryEntryOptions {
    pub directory_size: bool,
    pub r#virtual: bool,
}

pub struct PreparedDirectoryEntry {
    pub path: PathBuf,
    pub metadata: Metadata,
    pub symlink_destination: Option<PathBuf>,
    pub symlink_destination_metadata: Option<Metadata>,
    parent: Option<Arc<cap::ListingDir>>,
}

impl PreparedDirectoryEntry {
    fn open(&self, filesystem: &cap::CapFilesystem) -> std::io::Result<std::fs::File> {
        match (&self.parent, self.path.file_name()) {
            (Some(parent), Some(name)) => parent.open(name),
            _ => filesystem.open(self.symlink_destination.as_ref().unwrap_or(&self.path)),
        }
    }

    fn is_empty_file(&self) -> bool {
        (self.metadata.is_file() && self.metadata.len() == 0)
            || (self.symlink_destination.is_some()
                && self
                    .symlink_destination_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.is_file() && metadata.len() == 0))
    }

    fn cached_mime_type_blocking(
        &self,
        mime_cache: &crate::routes::MimeCache,
        open: impl FnOnce() -> std::io::Result<std::fs::File>,
    ) -> MimeCacheValue {
        let mime_key = MimeCacheKey::from(&self.metadata);

        if let Some(detected_mime) = mime_cache.get(&mime_key) {
            detected_mime
        } else if self.is_empty_file() {
            MimeCacheValue::text()
        } else {
            mime_cache.get_with_by_ref(&mime_key, || {
                let path = self.symlink_destination.as_ref().unwrap_or(&self.path);

                let mut buffer = [0; 64];
                let buffer = if self.metadata.is_file()
                    || (self.symlink_destination.is_some()
                        && self
                            .symlink_destination_metadata
                            .as_ref()
                            .is_some_and(|metadata| metadata.is_file()))
                {
                    match open() {
                        Ok(mut file) => {
                            #[cfg(target_os = "linux")]
                            rustix::fs::fadvise(&file, 0, None, rustix::fs::Advice::Random).ok();

                            let bytes_read =
                                std::io::Read::read(&mut file, &mut buffer).unwrap_or(0);

                            buffer.get(..bytes_read)
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                };

                crate::utils::detect_mime_type(path, buffer)
            })
        }
    }

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
    fn concurrent_mime_misses_open_once() -> Result<(), anyhow::Error> {
        use std::sync::{Barrier, atomic::AtomicUsize, mpsc};

        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let temp = tempfile::tempdir()?;
        std::fs::write(temp.path().join("data.bin"), b"shared MIME read")?;
        let filesystem = runtime.block_on(cap::CapFilesystem::new(temp.path()))?;
        let metadata = filesystem.symlink_metadata("data.bin")?;
        let cache = crate::routes::MimeCache::new(16);
        let start = Barrier::new(9);
        let opens = AtomicUsize::new(0);
        let release = AtomicBool::new(false);
        let (started, first_open) = mpsc::channel();

        let opened = std::thread::scope(|scope| {
            let mut workers = Vec::new();

            for _ in 0..8 {
                let prepared = PreparedDirectoryEntry {
                    path: PathBuf::from("data.bin"),
                    metadata: metadata.clone(),
                    symlink_destination: None,
                    symlink_destination_metadata: None,
                    parent: None,
                };

                let (cache, start, opens, release, started, filesystem) =
                    (&cache, &start, &opens, &release, &started, &filesystem);

                workers.push(scope.spawn(move || {
                    start.wait();

                    prepared.cached_mime_type_blocking(cache, || {
                        if opens.fetch_add(1, Ordering::Relaxed) == 0 {
                            started.send(()).expect("notifying first MIME open failed");
                            while !release.load(Ordering::Acquire) {
                                std::thread::yield_now();
                            }
                        }

                        filesystem.open("data.bin")
                    })
                }));
            }

            start.wait();

            let opened = first_open.recv_timeout(std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(20));
            release.store(true, Ordering::Release);

            for worker in workers {
                let value = worker.join().expect("MIME worker panicked");
                assert_eq!(value.mime, "application/octet-stream");
                assert!(value.valid_utf8);
            }

            opened
        });

        opened?;
        assert_eq!(opens.load(Ordering::Relaxed), 1);
        Ok(())
    }

    fn mount(target: &str) -> crate::server::configuration::Mount {
        crate::server::configuration::Mount {
            default: false,
            target: target.into(),
            source: "/mnt/allowed/source".into(),
            read_only: false,
        }
    }

    // Filesystem
    #[test]
    fn mount_points_and_virtual_parents_cannot_be_removed_or_renamed() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir_all(root.join("mods")).unwrap();
            std::fs::write(root.join("mods/a.jar"), b"x").unwrap();
            std::fs::write(root.join("x.txt"), b"x").unwrap();

            server.filesystem.update_mounts(&[
                mount("/home/container/mods"),
                mount("/home/container/plugins/data"),
            ]);

            for path in ["mods", "plugins", "plugins/data"] {
                assert!(
                    server.filesystem.is_mount_gateway(Path::new(path)),
                    "{path}"
                );
                assert!(
                    server
                        .filesystem
                        .async_is_protected_path(Path::new(path))
                        .await,
                    "{path}"
                );
                assert!(
                    server
                        .filesystem
                        .is_ignored(Path::new(path), FileType::File),
                    "{path}"
                );
                assert!(
                    !server.filesystem.is_ignored(Path::new(path), FileType::Dir),
                    "{path}"
                );
            }
            assert!(!server.filesystem.is_mount_gateway(Path::new("mods/a.jar")));
            assert!(!server.filesystem.is_mount_gateway(Path::new("")));

            assert!(server.filesystem.truncate_path("mods").await.is_err());
            assert!(server.filesystem.remove_empty_dir("plugins").await.is_err());
            assert!(
                server
                    .filesystem
                    .rename_path("mods", "mods2", RenameParents::Require)
                    .await
                    .is_err()
            );
            assert!(
                server
                    .filesystem
                    .rename_path("x.txt", "plugins", RenameParents::Require)
                    .await
                    .is_err()
            );
            assert!(
                server
                    .filesystem
                    .trash
                    .trash(&server, Path::new("mods"), trash::TrashSource::Api)
                    .await
                    .is_err()
            );
            assert!(root.join("mods/a.jar").is_file());
            assert!(root.join("x.txt").is_file());

            assert!(server.filesystem.truncate_path("mods/a.jar").await.is_ok());

            server.filesystem.update_mounts(&[]);
            assert!(!server.filesystem.is_mount_gateway(Path::new("mods")));
            assert!(server.filesystem.truncate_path("mods").await.is_ok());
        });
    }

    #[test]
    fn backup_browsing_directory_is_never_a_write_target() {
        crate::server::Server::with_mock(|server| async move {
            assert!(
                server
                    .filesystem
                    .is_ignored(Path::new(".backups"), FileType::Dir)
            );
            assert!(
                server
                    .filesystem
                    .is_ignored(Path::new(".backups/abc/world"), FileType::File)
            );
            assert!(
                server
                    .filesystem
                    .async_is_protected_path(Path::new(".backups/abc"))
                    .await
            );
            assert!(
                server
                    .filesystem
                    .rename_path("missing", ".backups/x", RenameParents::Create)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn zfs_control_dir_is_hidden_and_protected_on_a_dataset_root() {
        crate::server::Server::with_mock(|server| async move {
            let filesystem = &server.filesystem;
            filesystem.zfs_dataset_root.store(true, Ordering::Relaxed);

            for (path, expected) in [
                (".zfs", true),
                (".zfs/snapshot/backup-x/file", true),
                ("/.zfs/snapshot", true),
                ("./.zfs", true),
                ("sub/.zfs", false),
                (".zfsx", false),
            ] {
                let path = Path::new(path);
                for file_type in [FileType::Dir, FileType::File] {
                    assert_eq!(
                        filesystem.is_virtual_write_target(path, file_type),
                        expected,
                        "{path:?} {file_type:?}"
                    );
                    assert_eq!(
                        filesystem.is_ignored(path, file_type),
                        expected,
                        "{path:?} {file_type:?}"
                    );
                    assert_eq!(
                        filesystem.async_is_ignored(path, file_type).await,
                        expected,
                        "{path:?} {file_type:?}"
                    );
                }
                assert_eq!(
                    filesystem.async_is_protected_path(path).await,
                    expected,
                    "{path:?}"
                );
            }
        });
    }

    #[test]
    fn zfs_control_dir_is_ordinary_off_a_dataset_root() {
        crate::server::Server::with_mock(|server| async move {
            let filesystem = &server.filesystem;
            let path = Path::new(".zfs");

            for file_type in [FileType::Dir, FileType::File] {
                assert!(!filesystem.is_virtual_write_target(path, file_type));
                assert!(!filesystem.is_ignored(path, file_type));
                assert!(!filesystem.async_is_ignored(path, file_type).await);
            }
            assert!(!filesystem.async_is_protected_path(path).await);
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_into_zfs_control_dir_is_ignored_on_a_dataset_root() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir_all(root.join(".zfs/snapshot")).unwrap();
            std::os::unix::fs::symlink(".zfs/snapshot", root.join("link")).unwrap();
            server.filesystem.update_ignored(&[] as &[&str]).await;
            server
                .filesystem
                .zfs_dataset_root
                .store(true, Ordering::Relaxed);

            assert!(
                server
                    .filesystem
                    .async_is_ignored(Path::new("link"), FileType::Symlink)
                    .await
            );
        });
    }

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

    #[cfg(unix)]
    struct CopyFixture {
        server: crate::server::Server,
        root: PathBuf,
        _temp: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl CopyFixture {
        async fn new() -> Result<Self, anyhow::Error> {
            let (temp, server) = crate::server::Server::mock_in_tempdir().await;
            let root = server.filesystem.base_path.to_path_buf();

            Ok(Self {
                server,
                root,
                _temp: temp,
            })
        }

        fn write_source(&self) -> Result<(), anyhow::Error> {
            use std::os::unix::fs::PermissionsExt;

            std::fs::create_dir_all(self.root.join("src/nested"))?;
            std::fs::write(self.root.join("src/a.txt"), b"alpha")?;
            std::fs::write(self.root.join("src/nested/b.bin"), b"\x00\x01\x02beta")?;
            std::os::unix::fs::symlink("a.txt", self.root.join("src/link"))?;

            for (path, mode) in [("src/a.txt", 0o640), ("src/nested/b.bin", 0o755)] {
                let file = std::fs::File::open(self.root.join(path))?;
                file.set_permissions(std::fs::Permissions::from_mode(mode))?;
                file.set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000),
                )?;
            }

            Ok(())
        }

        async fn copy(
            &self,
            source: &str,
            destination: &str,
            destination_filesystem: Option<Arc<dyn VirtualWritableFilesystem>>,
        ) -> Result<(), anyhow::Error> {
            let (path, filesystem) = self
                .server
                .filesystem
                .resolve_readable_fs(&self.server, Path::new(source))
                .await;
            let metadata = filesystem.async_metadata(&path).await?;
            let (destination_path, writable) = match destination_filesystem {
                Some(writable) => (PathBuf::from(destination), writable),
                None => {
                    self.server
                        .filesystem
                        .resolve_writable_fs(&self.server, destination)
                        .await
                }
            };

            self.server
                .filesystem
                .copy_path(
                    archive::create::ArchiveProgress::default(),
                    &self.server,
                    metadata,
                    path,
                    filesystem,
                    destination_path,
                    writable,
                )
                .await
        }
    }

    #[cfg(unix)]
    fn assert_copied_file(
        path: &Path,
        contents: &[u8],
        mode: u32,
        copied_after: std::time::SystemTime,
    ) -> Result<(), anyhow::Error> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = std::fs::symlink_metadata(path)?;
        assert!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        );
        assert_eq!(std::fs::read(path)?, contents, "{}", path.display());
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            mode,
            "{} mode",
            path.display()
        );
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert!(
            metadata.modified()? >= copied_after,
            "{} keeps the copy time, not the source mtime",
            path.display()
        );

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn copy_path_applies_mode_and_owner_on_the_open_file() -> Result<(), anyhow::Error> {
        use std::os::unix::fs::PermissionsExt;

        tokio_test::block_on(async {
            let fixture = CopyFixture::new().await?;
            fixture.write_source()?;
            let started = std::time::SystemTime::now() - std::time::Duration::from_secs(1);

            fixture.copy("src/a.txt", "copied.txt", None).await?;
            assert_copied_file(&fixture.root.join("copied.txt"), b"alpha", 0o640, started)?;

            fixture.copy("src", "tree", None).await?;
            assert_copied_file(&fixture.root.join("tree/a.txt"), b"alpha", 0o640, started)?;
            assert_copied_file(
                &fixture.root.join("tree/nested/b.bin"),
                b"\x00\x01\x02beta",
                0o755,
                started,
            )?;
            assert!(std::fs::symlink_metadata(fixture.root.join("tree/link"))?.is_symlink());

            std::fs::write(
                fixture.root.join("existing.txt"),
                b"a much longer previous body",
            )?;
            std::fs::set_permissions(
                fixture.root.join("existing.txt"),
                std::fs::Permissions::from_mode(0o600),
            )?;
            fixture.copy("src/a.txt", "existing.txt", None).await?;
            assert_copied_file(&fixture.root.join("existing.txt"), b"alpha", 0o640, started)?;

            Ok(())
        })
    }

    #[cfg(unix)]
    #[test]
    fn copy_path_across_filesystems_applies_mode_on_the_open_file() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let fixture = CopyFixture::new().await?;
            fixture.write_source()?;
            let started = std::time::SystemTime::now() - std::time::Duration::from_secs(1);

            let other = tempfile::tempdir()?;
            let other_cap = cap::CapFilesystem::new(other.path()).await?;
            let mut destination = other_cap.get_virtual(fixture.server.clone());
            destination.is_writable = true;
            let destination: Arc<dyn VirtualWritableFilesystem> = Arc::new(destination);

            fixture
                .copy("src/a.txt", "copied.txt", Some(destination.clone()))
                .await?;
            assert_copied_file(&other.path().join("copied.txt"), b"alpha", 0o640, started)?;

            fixture.copy("src", "tree", Some(destination)).await?;
            assert_copied_file(&other.path().join("tree/a.txt"), b"alpha", 0o640, started)?;
            assert_copied_file(
                &other.path().join("tree/nested/b.bin"),
                b"\x00\x01\x02beta",
                0o755,
                started,
            )?;
            assert!(std::fs::symlink_metadata(other.path().join("tree/link"))?.is_symlink());

            Ok(())
        })
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "timing and syscall probe for copy_path, run with --ignored under strace"]
    fn copy_path_many_files_probe() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let fixture = CopyFixture::new().await?;
            let files: usize = std::env::var("COPY_PROBE_FILES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(2000);

            std::fs::create_dir_all(fixture.root.join("src/nested"))?;
            for index in 0..files {
                let directory = if index % 2 == 0 { "src" } else { "src/nested" };
                std::fs::write(
                    fixture
                        .root
                        .join(directory)
                        .join(format!("file-{index:05}.bin")),
                    b"0123456789abcdef",
                )?;
            }

            let other = tempfile::tempdir()?;
            let destination = if std::env::var_os("COPY_PROBE_CROSS").is_some() {
                let mut destination = cap::CapFilesystem::new(other.path())
                    .await?
                    .get_virtual(fixture.server.clone());
                destination.is_writable = true;

                Some(Arc::new(destination) as Arc<dyn VirtualWritableFilesystem>)
            } else {
                None
            };

            let started = std::time::Instant::now();
            fixture.copy("src", "tree", destination).await?;
            eprintln!(
                "copy_path probe: {files} files in {:?} ({:.1} us/file)",
                started.elapsed(),
                started.elapsed().as_secs_f64() * 1e6 / files as f64
            );

            Ok(())
        })
    }

    // Filesystem::create_chowned_dir_all

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn create_chowned_dir_all_chowns_created_components_and_applies_mode_to_leaf()
    -> Result<(), anyhow::Error> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        tokio_test::block_on(async {
            let (_temp, server) = crate::server::Server::mock_in_tempdir().await;
            {
                let user = &mut server
                    .app_state
                    .config
                    .mutate_in_place_for_testing()
                    .system
                    .user;
                user.uid = 4242;
                user.gid = 4243;
            }
            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir(root.join("existing"))?;
            std::fs::create_dir(root.join("reference"))?;
            let existing_owner = std::fs::metadata(root.join("existing"))?.uid();
            let meta = |path: &str| std::fs::metadata(root.join(path));
            let mode = |path: &str| -> Result<u32, std::io::Error> {
                Ok(meta(path)?.permissions().mode() & 0o777)
            };
            let default_mode = mode("reference")?;
            let leaf_mode = if default_mode == 0o777 { 0o775 } else { 0o777 };

            server.filesystem.create_chowned_dir_all(
                "existing/b/c",
                Some(PortablePermissions::from_mode_dir(leaf_mode)),
            )?;
            server
                .filesystem
                .async_create_chowned_dir_all("x/y", None)
                .await?;

            for path in ["existing/b", "existing/b/c", "x", "x/y"] {
                let metadata = meta(path)?;
                assert_eq!((metadata.uid(), metadata.gid()), (4242, 4243), "{path}");
            }
            assert_eq!(meta("existing")?.uid(), existing_owner);
            assert_eq!(mode("existing/b/c")?, leaf_mode);
            assert_eq!(mode("existing/b")?, default_mode);

            server
                .filesystem
                .async_create_chowned_dir_all(
                    "existing/b/c",
                    Some(PortablePermissions::from_mode_dir(0o700)),
                )
                .await?;
            assert_eq!(mode("existing/b/c")?, 0o700);

            Ok(())
        })
    }

    fn write_vault(root: &Path, directory: &str) {
        std::fs::create_dir_all(root.join(directory).join("Vault")).unwrap();
        std::fs::write(root.join(directory).join("Vault/config.yml"), b"secret").unwrap();
        std::fs::write(root.join(directory).join("Vault/other.yml"), b"public").unwrap();
    }

    // RequestIgnored::contains_ignored
    #[test]
    fn contains_ignored_sees_a_pattern_naming_a_deeper_entry() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            write_vault(&root, "plugins");
            write_vault(&root, "mods");
            let ignored = RequestIgnored::compile(&["plugins/Vault/config.yml"]).unwrap();

            let plugins = Path::new("plugins");
            assert!(
                ignored
                    .contains_ignored(&server, FileType::Dir, plugins, &[plugins])
                    .await
            );

            let mods = Path::new("mods");
            assert!(
                !ignored
                    .contains_ignored(&server, FileType::Dir, mods, &[mods])
                    .await
            );
        });
    }

    #[test]
    fn contains_ignored_judges_contents_at_the_destination() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            write_vault(&root, "p2");
            let ignored = RequestIgnored::compile(&["plugins/Vault/config.yml"]).unwrap();
            let p2 = Path::new("p2");

            assert!(
                !ignored
                    .contains_ignored(&server, FileType::Dir, p2, &[p2, Path::new("other")])
                    .await
            );
            assert!(
                ignored
                    .contains_ignored(&server, FileType::Dir, p2, &[p2, Path::new("plugins")])
                    .await
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn contains_ignored_resolves_a_symlinked_destination_parent() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir_all(root.join("plugins")).unwrap();
            std::os::unix::fs::symlink("plugins", root.join("alias")).unwrap();
            std::fs::create_dir_all(root.join("staging")).unwrap();
            std::fs::write(root.join("staging/config.yml"), b"secret").unwrap();
            let ignored = RequestIgnored::compile(&["plugins/Vault/config.yml"]).unwrap();
            let staging = Path::new("staging");

            assert!(
                ignored
                    .contains_ignored(
                        &server,
                        FileType::Dir,
                        staging,
                        &[staging, Path::new("alias/Vault")]
                    )
                    .await
            );
        });
    }

    #[test]
    fn contains_ignored_applies_the_denylist_without_a_request_list() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            write_vault(&root, "plugins");
            let plugins = Path::new("plugins");
            let ignored = RequestIgnored::default();

            assert!(
                !ignored
                    .contains_ignored(&server, FileType::Dir, plugins, &[plugins])
                    .await
            );

            server
                .filesystem
                .update_ignored(&["plugins/Vault/config.yml"])
                .await;
            assert!(
                ignored
                    .contains_ignored(&server, FileType::Dir, plugins, &[plugins])
                    .await
            );
        });
    }

    #[test]
    fn contains_ignored_matches_unanchored_patterns_deep_in_the_tree() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir_all(root.join("cfg/a/b")).unwrap();
            std::fs::write(root.join("cfg/a/b/secret.key"), b"key").unwrap();
            std::fs::write(root.join("cfg/a/b/public.txt"), b"txt").unwrap();
            let cfg = Path::new("cfg");

            let ignored = RequestIgnored::compile(&["*.key"]).unwrap();
            assert!(
                ignored
                    .contains_ignored(&server, FileType::Dir, cfg, &[cfg])
                    .await
            );

            let ignored = RequestIgnored::compile(&["*.pem"]).unwrap();
            assert!(
                !ignored
                    .contains_ignored(&server, FileType::Dir, cfg, &[cfg])
                    .await
            );
        });
    }

    #[test]
    fn contains_ignored_is_false_for_files() {
        crate::server::Server::with_mock(|server| async move {
            let root = server.filesystem.base_path.to_path_buf();
            write_vault(&root, "plugins");
            let ignored = RequestIgnored::compile(&["*.yml"]).unwrap();
            let file = Path::new("plugins/Vault/other.yml");

            assert!(
                !ignored
                    .contains_ignored(&server, FileType::File, file, &[file])
                    .await
            );
        });
    }

    async fn mount_mods(server: &crate::server::Server) -> tempfile::TempDir {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source.path().join("sub")).unwrap();
        std::fs::write(source.path().join("sub/secret.key"), b"key").unwrap();
        std::fs::write(source.path().join("secret.jar"), b"secret").unwrap();
        std::fs::write(source.path().join("ok.jar"), b"ok").unwrap();

        let source_path: compact_str::CompactString = source.path().to_string_lossy().into();
        server
            .app_state
            .config
            .mutate_in_place_for_testing()
            .allowed_mounts = vec![source_path.clone()];
        let mount = crate::server::configuration::Mount {
            default: false,
            target: "/home/container/mods".into(),
            source: source_path,
            read_only: false,
        };
        server
            .configuration
            .write()
            .await
            .mounts
            .push(mount.clone());
        server.filesystem.update_mounts(&[mount]);

        source
    }

    async fn readable_in_mount(
        server: &crate::server::Server,
        path: &str,
        ignored: &RequestIgnored,
    ) -> (PathBuf, Arc<dyn VirtualReadableFilesystem>) {
        let (path, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(server, Path::new(path), ignored)
            .await;
        assert!(!filesystem.is_primary_server_fs());

        (path, filesystem)
    }

    async fn mount_root_names(
        server: &crate::server::Server,
        ignored: &RequestIgnored,
    ) -> Vec<String> {
        let (root, filesystem) = readable_in_mount(server, "mods", ignored).await;
        let listing = filesystem
            .async_read_dir(
                &root,
                None,
                1,
                IsIgnoredFn::default(),
                crate::models::DirectorySortingMode::NameAsc,
            )
            .await
            .unwrap();

        listing
            .entries
            .into_iter()
            .map(|entry| entry.name.to_string())
            .collect()
    }

    async fn readable_contents(
        server: &crate::server::Server,
        path: &str,
        ignored: &RequestIgnored,
    ) -> Option<Vec<u8>> {
        let (path, filesystem) = readable_in_mount(server, path, ignored).await;
        filesystem.async_metadata(&path).await.ok()?;
        let mut read = filesystem.async_read_file(&path, None).await.ok()?;
        let mut contents = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut read.reader, &mut contents)
            .await
            .ok()?;

        Some(contents)
    }

    // Filesystem::resolve_readable_fs_ignoring
    #[test]
    fn resolve_readable_fs_ignoring_hides_request_ignored_entries_inside_a_mount() {
        crate::server::Server::with_mock(|server| async move {
            let _source = mount_mods(&server).await;
            let ignored = RequestIgnored::compile(&["mods/secret.jar"]).unwrap();

            let names = mount_root_names(&server, &ignored).await;
            assert!(!names.contains(&"secret.jar".to_string()), "{names:?}");
            assert!(names.contains(&"ok.jar".to_string()), "{names:?}");
            assert_eq!(
                readable_contents(&server, "mods/secret.jar", &ignored).await,
                None
            );
            assert_eq!(
                readable_contents(&server, "mods/ok.jar", &ignored)
                    .await
                    .as_deref(),
                Some(&b"ok"[..])
            );

            let unfiltered = RequestIgnored::default();
            let names = mount_root_names(&server, &unfiltered).await;
            assert!(names.contains(&"secret.jar".to_string()), "{names:?}");
            assert_eq!(
                readable_contents(&server, "mods/secret.jar", &unfiltered)
                    .await
                    .as_deref(),
                Some(&b"secret"[..])
            );
        });
    }

    #[test]
    fn resolve_readable_fs_ignoring_applies_the_denylist_inside_a_mount() {
        crate::server::Server::with_mock(|server| async move {
            let _source = mount_mods(&server).await;
            server.filesystem.update_ignored(&["mods/secret.jar"]).await;
            let ignored = RequestIgnored::default();

            let names = mount_root_names(&server, &ignored).await;
            assert!(!names.contains(&"secret.jar".to_string()), "{names:?}");
            assert!(names.contains(&"ok.jar".to_string()), "{names:?}");
            assert_eq!(
                readable_contents(&server, "mods/secret.jar", &ignored).await,
                None
            );
        });
    }

    #[test]
    fn resolve_readable_fs_ignoring_hides_a_mount_named_by_the_list() {
        crate::server::Server::with_mock(|server| async move {
            let _source = mount_mods(&server).await;
            let ignored = RequestIgnored::compile(&["mods"]).unwrap();

            for path in ["mods/ok.jar", "mods/sub/secret.key"] {
                let (path, filesystem) = server
                    .filesystem
                    .resolve_readable_fs_ignoring(&server, Path::new(path), &ignored)
                    .await;
                assert!(
                    filesystem.async_read_file(&path, None).await.is_err(),
                    "{}",
                    path.display()
                );
            }

            let (path, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, "mods/ok.jar", &ignored)
                .await;
            assert!(filesystem.async_create_file(&path).await.is_err());
        });
    }

    // Filesystem::resolve_writable_fs_ignoring
    #[test]
    fn resolve_writable_fs_ignoring_refuses_ignored_entries_inside_a_mount() {
        crate::server::Server::with_mock(|server| async move {
            let source = mount_mods(&server).await;
            let ignored = RequestIgnored::compile(&["mods/secret.jar"]).unwrap();

            let (path, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, "mods/secret.jar", &ignored)
                .await;
            assert!(!filesystem.is_primary_server_fs());
            assert!(filesystem.async_create_file(&path).await.is_err());
            assert!(filesystem.async_remove_file(&path).await.is_err());
            assert_eq!(
                std::fs::read(source.path().join("secret.jar")).unwrap(),
                b"secret"
            );

            let (path, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, "mods/ok.jar", &ignored)
                .await;
            assert!(filesystem.async_create_file(&path).await.is_ok());
            assert!(filesystem.async_remove_file(&path).await.is_ok());
            assert!(!source.path().join("ok.jar").exists());
        });
    }

    // VirtualWritableFilesystem::async_holds_ignored
    #[test]
    fn async_holds_ignored_judges_mount_entries_at_their_server_path() {
        crate::server::Server::with_mock(|server| async move {
            let _source = mount_mods(&server).await;
            let holds = |patterns: &'static [&'static str], roots: &'static [&'static str]| {
                let server = server.clone();
                async move {
                    let ignored = if patterns.is_empty() {
                        RequestIgnored::default()
                    } else {
                        RequestIgnored::compile(patterns).unwrap()
                    };
                    let (directory, filesystem) = server
                        .filesystem
                        .resolve_writable_fs_ignoring(&server, "mods/sub", &ignored)
                        .await;
                    assert!(!filesystem.is_primary_server_fs());
                    let roots: Vec<&Path> = if roots.is_empty() {
                        vec![directory.as_path()]
                    } else {
                        roots.iter().map(Path::new).collect()
                    };

                    filesystem.async_holds_ignored(&directory, &roots).await
                }
            };

            assert!(holds(&["mods/sub/secret.key"], &[]).await);
            assert!(holds(&["mods/dest/secret.key"], &["dest"]).await);
            assert!(!holds(&["mods/other/secret.key"], &["dest"]).await);
            assert!(!holds(&[], &["dest"]).await);
        });
    }

    fn allow_sources(server: &crate::server::Server) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a")).unwrap();
        std::fs::create_dir_all(root.path().join("b")).unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        server
            .app_state
            .config
            .mutate_in_place_for_testing()
            .allowed_mounts = vec![canonical.to_string_lossy().into()];

        (root, canonical.join("a"), canonical.join("b"))
    }

    fn sourced_mount(
        target: &str,
        source: &Path,
        read_only: bool,
    ) -> crate::server::configuration::Mount {
        crate::server::configuration::Mount {
            default: false,
            target: target.into(),
            source: source.to_string_lossy().into(),
            read_only,
        }
    }

    // Filesystem::match_mount
    #[test]
    fn match_mount_prefers_deepest_regardless_of_order() {
        crate::server::Server::with_mock(|server| async move {
            let (_root, a, b) = allow_sources(&server);
            let shallow = sourced_mount("/home/container/mods", &a, false);
            let deep = sourced_mount("/home/container/mods/deep", &b, false);

            for mounts in [
                [shallow.clone(), deep.clone()],
                [deep.clone(), shallow.clone()],
            ] {
                let found = Filesystem::match_mount(
                    &server.app_state.config,
                    &mounts,
                    Path::new("mods/deep/x.jar"),
                    &mut None,
                )
                .unwrap();
                assert_eq!(found.target, Path::new("mods/deep"));
                assert_eq!(found.inner_path, Path::new("x.jar"));
                assert_eq!(found.source_path, b);
            }
        });
    }

    #[test]
    fn match_mount_takes_first_in_config_order_on_equal_depth() {
        crate::server::Server::with_mock(|server| async move {
            let (_root, a, b) = allow_sources(&server);
            let mounts = [
                sourced_mount("/home/container/mods", &b, false),
                sourced_mount("/home/container/mods", &a, false),
            ];

            let found = Filesystem::match_mount(
                &server.app_state.config,
                &mounts,
                Path::new("mods/x.jar"),
                &mut None,
            )
            .unwrap();
            assert_eq!(found.source_path, b);
        });
    }

    #[test]
    fn match_mount_falls_back_when_deeper_source_is_unresolvable() {
        crate::server::Server::with_mock(|server| async move {
            let (_root, a, _b) = allow_sources(&server);
            let mounts = [
                mount("/home/container/mods/deep"),
                sourced_mount("/home/container/mods", &a, false),
            ];

            let found = Filesystem::match_mount(
                &server.app_state.config,
                &mounts,
                Path::new("mods/deep/x.jar"),
                &mut None,
            )
            .unwrap();
            assert_eq!(found.target, Path::new("mods"));
            assert_eq!(found.inner_path, Path::new("deep/x.jar"));
            assert_eq!(found.source_path, a);
        });
    }

    #[test]
    fn match_mount_outside_mounts_is_none_and_skips_loading_allowed() {
        crate::server::Server::with_mock(|server| async move {
            let (_root, a, _b) = allow_sources(&server);
            let mounts = [sourced_mount("/home/container/mods", &a, false)];

            let mut allowed = None;
            for path in ["plugins/x.jar", "modsX/a", ""] {
                assert!(
                    Filesystem::match_mount(
                        &server.app_state.config,
                        &mounts,
                        Path::new(path),
                        &mut allowed,
                    )
                    .is_none(),
                    "{path}"
                );
            }
            assert!(allowed.is_none());
        });
    }

    #[test]
    fn match_mount_on_target_itself_has_empty_inner_path_and_keeps_read_only() {
        crate::server::Server::with_mock(|server| async move {
            let (_root, a, _b) = allow_sources(&server);
            let mounts = [sourced_mount("/home/container/mods", &a, true)];

            let found = Filesystem::match_mount(
                &server.app_state.config,
                &mounts,
                Path::new("mods"),
                &mut None,
            )
            .unwrap();
            assert_eq!(found.inner_path, Path::new(""));
            assert_eq!(found.target, Path::new("mods"));
            assert!(found.read_only);
        });
    }

    // Filesystem::mount_infos
    #[test]
    fn mount_infos_keeps_config_order_and_omits_invalid_mounts() {
        crate::server::Server::with_mock(|server| async move {
            let (_root, a, b) = allow_sources(&server);
            let mounts = [
                sourced_mount("/home/container/plugins", &b, false),
                mount("/home/container/unresolvable"),
                sourced_mount("/srv/outside", &a, false),
                sourced_mount("/home/container", &a, false),
                sourced_mount("/home/containerX/mods", &a, false),
                sourced_mount("/home/container/mods", &a, false),
            ];

            let targets: Vec<PathBuf> =
                Filesystem::mount_infos(&server.app_state.config, &mounts, &mut None)
                    .into_iter()
                    .map(|info| info.relative_target)
                    .collect();
            assert_eq!(targets, [PathBuf::from("plugins"), PathBuf::from("mods")]);
        });
    }
}
