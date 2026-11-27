use parking_lot::Mutex;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(target_os = "linux")]
mod manager;

#[cfg(not(target_os = "linux"))]
mod manager {
    use super::InotifyServerNotifier;

    #[derive(Default)]
    pub struct InotifyManager;

    impl InotifyManager {
        pub fn new() -> Self {
            Self
        }

        pub async fn register_server_with_notifier(
            &self,
            _notifier: InotifyServerNotifier,
            _uuid: uuid::Uuid,
        ) -> Result<bool, anyhow::Error> {
            Ok(false)
        }

        pub async fn unregister_server(&self, _uuid: uuid::Uuid) {}
    }
}

pub use manager::InotifyManager;

type FirewallFiles = Arc<Mutex<Option<(Vec<PathBuf>, Arc<tokio::sync::Notify>)>>>;

/// Directories whose own entries changed, and directories whose whole subtree has to be
/// walked again because it appeared (created or moved in) or the events were lost.
#[derive(Default)]
pub struct ModifiedPaths {
    pub directories: Vec<PathBuf>,
    pub trees: Vec<PathBuf>,
}

impl ModifiedPaths {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const MAX_PATHS_BEFORE_DEDUP: usize = 512;

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.directories.is_empty() && self.trees.is_empty()
    }

    fn whole(root: PathBuf) -> Self {
        Self {
            directories: Vec::new(),
            trees: vec![root],
        }
    }

    fn deduplicate(&mut self) {
        self.trees = crate::utils::deduplicate_paths(std::mem::take(&mut self.trees));
        self.directories.sort();
        self.directories.dedup();

        let trees = &self.trees;
        self.directories
            .retain(|directory| !trees.iter().any(|tree| directory.starts_with(tree)));
    }
}

#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct InotifyServerNotifier {
    path: PathBuf,
    modified_paths: Arc<Mutex<ModifiedPaths>>,
    is_trusted: Arc<AtomicBool>,
    dirty_flags: [Arc<AtomicBool>; 2],
    firewall_files: FirewallFiles,
}

impl InotifyServerNotifier {
    pub fn new(path: PathBuf, dirty_flags: [Arc<AtomicBool>; 2]) -> Self {
        Self {
            path: path.clone(),
            modified_paths: Arc::new(Mutex::new(ModifiedPaths::whole(path))),
            is_trusted: Arc::new(AtomicBool::new(true)),
            dirty_flags,
            firewall_files: Arc::new(Mutex::new(None)),
        }
    }

    pub fn watch_firewall_files(&self, paths: Vec<PathBuf>, changed: Arc<tokio::sync::Notify>) {
        *self.firewall_files.lock() = if paths.is_empty() {
            None
        } else {
            Some((paths, changed))
        };
    }

    #[inline]
    pub fn is_trusted(&self) -> bool {
        self.is_trusted.load(Ordering::Relaxed)
    }

    pub fn clear_modified_paths(&self) {
        *self.modified_paths.lock() = ModifiedPaths::default();
    }

    pub fn take_modified_paths(&self) -> ModifiedPaths {
        let mut paths = std::mem::take(&mut *self.modified_paths.lock());
        paths.deduplicate();

        paths
    }
}
