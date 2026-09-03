use notify::Watcher;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

type ServerNotifiers = Arc<Mutex<HashMap<uuid::Uuid, InotifyServerNotifier>>>;
type FirewallFiles = Arc<Mutex<Option<(Vec<PathBuf>, Arc<tokio::sync::Notify>)>>>;

pub struct InotifyManager {
    watcher: Arc<Mutex<notify::RecommendedWatcher>>,
    server_notifiers: ServerNotifiers,
}

impl InotifyManager {
    pub fn new() -> Result<Self, notify::Error> {
        let server_notifiers: ServerNotifiers = Arc::new(Mutex::new(HashMap::new()));

        let watcher = notify::RecommendedWatcher::new(
            {
                let server_notifiers = Arc::clone(&server_notifiers);

                move |res: Result<notify::Event, notify::Error>| match res {
                    Ok(event) => {
                        if event.kind.is_access() || event.kind.is_other() {
                            return;
                        }

                        for path in event.paths {
                            let notifier = {
                                let notifiers = server_notifiers.lock();
                                notifiers
                                    .values()
                                    .find(|n| path.starts_with(&n.path))
                                    .cloned()
                            };
                            if let Some(notifier) = notifier {
                                notifier.add_path(path);
                            }
                        }
                    }
                    Err(err) => {
                        if matches!(err.kind, notify::ErrorKind::MaxFilesWatch) {
                            tracing::error!(
                                "os file watch limit reached, inotify sender unsure of state, falling back: {}",
                                err
                            );

                            for notifier in server_notifiers.lock().values() {
                                notifier.is_trusted.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                }
            },
            notify::Config::default().with_follow_symlinks(false),
        )?;

        Ok(Self {
            watcher: Arc::new(parking_lot::Mutex::new(watcher)),
            server_notifiers,
        })
    }

    pub async fn register_server_with_notifier(
        &self,
        notifier: InotifyServerNotifier,
        uuid: uuid::Uuid,
    ) -> Result<bool, anyhow::Error> {
        if notify::RecommendedWatcher::kind() == notify::WatcherKind::PollWatcher {
            return Ok(false);
        }

        let base_path = notifier.path.clone();
        let watcher = Arc::clone(&self.watcher);
        let server_notifiers = Arc::clone(&self.server_notifiers);

        tokio::task::spawn_blocking(move || {
            watcher
                .lock()
                .watch(&base_path, notify::RecursiveMode::Recursive)?;
            server_notifiers.lock().insert(uuid, notifier);

            Ok::<_, anyhow::Error>(())
        })
        .await??;

        Ok(true)
    }

    pub async fn unregister_server(&self, uuid: uuid::Uuid) {
        if let Some(notifier) = self.server_notifiers.lock().remove(&uuid) {
            crate::spawn_blocking_handled({
                let path = notifier.path.clone();
                let watcher = Arc::clone(&self.watcher);

                move || watcher.lock().unwatch(&path)
            });
        }
    }
}

#[derive(Clone)]
pub struct InotifyServerNotifier {
    path: PathBuf,
    modified_paths: Arc<Mutex<Vec<PathBuf>>>,
    is_trusted: Arc<AtomicBool>,
    dirty_flags: [Arc<AtomicBool>; 2],
    firewall_files: FirewallFiles,
}

impl InotifyServerNotifier {
    pub fn new(path: PathBuf, dirty_flags: [Arc<AtomicBool>; 2]) -> Self {
        Self {
            path: path.clone(),
            modified_paths: Arc::new(Mutex::new(vec![path])),
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

    fn add_path(&self, path: PathBuf) {
        const MAX_PATHS_BEFORE_DEDUP: usize = 512;

        for flag in &self.dirty_flags {
            flag.store(true, Ordering::Relaxed);
        }

        if let Some((files, changed)) = &*self.firewall_files.lock()
            && files.iter().any(|file| file.starts_with(&path))
        {
            changed.notify_one();
        }

        let mut paths = self.modified_paths.lock();
        if paths.first() == Some(&self.path) {
            return;
        }

        paths.push(path);

        if paths.len() >= MAX_PATHS_BEFORE_DEDUP {
            *paths = crate::utils::deduplicate_paths(std::mem::take(&mut *paths));
        }

        if paths.len() >= MAX_PATHS_BEFORE_DEDUP {
            // still too many paths, just keep the base path
            *paths = vec![self.path.clone()];
        }
    }

    #[inline]
    pub fn is_trusted(&self) -> bool {
        self.is_trusted.load(Ordering::Relaxed)
    }

    pub fn clear_modified_paths(&self) {
        let mut paths = self.modified_paths.lock();
        paths.clear();
    }

    pub fn take_modified_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.modified_paths.lock();
        crate::utils::deduplicate_paths(std::mem::take(&mut *paths))
    }
}
