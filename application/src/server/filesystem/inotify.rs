use notify::Watcher;
use parking_lot::Mutex;
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

type ServerNotifiers = Arc<Mutex<Notifiers>>;
type FirewallFiles = Arc<Mutex<Option<(Vec<PathBuf>, Arc<tokio::sync::Notify>)>>>;

#[derive(Default)]
struct Notifiers {
    by_path: HashMap<PathBuf, InotifyServerNotifier>,
    by_uuid: HashMap<uuid::Uuid, PathBuf>,
    /// How many roots sit at each component count
    depths: BTreeMap<usize, usize>,
}

impl Notifiers {
    fn insert(&mut self, uuid: uuid::Uuid, notifier: InotifyServerNotifier) {
        self.remove(&uuid);

        let path = notifier.path.clone();

        if self.by_path.insert(path.clone(), notifier).is_none() {
            *self.depths.entry(path.components().count()).or_insert(0) += 1;
        }

        self.by_uuid.insert(uuid, path);
    }

    fn remove(&mut self, uuid: &uuid::Uuid) -> Option<InotifyServerNotifier> {
        let path = self.by_uuid.remove(uuid)?;
        let notifier = self.by_path.remove(&path)?;

        if let std::collections::btree_map::Entry::Occupied(mut entry) =
            self.depths.entry(path.components().count())
        {
            let remaining = entry.get_mut();
            *remaining -= 1;

            if *remaining == 0 {
                entry.remove();
            }
        }

        Some(notifier)
    }

    fn find(&self, path: &Path) -> Option<&InotifyServerNotifier> {
        let depth = path.components().count();

        self.depths
            .keys()
            .rev()
            .filter(|&&root_depth| root_depth <= depth)
            .find_map(|&root_depth| self.by_path.get(path.ancestors().nth(depth - root_depth)?))
    }

    fn values(&self) -> impl Iterator<Item = &InotifyServerNotifier> {
        self.by_path.values()
    }
}

pub struct InotifyManager {
    watcher: Arc<Mutex<notify::RecommendedWatcher>>,
    server_notifiers: ServerNotifiers,
}

impl InotifyManager {
    pub fn new() -> Result<Self, notify::Error> {
        let server_notifiers = ServerNotifiers::default();

        let watcher = notify::RecommendedWatcher::new(
            {
                let server_notifiers = Arc::clone(&server_notifiers);

                move |res: Result<notify::Event, notify::Error>| match res {
                    Ok(event) => {
                        if event.kind.is_access() || event.kind.is_other() {
                            return;
                        }

                        for path in event.paths {
                            let notifier = server_notifiers.lock().find(&path).cloned();

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

#[cfg(test)]
mod tests {
    use super::*;

    fn notifier(path: &str) -> InotifyServerNotifier {
        InotifyServerNotifier::new(
            PathBuf::from(path),
            [
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ],
        )
    }

    fn registered(paths: &[&str]) -> (Notifiers, Vec<uuid::Uuid>) {
        let mut notifiers = Notifiers::default();
        let uuids: Vec<_> = paths.iter().map(|_| uuid::Uuid::new_v4()).collect();

        for (uuid, path) in uuids.iter().zip(paths) {
            notifiers.insert(*uuid, notifier(path));
        }

        (notifiers, uuids)
    }

    #[test]
    fn finds_the_server_an_event_path_belongs_to() {
        let (notifiers, _) = registered(&["/var/lib/wings/volumes/a", "/var/lib/wings/volumes/b"]);

        let found = notifiers
            .find(Path::new("/var/lib/wings/volumes/b/world/region/r.0.0.mca"))
            .expect("event path should resolve to a server");

        assert_eq!(found.path, PathBuf::from("/var/lib/wings/volumes/b"));
    }

    #[test]
    fn finds_the_root_itself() {
        let (notifiers, _) = registered(&["/var/lib/wings/volumes/a"]);

        assert!(
            notifiers
                .find(Path::new("/var/lib/wings/volumes/a"))
                .is_some()
        );
    }

    #[test]
    fn ignores_paths_outside_every_root() {
        let (notifiers, _) = registered(&["/var/lib/wings/volumes/a"]);

        assert!(
            notifiers
                .find(Path::new("/var/lib/wings/volumes/z/x.yml"))
                .is_none()
        );
        assert!(notifiers.find(Path::new("/var/lib/wings")).is_none());
        assert!(notifiers.find(Path::new("/etc/passwd")).is_none());
    }

    #[test]
    fn prefers_the_deepest_matching_root() {
        let (notifiers, _) = registered(&[
            "/var/lib/wings/volumes/a",
            "/var/lib/wings/volumes/a/mounts/shared",
        ]);

        let found = notifiers
            .find(Path::new("/var/lib/wings/volumes/a/mounts/shared/pack.zip"))
            .expect("event path should resolve to a server");

        assert_eq!(
            found.path,
            PathBuf::from("/var/lib/wings/volumes/a/mounts/shared")
        );
    }

    #[test]
    fn removal_stops_lookups_and_drops_the_depth() {
        let (mut notifiers, uuids) =
            registered(&["/var/lib/wings/volumes/a", "/var/lib/wings/volumes/b"]);

        let removed = uuids.first().expect("uuid");
        assert!(notifiers.remove(removed).is_some());
        assert!(notifiers.remove(removed).is_none());

        assert!(
            notifiers
                .find(Path::new("/var/lib/wings/volumes/a/x.yml"))
                .is_none()
        );
        assert!(
            notifiers
                .find(Path::new("/var/lib/wings/volumes/b/x.yml"))
                .is_some()
        );

        let last = uuids.get(1).expect("uuid");
        assert!(notifiers.remove(last).is_some());
        assert!(
            notifiers.depths.is_empty(),
            "depth index should be empty once every root is gone"
        );
    }

    #[test]
    fn re_registering_a_server_does_not_double_count_its_depth() {
        let mut notifiers = Notifiers::default();
        let uuid = uuid::Uuid::new_v4();

        notifiers.insert(uuid, notifier("/var/lib/wings/volumes/a"));
        notifiers.insert(uuid, notifier("/var/lib/wings/volumes/a"));
        assert!(notifiers.remove(&uuid).is_some());

        assert!(notifiers.depths.is_empty(), "depth index leaked an entry");
        assert!(
            notifiers
                .find(Path::new("/var/lib/wings/volumes/a/x.yml"))
                .is_none()
        );
    }

    #[test]
    fn re_registering_a_server_elsewhere_drops_its_old_path() {
        let mut notifiers = Notifiers::default();
        let uuid = uuid::Uuid::new_v4();

        notifiers.insert(uuid, notifier("/var/lib/wings/volumes/a"));
        notifiers.insert(uuid, notifier("/srv/volumes/a"));

        assert!(
            notifiers
                .find(Path::new("/var/lib/wings/volumes/a/x.yml"))
                .is_none(),
            "the old root still matches events"
        );
        assert!(notifiers.find(Path::new("/srv/volumes/a/x.yml")).is_some());

        assert!(notifiers.remove(&uuid).is_some());
        assert!(notifiers.depths.is_empty(), "depth index leaked an entry");
    }
}
