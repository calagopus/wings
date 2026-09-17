use parking_lot::Mutex;
use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    mem::MaybeUninit,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

type FirewallFiles = Arc<Mutex<Option<(Vec<PathBuf>, Arc<tokio::sync::Notify>)>>>;
type WatchTable = Arc<Mutex<Watches>>;

const EVENT_BUFFER_SIZE: usize = 64 * 1024;
const EVENT_COALESCE_DELAY: Duration = Duration::from_millis(2);
const WATCH_FLAGS: WatchFlags = WatchFlags::ATTRIB
    .union(WatchFlags::CREATE)
    .union(WatchFlags::DELETE)
    .union(WatchFlags::DELETE_SELF)
    .union(WatchFlags::MODIFY)
    .union(WatchFlags::MOVED_FROM)
    .union(WatchFlags::MOVED_TO)
    .union(WatchFlags::MOVE_SELF)
    .union(WatchFlags::ONLYDIR)
    .union(WatchFlags::DONT_FOLLOW)
    // rustix's libc backend (forced on powerpc64/s390x/mips) hardcodes EXCL_UNLINK to 1,
    // which is IN_ACCESS, so subscribing by name turns every directory read into a modification.
    .union(WatchFlags::from_bits_retain(0x0400_0000));

struct WatchedDir {
    uuid: uuid::Uuid,
    path: PathBuf,
    notifier: InotifyServerNotifier,
}

struct ServerWatch {
    notifier: InotifyServerNotifier,
    descriptors: HashSet<i32>,
}

#[derive(Default)]
struct Watches {
    dirs: HashMap<i32, WatchedDir>,
    servers: HashMap<uuid::Uuid, ServerWatch>,
    closed: bool,
}

impl Watches {
    fn insert_dir(&mut self, wd: i32, uuid: uuid::Uuid, path: PathBuf) {
        let Some(notifier) = self
            .servers
            .get(&uuid)
            .map(|server| server.notifier.clone())
        else {
            return;
        };

        if let Some(existing) = self.dirs.get(&wd)
            && existing.uuid != uuid
            && existing.notifier.path.components().count() > notifier.path.components().count()
        {
            return;
        }

        if let Some(existing) = self.dirs.insert(
            wd,
            WatchedDir {
                uuid,
                path,
                notifier,
            },
        ) && existing.uuid != uuid
            && let Some(server) = self.servers.get_mut(&existing.uuid)
        {
            server.descriptors.remove(&wd);
        }

        if let Some(server) = self.servers.get_mut(&uuid) {
            server.descriptors.insert(wd);
        }
    }

    fn remove_dir(&mut self, wd: i32) -> Option<WatchedDir> {
        let dir = self.dirs.remove(&wd)?;

        if let Some(server) = self.servers.get_mut(&dir.uuid) {
            server.descriptors.remove(&wd);
        }

        Some(dir)
    }

    fn descriptors_under(&self, path: &Path) -> Vec<i32> {
        self.dirs
            .iter()
            .filter(|(_, dir)| dir.path.starts_with(path))
            .map(|(wd, _)| *wd)
            .collect()
    }

    fn overlapping_servers(&self, root: &Path) -> Vec<InotifyServerNotifier> {
        self.servers
            .values()
            .filter(|server| {
                server.notifier.path != root
                    && (server.notifier.path.starts_with(root)
                        || root.starts_with(&server.notifier.path))
            })
            .map(|server| server.notifier.clone())
            .collect()
    }
}

struct Inner {
    fd: Arc<OwnedFd>,
    table: WatchTable,
}

pub struct InotifyManager {
    inner: Option<Inner>,
}

impl Default for InotifyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InotifyManager {
    pub fn new() -> Self {
        let inner = match Self::start() {
            Ok(inner) => Some(inner),
            Err(err) => {
                tracing::error!(
                    "failed to initialize inotify, disk usage tracking falls back to full scans: {}",
                    err
                );

                None
            }
        };

        Self { inner }
    }

    fn start() -> Result<Inner, std::io::Error> {
        let fd = Arc::new(inotify::init(CreateFlags::CLOEXEC)?);
        let table = WatchTable::default();

        std::thread::Builder::new()
            .name("wings inotify".to_string())
            .spawn({
                let fd = Arc::clone(&fd);
                let table = Arc::clone(&table);

                move || Self::event_loop(&fd, &table)
            })?;

        Ok(Inner { fd, table })
    }

    fn event_loop(fd: &Arc<OwnedFd>, table: &WatchTable) {
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); EVENT_BUFFER_SIZE];
        let mut reader = inotify::Reader::new(&**fd, &mut buffer);
        let mut touched: HashSet<i32> = HashSet::new();
        let mut new_dirs: Vec<(uuid::Uuid, PathBuf)> = Vec::new();
        let mut stale_dirs: Vec<PathBuf> = Vec::new();

        loop {
            {
                let event = match reader.next() {
                    Ok(event) => event,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(err) => {
                        tracing::error!(
                            "inotify reader failed, disk usage tracking falls back to full scans: {}",
                            err
                        );

                        let mut table = table.lock();
                        table.closed = true;
                        for server in table.servers.values() {
                            server.notifier.is_trusted.store(false, Ordering::Relaxed);
                        }

                        return;
                    }
                };

                let flags = event.events();
                let wd = event.wd();
                let name = event
                    .file_name()
                    .map(|name| OsStr::from_bytes(name.to_bytes()));
                let mut table = table.lock();

                if flags.contains(ReadFlags::QUEUE_OVERFLOW) {
                    tracing::warn!(
                        "inotify event queue overflowed, rescanning every server on the next disk check"
                    );

                    for server in table.servers.values() {
                        server.notifier.add_path(server.notifier.path.clone());
                    }
                } else if flags.contains(ReadFlags::IGNORED) {
                    table.remove_dir(wd);
                } else if let Some(dir) = table.dirs.get(&wd) {
                    Self::handle_event(
                        dir,
                        wd,
                        flags,
                        name,
                        &mut touched,
                        &mut new_dirs,
                        &mut stale_dirs,
                    );
                }
            }

            if reader.is_buffer_empty() {
                touched.clear();

                for path in stale_dirs.drain(..) {
                    Self::unwatch_tree(fd, table, &path);
                }
                for (uuid, path) in new_dirs.drain(..) {
                    let _ = Self::watch_tree(fd, table, uuid, &path);
                }

                std::thread::sleep(EVENT_COALESCE_DELAY);
            }
        }
    }

    fn handle_event(
        dir: &WatchedDir,
        wd: i32,
        flags: ReadFlags,
        name: Option<&OsStr>,
        touched: &mut HashSet<i32>,
        new_dirs: &mut Vec<(uuid::Uuid, PathBuf)>,
        stale_dirs: &mut Vec<PathBuf>,
    ) {
        let notifier = &dir.notifier;

        if flags.contains(ReadFlags::UNMOUNT) {
            tracing::error!(
                path = %dir.path.display(),
                "watched directory was unmounted, inotify sender unsure of state, falling back"
            );
            notifier.is_trusted.store(false, Ordering::Relaxed);

            return;
        }

        if flags.intersects(ReadFlags::DELETE_SELF | ReadFlags::MOVE_SELF) {
            if dir.path == notifier.path {
                tracing::error!(
                    path = %dir.path.display(),
                    "server root was deleted or moved, inotify sender unsure of state, falling back"
                );
                notifier.is_trusted.store(false, Ordering::Relaxed);
            }

            notifier.add_path(dir.path.clone());

            return;
        }

        if flags.contains(ReadFlags::ISDIR)
            && let Some(name) = name
        {
            if flags.intersects(ReadFlags::CREATE | ReadFlags::MOVED_TO) {
                new_dirs.push((dir.uuid, dir.path.join(name)));
            } else if flags.contains(ReadFlags::MOVED_FROM) {
                stale_dirs.push(dir.path.join(name));
            }
        }

        if notifier.has_firewall_files() {
            notifier.add_path(match name {
                Some(name) => dir.path.join(name),
                None => dir.path.clone(),
            });
        } else if touched.insert(wd) {
            notifier.add_path(dir.path.clone());
        }
    }

    fn watch_tree(
        fd: &Arc<OwnedFd>,
        table: &WatchTable,
        uuid: uuid::Uuid,
        root: &Path,
    ) -> Result<(), std::io::Error> {
        let mut stack = vec![root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            {
                let mut table = table.lock();
                let Some(server) = table.servers.get(&uuid) else {
                    return Ok(());
                };

                match inotify::add_watch(fd, dir.as_path(), WATCH_FLAGS) {
                    Ok(wd) => table.insert_dir(wd, uuid, dir.clone()),
                    Err(rustix::io::Errno::NOSPC) => {
                        tracing::error!(
                            "os file watch limit reached, inotify sender unsure of state, falling back: {}",
                            rustix::io::Errno::NOSPC
                        );
                        server.notifier.is_trusted.store(false, Ordering::Relaxed);

                        return Err(rustix::io::Errno::NOSPC.into());
                    }
                    Err(err) if dir == root => return Err(err.into()),
                    Err(_) => continue,
                }
            }

            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                    stack.push(entry.path());
                }
            }
        }

        Ok(())
    }

    fn unwatch_tree(fd: &Arc<OwnedFd>, table: &WatchTable, path: &Path) {
        let mut table = table.lock();

        for wd in table.descriptors_under(path) {
            table.remove_dir(wd);
            let _ = inotify::remove_watch(fd, wd);
        }
    }

    fn unregister_inner(fd: &Arc<OwnedFd>, table: &WatchTable, uuid: uuid::Uuid) {
        let mut table = table.lock();
        let Some(server) = table.servers.remove(&uuid) else {
            return;
        };
        let overlapping = table.overlapping_servers(&server.notifier.path);

        for wd in server.descriptors {
            let Some(dir) = table.dirs.remove(&wd) else {
                continue;
            };
            let _ = inotify::remove_watch(fd, wd);

            for other in &overlapping {
                if dir.path.starts_with(&other.path) {
                    other.is_trusted.store(false, Ordering::Relaxed);
                }
            }
        }
    }

    pub async fn register_server_with_notifier(
        &self,
        notifier: InotifyServerNotifier,
        uuid: uuid::Uuid,
    ) -> Result<bool, anyhow::Error> {
        let Some(inner) = &self.inner else {
            return Ok(false);
        };

        let fd = Arc::clone(&inner.fd);
        let table = Arc::clone(&inner.table);

        let watching = tokio::task::spawn_blocking(move || {
            Self::unregister_inner(&fd, &table, uuid);

            {
                let mut table = table.lock();
                if table.closed {
                    return Ok(false);
                }

                table.servers.insert(
                    uuid,
                    ServerWatch {
                        notifier: notifier.clone(),
                        descriptors: HashSet::new(),
                    },
                );
            }

            if let Err(err) = Self::watch_tree(&fd, &table, uuid, &notifier.path) {
                Self::unregister_inner(&fd, &table, uuid);

                return Err(err);
            }

            Ok(true)
        })
        .await??;

        Ok(watching)
    }

    pub async fn unregister_server(&self, uuid: uuid::Uuid) {
        let Some(inner) = &self.inner else {
            return;
        };

        crate::spawn_blocking_handled({
            let fd = Arc::clone(&inner.fd);
            let table = Arc::clone(&inner.table);

            move || {
                Self::unregister_inner(&fd, &table, uuid);

                Ok::<_, std::io::Error>(())
            }
        });
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

    #[inline]
    fn has_firewall_files(&self) -> bool {
        self.firewall_files.lock().is_some()
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

    struct Harness {
        runtime: tokio::runtime::Runtime,
        manager: InotifyManager,
        root: tempfile::TempDir,
        notifier: InotifyServerNotifier,
        uuid: uuid::Uuid,
    }

    impl Harness {
        fn new() -> Self {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("runtime");
            let root = tempfile::tempdir().expect("tempdir");
            let notifier = InotifyServerNotifier::new(
                root.path().to_path_buf(),
                [
                    Arc::new(AtomicBool::new(false)),
                    Arc::new(AtomicBool::new(false)),
                ],
            );

            Self {
                runtime,
                manager: InotifyManager::new(),
                root,
                notifier,
                uuid: uuid::Uuid::new_v4(),
            }
        }

        fn register(&self) -> bool {
            let watching = self
                .runtime
                .block_on(
                    self.manager
                        .register_server_with_notifier(self.notifier.clone(), self.uuid),
                )
                .expect("register");
            self.notifier.clear_modified_paths();

            watching
        }

        fn watched_dirs(&self) -> Vec<PathBuf> {
            let inner = self.manager.inner.as_ref().expect("inotify available");
            let mut dirs: Vec<PathBuf> = inner
                .table
                .lock()
                .dirs
                .values()
                .map(|dir| dir.path.clone())
                .collect();
            dirs.sort();

            dirs
        }

        fn wait_until(&self, mut condition: impl FnMut(&Self) -> bool) -> bool {
            for _ in 0..200 {
                if condition(self) {
                    return true;
                }

                std::thread::sleep(Duration::from_millis(10));
            }

            condition(self)
        }

        fn wait_for_modified(&self, path: &Path) -> bool {
            let mut seen = Vec::new();

            self.wait_until(|harness| {
                seen.extend(harness.notifier.take_modified_paths());
                seen.iter().any(|modified| modified == path)
            })
        }
    }

    #[test]
    fn watches_the_whole_tree_at_registration() {
        let harness = Harness::new();
        let nested = harness.root.path().join("a/b/c");
        std::fs::create_dir_all(&nested).expect("create nested dirs");

        assert!(harness.register());
        assert_eq!(
            harness.watched_dirs(),
            vec![
                harness.root.path().to_path_buf(),
                harness.root.path().join("a"),
                harness.root.path().join("a/b"),
                nested,
            ]
        );
    }

    #[test]
    fn new_directories_are_watched_and_their_contents_tracked() {
        let harness = Harness::new();
        assert!(harness.register());

        let sub = harness.root.path().join("world");
        std::fs::create_dir(&sub).expect("create dir");
        assert!(harness.wait_for_modified(harness.root.path()));
        assert!(harness.wait_until(|harness| harness.watched_dirs().len() == 2));

        std::fs::write(sub.join("level.dat"), b"x").expect("write file");
        assert!(harness.wait_for_modified(&sub));
        assert!(
            harness
                .notifier
                .dirty_flags
                .iter()
                .all(|flag| flag.load(Ordering::Relaxed))
        );
    }

    #[test]
    fn deleting_a_subtree_drops_its_watches() {
        let harness = Harness::new();
        let sub = harness.root.path().join("a/b");
        std::fs::create_dir_all(&sub).expect("create nested dirs");
        assert!(harness.register());
        assert_eq!(harness.watched_dirs().len(), 3);

        std::fs::remove_dir_all(harness.root.path().join("a")).expect("remove tree");
        assert!(harness.wait_until(|harness| harness.watched_dirs().len() == 1));
        assert!(harness.wait_for_modified(harness.root.path()));
        assert!(harness.notifier.is_trusted());
    }

    #[test]
    fn renamed_directories_are_rewatched_under_their_new_name() {
        let harness = Harness::new();
        let old = harness.root.path().join("old");
        let new = harness.root.path().join("new");
        std::fs::create_dir_all(old.join("inner")).expect("create dirs");
        assert!(harness.register());

        std::fs::rename(&old, &new).expect("rename");
        assert!(harness.wait_until(|harness| {
            harness.watched_dirs()
                == vec![
                    harness.root.path().to_path_buf(),
                    new.clone(),
                    new.join("inner"),
                ]
        }));
        assert!(harness.wait_for_modified(harness.root.path()));

        std::fs::write(new.join("inner/file"), b"x").expect("write file");
        assert!(harness.wait_for_modified(&new.join("inner")));
    }

    #[test]
    fn unregistering_removes_every_watch() {
        let harness = Harness::new();
        std::fs::create_dir_all(harness.root.path().join("a/b")).expect("create dirs");
        assert!(harness.register());
        assert_eq!(harness.watched_dirs().len(), 3);

        harness
            .runtime
            .block_on(harness.manager.unregister_server(harness.uuid));
        assert!(harness.wait_until(|harness| harness.watched_dirs().is_empty()));

        std::fs::write(harness.root.path().join("a/b/file"), b"x").expect("write file");
        std::thread::sleep(Duration::from_millis(50));
        assert!(harness.notifier.take_modified_paths().is_empty());
    }

    #[test]
    fn removing_the_root_marks_the_server_untrusted() {
        let harness = Harness::new();
        let root = harness.root.path().join("server");
        std::fs::create_dir(&root).expect("create root");
        let notifier = InotifyServerNotifier::new(
            root.clone(),
            [
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ],
        );
        let uuid = uuid::Uuid::new_v4();
        assert!(
            harness
                .runtime
                .block_on(
                    harness
                        .manager
                        .register_server_with_notifier(notifier.clone(), uuid)
                )
                .expect("register")
        );

        std::fs::remove_dir(&root).expect("remove root");
        assert!(harness.wait_until(|_| !notifier.is_trusted()));
    }

    #[test]
    fn registering_a_missing_root_fails() {
        let harness = Harness::new();
        let notifier = InotifyServerNotifier::new(
            harness.root.path().join("missing"),
            [
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ],
        );

        assert!(
            harness
                .runtime
                .block_on(
                    harness
                        .manager
                        .register_server_with_notifier(notifier, uuid::Uuid::new_v4())
                )
                .is_err()
        );
        assert!(harness.watched_dirs().is_empty());
    }

    #[test]
    fn firewall_files_are_reported_by_exact_path() {
        let harness = Harness::new();
        assert!(harness.register());

        let changed = Arc::new(tokio::sync::Notify::new());
        let watched = harness.root.path().join("firewall.txt");
        harness
            .notifier
            .watch_firewall_files(vec![watched.clone()], Arc::clone(&changed));

        std::fs::write(harness.root.path().join("other.txt"), b"x").expect("write other");
        assert!(harness.wait_for_modified(&harness.root.path().join("other.txt")));

        std::fs::write(&watched, b"x").expect("write watched");
        harness.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), changed.notified())
                .await
                .expect("firewall file change should be signalled");
        });
    }
}
