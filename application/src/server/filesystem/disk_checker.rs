use super::{
    cap::CapFilesystem,
    inotify::ModifiedPaths,
    usage::{DiskUsage, SpaceDelta, UsedSpace},
};
use crate::{server::resources::ResourceUsageWatchExt, utils::PortableSizeExt};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

#[derive(Default)]
struct PendingUpdate {
    pending: Option<(PathBuf, SpaceDelta)>,
}

impl PendingUpdate {
    fn push(&mut self, disk_usage: &mut DiskUsage, path: &Path, delta: SpaceDelta) {
        if let Some((pending_path, pending_delta)) = &mut self.pending
            && pending_path == path
        {
            pending_delta.logical += delta.logical;
            pending_delta.physical += delta.physical;
            return;
        }

        self.flush(disk_usage);
        self.pending = Some((path.to_path_buf(), delta));
    }

    fn flush(&mut self, disk_usage: &mut DiskUsage) {
        if let Some((path, delta)) = self.pending.take() {
            disk_usage.update_size(&path, delta);
        }
    }
}

fn space_delta(metadata: &cap_std::fs::Metadata) -> SpaceDelta {
    SpaceDelta::new(
        metadata.size_logical() as i64,
        metadata.size_physical() as i64,
    )
}

fn existing_directory<'a>(cap_filesystem: &CapFilesystem, path: &'a Path) -> Option<&'a Path> {
    let relative = path.strip_prefix(&cap_filesystem.base_path).ok()?;

    cap_filesystem
        .symlink_metadata(relative)
        .is_ok_and(|metadata| metadata.is_dir())
        .then_some(relative)
}

fn walk_tree(cap_filesystem: &CapFilesystem, dir: &Path) -> Result<DiskUsage, anyhow::Error> {
    let mut tree = DiskUsage::default();
    #[cfg(unix)]
    let mut seen_inodes = HashSet::new();

    let mut walker = cap_filesystem.walk_dir(dir)?;
    let mut pending = PendingUpdate::default();
    while let Some(entry) = walker.next_entry() {
        let entry = entry?;
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let delta = space_delta(&metadata);

        let relative = match entry.path.strip_prefix(dir) {
            Ok(relative) => relative,
            Err(_) => continue,
        };

        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;

            if !metadata.is_dir() && metadata.nlink() > 1 && !seen_inodes.insert(metadata.ino()) {
                if let Some(parent) = relative.parent() {
                    pending.push(&mut tree, parent, SpaceDelta::only_logical(delta.logical));
                }
                continue;
            }
        }

        if metadata.is_dir() {
            pending.push(&mut tree, relative, delta);
        } else if let Some(parent) = relative.parent() {
            pending.push(&mut tree, parent, delta);
        }
    }
    pending.flush(&mut tree);

    if dir.components().next().is_some()
        && let Ok(metadata) = cap_filesystem.symlink_metadata(dir)
    {
        tree.update_size(Path::new(""), space_delta(&metadata));
    }

    Ok(tree)
}

fn scan_tree(
    cap_filesystem: &CapFilesystem,
    disk_usage: &RwLock<DiskUsage>,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    let tree = walk_tree(cap_filesystem, dir)?;

    let mut disk_usage = disk_usage.blocking_write();
    let old_tree = if dir.components().next().is_none() {
        Some(std::mem::replace(&mut *disk_usage, tree))
    } else {
        let old_tree = disk_usage.remove_path(dir);
        disk_usage.add_directory(&DiskUsage::path_component_keys(dir), tree);

        old_tree
    };
    drop(disk_usage);
    drop(old_tree);

    Ok(())
}

/// Recounts the files directly inside `dir` and keeps the usage of its subdirectories,
/// which report their own changes. Subdirectories without usage yet are walked.
fn scan_directory(
    cap_filesystem: &CapFilesystem,
    disk_usage: &RwLock<DiskUsage>,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    let is_root = dir.components().next().is_none();
    if !is_root && disk_usage.blocking_read().get_path(dir).is_none() {
        return scan_tree(cap_filesystem, disk_usage, dir);
    }

    let mut own = UsedSpace::default();
    if !is_root && let Ok(metadata) = cap_filesystem.symlink_metadata(dir) {
        own.add_logical(metadata.size_logical());
        own.add_physical(metadata.size_physical());
    }

    #[cfg(unix)]
    let mut seen_inodes = HashSet::new();
    let mut subdirectories = Vec::new();

    let mut entries = cap_filesystem.read_dir(dir)?;
    while let Some(entry) = entries.next() {
        let entry = entry?;
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            subdirectories.push(entry.file_name());
            continue;
        }

        own.add_logical(metadata.size_logical());

        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;

            if metadata.nlink() > 1 && !seen_inodes.insert(metadata.ino()) {
                continue;
            }
        }

        own.add_physical(metadata.size_physical());
    }

    let unknown: Vec<bool> = {
        let disk_usage = disk_usage.blocking_read();

        subdirectories
            .iter()
            .map(|name| disk_usage.get_path(&dir.join(name)).is_none())
            .collect()
    };

    let mut children = Vec::with_capacity(subdirectories.len());
    for (name, unknown) in subdirectories.into_iter().zip(unknown) {
        let walked = if unknown {
            Some(walk_tree(cap_filesystem, &dir.join(&name))?)
        } else {
            None
        };

        children.push((name, walked));
    }

    let mut disk_usage = disk_usage.blocking_write();
    if is_root {
        disk_usage.rebuild(own, children);
    } else {
        let mut node = disk_usage.remove_path(dir).unwrap_or_default();
        node.rebuild(own, children);
        disk_usage.add_directory(&DiskUsage::path_component_keys(dir), node);
    }

    Ok(())
}

pub struct DiskCheckerContext {
    pub config: Arc<crate::config::Config>,
    pub disk_usage: Arc<RwLock<super::usage::DiskUsage>>,
    pub disk_usage_cached_logical: Arc<AtomicU64>,
    pub disk_usage_cached_physical: Arc<AtomicU64>,
    pub disk_checker_state_dirty: Arc<AtomicBool>,
    pub disk_checker_rescan: Arc<tokio::sync::Notify>,
    pub disk_check_completed: Arc<tokio::sync::Notify>,
    pub cap_filesystem: super::cap::CapFilesystem,
    pub server_notifier: super::inotify::InotifyServerNotifier,
    pub use_server_notifier: Arc<AtomicBool>,
    pub last_disk_check: Arc<AtomicU64>,
    pub resource_usage: tokio::sync::watch::Sender<crate::server::resources::ResourceUsage>,
}

pub async fn run(ctx: DiskCheckerContext) {
    let DiskCheckerContext {
        config,
        disk_usage,
        disk_usage_cached_logical,
        disk_usage_cached_physical,
        disk_checker_state_dirty,
        disk_checker_rescan,
        disk_check_completed,
        cap_filesystem,
        server_notifier,
        use_server_notifier,
        last_disk_check,
        resource_usage,
    } = ctx;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let mut full_disk_check_counter = 0;
    let mut force_scan = false;

    loop {
        let semaphore = config.disk_check_concurrency_semaphore.load();
        let permit = semaphore
            .acquire()
            .await
            .expect("failed to acquire disk check concurrency semaphore");

        let run_inner = |paths_to_scan: Option<ModifiedPaths>| {
            let cap_filesystem = cap_filesystem.clone();
            let disk_usage = disk_usage.clone();
            let disk_usage_cached_logical = disk_usage_cached_logical.clone();
            let disk_usage_cached_physical = disk_usage_cached_physical.clone();
            let resource_usage = resource_usage.clone();

            async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    tracing::debug!(
                        path = %cap_filesystem.base_path.display(),
                        "checking disk usage"
                    );

                    match paths_to_scan {
                        Some(modified_paths) if modified_paths.is_empty() => {
                            tracing::debug!(
                                path = %cap_filesystem.base_path.display(),
                                "skipping disk usage check, no modified paths"
                            );
                            return Ok(());
                        }
                        Some(modified_paths)
                            if modified_paths.trees.first().map(PathBuf::as_path)
                                != Some(&*cap_filesystem.base_path) =>
                        {
                            tracing::debug!(
                                path = %cap_filesystem.base_path.display(),
                                "checking disk usage for {} modified directories and {} new trees",
                                modified_paths.directories.len(),
                                modified_paths.trees.len()
                            );

                            for tree in &modified_paths.trees {
                                if let Some(tree) = existing_directory(&cap_filesystem, tree) {
                                    scan_tree(&cap_filesystem, &disk_usage, tree)?;
                                }
                            }
                            for directory in &modified_paths.directories {
                                if let Some(directory) =
                                    existing_directory(&cap_filesystem, directory)
                                {
                                    scan_directory(&cap_filesystem, &disk_usage, directory)?;
                                }
                            }
                        }
                        _ => scan_tree(&cap_filesystem, &disk_usage, Path::new(""))?,
                    }

                    let disk_usage = disk_usage.blocking_read();
                    let space = disk_usage.space;
                    let trash_space = super::trash::physical_usage(&disk_usage);
                    drop(disk_usage);

                    disk_usage_cached_logical.store(space.get_logical(), Ordering::Relaxed);
                    disk_usage_cached_physical.store(space.get_physical(), Ordering::Relaxed);
                    resource_usage.publish_disk_usage(space.get_physical());
                    resource_usage.publish_trash_usage(trash_space);

                    tracing::debug!(
                        path = %cap_filesystem.base_path.display(),
                        "{} bytes disk usage",
                        space.get_logical()
                    );

                    Ok(())
                })
                .await?
            }
        };

        if !disk_checker_state_dirty.swap(false, Ordering::Relaxed) && !force_scan {
            tracing::debug!(
                path = %cap_filesystem.base_path.display(),
                "skipping disk usage check due to server state inactivity"
            );
        } else {
            let paths_to_scan =
                if full_disk_check_counter % config.load().system.full_disk_check_every.max(1) == 0
                {
                    server_notifier.clear_modified_paths();
                    None
                } else if use_server_notifier.load(Ordering::Relaxed)
                    && server_notifier.is_trusted()
                    && !force_scan
                {
                    Some(server_notifier.take_modified_paths())
                } else {
                    None
                };

            full_disk_check_counter += 1;

            match run_inner(paths_to_scan).await {
                Ok(_) => {
                    tracing::debug!(
                        path = %cap_filesystem.base_path.display(),
                        "disk usage check completed successfully"
                    );

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    last_disk_check.store(now, Ordering::Relaxed);
                    disk_check_completed.notify_waiters();
                }
                Err(err) => {
                    tracing::error!(
                        path = %cap_filesystem.base_path.display(),
                        "disk usage check failed: {}",
                        err
                    );
                }
            }
        }

        force_scan = false;
        drop(permit);

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(
                config.load().system.disk_check_interval,
            )) => {},
            _ = disk_checker_rescan.notified() => {
                force_scan = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, CapFilesystem) {
        let dir = tempfile::tempdir().expect("tempdir");
        for (path, size) in [("a/x.bin", 100), ("a/b/y.bin", 50), ("c/z.bin", 10)] {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
            std::fs::write(path, vec![1u8; size]).expect("write file");
        }

        let cap = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(CapFilesystem::new(dir.path()))
            .expect("cap filesystem");

        (dir, cap)
    }

    fn full_scan(cap: &CapFilesystem) -> RwLock<DiskUsage> {
        let usage = RwLock::new(DiskUsage::default());
        scan_tree(cap, &usage, Path::new("")).expect("full scan");

        usage
    }

    fn assert_same_usage(partial: &RwLock<DiskUsage>, full: &RwLock<DiskUsage>, probes: &[&str]) {
        let (partial, full) = (partial.blocking_read(), full.blocking_read());

        assert_eq!(partial.space.get_logical(), full.space.get_logical());
        assert_eq!(partial.space.get_physical(), full.space.get_physical());
        for probe in probes {
            let (got, want) = (
                partial.get_size(Path::new(probe)),
                full.get_size(Path::new(probe)),
            );
            assert_eq!(
                got.map(|s| (s.get_logical(), s.get_physical())),
                want.map(|s| (s.get_logical(), s.get_physical())),
                "{probe}"
            );
        }
    }

    // scan_directory
    #[test]
    fn rescanning_a_changed_directory_matches_a_full_scan() {
        let (dir, cap) = fixture();
        let usage = full_scan(&cap);

        std::fs::write(dir.path().join("a/x.bin"), vec![1u8; 4000]).expect("grow file");
        std::fs::write(dir.path().join("a/new.bin"), vec![1u8; 30]).expect("add file");

        let changed = dir.path().join("a");
        let relative = existing_directory(&cap, &changed).expect("existing directory");
        scan_directory(&cap, &usage, relative).expect("partial scan");

        assert_same_usage(&usage, &full_scan(&cap), &["a", "a/b", "c"]);
    }

    // scan_tree
    #[test]
    fn scanning_a_new_subtree_matches_a_full_scan() {
        let (dir, cap) = fixture();
        let usage = full_scan(&cap);

        std::fs::create_dir_all(dir.path().join("d/e")).expect("create dirs");
        std::fs::write(dir.path().join("d/e/f.bin"), vec![1u8; 70]).expect("write file");

        let added = dir.path().join("d");
        let relative = existing_directory(&cap, &added).expect("existing directory");
        scan_tree(&cap, &usage, relative).expect("subtree scan");

        assert_same_usage(&usage, &full_scan(&cap), &["a", "c", "d", "d/e"]);
    }
}
