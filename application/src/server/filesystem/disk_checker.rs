use super::usage::{DiskUsage, SpaceDelta};
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

        let run_inner = |paths_to_scan: Option<Vec<PathBuf>>| {
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

                    'selective_scan: {
                        if let Some(modified_paths) = paths_to_scan {
                            if modified_paths.is_empty() {
                                tracing::debug!(
                                    path = %cap_filesystem.base_path.display(),
                                    "skipping disk usage check, no modified paths"
                                );
                                return Ok(());
                            }

                            let mut dirs_to_scan = Vec::new();
                            for modified_path in &modified_paths {
                                let relative =
                                    match modified_path.strip_prefix(&*cap_filesystem.base_path) {
                                        Ok(relative) => relative,
                                        Err(_) => continue,
                                    };

                                let dir = match cap_filesystem.symlink_metadata(relative) {
                                    Ok(metadata) if metadata.is_dir() => relative.to_path_buf(),
                                    Ok(_) => match relative.parent() {
                                        Some(relative) => relative.to_path_buf(),
                                        None => continue,
                                    },
                                    Err(_) => {
                                        let mut parent = relative;
                                        loop {
                                            parent = match parent.parent() {
                                                Some(p) => p,
                                                None => break,
                                            };

                                            match cap_filesystem.symlink_metadata(parent) {
                                                Ok(metadata) if metadata.is_dir() => {
                                                    dirs_to_scan.push(parent.to_path_buf());
                                                    break;
                                                }
                                                _ => continue,
                                            }
                                        }

                                        parent.to_path_buf()
                                    }
                                };

                                dirs_to_scan.push(dir);
                            }

                            let dirs_to_scan = crate::utils::deduplicate_paths(dirs_to_scan);

                            if dirs_to_scan.first().is_some_and(|p| p == Path::new("")) {
                                break 'selective_scan;
                            }

                            tracing::debug!(
                                path = %cap_filesystem.base_path.display(),
                                "checking disk usage for {} modified directories: {:?}",
                                dirs_to_scan.len(),
                                dirs_to_scan
                            );

                            for dir in &dirs_to_scan {
                                let mut tmp_disk_usage = DiskUsage::default();
                                #[cfg(unix)]
                                let mut seen_inodes = HashSet::new();

                                let mut walker = cap_filesystem.walk_dir(dir)?;
                                let mut pending = PendingUpdate::default();
                                while let Some(entry) = walker.next_entry() {
                                    let entry = entry?;
                                    let path = &entry.path;
                                    let metadata = match entry.metadata() {
                                        Ok(metadata) => metadata,
                                        Err(_) => continue,
                                    };
                                    let delta = SpaceDelta::new(
                                        metadata.size_logical() as i64,
                                        metadata.size_physical() as i64,
                                    );

                                    let relative = match path.strip_prefix(dir) {
                                        Ok(relative) => relative,
                                        Err(_) => continue,
                                    };

                                    #[cfg(unix)]
                                    {
                                        use cap_std::fs::MetadataExt;

                                        if !metadata.is_dir() && metadata.nlink() > 1 {
                                            if seen_inodes.contains(&metadata.ino()) {
                                                if let Some(parent) = relative.parent() {
                                                    pending.push(
                                                        &mut tmp_disk_usage,
                                                        parent,
                                                        SpaceDelta::only_logical(delta.logical),
                                                    );
                                                }
                                                continue;
                                            } else {
                                                seen_inodes.insert(metadata.ino());
                                            }
                                        }
                                    }

                                    if metadata.is_dir() {
                                        pending.push(&mut tmp_disk_usage, relative, delta);
                                    } else if let Some(parent) = relative.parent() {
                                        pending.push(&mut tmp_disk_usage, parent, delta);
                                    }
                                }
                                pending.flush(&mut tmp_disk_usage);

                                let mut disk_usage_write = disk_usage.blocking_write();
                                disk_usage_write.remove_path(dir);
                                disk_usage_write.add_directory(
                                    &DiskUsage::path_component_keys(dir),
                                    tmp_disk_usage,
                                );
                                let root_space = disk_usage_write.space;
                                drop(disk_usage_write);

                                disk_usage_cached_logical
                                    .store(root_space.get_logical(), Ordering::Relaxed);
                                disk_usage_cached_physical
                                    .store(root_space.get_physical(), Ordering::Relaxed);
                                resource_usage.publish_disk_usage(root_space.get_physical());
                            }

                            return Ok(());
                        }
                    }

                    let mut tmp_disk_usage = DiskUsage::default();
                    #[cfg(unix)]
                    let mut seen_inodes = HashSet::new();
                    let mut total_entries = 0;
                    let mut total_size = 0;
                    let mut total_size_physical = 0;

                    let mut walker = cap_filesystem.walk_dir(Path::new(""))?;
                    let mut pending = PendingUpdate::default();

                    while let Some(entry) = walker.next_entry() {
                        let entry = entry?;
                        let path = &entry.path;

                        let metadata = match entry.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => continue,
                        };
                        let delta = SpaceDelta::new(
                            metadata.size_logical() as i64,
                            metadata.size_physical() as i64,
                        );

                        total_entries += 1;

                        #[cfg(unix)]
                        {
                            use cap_std::fs::MetadataExt;

                            if !metadata.is_dir() && metadata.nlink() > 1 {
                                if seen_inodes.contains(&metadata.ino()) {
                                    if let Some(parent) = path.parent() {
                                        pending.push(
                                            &mut tmp_disk_usage,
                                            parent,
                                            SpaceDelta::only_logical(delta.logical),
                                        );
                                    }
                                    total_size += metadata.size_logical();
                                    continue;
                                } else {
                                    seen_inodes.insert(metadata.ino());
                                }
                            }
                        }

                        if metadata.is_dir() {
                            pending.push(&mut tmp_disk_usage, path, delta);
                        } else if let Some(parent) = path.parent() {
                            pending.push(&mut tmp_disk_usage, parent, delta);
                        }

                        total_size += metadata.size_logical();
                        total_size_physical += metadata.size_physical();
                    }
                    pending.flush(&mut tmp_disk_usage);

                    let old_disk_usage =
                        std::mem::replace(&mut *disk_usage.blocking_write(), tmp_disk_usage);
                    disk_usage_cached_logical.store(total_size, Ordering::Relaxed);
                    disk_usage_cached_physical.store(total_size_physical, Ordering::Relaxed);
                    resource_usage.publish_disk_usage(total_size_physical);
                    drop(old_disk_usage);

                    tracing::debug!(
                        path = %cap_filesystem.base_path.display(),
                        total_entries = total_entries,
                        "{} bytes disk usage",
                        total_size
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
                if full_disk_check_counter % config.load().system.full_disk_check_every == 0 {
                    None
                } else if use_server_notifier.load(Ordering::Relaxed)
                    && server_notifier.is_trusted()
                    && !force_scan
                {
                    let paths = server_notifier.take_modified_paths();

                    tracing::debug!(
                        path = %cap_filesystem.base_path.display(),
                        "checking disk usage for {} modified paths",
                        paths.len()
                    );
                    Some(paths)
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
