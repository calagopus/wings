use super::super::{
    Archive, ExtractOptions, ZIP_SYMLINK_MAX_BYTES, create::ArchiveProgress, open_zip,
    zip_entry_get_modified_time, zip_entry_read_symlink_target,
};
use crate::{
    io::{
        SafeSliceExt,
        abort::{AbortGuard, AbortReader},
    },
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    utils::PortablePermissions,
};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

/// Bytes a zip worker collects before writing, so an inflate step of a few KiB
/// does not become a write syscall of its own.
const ZIP_COPY_BUFFER: usize = 256 * 1024;
/// Entries of one directory handed to a zip worker at a time; larger directories
/// are split so a single huge one still spreads across the workers.
const ZIP_GROUP_MAX_ENTRIES: usize = 512;
/// Bytes of one directory handed to a zip worker at a time, so a directory of a
/// few large files is still shared between workers instead of extracted by one.
const ZIP_GROUP_MAX_BYTES: u64 = 16 * 1024 * 1024;

enum ZipEntryKind {
    File,
    Symlink,
}

struct ZipEntryPlan {
    index: usize,
    kind: ZipEntryKind,
    path: PathBuf,
    size: u64,
    permissions: Option<PortablePermissions>,
    modified_time: Option<std::time::SystemTime>,
}

struct ZipDirectory {
    path: PathBuf,
    mode: u32,
    modified_time: Option<std::time::SystemTime>,
}

/// Splits a plan sorted by parent directory into runs a single worker extracts,
/// so no two workers create files in the same directory at the same time.
fn zip_entry_groups(plan: &[ZipEntryPlan]) -> Vec<std::ops::Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    let mut bytes = 0;

    for (index, entry) in plan.iter().enumerate() {
        let same_parent = plan
            .get(start)
            .is_some_and(|first| first.path.parent() == entry.path.parent());

        if index > start
            && (!same_parent
                || index - start >= ZIP_GROUP_MAX_ENTRIES
                || bytes >= ZIP_GROUP_MAX_BYTES)
        {
            groups.push(start..index);
            start = index;
            bytes = 0;
        }

        bytes += entry.size;
    }

    if start < plan.len() {
        groups.push(start..plan.len());
    }

    groups
}

pub async fn extract_zip(
    archive: Archive,
    destination: PathBuf,
    destination_filesystem: Arc<dyn VirtualWritableFilesystem>,
    progress: ArchiveProgress,
    total: Option<Arc<AtomicU64>>,
    options: ExtractOptions,
) -> Result<(), anyhow::Error> {
    let Archive { server, source, .. } = archive;

    let source = source.seekable()?;
    let (guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        let reader = super::super::multi_reader::MultiReader::from_seekable(source)?;
        let reader = AbortReader::new(reader, listener);
        let mut archive = open_zip(reader)?;

        let mut plan = Vec::with_capacity(archive.len());
        let mut directories = Vec::new();
        let mut entry_total = 0;

        for index in 0..archive.len() {
            let entry = archive.by_index(index)?;
            let Some(path) = entry.enclosed_name() else {
                continue;
            };
            let Some(destination_path) = options.resolve(&destination, &path) else {
                continue;
            };

            if destination_filesystem
                .is_ignored(&destination_path, FileType::from_is_dir(entry.is_dir()))
            {
                continue;
            }

            if entry.is_dir() {
                directories.push(ZipDirectory {
                    path: destination_path,
                    mode: entry.unix_mode().unwrap_or(0o755),
                    modified_time: zip_entry_get_modified_time(&entry),
                });
            } else if entry.is_file() {
                entry_total += entry.size();
                plan.push(ZipEntryPlan {
                    index,
                    kind: ZipEntryKind::File,
                    path: destination_path,
                    size: entry.size(),
                    permissions: entry.unix_mode().map(PortablePermissions::from_mode_file),
                    modified_time: zip_entry_get_modified_time(&entry),
                });
            } else if entry.is_symlink() && (1..=ZIP_SYMLINK_MAX_BYTES).contains(&entry.size()) {
                entry_total += entry.size();
                plan.push(ZipEntryPlan {
                    index,
                    kind: ZipEntryKind::Symlink,
                    path: destination_path,
                    size: entry.size(),
                    permissions: None,
                    modified_time: zip_entry_get_modified_time(&entry),
                });
            }
        }

        if let Some(total) = total {
            total.store(entry_total, Ordering::Relaxed);
        }

        for directory in &directories {
            destination_filesystem.create_dir_all(&directory.path)?;
            destination_filesystem.set_permissions(
                &directory.path,
                FileType::Dir,
                PortablePermissions::from_mode_dir(directory.mode),
            )?;
        }

        plan.sort_by(|a, b| a.path.parent().cmp(&b.path.parent()));
        let groups = zip_entry_groups(&plan);

        let mut last_parent = None;
        for group in &groups {
            if let Some(entry) = plan.get(group.start)
                && let Some(parent) = entry.path.parent()
                && last_parent != Some(parent)
            {
                destination_filesystem.create_dir_all(&parent)?;
                last_parent = Some(parent);
            }
        }

        let pool = crate::threading::build_pool(options.threads(&server))?;

        let error = Arc::new(crate::threading::SharedError::new());
        let group_index = AtomicUsize::new(0);

        pool.in_place_scope(|scope| {
            let plan = &plan;
            let groups = &groups;
            let group_index = &group_index;
            let archive = &archive;
            let progress = &progress;
            let destination_filesystem = &destination_filesystem;
            let error = &error;

            scope.spawn_broadcast(move |_, _| {
                let mut archive = archive.clone();
                let mut buffer = crate::io::mem_buffer(ZIP_COPY_BUFFER);

                let mut run = || -> Result<(), anyhow::Error> {
                    loop {
                        if error.stopped() {
                            return Ok(());
                        }

                        let group = group_index.fetch_add(1, Ordering::SeqCst);
                        let Some(range) = groups.get(group) else {
                            return Ok(());
                        };

                        for entry in plan.get_slice(range.clone())? {
                            if error.stopped() {
                                return Ok(());
                            }

                            match entry.kind {
                                ZipEntryKind::File => {
                                    options.on_file(&entry.path);

                                    let zip_entry = archive.by_index(entry.index)?;
                                    let mut writer = destination_filesystem
                                        .create_file_with_metadata(
                                            &entry.path,
                                            entry.permissions,
                                            entry.modified_time,
                                        )?;
                                    let mut reader = progress.counting_reader(zip_entry);

                                    crate::io::copy_shared(&mut buffer, &mut reader, &mut writer)?;
                                    writer.flush()?;
                                    drop(writer);

                                    progress.increment_files();
                                }
                                ZipEntryKind::Symlink => {
                                    let mut zip_entry = archive.by_index(entry.index)?;
                                    let link = zip_entry_read_symlink_target(&mut zip_entry)
                                        .unwrap_or_default();

                                    if let Err(err) =
                                        destination_filesystem.create_symlink(&link, &entry.path)
                                    {
                                        tracing::debug!(
                                            path = %entry.path.display(),
                                            "failed to create symlink from archive: {:#?}",
                                            err
                                        );
                                    } else if let Some(modified_time) = entry.modified_time {
                                        destination_filesystem.set_times(
                                            &entry.path,
                                            FileType::Symlink,
                                            modified_time,
                                            None,
                                        )?;
                                    }

                                    progress.increment_bytes(zip_entry.size());
                                }
                            }
                        }
                    }
                };

                if let Err(err) = run() {
                    error.fail(err);
                }
            });
        });

        if let Some(err) = error.take() {
            return Err(err);
        }

        for directory in directories {
            if let Some(modified_time) = directory.modified_time {
                destination_filesystem.set_times(
                    &directory.path,
                    FileType::Dir,
                    modified_time,
                    None,
                )?;
            }
        }

        Ok(())
    })
    .await??;

    drop(guard);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // zip_entry_groups

    fn plan_entry(index: usize, path: &str) -> ZipEntryPlan {
        sized_plan_entry(index, path, 0)
    }

    fn sized_plan_entry(index: usize, path: &str, size: u64) -> ZipEntryPlan {
        ZipEntryPlan {
            index,
            kind: ZipEntryKind::File,
            path: PathBuf::from(path),
            size,
            permissions: None,
            modified_time: None,
        }
    }

    #[test]
    fn zip_entry_groups_splits_on_parent_directory() {
        let plan = [
            plan_entry(0, "a/one"),
            plan_entry(1, "a/two"),
            plan_entry(2, "b/one"),
            plan_entry(3, "c/d/one"),
            plan_entry(4, "c/d/two"),
            plan_entry(5, "c/d/three"),
        ];

        assert_eq!(zip_entry_groups(&plan), vec![0..2, 2..3, 3..6]);
        assert!(zip_entry_groups(&[]).is_empty());
    }

    #[test]
    fn zip_entry_groups_caps_a_huge_directory() {
        let plan: Vec<_> = (0..ZIP_GROUP_MAX_ENTRIES * 2 + 5)
            .map(|i| plan_entry(i, &format!("big/file-{i}")))
            .collect();

        let groups = zip_entry_groups(&plan);

        assert_eq!(groups.len(), 3);
        assert!(
            groups
                .iter()
                .all(|group| group.len() <= ZIP_GROUP_MAX_ENTRIES)
        );
        assert_eq!(
            groups.iter().map(|group| group.len()).sum::<usize>(),
            plan.len()
        );
        assert_eq!(groups.first().map(|group| group.start), Some(0));
    }

    #[test]
    fn zip_entry_groups_caps_bytes_per_group() {
        let plan: Vec<_> = (0..6)
            .map(|i| sized_plan_entry(i, &format!("region/r.{i}.mca"), ZIP_GROUP_MAX_BYTES / 2))
            .collect();

        assert_eq!(zip_entry_groups(&plan), vec![0..2, 2..4, 4..6]);

        let huge = [
            sized_plan_entry(0, "libraries/one.jar", ZIP_GROUP_MAX_BYTES * 3),
            sized_plan_entry(1, "libraries/two.jar", 10),
        ];

        assert_eq!(zip_entry_groups(&huge), vec![0..1, 1..2]);
    }
}
