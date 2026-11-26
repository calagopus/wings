use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::abort::{AbortGuard, AbortReader},
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    utils::PortablePermissions,
};
use ddup_bak::archive::entries::Entry;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const FILES_IN_FLIGHT: usize = 256;

pub async fn extract_ddup(
    archive: Archive,
    destination: PathBuf,
    destination_filesystem: Arc<dyn VirtualWritableFilesystem>,
    progress: ArchiveProgress,
    total: Option<Arc<AtomicU64>>,
    options: ExtractOptions,
) -> Result<(), anyhow::Error> {
    let Archive { server, source, .. } = archive;

    let (mut file, _) = source.file()?;
    let (guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        file.seek(SeekFrom::Start(0))?;
        let archive = ddup_bak::archive::Archive::open_file(file)?;

        if let Some(total) = total {
            let mut size = 0;
            let mut pending: Vec<&Entry> = archive.entries().iter().collect();
            while let Some(entry) = pending.pop() {
                match entry {
                    Entry::File(file) => size += file.size,
                    Entry::Directory(dir) => pending.extend(&dir.entries),
                    Entry::Symlink(_) => {}
                }
            }

            total.store(size, Ordering::Relaxed);
        }

        let pool = crate::threading::build_pool(options.threads(&server))?;

        enum Step {
            Enter(Arc<Path>, Entry),
            Leave(PathBuf, std::time::SystemTime),
        }

        let error = Arc::new(crate::threading::SharedError::new());
        let in_flight = crate::threading::InFlightLimit::new(FILES_IN_FLIGHT);

        pool.in_place_scope(|scope| -> Result<(), anyhow::Error> {
            let root: Arc<Path> = Arc::from(Path::new(""));
            let mut steps: Vec<Step> = archive
                .into_entries()
                .into_iter()
                .rev()
                .map(|entry| Step::Enter(Arc::clone(&root), entry))
                .collect();

            while let Some(step) = steps.pop() {
                let (parent, entry) = match step {
                    Step::Enter(parent, entry) => (parent, entry),
                    Step::Leave(path, mtime) => {
                        destination_filesystem.set_times(&path, FileType::Dir, mtime, None)?;
                        continue;
                    }
                };

                if error.stopped() {
                    continue;
                }

                let relative = parent.join(entry.name());
                let Some(destination_path) = options.resolve(&destination, &relative) else {
                    continue;
                };

                if destination_filesystem.is_ignored(
                    &destination_path,
                    FileType::from_is_dir(entry.is_directory()),
                ) {
                    continue;
                }

                if listener.is_aborted() {
                    return Err(anyhow::anyhow!("operation aborted"));
                }

                match entry {
                    Entry::Directory(dir) => {
                        destination_filesystem.create_dir_all(
                            &destination_path,
                            Some(PortablePermissions::from_mode_dir(dir.mode.bits())),
                        )?;

                        let parent: Arc<Path> = Arc::from(relative.as_path());
                        steps.push(Step::Leave(destination_path, dir.mtime));
                        steps.extend(
                            dir.entries
                                .into_iter()
                                .rev()
                                .map(|entry| Step::Enter(Arc::clone(&parent), entry)),
                        );
                    }
                    Entry::File(file) => {
                        options.on_file(&destination_path);

                        let permit = in_flight.acquire();
                        let mut writer = destination_filesystem.create_file_with_metadata(
                            &destination_path,
                            Some(PortablePermissions::from_mode_file(file.mode.bits())),
                            Some(file.mtime),
                        )?;

                        let reader = AbortReader::new(file, listener.clone());
                        let mut reader = progress.counting_reader(reader);

                        let error = Arc::clone(&error);
                        let progress = progress.clone();
                        scope.spawn(move |_| {
                            let _permit = permit;
                            let run = || -> Result<(), std::io::Error> {
                                crate::io::copy(&mut reader, &mut writer)?;
                                writer.flush()?;
                                drop(writer);

                                progress.increment_files();

                                Ok(())
                            };

                            if let Err(err) = run() {
                                tracing::debug!(
                                    path = %destination_path.display(),
                                    "failed to extract file from archive: {:#?}",
                                    err
                                );

                                error.fail(err);
                            }
                        });
                    }
                    Entry::Symlink(link) => {
                        if let Err(err) = destination_filesystem.create_symlink_with_metadata(
                            &link.target,
                            &destination_path,
                            Some(link.mtime),
                        ) {
                            tracing::debug!(
                                path = %destination_path.display(),
                                "failed to create symlink from archive: {:#?}",
                                err
                            );
                        }
                    }
                }
            }

            Ok(())
        })?;

        if let Some(err) = error.take() {
            return Err(err.into());
        }

        Ok(())
    })
    .await??;

    drop(guard);

    Ok(())
}
