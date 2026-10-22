use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::abort::{AbortGuard, AbortReader},
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    utils::PortablePermissions,
};
use itaf::decoder::ArchiveEntry;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub async fn extract_itaf(
    archive: Archive,
    destination: PathBuf,
    destination_filesystem: Arc<dyn VirtualWritableFilesystem>,
    progress: ArchiveProgress,
    total: Option<Arc<AtomicU64>>,
    options: ExtractOptions,
) -> Result<(), anyhow::Error> {
    let Archive {
        compression,
        server,
        size,
        source,
        ..
    } = archive;

    let (guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        let threads = options.threads(&server);
        let (read_progress, write_progress) = options.progress(&progress);
        let reader = super::decompressed_reader(source, compression, threads, &read_progress)?;
        let reader = AbortReader::new(reader, listener.clone());

        if let Some(total) = total
            && let Some(size) = size
        {
            total.store(size, Ordering::Relaxed);
        }

        let decoder = itaf::decoder::ItafDecoder::new(reader)?;
        let mut directory_entries = chunked_vec::ChunkedVec::new();
        let mut hard_links = Vec::new();

        super::writers::with_writers(
            threads,
            &destination_filesystem,
            &write_progress,
            &listener,
            |writers| {
                for entry in decoder.entries() {
                    if writers.stopped() {
                        break;
                    }

                    let mut entry = entry?;
                    let Some(destination_path) =
                        options.resolve(&destination, &entry.enclosed_path())
                    else {
                        continue;
                    };

                    if destination_filesystem.is_ignored(
                        &destination_path,
                        FileType::from_is_dir(matches!(entry, ArchiveEntry::Directory(_))),
                    ) {
                        continue;
                    }

                    match &mut entry {
                        ArchiveEntry::Directory(dir) => {
                            let metadata = dir.metadata();

                            destination_filesystem.create_dir_all(&destination_path)?;
                            destination_filesystem.set_permissions(
                                &destination_path,
                                FileType::Dir,
                                PortablePermissions::from_mode_dir(metadata.mode),
                            )?;

                            if directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES {
                                directory_entries.push((destination_path, metadata.modified));
                            }
                        }
                        ArchiveEntry::File(file) => {
                            options.on_file(&destination_path);

                            let metadata = file.metadata();
                            let permissions = PortablePermissions::from_mode_file(metadata.mode);
                            let modified_time = metadata.modified;
                            let size = file.size();

                            if !writers.file(
                                destination_path,
                                size,
                                Some(permissions),
                                Some(modified_time),
                                file,
                            )? {
                                break;
                            }
                        }
                        ArchiveEntry::Symlink(link) => {
                            if !writers.symlink(
                                destination_path,
                                link.target().to_path_buf(),
                                Some(link.metadata().modified),
                            ) {
                                break;
                            }
                        }
                        ArchiveEntry::Hardlink(link) => {
                            let target = link.enclosed_target();
                            if target.as_os_str().is_empty() {
                                continue;
                            }

                            if let Some(target) = options.resolve(&destination, &target) {
                                hard_links.push((destination_path, target));
                            }
                        }
                    }
                }

                Ok(())
            },
        )?;

        for (path, target) in hard_links {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                destination_filesystem.create_dir_all(&parent)?;
            }

            if let Err(err) = destination_filesystem.create_hard_link(&target, &path) {
                tracing::debug!(
                    path = %path.display(),
                    target = %target.display(),
                    "failed to create hardlink from archive: {:#?}",
                    err
                );
            }
        }

        for (destination_path, modified_time) in directory_entries {
            destination_filesystem.set_times(
                &destination_path,
                FileType::Dir,
                modified_time,
                None,
            )?;
        }

        Ok(())
    })
    .await??;

    drop(guard);

    Ok(())
}
