use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::abort::{AbortGuard, AbortReader},
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    utils::PortablePermissions,
};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub async fn extract_pxar(
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
        let (read_progress, write_progress) = options.progress(&progress);
        let reader = super::decompressed_reader(
            source,
            compression,
            options.threads(&server),
            &read_progress,
        )?;
        let reader = AbortReader::new(reader, listener);
        let reader = std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

        if let Some(total) = total
            && let Some(size) = size
        {
            total.store(size, Ordering::Relaxed);
        }

        let mut decoder = pbs_client::pxar::decoder::Decoder::from_std(reader)?;
        let mut directory_entries = chunked_vec::ChunkedVec::new();
        let mut read_buffer = crate::io::mem_buffer(crate::BUFFER_SIZE);
        let mut last_parent = None;

        while let Some(entry) = decoder.next() {
            let entry = entry?;

            let relative = match entry.path().strip_prefix("/") {
                Ok(relative) if !relative.as_os_str().is_empty() => relative,
                _ => continue,
            };
            let Some(destination_path) = options.resolve(&destination, relative) else {
                continue;
            };

            let is_dir = matches!(entry.kind(), pbs_client::pxar::EntryKind::Directory);
            if destination_filesystem.is_ignored(&destination_path, FileType::from_is_dir(is_dir)) {
                continue;
            }

            let stat = entry.metadata().stat;
            let modified_time = std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_secs(stat.mtime.secs.max(0) as u64));

            match entry.kind() {
                pbs_client::pxar::EntryKind::Directory => {
                    let permissions = PortablePermissions::from_mode_dir(stat.mode);
                    destination_filesystem.create_dir_all(&destination_path)?;
                    destination_filesystem.set_permissions(
                        &destination_path,
                        FileType::Dir,
                        permissions,
                    )?;
                    if let Some(modified_time) = modified_time
                        && directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES
                    {
                        directory_entries.push((destination_path, modified_time));
                    }
                }
                pbs_client::pxar::EntryKind::File { .. } => {
                    options.on_file(&destination_path);

                    if let Some(parent) = destination_path.parent()
                        && last_parent.as_deref() != Some(parent)
                    {
                        destination_filesystem.create_dir_all(&parent)?;
                        last_parent = Some(parent.to_path_buf());
                    }

                    let permissions = PortablePermissions::from_mode_file(stat.mode);
                    let mut writer = write_progress
                        .counting_writer(destination_filesystem.create_file(&destination_path)?);

                    if let Some(mut contents) = decoder.contents()? {
                        crate::io::copy_shared(&mut read_buffer, &mut contents, &mut writer)?;
                    }
                    writer.flush()?;
                    drop(writer);

                    destination_filesystem.set_permissions(
                        &destination_path,
                        FileType::File,
                        permissions,
                    )?;
                    if let Some(modified_time) = modified_time {
                        destination_filesystem.set_times(
                            &destination_path,
                            FileType::File,
                            modified_time,
                            None,
                        )?;
                    }

                    write_progress.increment_files();
                }
                pbs_client::pxar::EntryKind::Symlink(target) => {
                    let target = target.as_os_str().to_os_string();

                    if let Err(err) =
                        destination_filesystem.create_symlink(&target, &destination_path)
                    {
                        tracing::debug!(
                            path = %destination_path.display(),
                            "failed to create symlink from archive: {:#?}",
                            err
                        );
                    } else if let Some(modified_time) = modified_time {
                        destination_filesystem.set_times(
                            &destination_path,
                            FileType::Symlink,
                            modified_time,
                            None,
                        )?;
                    }
                }
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
