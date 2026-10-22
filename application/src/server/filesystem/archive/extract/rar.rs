use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::abort::{AbortGuard, AbortWriter},
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

fn dos_time_to_unix(dos_time: u32) -> Option<u64> {
    let seconds = (dos_time & 0x1F) * 2;
    let minutes = (dos_time >> 5) & 0x3F;
    let hours = (dos_time >> 11) & 0x1F;
    let day = (dos_time >> 16) & 0x1F;
    let month = (dos_time >> 21) & 0x0F;
    let year = ((dos_time >> 25) & 0x7F) + 1980;

    let date = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)?;
    let time = chrono::NaiveTime::from_hms_opt(hours, minutes, seconds)?;

    Some(chrono::NaiveDateTime::new(date, time).and_utc().timestamp() as u64)
}

pub async fn extract_rar(
    archive: Archive,
    destination: PathBuf,
    destination_filesystem: Arc<dyn VirtualWritableFilesystem>,
    progress: ArchiveProgress,
    total: Option<Arc<AtomicU64>>,
    options: ExtractOptions,
) -> Result<(), anyhow::Error> {
    let Archive { server, source, .. } = archive;

    let (file, path) = source.file()?;
    let (guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        #[cfg(target_os = "linux")]
        let archive_path = {
            let _ = (server, path);
            crate::server::filesystem::cap::proc_fd_path(&file)
        };
        #[cfg(not(target_os = "linux"))]
        let archive_path = {
            drop(file);

            server
                .filesystem
                .base_path
                .join(server.filesystem.relative_path(&path))
        };

        if let Some(total) = total {
            let mut entry_total = 0;
            let archive = unrar::Archive::new(&archive_path).open_for_listing()?;
            for entry in archive.flatten() {
                entry_total += entry.unpacked_size;
            }

            total.store(entry_total, Ordering::Relaxed);
        }

        let mut archive = unrar::Archive::new(&archive_path).open_for_processing()?;
        let mut directory_entries = chunked_vec::ChunkedVec::new();
        let mut last_parent = None;

        loop {
            let entry = match archive.read_header()? {
                Some(entry) => entry,
                None => break,
            };

            let Some(destination_path) = options.resolve(&destination, &entry.entry().filename)
            else {
                archive = entry.skip()?;
                continue;
            };

            if destination_filesystem.is_ignored(
                &destination_path,
                FileType::from_is_dir(entry.entry().is_directory()),
            ) {
                archive = entry.skip()?;
                continue;
            }

            if listener.is_aborted() {
                return Err(anyhow::anyhow!("operation aborted"));
            }

            if entry.entry().is_directory() {
                destination_filesystem.create_dir_all(&destination_path)?;

                if let Some(modified_time) = dos_time_to_unix(entry.entry().file_time)
                    && directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES
                {
                    directory_entries.push((destination_path, modified_time));
                }

                archive = entry.skip()?;
            } else {
                options.on_file(&destination_path);

                if let Some(parent) = destination_path.parent()
                    && last_parent.as_deref() != Some(parent)
                {
                    destination_filesystem.create_dir_all(&parent)?;
                    last_parent = Some(parent.to_path_buf());
                }

                let modified_time = dos_time_to_unix(entry.entry().file_time)
                    .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs));

                let writer = destination_filesystem.create_file(&destination_path)?;
                let mut writer =
                    progress.counting_writer(AbortWriter::new(writer, listener.clone()));

                let processed_archive = entry.read_to(&mut writer).map_err(std::io::Error::from)?;
                writer.flush()?;

                if let Some(modified_time) = modified_time {
                    destination_filesystem.set_times(
                        &destination_path,
                        FileType::File,
                        modified_time,
                        None,
                    )?;
                }

                progress.increment_files();

                archive = processed_archive;
            }
        }

        for (destination_path, modified_time) in directory_entries {
            destination_filesystem.set_times(
                &destination_path,
                FileType::Dir,
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(modified_time))
                    .unwrap_or_else(std::time::SystemTime::now),
                None,
            )?;
        }

        Ok(())
    })
    .await??;

    drop(guard);

    Ok(())
}
