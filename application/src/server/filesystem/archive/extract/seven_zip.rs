use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::abort::{AbortGuard, AbortReader},
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub async fn extract_seven_zip(
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
        let password = sevenz_rust2::Password::empty();
        let archive = sevenz_rust2::Archive::read(&mut reader.clone(), &password)?;

        if let Some(total) = total {
            total.store(
                archive.files.iter().map(|f| f.size).sum(),
                Ordering::Relaxed,
            );
        }

        let pool = crate::threading::build_pool(options.threads(&server))?;

        let error = Arc::new(crate::threading::SharedError::new());

        pool.in_place_scope(|scope| {
            for block_index in 0..archive.blocks.len() {
                let archive = archive.clone();
                let progress = progress.clone();
                let mut reader = reader.clone();
                let destination = destination.clone();
                let destination_filesystem = destination_filesystem.clone();
                let error = Arc::clone(&error);
                let options = options.clone();

                scope.spawn(move |_| {
                    if error.stopped() {
                        return;
                    }

                    let password = sevenz_rust2::Password::empty();
                    let folder = sevenz_rust2::BlockDecoder::new(
                        1,
                        block_index,
                        &archive,
                        &password,
                        &mut reader,
                    );

                    let mut read_buffer = crate::io::mem_buffer(crate::BUFFER_SIZE);
                    let mut last_parent = None;
                    // entries of a block share one decoder, so a skipped entry still has
                    // to be read for the next one to start at the right offset
                    let skip = |reader: &mut dyn Read| {
                        std::io::copy(reader, &mut std::io::sink())
                            .map(|_| true)
                            .map_err(|err| sevenz_rust2::Error::Other(err.to_string().into()))
                    };

                    if let Err(err) = folder.for_each_entries(&mut |entry, reader| {
                        let path = entry.name();
                        if path.starts_with('/') || path.starts_with('\\') {
                            return skip(reader);
                        }

                        let Some(destination_path) = options.resolve(&destination, Path::new(path))
                        else {
                            return skip(reader);
                        };

                        if destination_filesystem.is_ignored(
                            &destination_path,
                            FileType::from_is_dir(entry.is_directory()),
                        ) {
                            return skip(reader);
                        }

                        if entry.is_directory() {
                            if let Err(err) =
                                destination_filesystem.create_dir_all(&destination_path)
                            {
                                return Err(sevenz_rust2::Error::Other(err.to_string().into()));
                            }
                        } else {
                            options.on_file(&destination_path);

                            if let Some(parent) = destination_path.parent()
                                && last_parent.as_deref() != Some(parent)
                            {
                                if let Err(err) = destination_filesystem.create_dir_all(&parent) {
                                    return Err(sevenz_rust2::Error::Other(err.to_string().into()));
                                }
                                last_parent = Some(parent.to_path_buf());
                            }

                            let modified_time = if entry.has_last_modified_date {
                                Some(entry.last_modified_date.into())
                            } else {
                                None
                            };

                            let mut writer = destination_filesystem
                                .create_file(&destination_path)
                                .map_err(|e| std::io::Error::other(e.to_string()))?;

                            let mut reader = progress.counting_reader(reader);

                            crate::io::copy_shared(&mut read_buffer, &mut reader, &mut writer)?;
                            writer.flush()?;
                            drop(writer);

                            if let Some(modified_time) = modified_time {
                                destination_filesystem
                                    .set_times(
                                        &destination_path,
                                        FileType::File,
                                        modified_time,
                                        None,
                                    )
                                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                            }

                            progress.increment_files();
                        }

                        Ok(true)
                    }) {
                        error.fail(err);
                    }
                });
            }
        });

        if let Some(err) = error.take() {
            Err(err.into())
        } else {
            for entry in archive.files {
                if entry.is_directory() {
                    let path = entry.name();
                    if path.starts_with('/') || path.starts_with('\\') {
                        continue;
                    }

                    let Some(destination_path) = options.resolve(&destination, Path::new(path))
                    else {
                        continue;
                    };

                    if destination_filesystem.is_ignored(&destination_path, FileType::Dir) {
                        continue;
                    }

                    destination_filesystem.create_dir_all(&destination_path)?;

                    if entry.has_last_modified_date {
                        destination_filesystem.set_times(
                            &destination_path,
                            FileType::Dir,
                            entry.last_modified_date.into(),
                            None,
                        )?;
                    }
                }
            }

            Ok(())
        }
    })
    .await??;

    drop(guard);

    Ok(())
}
