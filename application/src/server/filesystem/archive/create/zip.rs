use super::ArchiveProgress;
use crate::{
    io::{
        abort::{AbortGuard, AbortWriter},
        compression::CompressionLevel,
        fixed_reader::FixedReader,
    },
    server::filesystem::virtualfs::IsIgnoredFn,
    utils::PortablePermissions,
};
use chrono::{Datelike, Timelike};
use std::{
    io::{Seek, Write},
    path::Path,
};

pub struct CreateZipOptions {
    pub compression_level: CompressionLevel,
}

pub async fn create_zip<W: Write + Seek + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: CreateZipOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = AbortWriter::new(destination, listener);
        let mut archive = zip::ZipWriter::new(writer);

        let mut read_buffer = vec![0; crate::BUFFER_SIZE];
        for source in sources {
            let relative = source.as_ref();
            let source = base.join(relative);

            let source_metadata = match filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %source.display(), "skipping source while creating zip archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let Some(source) = (is_ignored)(source_metadata.file_type().into(), source) else {
                continue;
            };

            let mut zip_options: zip::write::FileOptions<'_, ()> =
                zip::write::FileOptions::default()
                    .compression_level(Some(options.compression_level.to_deflate_level() as i64))
                    .unix_permissions(PortablePermissions::from(source_metadata.permissions()).mode() as u32)
                    .large_file(true);

            if let Ok(mtime) = source_metadata.modified() {
                let mtime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(mtime.into_std());

                if let Ok(mtime) = zip::DateTime::from_date_and_time(
                    mtime.year() as u16,
                    mtime.month() as u8,
                    mtime.day() as u8,
                    mtime.hour() as u8,
                    mtime.minute() as u8,
                    mtime.second() as u8,
                ) {
                    zip_options = zip_options.last_modified_time(mtime);
                }
            }

            if source_metadata.is_dir() {
                archive.add_directory(relative.to_string_lossy(), zip_options)?;
                progress.increment_bytes(source_metadata.len());

                let mut walker = filesystem
                    .walk_dir(source)?
                    .with_is_ignored(is_ignored.clone());
                while let Some(entry) = walker.next_entry() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            tracing::debug!("failed to read directory entry while creating zip archive: {err:#}");
                            break;
                        }
                    };
                    let path = &entry.path;

                    let relative = match path.strip_prefix(&base) {
                        Ok(path) => path,
                        Err(_) => continue,
                    };

                    let metadata = match entry.metadata() {
                        Ok(metadata) => metadata,
                        Err(err) => {
                            tracing::debug!(path = %path.display(), "skipping entry while creating zip archive, failed to read metadata: {err:#}");
                            continue;
                        }
                    };

                    let mut zip_options: zip::write::FileOptions<'_, ()> =
                        zip::write::FileOptions::default()
                            .compression_level(Some(
                                options.compression_level.to_deflate_level() as i64
                            ))
                            .unix_permissions(PortablePermissions::from(metadata.permissions()).mode() as u32)
                            .large_file(true);

                    if let Ok(mtime) = metadata.modified() {
                        let mtime: chrono::DateTime<chrono::Utc> =
                            chrono::DateTime::from(mtime.into_std());

                        if let Ok(mtime) = zip::DateTime::from_date_and_time(
                            mtime.year() as u16,
                            mtime.month() as u8,
                            mtime.day() as u8,
                            mtime.hour() as u8,
                            mtime.minute() as u8,
                            mtime.second() as u8,
                        ) {
                            zip_options = zip_options.last_modified_time(mtime);
                        }
                    }

                    if metadata.is_dir() {
                        archive.add_directory(relative.to_string_lossy(), zip_options)?;
                        progress.increment_bytes(metadata.len());
                    } else if metadata.is_file() {
                        let file = filesystem.open(path)?;
                        let reader = progress.counting_reader(file);
                        let mut reader =
                            FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                        archive.start_file(relative.to_string_lossy(), zip_options)?;
                        crate::io::copy_shared(&mut read_buffer, &mut reader, &mut archive)?;
                        progress.increment_files();
                    } else if let Ok(link_target) = filesystem.read_link_contents(path) {
                        archive.add_symlink(
                            relative.to_string_lossy(),
                            link_target.to_string_lossy(),
                            zip_options,
                        )?;
                        progress.increment_bytes(metadata.len());
                        progress.increment_files();
                    }
                }
            } else if source_metadata.is_file() {
                let file = filesystem.open(&source)?;
                let reader = progress.counting_reader(file);
                let mut reader = FixedReader::new_with_fixed_bytes(
                    reader,
                    source_metadata.len() as usize,
                );

                archive.start_file(relative.to_string_lossy(), zip_options)?;
                crate::io::copy_shared(&mut read_buffer, &mut reader, &mut archive)?;
                progress.increment_files();
            } else if let Ok(link_target) = filesystem.read_link_contents(&source) {
                archive.add_symlink(
                    relative.to_string_lossy(),
                    link_target.to_string_lossy(),
                    zip_options,
                )?;
                progress.increment_bytes(source_metadata.len());
                progress.increment_files();
            }
        }

        let mut inner = archive.finish()?.into_inner();
        inner.flush()?;

        Ok(inner)
    })
    .await?
}

pub async fn create_zip_streaming<W: Write + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: CreateZipOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = AbortWriter::new(destination, listener);
        let mut archive = zip::ZipWriter::new_stream(writer);

        let mut read_buffer = vec![0; crate::BUFFER_SIZE];
        for source in sources {
            let relative = source.as_ref();
            let source = base.join(relative);

            let source_metadata = match filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %source.display(), "skipping source while creating zip archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let Some(source) = (is_ignored)(source_metadata.file_type().into(), source) else {
                continue;
            };

            let mut zip_options: zip::write::FileOptions<'_, ()> =
                zip::write::FileOptions::default()
                    .compression_level(Some(options.compression_level.to_deflate_level() as i64))
                    .unix_permissions(PortablePermissions::from(source_metadata.permissions()).mode() as u32)
                    .large_file(true);

            if let Ok(mtime) = source_metadata.modified() {
                let mtime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(mtime.into_std());

                if let Ok(mtime) = zip::DateTime::from_date_and_time(
                    mtime.year() as u16,
                    mtime.month() as u8,
                    mtime.day() as u8,
                    mtime.hour() as u8,
                    mtime.minute() as u8,
                    mtime.second() as u8,
                ) {
                    zip_options = zip_options.last_modified_time(mtime);
                }
            }

            if source_metadata.is_dir() {
                archive.add_directory(relative.to_string_lossy(), zip_options)?;
                progress.increment_bytes(source_metadata.len());

                let mut walker = filesystem
                    .walk_dir(source)?
                    .with_is_ignored(is_ignored.clone());
                while let Some(entry) = walker.next_entry() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            tracing::debug!("failed to read directory entry while creating zip archive: {err:#}");
                            break;
                        }
                    };

                    let path = &entry.path;

                    let relative = match path.strip_prefix(&base) {
                        Ok(path) => path,
                        Err(_) => continue,
                    };

                    let metadata = match entry.metadata() {
                        Ok(metadata) => metadata,
                        Err(err) => {
                            tracing::debug!(path = %path.display(), "skipping entry while creating zip archive, failed to read metadata: {err:#}");
                            continue;
                        }
                    };

                    let mut zip_options: zip::write::FileOptions<'_, ()> =
                        zip::write::FileOptions::default()
                            .compression_level(Some(
                                options.compression_level.to_deflate_level() as i64
                            ))
                            .unix_permissions(PortablePermissions::from(metadata.permissions()).mode() as u32)
                            .large_file(true);

                    if let Ok(mtime) = metadata.modified() {
                        let mtime: chrono::DateTime<chrono::Utc> =
                            chrono::DateTime::from(mtime.into_std());

                        if let Ok(mtime) = zip::DateTime::from_date_and_time(
                            mtime.year() as u16,
                            mtime.month() as u8,
                            mtime.day() as u8,
                            mtime.hour() as u8,
                            mtime.minute() as u8,
                            mtime.second() as u8,
                        ) {
                            zip_options = zip_options.last_modified_time(mtime);
                        }
                    }

                    if metadata.is_dir() {
                        archive.add_directory(relative.to_string_lossy(), zip_options)?;
                        progress.increment_bytes(metadata.len());
                    } else if metadata.is_file() {
                        let file = filesystem.open(path)?;
                        let reader = progress.counting_reader(file);
                        let mut reader =
                            FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                        archive.start_file(relative.to_string_lossy(), zip_options)?;
                        crate::io::copy_shared(&mut read_buffer, &mut reader, &mut archive)?;
                        progress.increment_files();
                    } else if let Ok(link_target) = filesystem.read_link_contents(path) {
                        archive.add_symlink(
                            relative.to_string_lossy(),
                            link_target.to_string_lossy(),
                            zip_options,
                        )?;
                        progress.increment_bytes(metadata.len());
                        progress.increment_files();
                    }
                }
            } else if source_metadata.is_file() {
                let file = filesystem.open(&source)?;
                let reader = progress.counting_reader(file);
                let mut reader = FixedReader::new_with_fixed_bytes(
                    reader,
                    source_metadata.len() as usize,
                );

                archive.start_file(relative.to_string_lossy(), zip_options)?;
                crate::io::copy_shared(&mut read_buffer, &mut reader, &mut archive)?;
                progress.increment_files();
            } else if let Ok(link_target) = filesystem.read_link_contents(&source) {
                archive.add_symlink(
                    relative.to_string_lossy(),
                    link_target.to_string_lossy(),
                    zip_options,
                )?;
                progress.increment_bytes(source_metadata.len());
                progress.increment_files();
            }
        }

        let mut inner = archive.finish()?.into_inner().into_inner();
        inner.flush()?;

        Ok(inner)
    })
    .await?
}
