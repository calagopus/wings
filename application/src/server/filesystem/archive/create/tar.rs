use super::ArchiveProgress;
use crate::{
    io::{
        abort::{AbortGuard, AbortWriter},
        compression::{CompressionLevel, CompressionType, writer::CompressionWriter},
        fixed_reader::FixedReader,
    },
    server::filesystem::virtualfs::IsIgnoredFn,
    utils::PortablePermissions,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub struct CreateTarOptions {
    pub compression_type: CompressionType,
    pub compression_level: CompressionLevel,
    pub threads: usize,
}

pub async fn create_tar<W: Write + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: CreateTarOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = CompressionWriter::new(
            destination,
            options.compression_type,
            options.compression_level,
            options.threads,
        )?;
        let writer = AbortWriter::new(writer, listener);
        let mut archive = tar::Builder::new(writer);

        for source in sources {
            let relative = source.as_ref();
            let source = base.join(relative);

            let source_metadata = match filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %source.display(), "skipping source while creating tar archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let Some(source) = (is_ignored)(source_metadata.file_type().into(), source) else {
                continue;
            };

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(PortablePermissions::from(source_metadata.permissions()).mode() as u32);
            header.set_mtime(
                source_metadata
                    .modified()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs(),
            );

            if source_metadata.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);

                archive.append_data(&mut header, relative, std::io::empty())?;
                progress.increment_bytes(source_metadata.len());

                let mut walker = filesystem
                    .walk_dir(source)?
                    .with_is_ignored(is_ignored.clone());
                while let Some(entry) = walker.next_entry() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            tracing::debug!("failed to read directory entry while creating tar archive: {err:#}");
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
                            tracing::debug!(path = %path.display(), "skipping entry while creating tar archive, failed to read metadata: {err:#}");
                            continue;
                        }
                    };

                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(PortablePermissions::from(metadata.permissions()).mode() as u32);
                    header.set_mtime(
                        metadata
                            .modified()
                            .map(|t| {
                                t.into_std()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                            })
                            .unwrap_or_default()
                            .as_secs(),
                    );

                    if metadata.is_dir() {
                        header.set_entry_type(tar::EntryType::Directory);

                        archive.append_data(&mut header, relative, std::io::empty())?;
                        progress.increment_bytes(metadata.len());
                    } else if metadata.is_file() {
                        let file = filesystem.open(path)?;
                        let reader = progress.counting_reader(file);
                        let reader =
                            FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                        header.set_size(metadata.len());
                        header.set_entry_type(tar::EntryType::Regular);

                        archive.append_data(&mut header, relative, reader)?;
                        progress.increment_files();
                    } else if let Ok(link_target) = filesystem.read_link_contents(path) {
                        header.set_entry_type(tar::EntryType::Symlink);

                        if header.set_link_name(link_target).is_ok() {
                            archive.append_data(&mut header, relative, std::io::empty())?;
                            progress.increment_bytes(metadata.len());
                            progress.increment_files();
                        }
                    }
                }
            } else if source_metadata.is_file() {
                let file = filesystem.open(&source)?;
                let reader = progress.counting_reader(file);
                let reader =
                    FixedReader::new_with_fixed_bytes(reader, source_metadata.len() as usize);
                let reader = std::io::BufReader::with_capacity(crate::BUFFER_SIZE, reader);

                header.set_size(source_metadata.len());
                header.set_entry_type(tar::EntryType::Regular);

                archive.append_data(&mut header, relative, reader)?;
                progress.increment_files();
            } else if let Ok(link_target) = filesystem.read_link_contents(&source) {
                header.set_entry_type(tar::EntryType::Symlink);

                if header.set_link_name(link_target).is_ok() {
                    archive.append_data(&mut header, relative, std::io::empty())?;
                    progress.increment_bytes(source_metadata.len());
                    progress.increment_files();
                }
            }
        }

        archive.finish()?;
        let mut inner = archive.into_inner()?.into_inner().finish()?;
        inner.flush()?;

        Ok(inner)
    })
    .await?
}

pub async fn create_tar_distributed<W: Write + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: async_channel::Receiver<PathBuf>,
    progress: ArchiveProgress,
    options: CreateTarOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = CompressionWriter::new(
            destination,
            options.compression_type,
            options.compression_level,
            options.threads,
        )?;
        let writer = AbortWriter::new(writer, listener);
        let mut archive = tar::Builder::new(writer);

        while let Ok(source) = sources.recv_blocking() {
            let relative = source;
            let source = base.join(&relative);

            let source_metadata = match filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %source.display(), "skipping source while creating tar archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(PortablePermissions::from(source_metadata.permissions()).mode() as u32);
            header.set_mtime(
                source_metadata
                    .modified()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs(),
            );

            if source_metadata.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);

                archive.append_data(&mut header, relative, std::io::empty())?;
                progress.increment_bytes(source_metadata.len());
            } else if source_metadata.is_file() {
                let file = filesystem.open(&source)?;
                let reader = progress.counting_reader(file);
                let reader =
                    FixedReader::new_with_fixed_bytes(reader, source_metadata.len() as usize);
                let reader = std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

                header.set_size(source_metadata.len());
                header.set_entry_type(tar::EntryType::Regular);

                archive.append_data(&mut header, relative, reader)?;
                progress.increment_files();
            } else if let Ok(link_target) = filesystem.read_link_contents(&source) {
                header.set_entry_type(tar::EntryType::Symlink);

                if header.set_link_name(link_target).is_ok() {
                    archive.append_data(&mut header, relative, std::io::empty())?;
                    progress.increment_bytes(source_metadata.len());
                    progress.increment_files();
                }
            }
        }

        archive.finish()?;
        let mut inner = archive.into_inner()?.into_inner().finish()?;
        inner.flush()?;

        Ok(inner)
    })
    .await?
}
