use super::ArchiveProgress;
use crate::{
    io::{
        SafeSliceExt,
        abort::{AbortGuard, AbortWriter},
        compression::{CompressionLevel, CompressionType, writer::CompressionWriter},
        fixed_reader::FixedReader,
    },
    server::filesystem::virtualfs::IsIgnoredFn,
    utils::PortablePermissions,
};
use compact_str::ToCompactString;
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use std::{
    borrow::Cow,
    io::Write,
    path::{Path, PathBuf},
};

pub struct CreateItafOptions {
    pub compression_type: CompressionType,
    pub compression_level: CompressionLevel,
    pub threads: usize,
    pub crc_enabled: bool,
}

fn itaf_metadata(metadata: &cap_std::fs::Metadata) -> Metadata {
    Metadata {
        uid: 0,
        gid: 0,
        mode: PortablePermissions::from(metadata.permissions()).mode() as u32,
        modified: metadata
            .modified()
            .map(|t| t.into_std())
            .unwrap_or_else(|_| std::time::SystemTime::now()),
    }
}

pub async fn create_itaf<W: Write + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: CreateItafOptions,
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
        let mut archive = ItafEncoder::new(
            writer,
            EncoderOptions {
                base_timestamp: None,
                crc_enabled: options.crc_enabled,
            },
        )?;

        for source in sources {
            let relative = source.as_ref();
            let source = base.join(relative);

            let source_metadata = match filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %source.display(), "skipping source while creating itaf archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let Some(source) = (is_ignored)(source_metadata.file_type().into(), source) else {
                continue;
            };

            let meta = itaf_metadata(&source_metadata);

            if source_metadata.is_dir() {
                let components = path_components(relative);
                enter_path_components(&mut archive, &components, &meta)?;

                let mut walker = filesystem
                    .walk_dir(source)?
                    .with_is_ignored(is_ignored.clone());

                let mut dir_stack = components
                    .into_iter()
                    .map(|c| c.to_compact_string())
                    .collect::<Vec<_>>();

                while let Some(entry) = walker.next_entry() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            tracing::debug!("failed to read directory entry while creating itaf archive: {err:#}");
                            break;
                        }
                    };

                    let path = &entry.path;

                    let rel = match path.strip_prefix(&base) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    let metadata = match entry.metadata() {
                        Ok(m) => m,
                        Err(err) => {
                            tracing::debug!(path = %path.display(), "skipping entry while creating itaf archive, failed to read metadata: {err:#}");
                            continue;
                        }
                    };

                    let entry_components = path_components(rel);
                    let entry_dirs =
                        entry_components.get_slice(..entry_components.len().saturating_sub(1))?;
                    let entry_name = match entry_components.last() {
                        Some(n) => n.clone(),
                        None => continue,
                    };

                    sync_dir_stack(&mut archive, &mut dir_stack, entry_dirs)?;

                    let entry_meta = itaf_metadata(&metadata);

                    if metadata.is_dir() {
                        archive.enter_dir(&entry_name, &entry_meta)?;
                        dir_stack.push(entry_name.to_compact_string());

                        progress.increment_bytes(metadata.len());
                    } else if metadata.is_file() {
                        let file = filesystem.open(path)?;
                        let reader = progress.counting_reader(file);
                        let reader =
                            FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                        archive
                            .add_file(&entry_name, &entry_meta, metadata.len(), &mut { reader })?;
                        progress.increment_files();
                    } else if let Ok(link_target) = filesystem.read_link_contents(path) {
                        let target = link_target.to_string_lossy();

                        if itaf::spec::validate_name(&entry_name).is_ok() {
                            archive.add_symlink(
                                &entry_name,
                                &target,
                                symlink_targets_dir(&filesystem, path),
                                &entry_meta,
                            )?;
                            progress.increment_bytes(metadata.len());
                            progress.increment_files();
                        }
                    }
                }

                let target_depth = 0;
                while dir_stack.len() > target_depth {
                    archive.exit_dir()?;
                    dir_stack.pop();
                }

                progress.increment_bytes(source_metadata.len());
            } else if source_metadata.is_file() {
                let components = path_components(relative);
                let name = match components.last() {
                    Some(n) => n.clone(),
                    None => continue,
                };
                let enclosing = components.get_slice(..components.len().saturating_sub(1))?;

                enter_path_components(&mut archive, enclosing, &meta)?;

                let file = filesystem.open(&source)?;
                let reader = progress.counting_reader(file);
                let reader =
                    FixedReader::new_with_fixed_bytes(reader, source_metadata.len() as usize);

                archive.add_file(&name, &meta, source_metadata.len(), &mut { reader })?;
                progress.increment_files();

                exit_path_components(&mut archive, enclosing.len())?;
            } else if let Ok(link_target) = filesystem.read_link_contents(&source) {
                let components = path_components(relative);
                let name = match components.last() {
                    Some(n) => n.clone(),
                    None => continue,
                };
                let enclosing = components.get_slice(..components.len().saturating_sub(1))?;

                enter_path_components(&mut archive, enclosing, &meta)?;

                let target = link_target.to_string_lossy();
                if itaf::spec::validate_name(&name).is_ok() {
                    archive.add_symlink(
                        &name,
                        &target,
                        symlink_targets_dir(&filesystem, &source),
                        &meta,
                    )?;
                }

                exit_path_components(&mut archive, enclosing.len())?;

                progress.increment_bytes(source_metadata.len());
                progress.increment_files();
            }
        }

        let mut inner = archive.finish()?.into_inner().finish()?;
        inner.flush()?;

        Ok(inner)
    })
    .await?
}

pub async fn create_itaf_distributed<W: Write + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: async_channel::Receiver<PathBuf>,
    progress: ArchiveProgress,
    options: CreateItafOptions,
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
        let mut archive = ItafEncoder::new(
            writer,
            EncoderOptions {
                base_timestamp: None,
                crc_enabled: options.crc_enabled,
            },
        )?;

        let mut dir_stack = Vec::new();

        while let Ok(source) = sources.recv_blocking() {
            let relative = &source;
            let full = base.join(relative);

            let metadata = match filesystem.symlink_metadata(&full) {
                Ok(m) => m,
                Err(err) => {
                    tracing::debug!(path = %full.display(), "skipping source while creating itaf archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let meta = itaf_metadata(&metadata);

            let components = path_components(relative);
            if components.is_empty() {
                continue;
            }

            if metadata.is_dir() {
                let parent_components = components.get_slice(..components.len().saturating_sub(1))?;
                sync_dir_stack_with_meta(
                    &mut archive,
                    &mut dir_stack,
                    parent_components,
                    &filesystem,
                    &base,
                )?;

                let Some(name) = components.last() else {
                    continue;
                };
                archive.enter_dir(name, &meta)?;
                dir_stack.push(name.to_compact_string());

                progress.increment_bytes(metadata.len());
            } else if metadata.is_file() {
                let dir_components = components.get_slice(..components.len().saturating_sub(1))?;
                sync_dir_stack_with_meta(
                    &mut archive,
                    &mut dir_stack,
                    dir_components,
                    &filesystem,
                    &base,
                )?;

                let Some(name) = components.last() else {
                    continue;
                };

                let file = filesystem.open(&full)?;
                let reader = progress.counting_reader(file);
                let reader = FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                archive.add_file(name, &meta, metadata.len(), &mut { reader })?;
                progress.increment_files();
            } else if let Ok(link_target) = filesystem.read_link_contents(&full) {
                let dir_components = components.get_slice(..components.len().saturating_sub(1))?;
                sync_dir_stack_with_meta(
                    &mut archive,
                    &mut dir_stack,
                    dir_components,
                    &filesystem,
                    &base,
                )?;

                let Some(name) = components.last() else {
                    continue;
                };
                let target = link_target.to_string_lossy();
                if itaf::spec::validate_name(name).is_ok() {
                    archive.add_symlink(
                        name,
                        &target,
                        symlink_targets_dir(&filesystem, &full),
                        &meta,
                    )?;
                }

                progress.increment_bytes(metadata.len());
                progress.increment_files();
            }
        }

        exit_path_components(&mut archive, dir_stack.len())?;

        let mut inner = archive.finish()?.into_inner().finish()?;
        inner.flush()?;

        Ok(inner)
    })
    .await?
}

fn symlink_targets_dir(
    filesystem: &crate::server::filesystem::cap::CapFilesystem,
    path: &Path,
) -> bool {
    filesystem
        .metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

fn path_components<'a>(path: &'a Path) -> Vec<Cow<'a, str>> {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy()),
            _ => None,
        })
        .collect()
}

fn enter_path_components<W: Write>(
    archive: &mut ItafEncoder<W>,
    components: &[Cow<'_, str>],
    meta: &Metadata,
) -> Result<(), std::io::Error> {
    for component in components {
        archive.enter_dir(component, meta)?;
    }
    Ok(())
}

fn exit_path_components<W: Write>(
    archive: &mut ItafEncoder<W>,
    count: usize,
) -> Result<(), std::io::Error> {
    for _ in 0..count {
        archive.exit_dir()?;
    }
    Ok(())
}

fn sync_dir_stack<W: Write>(
    archive: &mut ItafEncoder<W>,
    dir_stack: &mut Vec<compact_str::CompactString>,
    target: &[Cow<'_, str>],
) -> Result<(), std::io::Error> {
    let shared = dir_stack
        .iter()
        .zip(target.iter())
        .take_while(|(a, b)| a == b)
        .count();
    while dir_stack.len() > shared {
        archive.exit_dir()?;
        dir_stack.pop();
    }

    for component in target.get_slice(shared..)? {
        let meta = Metadata {
            uid: 0,
            gid: 0,
            mode: 0o755,
            modified: std::time::SystemTime::now(),
        };
        archive.enter_dir(component, &meta)?;
        dir_stack.push(component.to_compact_string());
    }

    Ok(())
}

fn sync_dir_stack_with_meta<W: Write>(
    archive: &mut ItafEncoder<W>,
    dir_stack: &mut Vec<compact_str::CompactString>,
    target: &[Cow<'_, str>],
    filesystem: &crate::server::filesystem::cap::CapFilesystem,
    base: &Path,
) -> Result<(), std::io::Error> {
    let shared = dir_stack
        .iter()
        .zip(target.iter())
        .take_while(|(a, b)| a == b)
        .count();
    while dir_stack.len() > shared {
        archive.exit_dir()?;
        dir_stack.pop();
    }

    for component in target.get_slice(shared..)? {
        dir_stack.push(component.to_compact_string());

        let mut dir_path = base.to_path_buf();
        for seg in dir_stack.iter() {
            dir_path.push(seg);
        }

        let meta = match filesystem.symlink_metadata(&dir_path) {
            Ok(m) => itaf_metadata(&m),
            Err(err) => {
                tracing::debug!(path = %dir_path.display(), "falling back to default directory metadata while creating itaf archive, failed to read metadata: {err:#}");
                Metadata {
                    uid: 0,
                    gid: 0,
                    mode: 0o755,
                    modified: std::time::SystemTime::now(),
                }
            }
        };

        archive.enter_dir(component, &meta)?;
    }

    Ok(())
}
