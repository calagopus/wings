use super::ArchiveProgress;
use crate::{
    io::{
        abort::{AbortGuard, AbortWriter},
        compression::{CompressionLevel, CompressionType, writer::CompressionWriter},
        fixed_reader::FixedReader,
    },
    server::filesystem::{cap::FileType, virtualfs::IsIgnoredFn},
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

            let file_type: FileType = source_metadata.file_type().into();
            let verdict = (is_ignored)(file_type, source);
            let kept = verdict.is_kept();
            let Some(source) = verdict.reachable(file_type) else {
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
                if kept {
                    header.set_entry_type(tar::EntryType::Directory);

                    archive.append_data(&mut header, relative, std::io::empty())?;
                    progress.increment_bytes(source_metadata.len());
                }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::filesystem::{cap::CapFilesystem, ignore_list::IgnoreList};
    use std::{
        collections::HashMap,
        io::{Cursor, Read},
    };

    fn tar_tree_filtered(
        root: &Path,
        sources: Vec<&'static str>,
        is_ignored: IsIgnoredFn,
    ) -> Result<Vec<u8>, anyhow::Error> {
        tokio_test::block_on(async {
            let filesystem = CapFilesystem::new(root).await?;

            let archive = create_tar(
                filesystem,
                Cursor::new(Vec::new()),
                Path::new(""),
                sources,
                ArchiveProgress::default(),
                is_ignored,
                CreateTarOptions {
                    compression_type: CompressionType::None,
                    compression_level: CompressionLevel::BestSpeed,
                    threads: 1,
                },
            )
            .await?;

            Ok(archive.into_inner())
        })
    }

    // create_tar
    #[test]
    fn reincluded_subtree_is_archived_without_its_excluded_parents() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();

        std::fs::create_dir_all(root.join("game/csgo/cfg/nested"))?;
        std::fs::create_dir_all(root.join("game/hl2"))?;
        for (name, contents) in [
            ("game/csgo/cfg/server.cfg", "hostname wings"),
            ("game/csgo/cfg/nested/deep.cfg", "sv_cheats 0"),
            ("game/csgo/other.txt", "other"),
            ("game/hl2/hl2.txt", "hl2"),
            ("top.txt", "top"),
        ] {
            std::fs::write(root.join(name), contents)?;
        }

        let is_ignored = IsIgnoredFn::from(IgnoreList::from_lines(["*", "!game/csgo/cfg"])?);
        let bytes = tar_tree_filtered(root, vec!["game", "top.txt"], is_ignored)?;

        let mut archive = tar::Archive::new(Cursor::new(bytes));
        let mut files: HashMap<String, String> = HashMap::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = entry.path()?.to_string_lossy().into_owned();
            let name = name.trim_end_matches('/').to_string();

            if entry.header().entry_type().is_dir() {
                assert!(name != "game" && name != "game/csgo", "{name} was archived");
                continue;
            }

            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;

            assert!(files.insert(name, contents).is_none());
        }

        let mut names: Vec<&str> = files.keys().map(String::as_str).collect();
        names.sort_unstable();

        assert_eq!(
            names,
            ["game/csgo/cfg/nested/deep.cfg", "game/csgo/cfg/server.cfg"]
        );
        assert_eq!(
            files.get("game/csgo/cfg/server.cfg").map(String::as_str),
            Some("hostname wings")
        );
        assert_eq!(
            files
                .get("game/csgo/cfg/nested/deep.cfg")
                .map(String::as_str),
            Some("sv_cheats 0")
        );

        Ok(())
    }
}
