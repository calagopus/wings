use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::abort::{AbortGuard, AbortReader},
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    utils::PortablePermissions,
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub async fn extract_tar(
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

        let budget = super::tar_budget::TarMetadataBudget::default();
        let mut archive = tar::Archive::new(budget.reader(reader));
        archive.set_ignore_zeros(true);
        let mut directory_entries = chunked_vec::ChunkedVec::new();
        let entries = archive.entries()?;

        super::writers::with_writers(
            threads,
            &destination_filesystem,
            &write_progress,
            &listener,
            |writers| {
                for entry in entries {
                    if writers.stopped() {
                        break;
                    }

                    let mut entry = entry?;
                    budget.member(&mut entry)?;
                    let path = entry.path()?;

                    let Some(destination_path) = options.resolve(&destination, path.as_ref())
                    else {
                        continue;
                    };
                    let header = entry.header();

                    if destination_filesystem.is_ignored(
                        &destination_path,
                        FileType::from_is_dir(header.entry_type().is_dir()),
                    ) {
                        continue;
                    }

                    match header.entry_type() {
                        tar::EntryType::Directory => {
                            destination_filesystem.create_dir_all(&destination_path)?;
                            if let Ok(permissions) =
                                header.mode().map(PortablePermissions::from_mode_dir)
                            {
                                destination_filesystem.set_permissions(
                                    &destination_path,
                                    FileType::Dir,
                                    permissions,
                                )?;
                            }

                            if let Ok(modified_time) = header.mtime()
                                && directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES
                                && std::time::UNIX_EPOCH
                                    .checked_add(std::time::Duration::from_secs(modified_time))
                                    .is_some()
                            {
                                directory_entries.push((destination_path, modified_time));
                            }
                        }
                        tar::EntryType::Regular => {
                            options.on_file(&destination_path);

                            let permissions =
                                header.mode().map(PortablePermissions::from_mode_file).ok();
                            let modified_time = header.mtime().ok().and_then(|modified_time| {
                                std::time::UNIX_EPOCH
                                    .checked_add(std::time::Duration::from_secs(modified_time))
                            });
                            let size = entry.size();

                            if !writers.file(
                                destination_path,
                                size,
                                permissions,
                                modified_time,
                                &mut entry,
                            )? {
                                break;
                            }
                        }
                        tar::EntryType::Symlink => {
                            let link = entry
                                .link_name()
                                .unwrap_or_default()
                                .unwrap_or_default()
                                .into_owned();
                            let modified_time = header.mtime().ok().and_then(|modified_time| {
                                std::time::UNIX_EPOCH
                                    .checked_add(std::time::Duration::from_secs(modified_time))
                            });

                            if !writers.symlink(destination_path, link, modified_time) {
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                Ok(())
            },
        )?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Server;

    // extract_tar

    struct ExtractFixture {
        server: Server,
        root: PathBuf,

        _temp: tempfile::TempDir,
    }

    impl ExtractFixture {
        async fn new(threads: usize) -> Result<Self, anyhow::Error> {
            let (temp, server) = Server::mock_in_tempdir().await;
            server
                .app_state
                .config
                .mutate_in_place_for_testing()
                .api
                .file_decompression_threads = threads;
            let root = server.filesystem.base_path.to_path_buf();

            Ok(Self {
                server,
                root,
                _temp: temp,
            })
        }

        fn build(
            &self,
            entries: impl FnOnce(&mut tar::Builder<std::fs::File>),
        ) -> Result<(), anyhow::Error> {
            let file = std::fs::File::create(self.root.join("input.tar"))?;
            let mut builder = tar::Builder::new(file);
            entries(&mut builder);
            builder.finish()?;

            Ok(())
        }

        async fn extract(&self) -> Result<PathBuf, anyhow::Error> {
            let archive = Archive::open(self.server.clone(), PathBuf::from("input.tar")).await?;
            let (destination, filesystem) = self
                .server
                .filesystem
                .resolve_writable_fs(&self.server, "out")
                .await;

            archive
                .extract(
                    destination,
                    filesystem,
                    ArchiveProgress::default(),
                    None,
                    ExtractOptions::default(),
                )
                .await?;

            Ok(self.root.join("out"))
        }
    }

    fn file_header(size: u64, mode: u32, mtime: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(mode);
        header.set_mtime(mtime);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        header
    }

    fn add_file(builder: &mut tar::Builder<std::fs::File>, name: &str, data: &[u8]) {
        let mut header = file_header(data.len() as u64, 0o644, 1_700_000_000);
        builder
            .append_data(&mut header, name, data)
            .expect("append file");
    }

    fn random(len: usize) -> Vec<u8> {
        let mut state = 0x51edu64;

        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn extracted_tree_matches_the_archive_at_every_thread_count() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            for threads in [1, 2, 4] {
                let fixture = ExtractFixture::new(threads).await?;
                let big = random(5 * 1024 * 1024 + 13);
                let small = random(4096);

                fixture.build(|builder| {
                    let mut directory = tar::Header::new_gnu();
                    directory.set_size(0);
                    directory.set_mode(0o755);
                    directory.set_mtime(1_700_000_000);
                    directory.set_entry_type(tar::EntryType::Directory);
                    directory.set_cksum();
                    builder
                        .append_data(&mut directory, "plugins/", std::io::empty())
                        .expect("append dir");

                    for i in 0..50 {
                        add_file(builder, &format!("plugins/config-{i:02}.yml"), &small);
                    }
                    add_file(builder, "world.mca", &big);
                    add_file(builder, "server.properties", b"motd=hello");
                })?;

                let out = fixture.extract().await?;

                assert_eq!(
                    std::fs::read(out.join("world.mca"))?,
                    big,
                    "multi-chunk entry differs with {threads} threads"
                );
                assert_eq!(std::fs::read(out.join("server.properties"))?, b"motd=hello");

                for i in 0..50 {
                    assert_eq!(
                        std::fs::read(out.join(format!("plugins/config-{i:02}.yml")))?,
                        small,
                        "config-{i:02} differs with {threads} threads"
                    );
                }
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn duplicate_entries_keep_the_last_write() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let fixture = ExtractFixture::new(4).await?;

            fixture.build(|builder| {
                for i in 0..32 {
                    add_file(builder, &format!("dupe-{i:02}.txt"), b"first");
                    add_file(builder, &format!("dupe-{i:02}.txt"), b"second");
                }
            })?;

            let out = fixture.extract().await?;

            for i in 0..32 {
                assert_eq!(
                    std::fs::read(out.join(format!("dupe-{i:02}.txt")))?,
                    b"second",
                    "dupe-{i:02} did not keep the last write"
                );
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn a_symlink_replacing_a_file_is_not_racy() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            // symlinks shard on the path they occupy, so this cannot be
            // reordered against the file it replaces
            let fixture = ExtractFixture::new(4).await?;

            fixture.build(|builder| {
                add_file(builder, "target.txt", b"target");

                for i in 0..16 {
                    add_file(builder, &format!("link-{i:02}"), b"replaced");

                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o777);
                    header.set_mtime(1_700_000_000);
                    header.set_entry_type(tar::EntryType::Symlink);
                    builder
                        .append_link(&mut header, format!("link-{i:02}"), "target.txt")
                        .expect("append symlink");
                }
            })?;

            let out = fixture.extract().await?;

            for i in 0..16 {
                let path = out.join(format!("link-{i:02}"));
                let metadata = std::fs::symlink_metadata(&path)?;

                assert!(
                    metadata.file_type().is_symlink() || std::fs::read(&path)? == b"replaced",
                    "link-{i:02} is neither the symlink nor the file it replaced"
                );
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn directory_mtimes_survive_the_writers() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let fixture = ExtractFixture::new(4).await?;
            let mtime = 1_600_000_000;

            fixture.build(|builder| {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(mtime);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                builder
                    .append_data(&mut header, "world/", std::io::empty())
                    .expect("append dir");

                for i in 0..64 {
                    add_file(builder, &format!("world/r.{i}.mca"), b"region");
                }
            })?;

            let out = fixture.extract().await?;
            let modified = std::fs::metadata(out.join("world"))?.modified()?;
            let seconds = modified
                .duration_since(std::time::UNIX_EPOCH)
                .expect("directory mtime before the epoch")
                .as_secs();

            assert_eq!(
                seconds, mtime,
                "directory mtime was clobbered by the files written into it"
            );

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn file_modes_and_mtimes_are_preserved() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            use std::os::unix::fs::PermissionsExt;

            let fixture = ExtractFixture::new(2).await?;

            fixture.build(|builder| {
                let mut header = file_header(5, 0o600, 1_500_000_000);
                builder
                    .append_data(&mut header, "private.key", b"hello".as_slice())
                    .expect("append file");
            })?;

            let out = fixture.extract().await?;
            let metadata = std::fs::metadata(out.join("private.key"))?;

            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                metadata
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("mtime before the epoch")
                    .as_secs(),
                1_500_000_000
            );

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn file_modes_ignore_the_umask() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            use std::os::unix::fs::PermissionsExt;

            let fixture = ExtractFixture::new(2).await?;

            fixture.build(|builder| {
                for (name, mode) in [("shared.txt", 0o664), ("run.sh", 0o775)] {
                    let mut header = file_header(5, mode, 1_500_000_000);
                    builder
                        .append_data(&mut header, name, b"hello".as_slice())
                        .expect("append file");
                }
            })?;

            let out = fixture.extract().await?;

            for (name, mode) in [("shared.txt", 0o664), ("run.sh", 0o775)] {
                assert_eq!(
                    std::fs::metadata(out.join(name))?.permissions().mode() & 0o777,
                    mode,
                    "{name} mode was masked"
                );
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn extracting_over_an_existing_file_replaces_content_and_mode() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            use std::os::unix::fs::PermissionsExt;

            let fixture = ExtractFixture::new(2).await?;
            let existing = fixture.root.join("out").join("config.yml");
            std::fs::create_dir_all(fixture.root.join("out"))?;
            std::fs::write(&existing, b"a much longer previous config body")?;
            std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600))?;

            fixture.build(|builder| {
                let mut header = file_header(3, 0o664, 1_500_000_000);
                builder
                    .append_data(&mut header, "config.yml", b"new".as_slice())
                    .expect("append file");
            })?;

            let out = fixture.extract().await?;
            let path = out.join("config.yml");

            assert_eq!(std::fs::read(&path)?, b"new");
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o664
            );

            Ok(())
        })
    }
}
