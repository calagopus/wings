use crate::server::filesystem::{
    archive::{Archive, StreamableArchiveFormat, create::ArchiveProgress},
    cap::{CapFilesystem, WalkEntry},
    ignore_list::IgnoreList,
    virtualfs::VirtualReadableFilesystem,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncWriteExt;

pub(super) struct SnapshotDir {
    pub(super) root: PathBuf,
    pub(super) ignore_path: PathBuf,
    pub(super) what: &'static str,
}

impl SnapshotDir {
    async fn open(&self) -> Result<(CapFilesystem, IgnoreList), anyhow::Error> {
        if tokio::fs::metadata(&self.root).await.is_err() {
            return Err(anyhow::anyhow!(
                "{} does not exist: {}",
                self.what,
                self.root.display()
            ));
        }

        let filesystem = CapFilesystem::new(&self.root).await?;
        let ignore = read_ignore(&self.ignore_path).await?;

        Ok((filesystem, ignore))
    }

    pub(super) async fn archive_stream(
        &self,
        config: &crate::config::Config,
        archive_format: StreamableArchiveFormat,
        compression_level: crate::io::compression::CompressionLevel,
    ) -> Result<crate::io::fallible_reader::FalliblePipeReader, anyhow::Error> {
        let (filesystem, ignore) = self.open().await?;
        let names = filesystem.async_read_dir_all(Path::new("")).await?;
        let threads = config.load().api.file_compression_threads;
        let what = self.what;

        let (reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new(reader);

        tokio::spawn(async move {
            let writer = writer.into_sync();

            let result = match archive_format {
                StreamableArchiveFormat::Zip => {
                    crate::server::filesystem::archive::create::create_zip_streaming(
                        filesystem,
                        writer,
                        Path::new(""),
                        names,
                        ArchiveProgress::default(),
                        ignore.into(),
                        crate::server::filesystem::archive::create::CreateZipOptions {
                            compression_level,
                            threads,
                        },
                    )
                    .await
                    .map(|inner| inner.into_inner())
                }
                f if f.is_itaf() => crate::server::filesystem::archive::create::create_itaf(
                    filesystem,
                    writer,
                    Path::new(""),
                    names,
                    ArchiveProgress::default(),
                    ignore.into(),
                    crate::server::filesystem::archive::create::CreateItafOptions {
                        compression_type: f.compression_format(),
                        compression_level,
                        threads,
                        crc_enabled: true,
                    },
                )
                .await
                .map(|inner| inner.into_inner()),
                f => crate::server::filesystem::archive::create::create_tar(
                    filesystem,
                    writer,
                    Path::new(""),
                    names,
                    ArchiveProgress::default(),
                    ignore.into(),
                    crate::server::filesystem::archive::create::CreateTarOptions {
                        compression_type: f.compression_format(),
                        compression_level,
                        threads,
                    },
                )
                .await
                .map(|inner| inner.into_inner()),
            };

            match result {
                Ok(mut inner) => {
                    inner.shutdown().await.ok();
                    signal.succeed();
                }
                Err(err) => {
                    tracing::error!("failed to create archive from {what}: {err}");
                    signal.fail(err);
                }
            }
        });

        Ok(reader)
    }

    pub(super) async fn restore(
        &self,
        server: &crate::server::Server,
        progress: ArchiveProgress,
        total: Arc<AtomicU64>,
        threads: usize,
    ) -> Result<(), anyhow::Error> {
        let (filesystem, ignore) = self.open().await?;

        let total_task = {
            let filesystem = filesystem.clone();
            let ignore = ignore.clone();

            async move {
                tokio::task::spawn_blocking(move || {
                    let mut walker = filesystem
                        .walk_dir(Path::new(""))?
                        .with_is_ignored(ignore.into());
                    while let Some(Ok(entry)) = walker.next_entry() {
                        let metadata = match entry.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => continue,
                        };

                        total.fetch_add(metadata.len(), Ordering::Relaxed);
                    }

                    Ok::<(), anyhow::Error>(())
                })
                .await?
            }
        };

        let server = server.clone();
        let restore_task = async move {
            let directory_entries = Arc::new(parking_lot::Mutex::new(Vec::new()));

            filesystem
                .async_walk_dir(Path::new(""))
                .await?
                .with_is_ignored(ignore.into())
                .with_inline_dirs()
                .run_multithreaded(
                    threads,
                    Arc::new({
                        let server = server.clone();
                        let filesystem = filesystem.clone();
                        let progress = progress.clone();
                        let directory_entries = Arc::clone(&directory_entries);

                        move |entry: WalkEntry| {
                            let server = server.clone();
                            let filesystem = filesystem.clone();
                            let progress = progress.clone();
                            let directory_entries = Arc::clone(&directory_entries);

                            async move {
                                let metadata = match entry.async_metadata().await {
                                    Ok(metadata) => metadata,
                                    Err(_) => return Ok(()),
                                };
                                let path = entry.path;

                                if metadata.is_file() {
                                    super::log_restoring(&server, &path);

                                    let permissions = Some(crate::utils::PortablePermissions::from_mode_file(
                                        crate::utils::PortablePermissions::from(metadata.permissions()).mode(),
                                    ));
                                    let modified_time = metadata.modified().ok().map(|modified_time| modified_time.into_std());
                                    let bytes = progress.clone_bytes();

                                    super::create_with_parent(&server, &path, || {
                                        filesystem.async_quota_copy(
                                            &path,
                                            &path,
                                            &server,
                                            permissions,
                                            modified_time,
                                            bytes.as_ref(),
                                        )
                                    })
                                    .await?;
                                    progress.increment_files();
                                } else if metadata.is_dir() {
                                    server
                                        .filesystem
                                        .async_create_chowned_dir_all(&path, Some(metadata.permissions().into()))
                                        .await?;
                                    if let Ok(modified_time) = metadata.modified() {
                                        let mut directory_entries = directory_entries.lock();
                                        if directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES {
                                            directory_entries.push((path, modified_time.into_std()));
                                        }
                                    }
                                } else if metadata.is_symlink() && let Ok(target) = filesystem.async_read_link(&path).await {
                                    let modified_time = metadata.modified().ok().map(|modified_time| modified_time.into_std());
                                    if let Err(err) = super::create_with_parent(&server, &path, || {
                                        server.filesystem.async_symlink_with_modified(&target, &path, modified_time)
                                    })
                                    .await
                                    {
                                        tracing::debug!(path = %path.display(), "failed to create symlink from backup: {:?}", err);
                                    } else {
                                        progress.increment_files();
                                    }
                                }

                                Ok(())
                            }
                        }
                    }),
                ).await?;

            let directory_entries = std::mem::take(&mut *directory_entries.lock());
            tokio::task::spawn_blocking(move || {
                for (path, modified_time) in directory_entries {
                    server.filesystem.set_times(&path, modified_time, None)?;
                }

                Ok::<(), std::io::Error>(())
            })
            .await??;

            Ok::<(), anyhow::Error>(())
        };

        tokio::try_join!(total_task, restore_task)?;

        Ok(())
    }

    pub(super) async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        let (filesystem, ignore) = self.open().await?;

        Ok(Arc::new(
            filesystem
                .get_virtual(server.clone())
                .with_is_ignored(ignore.into()),
        ))
    }
}

async fn read_ignore(path: &Path) -> Result<IgnoreList, anyhow::Error> {
    let ignore_content = tokio::fs::read_to_string(path).await.unwrap_or_default();

    Ok(IgnoreList::from_lines(ignore_content.lines())?)
}
