use crate::{
    io::{
        SafeDigestExt,
        compression::{CompressionLevel, writer::CompressionWriter},
        fixed_reader::FixedReader,
    },
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::StreamableArchiveFormat,
            cap::FileType,
            virtualfs::{
                ByteRange, VirtualReadableFilesystem, archive::ddup_bak::VirtualDdupBakArchive,
            },
        },
    },
    utils::PortablePermissions,
};
use chrono::{Datelike, Timelike};
use ddup_bak::archive::entries::Entry;
use ignore::{WalkBuilder, overrides::OverrideBuilder};
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use sha1::Digest;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{io::AsyncReadExt, sync::RwLock};

static REPOSITORY: RwLock<Option<Arc<ddup_bak::repository::Repository>>> = RwLock::const_new(None);

pub async fn get_repository(
    config: &crate::config::Config,
) -> Result<Arc<ddup_bak::repository::Repository>, anyhow::Error> {
    if let Some(repository) = REPOSITORY.read().await.as_ref() {
        return Ok(Arc::clone(repository));
    }

    let path = config.resolve_as_path(|cfg| &cfg.system.backup_directory);
    if tokio::fs::metadata(path.join(".ddup-bak")).await.is_ok() {
        let repository = Arc::new(
            tokio::task::spawn_blocking(move || {
                ddup_bak::repository::Repository::open_or_rebuild(
                    &path,
                    1024 * 1024,
                    0,
                    None,
                    None,
                    None,
                )
            })
            .await??,
        );
        *REPOSITORY.write().await = Some(Arc::clone(&repository));

        Ok(repository)
    } else {
        let repository = Arc::new(
            tokio::task::spawn_blocking(move || {
                ddup_bak::repository::Repository::new(&path, 1024 * 1024, 0, None)
            })
            .await??,
        );
        repository.save()?;
        *REPOSITORY.write().await = Some(Arc::clone(&repository));

        Ok(repository)
    }
}

fn calculate_entry_size(total_size: &mut u64, total_files: &mut u64, entry: &Entry) {
    let mut stack = vec![entry];

    while let Some(entry) = stack.pop() {
        match entry {
            Entry::File(file) => {
                *total_size += file.size_real;
                *total_files += 1;
            }
            Entry::Directory(directory) => stack.extend(directory.entries.iter()),
            Entry::Symlink(_) => {
                *total_files += 1;
            }
        }
    }
}

pub struct DdupBakBackup {
    uuid: uuid::Uuid,
    archive: Arc<ddup_bak::archive::Archive>,
}

impl DdupBakBackup {
    fn tar_convert_entries(
        entry: &Entry,
        repository: &ddup_bak::repository::Repository,
        archive: &mut tar::Builder<impl Write + 'static>,
        parent_path: &Path,
    ) -> Result<(), anyhow::Error> {
        let mut stack: Vec<(PathBuf, &Entry)> = vec![(parent_path.to_path_buf(), entry)];

        while let Some((parent_path, entry)) = stack.pop() {
            let mut entry_header = tar::Header::new_gnu();
            entry_header.set_size(0);
            entry_header.set_mode(entry.mode().bits());
            entry_header.set_mtime(
                entry
                    .mtime()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            );

            let path = parent_path.join(entry.name());

            match entry {
                Entry::Directory(dir) => {
                    entry_header.set_entry_type(tar::EntryType::Directory);

                    archive.append_data(&mut entry_header, &path, std::io::empty())?;

                    for child in dir.entries.iter().rev() {
                        stack.push((path.clone(), child));
                    }
                }
                Entry::File(file) => {
                    entry_header.set_entry_type(tar::EntryType::Regular);
                    entry_header.set_size(file.size_real);

                    let reader = FixedReader::new_with_fixed_bytes(
                        Box::new(repository.entry_reader(Entry::File(file.clone()))?),
                        file.size_real as usize,
                    );

                    archive.append_data(&mut entry_header, &path, reader)?;
                }
                Entry::Symlink(link) => {
                    entry_header.set_entry_type(tar::EntryType::Symlink);

                    archive.append_link(&mut entry_header, &path, &link.target)?;
                }
            }
        }

        Ok(())
    }

    fn zip_convert_entries(
        entry: &Entry,
        repository: &ddup_bak::repository::Repository,
        zip: &mut zip::ZipWriter<
            zip::write::StreamWriter<
                tokio_util::io::SyncIoBridge<tokio::io::WriteHalf<tokio::io::SimplexStream>>,
            >,
        >,
        compression_level: CompressionLevel,
        parent_path: &Path,
    ) -> Result<(), anyhow::Error> {
        let mut stack: Vec<(PathBuf, &Entry)> = vec![(parent_path.to_path_buf(), entry)];

        while let Some((parent_path, entry)) = stack.pop() {
            let size = match entry {
                Entry::File(file) => file.size,
                _ => 0,
            };

            let mut options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_level(Some(compression_level.to_deflate_level() as i64))
                .unix_permissions(entry.mode().bits())
                .large_file(size >= u32::MAX as u64);
            {
                let mtime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(entry.mtime());

                options = options.last_modified_time(
                    zip::DateTime::from_date_and_time(
                        mtime.year() as u16,
                        mtime.month() as u8,
                        mtime.day() as u8,
                        mtime.hour() as u8,
                        mtime.minute() as u8,
                        mtime.second() as u8,
                    )
                    .unwrap_or_default(),
                );
            }

            let path = parent_path.join(entry.name());

            match entry {
                Entry::Directory(dir) => {
                    zip.add_directory(path.to_string_lossy(), options)?;

                    for child in dir.entries.iter().rev() {
                        stack.push((path.clone(), child));
                    }
                }
                Entry::File(file) => {
                    let mut reader = FixedReader::new_with_fixed_bytes(
                        Box::new(repository.entry_reader(Entry::File(file.clone()))?),
                        file.size_real as usize,
                    );

                    zip.start_file(path.to_string_lossy(), options)?;
                    crate::io::copy(&mut reader, zip)?;
                }
                Entry::Symlink(link) => {
                    zip.add_symlink(&link.name, &link.target, options)?;
                }
            }
        }

        Ok(())
    }

    fn itaf_convert_entries<W: std::io::Write>(
        entry: &Entry,
        repository: &ddup_bak::repository::Repository,
        itaf_enc: &mut ItafEncoder<W>,
        parent_path: &Path,
    ) -> Result<(), anyhow::Error> {
        enum Work<'a> {
            Visit {
                parent_path: PathBuf,
                entry: &'a Entry,
            },
            ExitDir,
        }

        let mut stack: Vec<Work> = vec![Work::Visit {
            parent_path: parent_path.to_path_buf(),
            entry,
        }];

        while let Some(work) = stack.pop() {
            let (parent_path, entry) = match work {
                Work::ExitDir => {
                    itaf_enc.exit_dir()?;
                    continue;
                }
                Work::Visit { parent_path, entry } => (parent_path, entry),
            };

            let path = parent_path.join(entry.name());

            let mtime = entry
                .mtime()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let meta = Metadata {
                uid: 0,
                gid: 0,
                mode: entry.mode().bits(),
                modified: std::time::UNIX_EPOCH + mtime,
            };
            let name: compact_str::CompactString = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into();

            match entry {
                Entry::Directory(dir) => {
                    if itaf::spec::validate_name(&name).is_ok() {
                        itaf_enc.enter_dir(&name, &meta)?;
                        stack.push(Work::ExitDir);
                        for child in dir.entries.iter().rev() {
                            stack.push(Work::Visit {
                                parent_path: path.clone(),
                                entry: child,
                            });
                        }
                    }
                }
                Entry::File(file) => {
                    if itaf::spec::validate_name(&name).is_ok() {
                        let mut reader = FixedReader::new_with_fixed_bytes(
                            Box::new(repository.entry_reader(Entry::File(file.clone()))?),
                            file.size_real as usize,
                        );
                        itaf_enc.add_file(&name, &meta, file.size_real, &mut reader)?;
                    }
                }
                Entry::Symlink(link) => {
                    if itaf::spec::validate_name(&name).is_ok() {
                        itaf_enc.add_symlink(&name, &link.target, false, &meta)?;
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl BackupFindExt for DdupBakBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        let repository = get_repository(&state.config).await?;
        let path = repository.archive_path(&uuid.to_string());

        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        let repository = get_repository(&state.config).await?;

        if let Ok(archive) =
            tokio::task::spawn_blocking(move || repository.get_archive(&uuid.to_string())).await?
        {
            Ok(Some(Backup::DdupBak(DdupBakBackup {
                uuid,
                archive: Arc::new(archive),
            })))
        } else {
            Ok(None)
        }
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for DdupBakBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let repository = get_repository(&server.app_state.config).await?;
        let path = repository.archive_path(&uuid.to_string());

        let total_task = {
            let filesystem = server.filesystem.clone();
            let total = Arc::clone(&total);
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

                    Ok::<_, anyhow::Error>(())
                })
                .await?
            }
        };

        let server = server.clone();
        let archive_task =
            tokio::task::spawn_blocking(move || -> Result<(u64, u64), anyhow::Error> {
                let mut override_builder = OverrideBuilder::new(&server.filesystem.base_path);

                for line in ignore_raw.lines() {
                    if let Some(line) = line.trim().strip_prefix('!') {
                        override_builder.add(line).ok();
                    } else {
                        override_builder.add(&format!("!{}", line.trim())).ok();
                    }
                }

                let archive = repository.create_archive(
                    &uuid.to_string(),
                    Some(
                        WalkBuilder::new(&server.filesystem.base_path)
                            .overrides(override_builder.build()?)
                            .ignore(false)
                            .git_ignore(false)
                            .follow_links(false)
                            .git_global(false)
                            .hidden(false)
                            .build(),
                    ),
                    Some(&server.filesystem.base_path),
                    None,
                    Some({
                        let compression_format = server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .ddup_bak
                            .compression_format;

                        Arc::new(move |_, metadata| {
                            progress.increment_bytes(metadata.len());
                            progress.increment_files();

                            match compression_format {
                                crate::config::SystemBackupsDdupBakCompressionFormat::None => {
                                    ddup_bak::archive::CompressionFormat::None
                                }
                                crate::config::SystemBackupsDdupBakCompressionFormat::Deflate => {
                                    ddup_bak::archive::CompressionFormat::Deflate
                                }
                                crate::config::SystemBackupsDdupBakCompressionFormat::Gzip => {
                                    ddup_bak::archive::CompressionFormat::Gzip
                                }
                                crate::config::SystemBackupsDdupBakCompressionFormat::Brotli => {
                                    ddup_bak::archive::CompressionFormat::Brotli
                                }
                            }
                        })
                    }),
                    server
                        .app_state
                        .config
                        .load()
                        .system
                        .backups
                        .ddup_bak
                        .create_threads,
                )?;

                repository.save()?;

                let mut total_size = 0;
                let mut total_files = 0;

                for entry in archive.entries.into_iter() {
                    calculate_entry_size(&mut total_size, &mut total_files, &entry);
                }

                Ok((total_size, total_files))
            });

        let (total_size, total_files) = match tokio::join!(total_task, archive_task) {
            (Ok(()), Ok(Ok(size))) => size,
            (Err(err), _) => return Err(err),
            (_, Err(err)) => return Err(err.into()),
            (_, Ok(Err(err))) => return Err(err),
        };

        let mut sha1 = sha1::Sha1::new();
        let mut file = tokio::fs::File::open(path).await?;

        let mut buffer = vec![0; crate::BUFFER_SIZE];
        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            sha1.safe_update(&buffer, bytes_read)?;
        }

        Ok(RawServerBackup {
            checksum: format!(
                "{}-{}",
                file.metadata().await?.len(),
                hex::encode(sha1.finalize())
            ),
            checksum_type: "ddup-sha1".into(),
            size: total_size,
            files: total_files,
            successful: true,
            browsable: true,
            streaming: true,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for DdupBakBackup {
    #[inline]
    fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    async fn download(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        _range: Option<ByteRange>,
    ) -> Result<ApiResponse, anyhow::Error> {
        let repository = get_repository(&state.config).await?;

        let archive = self.archive.clone();
        let compression_level = state.config.load().system.backups.compression_level;
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = tokio_util::io::SyncIoBridge::new(writer);
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    for entry in archive.entries.iter() {
                        DdupBakBackup::zip_convert_entries(
                            entry,
                            &repository,
                            &mut zip,
                            compression_level,
                            Path::new(""),
                        )?;
                    }

                    let mut inner = zip.finish()?.into_inner();
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            f if f.is_tar() => {
                let writer = CompressionWriter::new(
                    tokio_util::io::SyncIoBridge::new(writer),
                    f.compression_format(),
                    compression_level,
                    state.config.load().api.file_compression_threads,
                )?;

                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let mut tar = tar::Builder::new(writer);
                    tar.mode(tar::HeaderMode::Complete);

                    for entry in archive.entries.iter() {
                        DdupBakBackup::tar_convert_entries(
                            entry,
                            &repository,
                            &mut tar,
                            Path::new(""),
                        )?;
                    }

                    tar.finish()?;
                    let mut inner = tar.into_inner()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            f if f.is_itaf() => {
                let writer = CompressionWriter::new(
                    tokio_util::io::SyncIoBridge::new(writer),
                    f.compression_format(),
                    compression_level,
                    state.config.load().api.file_compression_threads,
                )?;

                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let mut itaf_enc = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;

                    for entry in archive.entries.iter() {
                        DdupBakBackup::itaf_convert_entries(
                            entry,
                            &repository,
                            &mut itaf_enc,
                            Path::new(""),
                        )?;
                    }

                    let mut inner = itaf_enc.finish()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            _ => {
                tracing::error!(
                    "unsupported archive format for ddup_bak backup download: {}",
                    archive_format.extension()
                );
            }
        }

        Ok(ApiResponse::new_stream(reader)
            .with_header(
                "Content-Disposition",
                &format!(
                    "attachment; filename={}.{}",
                    self.uuid,
                    archive_format.extension()
                ),
            )
            .with_header("Content-Type", archive_format.mime_type()))
    }

    async fn restore(
        &self,
        server: &crate::server::Server,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let repository = get_repository(&server.app_state.config).await?;

        let archive = self.archive.clone();

        let server = server.clone();
        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut total_size = 0;

            for entry in archive.entries.iter() {
                calculate_entry_size(&mut total_size, &mut 0, entry);
            }

            total.store(total_size, Ordering::SeqCst);

            fn restore_entry(
                repository: &Arc<ddup_bak::repository::Repository>,
                entry: &Entry,
                path: &Path,
                server: &crate::server::Server,
                progress: &crate::server::filesystem::archive::create::ArchiveProgress,
            ) -> Result<(), anyhow::Error> {
                enum Work<'a> {
                    Visit {
                        parent: PathBuf,
                        entry: &'a Entry,
                    },
                    FinishDir {
                        path: PathBuf,
                        mtime: std::time::SystemTime,
                    },
                }

                let mut stack = vec![Work::Visit {
                    parent: path.to_path_buf(),
                    entry,
                }];

                while let Some(work) = stack.pop() {
                    let (parent, entry) = match work {
                        Work::FinishDir { path, mtime } => {
                            server.filesystem.set_times(&path, mtime, None)?;
                            continue;
                        }
                        Work::Visit { parent, entry } => (parent, entry),
                    };

                    let path = parent.join(entry.name());

                    if server
                        .filesystem
                        .is_ignored(&path, FileType::from_is_dir(entry.is_directory()))
                    {
                        continue;
                    }

                    match entry {
                        Entry::File(file) => {
                            server.log_daemon(compact_str::format_compact!("(restoring): {}", path.display()));

                            if let Some(parent) = path.parent() {
                                server.filesystem.create_chowned_dir_all(parent)?;
                            }

                            let mut writer = crate::server::filesystem::file::ServerFile::new(
                                server.clone(),
                                &path,
                                Some(PortablePermissions::from_mode_file(file.mode.bits())),
                                Some(file.mtime),
                            )?;
                            let reader = repository.entry_reader(Entry::File(file.clone()))?;
                            let mut reader = progress.counting_reader(reader);

                            crate::io::copy(&mut reader, &mut writer)?;
                            writer.flush()?;

                            progress.increment_files();
                        }
                        Entry::Directory(directory) => {
                            server.filesystem.create_chowned_dir_all(&path)?;
                            server.filesystem.set_permissions(
                                &path,
                                PortablePermissions::from_mode_dir(directory.mode.bits()),
                            )?;

                            stack.push(Work::FinishDir {
                                path: path.clone(),
                                mtime: directory.mtime,
                            });

                            for child in directory.entries.iter().rev() {
                                stack.push(Work::Visit {
                                    parent: path.clone(),
                                    entry: child,
                                });
                            }
                        }
                        Entry::Symlink(symlink) => {
                            if let Err(err) = server.filesystem.symlink(&symlink.target, &path) {
                                tracing::debug!(path = %path.display(), "failed to create symlink from backup: {:?}", err);
                            } else {
                                progress.increment_files();

                                server.filesystem.set_times(&path, symlink.mtime, None)?;
                            }
                        }
                    }
                }

                Ok(())
            }

            for entry in archive.entries() {
                restore_entry(
                    &repository,
                    entry,
                    Path::new("."),
                    &server,
                    &progress,
                )?;
            }

            Ok(())
        })
        .await??;

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        let repository = get_repository(&state.config).await?;

        let uuid = self.uuid;
        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            repository.delete_archive(&uuid.to_string(), None)?;
            repository.save()?;

            Ok(())
        })
        .await??;

        state
            .backup_manager
            .invalidate_cached_browse(self.uuid)
            .await;

        Ok(())
    }

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        let repository = get_repository(&server.app_state.config).await?;
        let path = repository.archive_path(&self.uuid.to_string());

        let metadata = tokio::fs::metadata(&path).await?;

        Ok(Arc::new(VirtualDdupBakArchive::new(
            server.clone(),
            self.archive.clone(),
            metadata
                .created()
                .map_or_else(|_| Default::default(), |dt| dt.into()),
            Some(get_repository(&server.app_state.config).await?),
        )))
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for DdupBakBackup {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let repository = get_repository(&server.app_state.config).await?;

        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            repository.delete_archive(&uuid.to_string(), None)?;
            repository.save()?;

            Ok(())
        })
        .await??;

        Ok(())
    }
}
