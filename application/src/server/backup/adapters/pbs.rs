use crate::{
    io::{
        SafeSliceExt,
        compression::{CompressionLevel, writer::CompressionWriter},
        counting_reader::CountingReader,
        fixed_reader::FixedReader,
        limited_reader::LimitedReader,
        limited_writer::LimitedWriter,
    },
    models::{DirectoryEntry, DirectorySortingMode},
    remote::backups::{PbsBackupConfiguration, RawServerBackup},
    response::ApiResponse,
    routes::MimeCacheValue,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::{StreamableArchiveFormat, create::CreatePxarOptions},
            cap::FileType,
            file::ServerFile,
            virtualfs::{
                AsyncFileRead, AsyncReadableFileStream, ByteRange, DirectoryListing,
                DirectoryStreamWalk, DirectoryWalk, FileMetadata, FileRead, IsIgnoredFn,
                VirtualReadableFilesystem,
            },
        },
    },
    utils::{CmpExt, PortablePermissions, detect_mime_type},
};
use chrono::{Datelike, Timelike};
use compact_str::{CompactString, ToCompactString};
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata as ItafMetadata};
use pbs_client::{
    accessor::{ArchiveEntry, ArchiveEntryKind, PbsArchive},
    config::PbsConfig,
    manifest::{BackupManifest, MANIFEST_BLOB_NAME},
    naming,
    pxar::{EntryKind, decoder::Decoder},
    reader::PbsBackupReader,
    rest::PbsClient,
    writer::{ARCHIVE_NAME, META_BLOB_NAME, PbsBackupWriter},
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncWriteExt;
use tokio_util::io::SyncIoBridge;

pub struct PbsBackup {
    uuid: uuid::Uuid,
    config: PbsConfig,
    backup_id: CompactString,
    backup_time: i64,
}

fn build_config(remote: PbsBackupConfiguration) -> PbsConfig {
    PbsConfig {
        url: remote.url.into(),
        datastore: remote.datastore.into(),
        namespace: remote.namespace.map(Into::into),
        token_id: remote.token_id.into(),
        token_secret: remote.token_secret.into(),
        fingerprint: remote.fingerprint.into(),
        backup_id_prefix: remote.backup_id_prefix.map(Into::into),
    }
}

#[async_trait::async_trait]
impl BackupFindExt for PbsBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        match state.config.client.backup_pbs_configuration(uuid).await {
            Ok(remote) => Ok(remote.server_uuid.is_some()),
            Err(_) => Ok(false),
        }
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        let remote = match state.config.client.backup_pbs_configuration(uuid).await {
            Ok(remote) => remote,
            Err(_) => return Ok(None),
        };

        let Some(server_uuid) = remote.server_uuid else {
            return Ok(None);
        };
        let backup_time = remote.backup_created.timestamp();

        let config = build_config(remote);
        let backup_id = naming::backup_id(config.id_prefix(), server_uuid);

        Ok(Some(Backup::ProxmoxBackupServer(PbsBackup {
            uuid,
            config,
            backup_id,
            backup_time,
        })))
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for PbsBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        _ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let remote = server
            .app_state
            .config
            .client
            .backup_pbs_configuration(uuid)
            .await?;
        let backup_time = remote.backup_created.timestamp();
        let config = build_config(remote);
        config.validate().map_err(|err| anyhow::anyhow!("{err}"))?;

        let backup_id = naming::backup_id(config.id_prefix(), server.uuid);

        let (archive_reader, archive_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let total_task = {
            let total = Arc::clone(&total);
            let server = server.clone();
            let ignore = ignore.clone();

            async move {
                let mut walker = server
                    .filesystem
                    .async_walk_dir(Path::new(""))
                    .await?
                    .with_is_ignored(ignore.into());
                let mut total_files = 0u64;
                while let Some(Ok((_, path))) = walker.next_entry().await {
                    let metadata = match server.filesystem.async_symlink_metadata(&path).await {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };
                    total.fetch_add(metadata.len(), Ordering::Relaxed);
                    if !metadata.is_dir() {
                        total_files += 1;
                    }
                }
                Ok::<_, anyhow::Error>(total_files)
            }
        };

        let (catalog_tx, catalog_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        let archive_task = {
            let server = server.clone();
            let ignore = ignore.clone();
            let progress = Arc::clone(&progress);

            async move {
                let sources = server.filesystem.async_read_dir_all(Path::new("")).await?;
                let writer = LimitedWriter::new_with_bytes_per_second(
                    SyncIoBridge::new(archive_writer),
                    server
                        .app_state
                        .config
                        .load()
                        .system
                        .backups
                        .write_limit
                        .as_bytes(),
                );

                let (writer, catalog) = crate::server::filesystem::archive::create::create_pxar(
                    server.filesystem.clone(),
                    writer,
                    Path::new(""),
                    sources,
                    Some(progress),
                    ignore.into(),
                    CreatePxarOptions {
                        catalog_archive_name: pbs_client::writer::ARCHIVE_PXAR_NAME.to_string(),
                    },
                )
                .await?;

                writer.into_inner().into_inner().shutdown().await?;

                let _ = catalog_tx.send(catalog);

                Ok::<_, anyhow::Error>(())
            }
        };

        let pbs_task = {
            let config = config.clone();
            let backup_id = backup_id.clone();
            let server_uuid = server.uuid;

            async move {
                let reader = SyncIoBridge::new(archive_reader);
                let mut writer = PbsBackupWriter::connect(&config, &backup_id, backup_time).await?;

                let known_chunks = match writer.previous_archive_digests(ARCHIVE_NAME).await {
                    Ok(digests) => digests,
                    Err(err) => {
                        tracing::debug!(
                            "no reusable chunks from previous PBS snapshot, uploading full archive: {:?}",
                            err
                        );
                        Default::default()
                    }
                };

                let archive = writer.upload_archive(reader, known_chunks).await?;

                let catalog = catalog_rx
                    .await
                    .map_err(|_| anyhow::anyhow!("catalog was not produced"))?;
                let catalog_file = writer
                    .upload_archive_named(
                        pbs_client::catalog::CATALOG_NAME,
                        std::io::Cursor::new(catalog),
                        Default::default(),
                    )
                    .await?;

                let metadata = serde_json::json!({
                    "backup_uuid": uuid,
                    "server_uuid": server_uuid,
                    "backup_id": backup_id,
                    "backup_time": backup_time,
                    "archive": ARCHIVE_NAME,
                    "catalog": pbs_client::catalog::CATALOG_NAME,
                    "wings_version": env!("CARGO_PKG_VERSION"),
                });
                let meta_file = writer
                    .upload_blob(META_BLOB_NAME, &serde_json::to_vec(&metadata)?)
                    .await?;

                let mut manifest =
                    BackupManifest::new(naming::BACKUP_TYPE, backup_id.as_str(), backup_time);
                let checksum = archive.file.csum.clone();
                manifest.add_file(archive.file);
                manifest.add_file(catalog_file.file);
                manifest.add_file(meta_file);
                writer.finish(&manifest).await?;

                Ok::<_, anyhow::Error>((archive.size, checksum))
            }
        };

        let (total_files, _, (size, checksum)) =
            tokio::try_join!(total_task, archive_task, pbs_task)?;

        Ok(RawServerBackup {
            checksum,
            checksum_type: "sha256".into(),
            size,
            files: total_files,
            successful: true,
            browsable: true,
            streaming: true,
            parts: vec![],
        })
    }
}

fn relative_archive_path(path: &Path) -> Option<PathBuf> {
    match path.strip_prefix("/") {
        Ok(relative) if !relative.as_os_str().is_empty() => Some(relative.to_path_buf()),
        _ => None,
    }
}

#[async_trait::async_trait]
impl BackupExt for PbsBackup {
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
        let session =
            PbsBackupReader::connect(&self.config, &self.backup_id, self.backup_time).await?;

        let (pxar_reader, pxar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        tokio::spawn(async move {
            let mut pxar_writer = pxar_writer;
            if let Err(err) = session.reassemble_archive(&mut pxar_writer, None).await {
                tracing::error!("failed to reassemble PBS archive for download: {:?}", err);
            }
            let _ = pxar_writer.shutdown().await;
        });

        let compression_level = state.config.load().system.backups.compression_level;
        let threads = state.config.load().api.file_compression_threads;

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let mut zip = zip::ZipWriter::new_stream(SyncIoBridge::new(writer));
                    let mut decoder = Decoder::from_std(SyncIoBridge::new(pxar_reader))?;
                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];

                    while let Some(entry) = decoder.next() {
                        let entry = entry?;
                        let Some(path) = relative_archive_path(entry.path()) else {
                            continue;
                        };
                        let stat = entry.metadata().stat;

                        let mut options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .unix_permissions((stat.mode & 0o7777) as u32)
                                .large_file(true);
                        if let Some(mtime) = chrono::DateTime::from_timestamp(stat.mtime.secs, 0)
                            && let Ok(mtime) = zip::DateTime::from_date_and_time(
                                mtime.year() as u16,
                                mtime.month() as u8,
                                mtime.day() as u8,
                                mtime.hour() as u8,
                                mtime.minute() as u8,
                                mtime.second() as u8,
                            )
                        {
                            options = options.last_modified_time(mtime);
                        }

                        match entry.kind() {
                            EntryKind::Directory => {
                                zip.add_directory(path.to_string_lossy(), options)?;
                            }
                            EntryKind::File { .. } => {
                                zip.start_file(path.to_string_lossy(), options)?;
                                if let Some(mut contents) = decoder.contents()? {
                                    crate::io::copy_shared(
                                        &mut read_buffer,
                                        &mut contents,
                                        &mut zip,
                                    )?;
                                }
                            }
                            EntryKind::Symlink(target) => {
                                zip.add_symlink(
                                    path.to_string_lossy(),
                                    target.as_os_str().to_string_lossy(),
                                    options,
                                )?;
                            }
                        }
                    }

                    let mut inner = zip.finish()?.into_inner();
                    inner.flush()?;
                    inner.shutdown()?;
                    Ok(())
                });
            }
            f if f.is_tar() => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        threads,
                    )?;
                    let mut tar = tar::Builder::new(writer);
                    let mut decoder = Decoder::from_std(SyncIoBridge::new(pxar_reader))?;

                    while let Some(entry) = decoder.next() {
                        let entry = entry?;
                        let Some(path) = relative_archive_path(entry.path()) else {
                            continue;
                        };
                        let stat = entry.metadata().stat;

                        let mut header = tar::Header::new_gnu();
                        header.set_mode((stat.mode & 0o7777) as u32);
                        header.set_mtime(stat.mtime.secs.max(0) as u64);
                        header.set_uid(0);
                        header.set_gid(0);

                        match entry.kind() {
                            EntryKind::Directory => {
                                header.set_entry_type(tar::EntryType::Directory);
                                header.set_size(0);
                                tar.append_data(
                                    &mut header,
                                    format!("{}/", path.display()),
                                    std::io::empty(),
                                )?;
                            }
                            EntryKind::File { size, .. } => {
                                header.set_entry_type(tar::EntryType::Regular);
                                header.set_size(*size);
                                match decoder.contents()? {
                                    Some(mut contents) => {
                                        tar.append_data(&mut header, &path, &mut contents)?
                                    }
                                    None => {
                                        tar.append_data(&mut header, &path, std::io::empty())?
                                    }
                                }
                            }
                            EntryKind::Symlink(target) => {
                                header.set_entry_type(tar::EntryType::Symlink);
                                header.set_size(0);
                                tar.append_link(&mut header, &path, target.as_os_str())?;
                            }
                        }
                    }

                    tar.finish()?;
                    let mut inner = tar.into_inner()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;
                    Ok(())
                });
            }
            f if f.is_itaf() => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        threads,
                    )?;
                    let mut encoder = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;
                    let mut decoder = Decoder::from_std(SyncIoBridge::new(pxar_reader))?;
                    let mut dir_stack: Vec<CompactString> = Vec::new();

                    while let Some(entry) = decoder.next() {
                        let entry = entry?;
                        let Some(path) = relative_archive_path(entry.path()) else {
                            continue;
                        };
                        let stat = entry.metadata().stat;

                        let components: Vec<_> = path
                            .components()
                            .filter_map(|c| match c {
                                std::path::Component::Normal(s) => Some(s.to_string_lossy()),
                                _ => None,
                            })
                            .collect();
                        let Some(name) = components.last().cloned() else {
                            continue;
                        };
                        let parent = components.get_slice(..components.len() - 1)?;

                        let meta = ItafMetadata {
                            uid: 0,
                            gid: 0,
                            mode: (stat.mode & 0o7777) as u32,
                            modified: std::time::UNIX_EPOCH
                                + std::time::Duration::from_secs(stat.mtime.secs.max(0) as u64),
                        };

                        let shared = dir_stack
                            .iter()
                            .zip(parent.iter())
                            .take_while(|(a, b)| a == b)
                            .count();
                        while dir_stack.len() > shared {
                            encoder.exit_dir()?;
                            dir_stack.pop();
                        }
                        for component in parent.get_slice(shared..)? {
                            encoder.enter_dir(
                                component,
                                &ItafMetadata {
                                    uid: 0,
                                    gid: 0,
                                    mode: 0o755,
                                    modified: std::time::SystemTime::now(),
                                },
                            )?;
                            dir_stack.push(component.to_compact_string());
                        }

                        match entry.kind() {
                            EntryKind::Directory => {
                                encoder.enter_dir(&name, &meta)?;
                                dir_stack.push(name.to_compact_string());
                            }
                            EntryKind::File { size, .. } => {
                                let size = *size;
                                match decoder.contents()? {
                                    Some(mut contents) => {
                                        encoder.add_file(&name, &meta, size, &mut contents)?
                                    }
                                    None => encoder.add_file(
                                        &name,
                                        &meta,
                                        size,
                                        &mut std::io::empty(),
                                    )?,
                                }
                            }
                            EntryKind::Symlink(target) => {
                                let target = target.as_os_str().to_string_lossy();
                                if itaf::spec::validate_name(&name).is_ok() {
                                    encoder.add_symlink(&name, &target, false, &meta)?;
                                }
                            }
                        }
                    }

                    while dir_stack.pop().is_some() {
                        encoder.exit_dir()?;
                    }

                    let mut inner = encoder.finish()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;
                    Ok(())
                });
            }
            _ => {
                tracing::error!(
                    "unsupported archive format for PBS backup download: {}",
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
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        _download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        let mut reader =
            PbsBackupReader::connect(&self.config, &self.backup_id, self.backup_time).await?;

        if let Ok(manifest_raw) = reader.download_file(MANIFEST_BLOB_NAME).await
            && let Ok(json) = pbs_client::datablob::decode_blob(&manifest_raw)
            && let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&json)
            && let Some(files) = manifest.get("files").and_then(|files| files.as_array())
        {
            for file in files {
                if file.get("filename").and_then(|name| name.as_str()) == Some(ARCHIVE_NAME)
                    && let Some(size) = file.get("size").and_then(|size| size.as_u64())
                {
                    total.store(size, Ordering::SeqCst);
                }
            }
        }

        let (pxar_reader, pxar_writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let fetch_task = {
            let progress = Arc::clone(&progress);
            async move {
                let mut pxar_writer = pxar_writer;
                reader
                    .reassemble_archive(&mut pxar_writer, Some(progress))
                    .await?;
                pxar_writer.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            }
        };

        let extract_task = {
            let server = server.clone();
            async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let reader = SyncIoBridge::new(pxar_reader);
                    let reader = LimitedReader::new_with_bytes_per_second(
                        reader,
                        server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .read_limit
                            .as_bytes(),
                    );
                    let reader =
                        std::io::BufReader::with_capacity(crate::TRANSFER_BUFFER_SIZE, reader);

                    let mut decoder = Decoder::from_std(reader)?;
                    let mut directory_entries = Vec::new();
                    let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];

                    while let Some(entry) = decoder.next() {
                        let entry = entry?;
                        let Some(path) = relative_archive_path(entry.path()) else {
                            continue;
                        };

                        let stat = entry.metadata().stat;
                        let mode = (stat.mode & 0o7777) as u32;
                        let mtime = std::time::UNIX_EPOCH
                            + std::time::Duration::from_secs(stat.mtime.secs.max(0) as u64);

                        match entry.kind() {
                            EntryKind::Directory => {
                                server.filesystem.create_chowned_dir_all(path.as_path())?;
                                server.filesystem.set_permissions(
                                    path.as_path(),
                                    PortablePermissions::from_mode(mode),
                                )?;
                                directory_entries.push((path, mtime));
                            }
                            EntryKind::File { .. } => {
                                server.log_daemon(compact_str::format_compact!(
                                    "(restoring): {}",
                                    path.display()
                                ));

                                if let Some(parent) = path.parent() {
                                    server.filesystem.create_chowned_dir_all(parent)?;
                                }

                                let mut writer = ServerFile::new(
                                    server.clone(),
                                    &path,
                                    Some(PortablePermissions::from_mode(mode)),
                                    Some(mtime),
                                )?;

                                if let Some(mut contents) = decoder.contents()? {
                                    crate::io::copy_shared(&mut read_buffer, &mut contents, &mut writer)?;
                                }
                                writer.flush()?;
                            }
                            EntryKind::Symlink(target) => {
                                if let Err(err) =
                                    server.filesystem.symlink(target.as_os_str(), path.as_path())
                                {
                                    tracing::debug!(path = %path.display(), "failed to create symlink from PBS backup: {:?}", err);
                                } else {
                                    server.filesystem.set_times(path.as_path(), mtime, None)?;
                                }
                            }
                        }
                    }

                    for (destination_path, modified_time) in directory_entries {
                        server
                            .filesystem
                            .set_times(&destination_path, modified_time, None)?;
                    }

                    Ok(())
                })
                .await?
            }
        };

        tokio::try_join!(fetch_task, extract_task)?;

        server.filesystem.rerun_disk_checker().await;

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        if !naming::is_calagopus_id(self.config.id_prefix(), &self.backup_id) {
            return Err(anyhow::anyhow!(
                "refusing to delete PBS snapshot with non-Calagopus backup-id '{}'",
                self.backup_id
            ));
        }

        state
            .backup_manager
            .invalidate_cached_browse(self.uuid)
            .await;

        let client = PbsClient::new(self.config.clone())?;
        client
            .delete_snapshot(naming::BACKUP_TYPE, &self.backup_id, self.backup_time)
            .await?;

        Ok(())
    }

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        let archive =
            Arc::new(PbsArchive::connect(&self.config, &self.backup_id, self.backup_time).await?);

        let catalog = archive.read_catalog().await?;
        let entries =
            tokio::task::spawn_blocking(move || pbs_client::catalog::parse_catalog(&catalog))
                .await??;

        Ok(Arc::new(PbsVirtualFilesystem {
            server: server.clone(),
            archive,
            tree: Arc::new(PbsTreeNode::build(entries)),
        }))
    }
}

struct PbsFileMeta {
    file_type: FileType,
    mode: u32,
    size: u64,
    mtime: chrono::DateTime<chrono::Utc>,
    symlink: Option<PathBuf>,
}

#[derive(Default)]
struct PbsTreeNode {
    size: u64,
    mtime: chrono::DateTime<chrono::Utc>,
    mode: u32,
    has_explicit_entry: bool,
    dirs: Vec<(CompactString, PbsTreeNode)>,
    files: Vec<(CompactString, PbsFileMeta)>,
}

impl PbsTreeNode {
    fn build(entries: Vec<ArchiveEntry>) -> Self {
        let mut root = PbsTreeNode::default();
        for entry in entries {
            root.insert(entry);
        }
        root.aggregate_sizes();
        root
    }

    fn insert(&mut self, entry: ArchiveEntry) {
        let components: Vec<&str> = entry
            .path
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        if components.is_empty() {
            return;
        }

        let mtime = chrono::DateTime::from_timestamp(entry.mtime, 0).unwrap_or_default();

        match entry.kind {
            ArchiveEntryKind::Directory => {
                let node = self.upsert_dir_path(&components);
                node.has_explicit_entry = true;
                node.mtime = mtime;
                node.mode = entry.mode;
            }
            ArchiveEntryKind::File | ArchiveEntryKind::Symlink => {
                let (leaf, parents) = match components.split_last() {
                    Some(value) => value,
                    None => return,
                };

                let parent = self.upsert_dir_path(parents);
                let meta = PbsFileMeta {
                    file_type: match entry.kind {
                        ArchiveEntryKind::Symlink => FileType::Symlink,
                        _ => FileType::File,
                    },
                    mode: entry.mode,
                    size: entry.size,
                    mtime,
                    symlink: entry.symlink,
                };

                match parent.files.binary_search_by(|(n, _)| n.as_str().cmp(leaf)) {
                    Ok(idx) => {
                        if let Some(slot) = parent.files.get_mut(idx) {
                            slot.1 = meta;
                        }
                    }
                    Err(idx) => parent.files.insert(idx, (leaf.to_compact_string(), meta)),
                }
            }
        }
    }

    fn upsert_dir_path(&mut self, components: &[&str]) -> &mut PbsTreeNode {
        let mut current = self;
        for name in components {
            let idx = match current.dirs.binary_search_by(|(n, _)| n.as_str().cmp(name)) {
                Ok(idx) => idx,
                Err(idx) => {
                    current
                        .dirs
                        .insert(idx, (name.to_compact_string(), PbsTreeNode::default()));
                    idx
                }
            };
            // SAFETY: `idx` is a valid index into `current.dirs` by construction above.
            current = unsafe { &mut current.dirs.get_unchecked_mut(idx).1 };
        }
        current
    }

    fn aggregate_sizes(&mut self) -> u64 {
        let mut total: u64 = self.files.iter().map(|(_, m)| m.size).sum();
        for (_, child) in self.dirs.iter_mut() {
            total = total.saturating_add(child.aggregate_sizes());
        }
        self.size = total;
        total
    }

    fn lookup_dir(&self, path: &Path) -> Option<&PbsTreeNode> {
        if path == Path::new("") || path == Path::new("/") {
            return Some(self);
        }
        let mut current = self;
        for component in path.components() {
            let name = component.as_os_str().to_str()?;
            let idx = current
                .dirs
                .binary_search_by(|(n, _)| n.as_str().cmp(name))
                .ok()?;
            current = &current.dirs.get(idx)?.1;
        }
        Some(current)
    }

    fn lookup_file(&self, path: &Path) -> Option<&PbsFileMeta> {
        let parent_path = path.parent()?;
        let leaf = path.file_name()?.to_str()?;
        let parent = self.lookup_dir(parent_path)?;
        let idx = parent
            .files
            .binary_search_by(|(n, _)| n.as_str().cmp(leaf))
            .ok()?;
        Some(&parent.files.get(idx)?.1)
    }
}

struct SubtreeEntry {
    relative: PathBuf,
    archive_path: PathBuf,
    file_type: FileType,
    mode: u32,
    mtime: chrono::DateTime<chrono::Utc>,
    size: u64,
    symlink: Option<PathBuf>,
}

struct PbsVirtualFilesystem {
    server: crate::server::Server,
    archive: Arc<PbsArchive>,
    tree: Arc<PbsTreeNode>,
}

fn mtime_to_system_time(mtime: chrono::DateTime<chrono::Utc>) -> std::time::SystemTime {
    mtime.into()
}

fn resolve_range(
    range: Option<ByteRange>,
    total: u64,
) -> (Option<(u64, u64)>, u64, Option<ByteRange>) {
    let Some(range) = range else {
        return (None, total, None);
    };

    let (start, len) = match (range.get_start(), range.get_end()) {
        (Some(start), Some(end)) => {
            let start = start.min(total);
            let end = end.saturating_add(1).min(total);
            (start, end.saturating_sub(start))
        }
        (Some(start), None) => {
            let start = start.min(total);
            (start, total.saturating_sub(start))
        }
        (None, Some(suffix)) => {
            let len = suffix.min(total);
            (total.saturating_sub(len), len)
        }
        (None, None) => (0, total),
    };

    (Some((start, len)), len, Some(range))
}

impl PbsVirtualFilesystem {
    fn directory_entry_from_dir_node(path: &Path, node: &PbsTreeNode) -> DirectoryEntry {
        let mode = if node.mode != 0 { node.mode } else { 0o755 };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: crate::server::filesystem::encode_mode(mode),
            mode_bits: compact_str::format_compact!("{:o}", mode & 0o777),
            size: node.size,
            size_physical: node.size,
            editable: false,
            inner_editable: false,
            directory: true,
            file: false,
            symlink: false,
            mime: MimeCacheValue::directory().mime,
            modified: node.mtime,
            created: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
        }
    }

    fn directory_entry_from_file_meta(
        path: &Path,
        meta: &PbsFileMeta,
        buffer: Option<&[u8]>,
    ) -> DirectoryEntry {
        let detected_mime = if meta.file_type.is_symlink() {
            MimeCacheValue::symlink()
        } else {
            detect_mime_type(path, buffer)
        };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: crate::server::filesystem::encode_mode(meta.mode),
            mode_bits: compact_str::format_compact!("{:o}", meta.mode & 0o777),
            size: meta.size,
            size_physical: meta.size,
            editable: meta.file_type.is_file() && detected_mime.valid_utf8,
            inner_editable: meta.file_type.is_file() && detected_mime.valid_inner_utf8,
            directory: false,
            file: meta.file_type.is_file(),
            symlink: meta.file_type.is_symlink(),
            mime: detected_mime.mime,
            modified: meta.mtime,
            created: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
        }
    }

    fn collect_subtree(
        node: &PbsTreeNode,
        archive_dir: &Path,
        relative_dir: &Path,
        is_ignored: &IsIgnoredFn,
        out: &mut Vec<SubtreeEntry>,
    ) {
        for (name, meta) in node.files.iter() {
            let archive_path = archive_dir.join(name.as_str());
            if (is_ignored)(meta.file_type, archive_path.clone()).is_none() {
                continue;
            }
            out.push(SubtreeEntry {
                relative: relative_dir.join(name.as_str()),
                archive_path,
                file_type: meta.file_type,
                mode: meta.mode,
                mtime: meta.mtime,
                size: meta.size,
                symlink: meta.symlink.clone(),
            });
        }

        for (name, child) in node.dirs.iter() {
            let archive_path = archive_dir.join(name.as_str());
            if (is_ignored)(FileType::Dir, archive_path.clone()).is_none() {
                continue;
            }
            let relative = relative_dir.join(name.as_str());
            let mode = if child.mode != 0 { child.mode } else { 0o755 };
            out.push(SubtreeEntry {
                relative: relative.clone(),
                archive_path: archive_path.clone(),
                file_type: FileType::Dir,
                mode,
                mtime: child.mtime,
                size: 0,
                symlink: None,
            });
            Self::collect_subtree(child, &archive_path, &relative, is_ignored, out);
        }
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for PbsVirtualFilesystem {
    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let path = path.as_ref();

        if path == Path::new("") || path == Path::new("/") {
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode(0o755),
                size: 0,
                modified: None,
                created: None,
            });
        }

        if let Some(node) = self.tree.lookup_dir(path) {
            let mode = if node.mode != 0 { node.mode } else { 0o755 };
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode(mode),
                size: node.size,
                modified: node
                    .has_explicit_entry
                    .then(|| mtime_to_system_time(node.mtime)),
                created: None,
            });
        }

        if let Some(meta) = self.tree.lookup_file(path) {
            return Ok(FileMetadata {
                file_type: meta.file_type,
                permissions: PortablePermissions::from_mode(meta.mode),
                size: meta.size,
                modified: Some(mtime_to_system_time(meta.mtime)),
                created: None,
            });
        }

        Err(anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        )))
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.metadata(path)
    }

    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.metadata(path)
    }
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        self.metadata(path)
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let path = path.as_ref();
        if let Some(node) = self.tree.lookup_dir(path) {
            return Ok(Self::directory_entry_from_dir_node(path, node));
        }
        if let Some(meta) = self.tree.lookup_file(path) {
            return Ok(Self::directory_entry_from_file_meta(path, meta, None));
        }
        Err(anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        )))
    }
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let path = path.as_ref();
        if let Some(node) = self.tree.lookup_dir(path) {
            return Ok(Self::directory_entry_from_dir_node(path, node));
        }
        if let Some(meta) = self.tree.lookup_file(path) {
            return Ok(Self::directory_entry_from_file_meta(
                path,
                meta,
                Some(buffer),
            ));
        }
        Err(anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        )))
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        use DirectorySortingMode::*;

        let path = path.as_ref().to_path_buf();
        let node = match self.tree.lookup_dir(&path) {
            Some(node) => node,
            None => {
                return Ok(DirectoryListing {
                    total_entries: 0,
                    entries: Vec::new(),
                });
            }
        };

        enum Child<'a> {
            Dir {
                path: PathBuf,
                node: &'a PbsTreeNode,
            },
            File {
                path: PathBuf,
                meta: &'a PbsFileMeta,
            },
        }

        let mut dir_children: Vec<Child<'_>> = Vec::new();
        let mut file_children: Vec<Child<'_>> = Vec::new();

        for (name, child_node) in node.dirs.iter() {
            let child_path = path.join(name.as_str());
            if (is_ignored)(FileType::Dir, child_path.clone()).is_none() {
                continue;
            }
            dir_children.push(Child::Dir {
                path: child_path,
                node: child_node,
            });
        }
        for (name, meta) in node.files.iter() {
            let child_path = path.join(name.as_str());
            if (is_ignored)(meta.file_type, child_path.clone()).is_none() {
                continue;
            }
            file_children.push(Child::File {
                path: child_path,
                meta,
            });
        }

        let cmp = |a: &Child<'_>, b: &Child<'_>| -> std::cmp::Ordering {
            let (a_path, a_size, a_mtime) = match a {
                Child::Dir { path, node } => (path, node.size, node.mtime),
                Child::File { path, meta } => (path, meta.size, meta.mtime),
            };
            let (b_path, b_size, b_mtime) = match b {
                Child::Dir { path, node } => (path, node.size, node.mtime),
                Child::File { path, meta } => (path, meta.size, meta.mtime),
            };

            match sort {
                NameAsc => a_path.cmp_ascii_case_insensitive(b_path),
                NameDesc => b_path.cmp_ascii_case_insensitive(a_path),
                SizeAsc | PhysicalSizeAsc => a_size.cmp(&b_size),
                SizeDesc | PhysicalSizeDesc => b_size.cmp(&a_size),
                ModifiedAsc | CreatedAsc => a_mtime.cmp(&b_mtime),
                ModifiedDesc | CreatedDesc => b_mtime.cmp(&a_mtime),
            }
        };

        dir_children.sort_unstable_by(&cmp);
        file_children.sort_unstable_by(&cmp);

        let total_entries = dir_children.len() + file_children.len();
        let merged = dir_children.into_iter().chain(file_children);

        let target: Vec<Child<'_>> = if let Some(per_page) = per_page {
            let start = page.saturating_sub(1) * per_page;
            merged.skip(start).take(per_page).collect()
        } else {
            merged.collect()
        };

        let mut entries = Vec::with_capacity(target.len());
        for child in target {
            match child {
                Child::Dir { path, node } => {
                    entries.push(Self::directory_entry_from_dir_node(&path, node));
                }
                Child::File { path, meta } => {
                    entries.push(Self::directory_entry_from_file_meta(&path, meta, None));
                }
            }
        }

        Ok(DirectoryListing {
            total_entries,
            entries,
        })
    }

    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let mut flat: Vec<(FileType, PathBuf)> = Vec::new();

        if let Some(start) = self.tree.lookup_dir(path.as_ref()) {
            fn walk(
                node: &PbsTreeNode,
                current_path: &Path,
                is_ignored: &IsIgnoredFn,
                out: &mut Vec<(FileType, PathBuf)>,
            ) {
                for (name, meta) in node.files.iter() {
                    let child_path = current_path.join(name.as_str());
                    if let Some(filtered) = (is_ignored)(meta.file_type, child_path) {
                        out.push((meta.file_type, filtered));
                    }
                }
                for (name, child) in node.dirs.iter() {
                    let child_path = current_path.join(name.as_str());
                    if let Some(filtered) = (is_ignored)(FileType::Dir, child_path.clone()) {
                        out.push((FileType::Dir, filtered));
                    }
                    walk(child, &child_path, is_ignored, out);
                }
            }

            walk(start, path.as_ref(), &is_ignored, &mut flat);
        }

        struct TreeWalk {
            items: std::vec::IntoIter<(FileType, PathBuf)>,
        }

        #[async_trait::async_trait]
        impl DirectoryWalk for TreeWalk {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.items.next().map(Ok)
            }
        }

        Ok(Box::new(TreeWalk {
            items: flat.into_iter(),
        }))
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        struct PbsDirStreamWalk {
            entry_wanted_notifier: Arc<tokio::sync::Notify>,
            entry_channel_rx: tokio::sync::mpsc::Receiver<
                Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>,
            >,
        }

        #[async_trait::async_trait]
        impl DirectoryStreamWalk for PbsDirStreamWalk {
            fn supports_multithreading(&self) -> bool {
                false
            }

            async fn next_entry(
                &mut self,
            ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>
            {
                self.entry_wanted_notifier.notify_one();
                self.entry_channel_rx.recv().await
            }
        }

        let mut flat: Vec<(FileType, PathBuf)> = Vec::new();
        if let Some(start) = self.tree.lookup_dir(path.as_ref()) {
            fn walk(
                node: &PbsTreeNode,
                current_path: &Path,
                is_ignored: &IsIgnoredFn,
                out: &mut Vec<(FileType, PathBuf)>,
            ) {
                for (name, meta) in node.files.iter() {
                    let child_path = current_path.join(name.as_str());
                    if let Some(filtered) = (is_ignored)(meta.file_type, child_path) {
                        out.push((meta.file_type, filtered));
                    }
                }
                for (name, child) in node.dirs.iter() {
                    let child_path = current_path.join(name.as_str());
                    if let Some(filtered) = (is_ignored)(FileType::Dir, child_path.clone()) {
                        out.push((FileType::Dir, filtered));
                    }
                    walk(child, &child_path, is_ignored, out);
                }
            }

            walk(start, path.as_ref(), &is_ignored, &mut flat);
        }

        let entry_wanted_notifier = Arc::new(tokio::sync::Notify::new());
        let (entry_channel_tx, entry_channel_rx) = tokio::sync::mpsc::channel(1);

        crate::spawn_handled({
            let entry_wanted_notifier = Arc::clone(&entry_wanted_notifier);
            let archive = Arc::clone(&self.archive);

            async move {
                for (file_type, entry_path) in flat {
                    entry_wanted_notifier.notified().await;

                    if file_type.is_file() {
                        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
                        entry_channel_tx
                            .send(Ok((
                                file_type,
                                entry_path.clone(),
                                Box::new(reader) as AsyncReadableFileStream,
                            )))
                            .await?;

                        let archive = Arc::clone(&archive);
                        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                            let mut reader = archive.open_reader(&entry_path, None)?;
                            let mut writer = SyncIoBridge::new(writer);
                            std::io::copy(&mut reader, &mut writer)?;
                            writer.shutdown()?;
                            Ok(())
                        })
                        .await??;
                    } else {
                        entry_channel_tx
                            .send(Ok((
                                file_type,
                                entry_path,
                                Box::new(tokio::io::empty()) as AsyncReadableFileStream,
                            )))
                            .await?;
                    }
                }

                entry_wanted_notifier.notify_one();
                Ok::<_, anyhow::Error>(())
            }
        });

        entry_wanted_notifier.notify_one();

        Ok(Box::new(PbsDirStreamWalk {
            entry_wanted_notifier,
            entry_channel_rx,
        }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let meta = self.metadata(path)?;
        if !meta.file_type.is_file() {
            return Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            )));
        }

        let (window, size, reader_range) = resolve_range(range, meta.size);
        let reader = self.archive.open_reader(path.as_ref(), window)?;

        Ok(FileRead {
            size,
            total_size: meta.size,
            reader_range,
            reader: Box::new(reader),
        })
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let meta = self.metadata(path)?;
        if !meta.file_type.is_file() {
            return Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            )));
        }

        let (window, size, reader_range) = resolve_range(range, meta.size);
        let archive = Arc::clone(&self.archive);
        let path = path.as_ref().to_path_buf();

        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
            let mut reader = archive.open_reader(&path, window)?;
            let mut writer = SyncIoBridge::new(writer);
            std::io::copy(&mut reader, &mut writer)?;
            writer.shutdown()?;
            Ok(())
        });

        Ok(AsyncFileRead {
            size,
            total_size: meta.size,
            reader_range,
            reader: Box::new(reader),
        })
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.as_ref();
        match self.tree.lookup_file(path) {
            Some(meta) if meta.file_type.is_symlink() => match &meta.symlink {
                Some(target) => Ok(target.clone()),
                None => Ok(self.archive.read_link(path)?),
            },
            _ => Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Symlink not found"
            ))),
        }
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.as_ref().to_path_buf();
        match self.tree.lookup_file(&path) {
            Some(meta) if meta.file_type.is_symlink() => match &meta.symlink {
                Some(target) => Ok(target.clone()),
                None => {
                    let archive = Arc::clone(&self.archive);
                    Ok(tokio::task::spawn_blocking(move || archive.read_link(&path)).await??)
                }
            },
            _ => Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Symlink not found"
            ))),
        }
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        bytes_archived: Option<Arc<AtomicU64>>,
        is_ignored: IsIgnoredFn,
    ) -> Result<tokio::io::ReadHalf<tokio::io::SimplexStream>, anyhow::Error> {
        let base_path = path.as_ref().to_path_buf();
        let node = match self.tree.lookup_dir(&base_path) {
            Some(node) => node,
            None => {
                return Err(anyhow::anyhow!(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "File not found"
                )));
            }
        };

        let mut entries = Vec::new();
        Self::collect_subtree(node, &base_path, Path::new(""), &is_ignored, &mut entries);

        let archive = Arc::clone(&self.archive);
        let threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = SyncIoBridge::new(writer);
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    for entry in entries {
                        let name = entry.relative.to_string_lossy();
                        let mut options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .unix_permissions(entry.mode)
                                .large_file(entry.size >= u32::MAX as u64);

                        if let Some(mtime) =
                            chrono::DateTime::from_timestamp(entry.mtime.timestamp(), 0)
                            && let Ok(dt) = zip::DateTime::from_date_and_time(
                                mtime.year() as u16,
                                mtime.month() as u8,
                                mtime.day() as u8,
                                mtime.hour() as u8,
                                mtime.minute() as u8,
                                mtime.second() as u8,
                            )
                        {
                            options = options.last_modified_time(dt);
                        }

                        match entry.file_type {
                            FileType::Dir => {
                                zip.add_directory(name, options)?;
                            }
                            FileType::File => {
                                zip.start_file(name, options)?;
                                let mut reader = archive.open_reader(&entry.archive_path, None)?;
                                let mut buffer = vec![0; crate::BUFFER_SIZE];
                                loop {
                                    let read = reader.read(&mut buffer)?;
                                    if read == 0 {
                                        break;
                                    }
                                    let chunk = buffer.get(..read).unwrap_or_default();
                                    zip.write_all(chunk)?;
                                    if let Some(counter) = &bytes_archived {
                                        counter.fetch_add(read as u64, Ordering::SeqCst);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    let mut inner = zip.finish()?.into_inner();
                    inner.flush()?;
                    inner.shutdown()?;
                    Ok(())
                });
            }
            f if f.is_tar() => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        threads,
                    )?;
                    let mut tar = tar::Builder::new(writer);

                    for entry in entries {
                        let mut header = tar::Header::new_gnu();
                        header.set_mode(entry.mode);
                        header.set_mtime(entry.mtime.timestamp().max(0) as u64);
                        header.set_uid(0);
                        header.set_gid(0);

                        match entry.file_type {
                            FileType::Dir => {
                                header.set_entry_type(tar::EntryType::Directory);
                                header.set_size(0);
                                tar.append_data(&mut header, &entry.relative, std::io::empty())?;
                            }
                            FileType::File => {
                                header.set_entry_type(tar::EntryType::Regular);
                                header.set_size(entry.size);
                                let reader = archive.open_reader(&entry.archive_path, None)?;
                                let reader: Box<dyn Read> = match &bytes_archived {
                                    Some(counter) => Box::new(CountingReader::new_with_bytes_read(
                                        reader,
                                        counter.clone(),
                                    )),
                                    None => reader,
                                };
                                let mut reader =
                                    FixedReader::new_with_fixed_bytes(reader, entry.size as usize);
                                tar.append_data(&mut header, &entry.relative, &mut reader)?;
                            }
                            FileType::Symlink => {
                                header.set_entry_type(tar::EntryType::Symlink);
                                header.set_size(0);
                                if let Some(target) = &entry.symlink {
                                    tar.append_link(&mut header, &entry.relative, target)?;
                                }
                            }
                            _ => {}
                        }
                    }

                    tar.finish()?;
                    let mut inner = tar.into_inner()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;
                    Ok(())
                });
            }
            f if f.is_itaf() => {
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        threads,
                    )?;
                    let mut itaf_enc = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;

                    let mut dir_stack: Vec<CompactString> = Vec::new();
                    for entry in entries {
                        let components: Vec<CompactString> = entry
                            .relative
                            .components()
                            .filter_map(|c| match c {
                                std::path::Component::Normal(s) => {
                                    Some(s.to_string_lossy().to_compact_string())
                                }
                                _ => None,
                            })
                            .collect();
                        let Some((name, parents)) = components.split_last() else {
                            continue;
                        };

                        let meta = ItafMetadata {
                            uid: 0,
                            gid: 0,
                            mode: entry.mode,
                            modified: mtime_to_system_time(entry.mtime),
                        };

                        let shared = dir_stack
                            .iter()
                            .zip(parents.iter())
                            .take_while(|(a, b)| a == b)
                            .count();
                        while dir_stack.len() > shared {
                            itaf_enc.exit_dir()?;
                            dir_stack.pop();
                        }
                        for component in parents.get(shared..).unwrap_or_default() {
                            itaf_enc.enter_dir(
                                component,
                                &ItafMetadata {
                                    uid: 0,
                                    gid: 0,
                                    mode: 0o755,
                                    modified: std::time::SystemTime::now(),
                                },
                            )?;
                            dir_stack.push(component.clone());
                        }

                        match entry.file_type {
                            FileType::Dir => {
                                itaf_enc.enter_dir(name, &meta)?;
                                dir_stack.push(name.clone());
                            }
                            FileType::File => {
                                let reader = archive.open_reader(&entry.archive_path, None)?;
                                let reader: Box<dyn Read> = match &bytes_archived {
                                    Some(counter) => Box::new(CountingReader::new_with_bytes_read(
                                        reader,
                                        counter.clone(),
                                    )),
                                    None => reader,
                                };
                                let mut reader =
                                    FixedReader::new_with_fixed_bytes(reader, entry.size as usize);
                                itaf_enc.add_file(name, &meta, entry.size, &mut reader)?;
                            }
                            FileType::Symlink => {
                                if let Some(target) = &entry.symlink
                                    && itaf::spec::validate_name(name).is_ok()
                                {
                                    let target = target.to_string_lossy();
                                    itaf_enc.add_symlink(name, &target, false, &meta)?;
                                }
                            }
                            _ => {}
                        }
                    }

                    while !dir_stack.is_empty() {
                        itaf_enc.exit_dir()?;
                        dir_stack.pop();
                    }

                    let mut inner = itaf_enc.finish()?.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;
                    Ok(())
                });
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported archive format for PBS backups: {}",
                    archive_format.extension()
                ));
            }
        }

        Ok(reader)
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        self.archive.close().await;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for PbsBackup {
    async fn clean(
        _server: &crate::server::Server,
        _uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
