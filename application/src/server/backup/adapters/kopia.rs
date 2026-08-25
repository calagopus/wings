use crate::{
    io::{
        SafeWriteExt, UninterruptedReadExt,
        compression::{CompressionLevel, writer::CompressionWriter},
    },
    models::DirectoryEntry,
    remote::backups::{KopiaBackupConfiguration, RawServerBackup},
    response::ApiResponse,
    routes::MimeCacheValue,
    server::{
        backup::{Backup, BackupCleanExt, BackupCreateExt, BackupExt, BackupFindExt},
        filesystem::{
            archive::StreamableArchiveFormat,
            cap::FileType,
            encode_mode,
            virtualfs::{
                AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead,
                AsyncReadableFileStream, ByteRange, DirectoryListing, DirectoryWalk, FileMetadata,
                FileRead, IsIgnoredFn, VirtualReadableFilesystem,
            },
        },
    },
    utils::{CmpExt, PortablePermissions},
};
use chrono::{Datelike, Timelike};
use compact_str::CompactString;
use serde::Deserialize;
use sha2::Digest;
use std::{
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncBufReadExt;

const BACKUP_UUID_TAG: &str = "backup-uuid";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KopiaManifest {
    id: String,
    root_entry: KopiaRootEntry,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KopiaRootEntry {
    #[serde(rename = "obj")]
    obj: String,
    #[serde(default)]
    summ: KopiaSummary,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KopiaSummary {
    #[serde(default)]
    size: u64,
    #[serde(default)]
    files: u64,
}

pub struct KopiaBackup {
    uuid: uuid::Uuid,
    root_oid: String,
    manifest_id: String,
    total_size: u64,

    config: Arc<crate::config::Config>,
    config_file: PathBuf,
    remote: Arc<KopiaBackupConfiguration>,
}

impl KopiaBackup {
    fn repository_slug(remote: &KopiaBackupConfiguration) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(remote.url.as_bytes());
        hasher.update([0]);
        hasher.update(remote.username.as_bytes());
        hex::encode(hasher.finalize().get(..8).unwrap_or(&[]))
    }

    fn get_kopia_state_path(config: &crate::config::Config) -> PathBuf {
        config
            .resolve_as_path(|cfg| &cfg.system.backup_directory)
            .join(".kopia")
    }

    fn get_config_file_path(
        config: &crate::config::Config,
        remote: &KopiaBackupConfiguration,
    ) -> PathBuf {
        Self::get_kopia_state_path(config).join(format!("{}.config", Self::repository_slug(remote)))
    }

    fn get_cache_dir_path(
        config: &crate::config::Config,
        remote: &KopiaBackupConfiguration,
    ) -> PathBuf {
        Self::get_kopia_state_path(config).join(format!("{}.cache", Self::repository_slug(remote)))
    }

    fn get_tokio_command(
        config_file: &Path,
        remote: &KopiaBackupConfiguration,
    ) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("kopia");
        command
            .env("KOPIA_PASSWORD", &remote.password)
            .env("TZ", "UTC")
            .arg("--config-file")
            .arg(config_file);

        command
    }

    fn get_std_command(
        config_file: &Path,
        remote: &KopiaBackupConfiguration,
    ) -> std::process::Command {
        let mut command = std::process::Command::new("kopia");
        command
            .env("KOPIA_PASSWORD", &remote.password)
            .env("TZ", "UTC")
            .arg("--config-file")
            .arg(config_file);

        command
    }

    fn parse_human_bytes(value: &str) -> Option<u64> {
        let value = value.trim();
        let (number, unit) = value.split_once(' ').unwrap_or((value, "B"));

        let number: f64 = number.parse().ok()?;
        let multiplier: f64 = match unit.trim() {
            "B" => 1.0,
            "KB" => 1e3,
            "MB" => 1e6,
            "GB" => 1e9,
            "TB" => 1e12,
            "PB" => 1e15,
            "EB" => 1e18,
            _ => return None,
        };

        Some((number * multiplier) as u64)
    }

    fn extract_parenthesised_bytes(line: &str, label: &str) -> Option<u64> {
        let start = line.find(label)? + label.len();
        let open = line.get(start..)?.find('(')? + start + 1;
        let close = line.get(open..)?.find(')')? + open;
        Self::parse_human_bytes(line.get(open..close)?)
    }

    fn extract_labelled_bytes(line: &str, label: &str, terminator: &str) -> Option<u64> {
        let start = line.find(label)? + label.len();
        let rest = line.get(start..)?;
        let end = rest.find(terminator).unwrap_or(rest.len());
        Self::parse_human_bytes(rest.get(..end)?)
    }

    async fn ensure_connected(
        config_file: &Path,
        cache_dir: &Path,
        remote: &KopiaBackupConfiguration,
    ) -> Result<(), anyhow::Error> {
        let status = Self::get_tokio_command(config_file, remote)
            .arg("repository")
            .arg("status")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        if matches!(status, Ok(status) if status.success()) {
            return Ok(());
        }

        if let Some(parent) = config_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::create_dir_all(cache_dir).await?;

        let (username, hostname) = remote
            .username
            .split_once('@')
            .unwrap_or((&remote.username, "wings"));

        let mut command = Self::get_tokio_command(config_file, remote);
        command
            .arg("repository")
            .arg("connect")
            .arg("server")
            .arg("--url")
            .arg(&remote.url);

        if let Some(fingerprint) = remote.fingerprint() {
            command.arg("--server-cert-fingerprint").arg(fingerprint);
        }

        let output = command
            .arg("--override-username")
            .arg(username)
            .arg("--override-hostname")
            .arg(hostname)
            .arg("--cache-directory")
            .arg(cache_dir)
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to connect to Kopia repository server at {}: {}",
                remote.url,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    async fn find_snapshot(
        config_file: &Path,
        remote: &KopiaBackupConfiguration,
        uuid: uuid::Uuid,
    ) -> Result<Option<KopiaManifest>, anyhow::Error> {
        let output = Self::get_tokio_command(config_file, remote)
            .arg("snapshot")
            .arg("list")
            .arg("--json")
            .arg("--all")
            .arg("--tags")
            .arg(format!("{BACKUP_UUID_TAG}:{uuid}"))
            .stderr(std::process::Stdio::null())
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to list Kopia snapshots: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut manifests: Vec<KopiaManifest> = serde_json::from_slice(&output.stdout)?;

        Ok(manifests.pop())
    }
}

#[async_trait::async_trait]
impl BackupFindExt for KopiaBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        let remote = match state.config.client.backup_kopia_configuration(uuid).await {
            Ok(remote) => remote,
            Err(_) => return Ok(false),
        };

        let config_file = Self::get_config_file_path(&state.config, &remote);
        let cache_dir = Self::get_cache_dir_path(&state.config, &remote);

        if Self::ensure_connected(&config_file, &cache_dir, &remote)
            .await
            .is_err()
        {
            return Ok(false);
        }

        Ok(Self::find_snapshot(&config_file, &remote, uuid)
            .await
            .unwrap_or(None)
            .is_some())
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        let remote = match state.config.client.backup_kopia_configuration(uuid).await {
            Ok(remote) => remote,
            Err(_) => return Ok(None),
        };

        let config_file = Self::get_config_file_path(&state.config, &remote);
        let cache_dir = Self::get_cache_dir_path(&state.config, &remote);

        if Self::ensure_connected(&config_file, &cache_dir, &remote)
            .await
            .is_err()
        {
            return Ok(None);
        }

        let manifest = match Self::find_snapshot(&config_file, &remote, uuid).await? {
            Some(manifest) => manifest,
            None => return Ok(None),
        };

        Ok(Some(Backup::Kopia(KopiaBackup {
            uuid,
            root_oid: manifest.root_entry.obj,
            manifest_id: manifest.id,
            total_size: manifest.root_entry.summ.size,
            config: Arc::clone(&state.config),
            config_file,
            remote: Arc::new(remote),
        })))
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for KopiaBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let remote = server
            .app_state
            .config
            .client
            .backup_kopia_configuration(uuid)
            .await?;

        let config_file = Self::get_config_file_path(&server.app_state.config, &remote);
        let cache_dir = Self::get_cache_dir_path(&server.app_state.config, &remote);
        Self::ensure_connected(&config_file, &cache_dir, &remote).await?;

        let source_path = server.filesystem.base_path.clone();

        let total_task = {
            let filesystem = server.filesystem.clone();
            let ignore = ignore.clone();
            let total = Arc::clone(&total);
            let progress = progress.clone();

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
                        if !metadata.is_dir() {
                            progress.increment_files();
                        }
                    }

                    Ok::<_, anyhow::Error>(())
                })
                .await?
            }
        };

        let ignore_lines: Vec<&str> = ignore_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        if !ignore_lines.is_empty() {
            let mut policy = Self::get_tokio_command(&config_file, &remote);
            policy.arg("policy").arg("set").arg(&source_path);
            for line in &ignore_lines {
                policy.arg("--add-ignore").arg(line);
            }

            if let Ok(output) = policy.output().await
                && !output.status.success()
            {
                tracing::warn!(
                    "failed to apply ignore policy for Kopia backup {}: {}",
                    uuid,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        let mut command = Self::get_tokio_command(&config_file, &remote);
        command
            .arg("--progress")
            .arg("--progress-update-interval")
            .arg("1s")
            .arg("--progress-estimation-type")
            .arg("rough")
            .arg("snapshot")
            .arg("create")
            .arg(&source_path)
            .arg("--json")
            .arg("--description")
            .arg(format!("wings backup {uuid}"));

        command
            .arg("--tags")
            .arg(format!("{BACKUP_UUID_TAG}:{uuid}"));
        for (key, value) in &remote.tags {
            command.arg("--tags").arg(format!("{key}:{value}"));
        }

        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let progress_task = {
            let progress = progress.clone();
            let stderr = child.stderr.take();

            async move {
                let Some(stderr) = stderr else {
                    return;
                };

                let mut segments = tokio::io::BufReader::new(stderr).split(b'\r');
                while let Ok(Some(segment)) = segments.next_segment().await {
                    let line = String::from_utf8_lossy(&segment);

                    let hashed = Self::extract_parenthesised_bytes(&line, "hashed ");
                    let cached = Self::extract_parenthesised_bytes(&line, "cached ");
                    let uploaded = Self::extract_labelled_bytes(&line, "uploaded ", ",");

                    progress.store_bytes(
                        (hashed.unwrap_or(0) + cached.unwrap_or(0)).max(uploaded.unwrap_or(0)),
                    );
                }
            }
        };

        let (output, _, total_result) =
            tokio::join!(child.wait_with_output(), progress_task, total_task);
        total_result?;
        let output = output?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to create Kopia snapshot: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let manifest: KopiaManifest = serde_json::from_slice(&output.stdout)?;
        let summary = &manifest.root_entry.summ;

        progress.store_bytes(total.load(Ordering::Relaxed));
        if summary.files > 0 {
            progress.store_files(summary.files);
        }

        Ok(RawServerBackup {
            checksum: manifest.id,
            checksum_type: "kopia".into(),
            size: summary.size,
            files: summary.files,
            successful: true,
            browsable: true,
            streaming: true,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for KopiaBackup {
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
        let compression_level = state.config.load().system.backups.compression_level;
        let file_compression_threads = state.config.load().api.file_compression_threads;
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        let spawn_restore = || {
            tokio::task::block_in_place(|| {
                Self::get_std_command(&self.config_file, &self.remote)
                    .arg("restore")
                    .arg(&self.root_oid)
                    .arg("/dev/stdout")
                    .arg("--mode")
                    .arg("tar")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
            })
        };

        match archive_format {
            StreamableArchiveFormat::Zip => {
                let child = spawn_restore()?;

                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = tokio_util::io::SyncIoBridge::new(writer);
                    let mut archive = zip::ZipWriter::new_stream(writer);

                    let stdout = child
                        .stdout
                        .ok_or_else(|| anyhow::anyhow!("kopia restore produced no stdout"))?;
                    let mut subtar = tar::Archive::new(stdout);
                    let entries = subtar.entries()?;

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    for entry in entries {
                        let mut entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?;

                        let is_dir = header.entry_type() == tar::EntryType::Directory;
                        let mode = header.mode().unwrap_or(if is_dir { 0o755 } else { 0o644 });
                        let size = header.size().unwrap_or(0);

                        let mut options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .unix_permissions(mode)
                                .large_file(size >= u32::MAX as u64);
                        if let Ok(mtime) = header.mtime()
                            && let Some(mtime) = chrono::DateTime::from_timestamp(mtime as i64, 0)
                        {
                            options =
                                options.last_modified_time(zip::DateTime::from_date_and_time(
                                    mtime.year() as u16,
                                    mtime.month() as u8,
                                    mtime.day() as u8,
                                    mtime.hour() as u8,
                                    mtime.minute() as u8,
                                    mtime.second() as u8,
                                )?);
                        }

                        match header.entry_type() {
                            tar::EntryType::Directory => {
                                archive.add_directory(relative.to_string_lossy(), options)?;
                            }
                            tar::EntryType::Regular => {
                                archive.start_file(relative.to_string_lossy(), options)?;
                                crate::io::copy_shared(&mut read_buffer, &mut entry, &mut archive)?;
                            }
                            _ => continue,
                        }
                    }

                    let mut inner = archive.finish()?.into_inner();
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            f if f.is_tar() => {
                let child = spawn_restore()?;

                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let mut writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;

                    let mut stdout = child
                        .stdout
                        .ok_or_else(|| anyhow::anyhow!("kopia restore produced no stdout"))?;
                    if let Err(err) = crate::io::copy(&mut stdout, &mut writer) {
                        tracing::error!("failed to compress tar archive for kopia backup: {}", err);
                    }

                    let mut inner = writer.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            _ => {
                tracing::error!(
                    "unsupported archive format for kopia backup download: {}",
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
        total.store(self.total_size, Ordering::Relaxed);

        let mut child = Self::get_tokio_command(&self.config_file, &self.remote)
            .arg("--progress")
            .arg("--progress-update-interval")
            .arg("1s")
            .arg("restore")
            .arg(&self.root_oid)
            .arg(&server.filesystem.base_path)
            .arg("--overwrite-files")
            .arg("--overwrite-directories")
            .arg("--overwrite-symlinks")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        if let Some(stderr) = child.stderr.take() {
            let mut segments = tokio::io::BufReader::new(stderr).split(b'\r');
            while let Ok(Some(segment)) = segments.next_segment().await {
                let line = compact_str::CompactString::from_utf8_lossy(segment.trim_ascii());
                if line.is_empty() {
                    continue;
                }

                let Some(restored) = Self::extract_parenthesised_bytes(&line, "Processed ") else {
                    continue;
                };

                progress.store_bytes(restored);
                if let Some(enqueued) = Self::extract_parenthesised_bytes(&line, " of ") {
                    total.store(enqueued, Ordering::Relaxed);
                }
                server.log_daemon(line);
            }
        }

        let status = child.wait().await?;
        if !status.success() {
            return Err(anyhow::anyhow!("failed to restore Kopia backup"));
        }

        progress.store_bytes(total.load(Ordering::Relaxed));
        server.filesystem.rerun_disk_checker();

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        let output = Self::get_tokio_command(&self.config_file, &self.remote)
            .arg("snapshot")
            .arg("delete")
            .arg(&self.manifest_id)
            .arg("--delete")
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to delete Kopia backup: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

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
        let cache_dir = Self::get_cache_dir_path(&self.config, &self.remote);
        Self::ensure_connected(&self.config_file, &cache_dir, &self.remote).await?;

        Ok(Arc::new(VirtualKopiaBackup {
            server: server.clone(),
            config_file: self.config_file.clone(),
            remote: Arc::clone(&self.remote),
            root_oid: Arc::from(self.root_oid.as_str()),
            root_size: self.total_size,
            dir_cache: moka::sync::Cache::builder().max_capacity(8192).build(),
        }))
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for KopiaBackup {
    async fn clean(
        _server: &crate::server::Server,
        _uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct KopiaEntry {
    file_type: FileType,
    mode: u32,
    size: u64,
    mtime: chrono::DateTime<chrono::Utc>,
    oid: String,
}

struct ParsedDir {
    entries: Vec<(CompactString, KopiaEntry)>,
}

#[derive(Deserialize)]
struct RawDirManifest {
    #[serde(default)]
    entries: Option<Vec<RawDirEntry>>,
}

#[derive(Deserialize)]
struct RawDirEntry {
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    entry_type: CompactString,
    #[serde(default)]
    mode: CompactString,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    mtime: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    obj: String,
    #[serde(default)]
    summ: Option<RawDirSummary>,
}

#[derive(Deserialize)]
struct RawDirSummary {
    #[serde(default)]
    size: u64,
}

fn parse_dir(bytes: &[u8]) -> Result<ParsedDir, anyhow::Error> {
    let raw: RawDirManifest = serde_json::from_slice(bytes)?;
    let epoch = chrono::DateTime::from_timestamp(0, 0).unwrap_or_default();

    let mut entries: Vec<(CompactString, KopiaEntry)> = raw
        .entries
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| {
            if e.name.is_empty() {
                return None;
            }

            let file_type = match e.entry_type.as_str() {
                "d" => FileType::Dir,
                "s" => FileType::Symlink,
                _ => FileType::File,
            };

            let default_mode = if file_type.is_dir() { 0o755 } else { 0o644 };
            let mode = if e.mode.is_empty() {
                default_mode
            } else {
                u32::from_str_radix(e.mode.as_str(), 8).unwrap_or(default_mode)
            };

            let size = if file_type.is_dir() {
                e.summ.map(|s| s.size).unwrap_or(0)
            } else {
                e.size
            };

            Some((
                CompactString::from(e.name),
                KopiaEntry {
                    file_type,
                    mode,
                    size,
                    mtime: e.mtime.unwrap_or(epoch),
                    oid: e.obj,
                },
            ))
        })
        .collect();

    entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    Ok(ParsedDir { entries })
}

pub struct VirtualKopiaBackup {
    server: crate::server::Server,
    config_file: PathBuf,
    remote: Arc<KopiaBackupConfiguration>,
    root_oid: Arc<str>,
    root_size: u64,
    dir_cache: moka::sync::Cache<Arc<str>, Arc<ParsedDir>>,
}

impl VirtualKopiaBackup {
    fn open_object(&self, oid: &str) -> Result<std::process::ChildStdout, anyhow::Error> {
        let child = KopiaBackup::get_std_command(&self.config_file, &self.remote)
            .arg("show")
            .arg(oid)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        child
            .stdout
            .ok_or_else(|| anyhow::anyhow!("kopia show produced no stdout"))
    }

    async fn load_dir(&self, oid: &str) -> Result<Arc<ParsedDir>, anyhow::Error> {
        if let Some(hit) = self.dir_cache.get(oid) {
            return Ok(hit);
        }

        let output = KopiaBackup::get_tokio_command(&self.config_file, &self.remote)
            .arg("show")
            .arg(oid)
            .stderr(std::process::Stdio::null())
            .output()
            .await?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to read Kopia directory object {oid}"
            ));
        }

        let parsed = Arc::new(parse_dir(&output.stdout)?);
        self.dir_cache.insert(oid.into(), Arc::clone(&parsed));

        Ok(parsed)
    }

    fn load_dir_blocking(&self, oid: &str) -> Result<Arc<ParsedDir>, anyhow::Error> {
        if let Some(hit) = self.dir_cache.get(oid) {
            return Ok(hit);
        }

        let output = KopiaBackup::get_std_command(&self.config_file, &self.remote)
            .arg("show")
            .arg(oid)
            .stderr(std::process::Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to read Kopia directory object {oid}"
            ));
        }

        let parsed = Arc::new(parse_dir(&output.stdout)?);
        self.dir_cache.insert(oid.into(), Arc::clone(&parsed));

        Ok(parsed)
    }

    fn not_found() -> anyhow::Error {
        anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        ))
    }

    async fn resolve_dir_oid(&self, path: &Path) -> Result<Arc<str>, anyhow::Error> {
        let mut oid = Arc::clone(&self.root_oid);
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let Some(name) = name.to_str() else {
                return Err(Self::not_found());
            };

            let dir = self.load_dir(&oid).await?;
            let idx = dir
                .entries
                .binary_search_by(|(n, _)| n.as_str().cmp(name))
                .map_err(|_| Self::not_found())?;
            let entry = &dir.entries.get(idx).ok_or_else(Self::not_found)?.1;
            if !entry.file_type.is_dir() {
                return Err(Self::not_found());
            }
            oid = Arc::from(entry.oid.as_str());
        }

        Ok(oid)
    }

    fn resolve_dir_oid_blocking(&self, path: &Path) -> Result<Arc<str>, anyhow::Error> {
        let mut oid = Arc::clone(&self.root_oid);
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let Some(name) = name.to_str() else {
                return Err(Self::not_found());
            };

            let dir = self.load_dir_blocking(&oid)?;
            let idx = dir
                .entries
                .binary_search_by(|(n, _)| n.as_str().cmp(name))
                .map_err(|_| Self::not_found())?;
            let entry = &dir.entries.get(idx).ok_or_else(Self::not_found)?.1;
            if !entry.file_type.is_dir() {
                return Err(Self::not_found());
            }
            oid = Arc::from(entry.oid.as_str());
        }

        Ok(oid)
    }

    async fn resolve_dir(&self, path: &Path) -> Result<Arc<ParsedDir>, anyhow::Error> {
        let oid = self.resolve_dir_oid(path).await?;
        self.load_dir(&oid).await
    }

    async fn lookup_entry(&self, path: &Path) -> Result<KopiaEntry, anyhow::Error> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(Self::not_found)?;

        let dir = self.resolve_dir(parent).await?;
        let idx = dir
            .entries
            .binary_search_by(|(n, _)| n.as_str().cmp(leaf))
            .map_err(|_| Self::not_found())?;

        Ok(dir.entries.get(idx).ok_or_else(Self::not_found)?.1.clone())
    }

    fn lookup_entry_blocking(&self, path: &Path) -> Result<KopiaEntry, anyhow::Error> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(Self::not_found)?;

        let oid = self.resolve_dir_oid_blocking(parent)?;
        let dir = self.load_dir_blocking(&oid)?;
        let idx = dir
            .entries
            .binary_search_by(|(n, _)| n.as_str().cmp(leaf))
            .map_err(|_| Self::not_found())?;

        Ok(dir.entries.get(idx).ok_or_else(Self::not_found)?.1.clone())
    }

    fn root_entry(&self) -> KopiaEntry {
        KopiaEntry {
            file_type: FileType::Dir,
            mode: 0o755,
            size: self.root_size,
            mtime: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
            oid: self.root_oid.to_string(),
        }
    }

    fn root_metadata(&self) -> FileMetadata {
        FileMetadata {
            file_type: FileType::Dir,
            permissions: PortablePermissions::from_mode_dir(0o755),
            size: 0,
            modified: None,
            created: None,
        }
    }

    fn metadata_from_entry(entry: &KopiaEntry) -> FileMetadata {
        FileMetadata {
            file_type: entry.file_type,
            permissions: if entry.file_type.is_dir() {
                PortablePermissions::from_mode_dir(entry.mode)
            } else {
                PortablePermissions::from_mode_file(entry.mode)
            },
            size: if entry.file_type.is_dir() {
                0
            } else {
                entry.size
            },
            modified: Some(entry.mtime.into()),
            created: None,
        }
    }

    fn directory_entry(path: &Path, entry: &KopiaEntry, buffer: Option<&[u8]>) -> DirectoryEntry {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into();
        let epoch = chrono::DateTime::from_timestamp(0, 0).unwrap_or_default();

        match entry.file_type {
            FileType::Dir => {
                let mode = if entry.mode != 0 { entry.mode } else { 0o755 };
                DirectoryEntry {
                    name,
                    mode: encode_mode(mode),
                    mode_bits: compact_str::format_compact!("{:o}", mode & 0o777),
                    size: entry.size,
                    size_physical: entry.size,
                    editable: false,
                    inner_editable: false,
                    directory: true,
                    file: false,
                    symlink: false,
                    r#virtual: true,
                    mime: MimeCacheValue::directory().mime,
                    modified: entry.mtime,
                    created: epoch,
                }
            }
            _ => {
                let detected_mime = if entry.file_type.is_symlink() {
                    MimeCacheValue::symlink()
                } else if entry.file_type.is_file() && entry.size == 0 {
                    MimeCacheValue::text()
                } else {
                    crate::utils::detect_mime_type(path, buffer)
                };

                DirectoryEntry {
                    name,
                    mode: encode_mode(entry.mode),
                    mode_bits: compact_str::format_compact!("{:o}", entry.mode & 0o777),
                    size: entry.size,
                    size_physical: entry.size,
                    editable: entry.file_type.is_file() && detected_mime.valid_utf8,
                    inner_editable: entry.file_type.is_file() && detected_mime.valid_inner_utf8,
                    directory: false,
                    file: entry.file_type.is_file(),
                    symlink: entry.file_type.is_symlink(),
                    r#virtual: true,
                    mime: detected_mime.mime,
                    modified: entry.mtime,
                    created: epoch,
                }
            }
        }
    }

    fn flatten_walk<'a>(
        &'a self,
        rel: PathBuf,
        oid: Arc<str>,
        is_ignored: &'a IsIgnoredFn,
        out: &'a mut Vec<(FileType, PathBuf, String)>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            let dir = match self.load_dir(&oid).await {
                Ok(dir) => dir,
                Err(err) => {
                    tracing::warn!(
                        rel = %rel.display(),
                        oid = %oid,
                        "kopia flatten_walk failed to load directory, skipping subtree: {:?}",
                        err,
                    );
                    return Ok(());
                }
            };

            for (name, entry) in dir.entries.iter() {
                if entry.file_type.is_dir() {
                    continue;
                }
                let child_path = rel.join(name.as_str());
                if let Some(filtered) = (is_ignored)(entry.file_type, child_path) {
                    out.push((entry.file_type, filtered, entry.oid.clone()));
                }
            }

            for (name, entry) in dir.entries.iter() {
                if !entry.file_type.is_dir() {
                    continue;
                }
                let child_path = rel.join(name.as_str());
                if let Some(filtered) = (is_ignored)(FileType::Dir, child_path.clone()) {
                    out.push((FileType::Dir, filtered, String::new()));
                }
                self.flatten_walk(child_path, Arc::from(entry.oid.as_str()), is_ignored, out)
                    .await?;
            }

            Ok(())
        })
    }

    fn flatten_walk_blocking(
        &self,
        rel: PathBuf,
        oid: Arc<str>,
        is_ignored: &IsIgnoredFn,
        out: &mut Vec<(FileType, PathBuf, String)>,
    ) -> Result<(), anyhow::Error> {
        let dir = match self.load_dir_blocking(&oid) {
            Ok(dir) => dir,
            Err(err) => {
                tracing::warn!(
                    rel = %rel.display(),
                    oid = %oid,
                    "kopia flatten_walk failed to load directory, skipping subtree: {:?}",
                    err,
                );
                return Ok(());
            }
        };

        for (name, entry) in dir.entries.iter() {
            if entry.file_type.is_dir() {
                continue;
            }
            let child_path = rel.join(name.as_str());
            if let Some(filtered) = (is_ignored)(entry.file_type, child_path) {
                out.push((entry.file_type, filtered, entry.oid.clone()));
            }
        }

        for (name, entry) in dir.entries.iter() {
            if !entry.file_type.is_dir() {
                continue;
            }
            let child_path = rel.join(name.as_str());
            if let Some(filtered) = (is_ignored)(FileType::Dir, child_path.clone()) {
                out.push((FileType::Dir, filtered, String::new()));
            }
            self.flatten_walk_blocking(child_path, Arc::from(entry.oid.as_str()), is_ignored, out)?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualKopiaBackup {
    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let path = path.as_ref();
        if path == Path::new("") || path == Path::new("/") {
            return Ok(self.root_metadata());
        }
        let entry = self.lookup_entry_blocking(path)?;
        Ok(Self::metadata_from_entry(&entry))
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let path = path.as_ref();
        if path == Path::new("") || path == Path::new("/") {
            return Ok(self.root_metadata());
        }
        let entry = self.lookup_entry(path).await?;
        Ok(Self::metadata_from_entry(&entry))
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
        self.async_metadata(path).await
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let path = path.as_ref();
        if path == Path::new("") || path == Path::new("/") {
            return Ok(Self::directory_entry(path, &self.root_entry(), None));
        }
        let entry = self.lookup_entry(path).await?;
        Ok(Self::directory_entry(path, &entry, None))
    }
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let path = path.as_ref();
        if path == Path::new("") || path == Path::new("/") {
            return Ok(Self::directory_entry(path, &self.root_entry(), None));
        }
        let entry = self.lookup_entry(path).await?;
        Ok(Self::directory_entry(path, &entry, Some(buffer)))
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        use crate::models::DirectorySortingMode::*;

        let path = path.as_ref().to_path_buf();
        let dir = match self.resolve_dir(&path).await {
            Ok(dir) => dir,
            Err(_) => {
                return Ok(DirectoryListing {
                    total_entries: 0,
                    entries: Vec::new(),
                });
            }
        };

        let mut dir_children: Vec<(PathBuf, &KopiaEntry)> = Vec::new();
        let mut file_children: Vec<(PathBuf, &KopiaEntry)> = Vec::new();

        for (name, entry) in dir.entries.iter() {
            let child_path = match is_ignored
                .call_async(entry.file_type, path.join(name.as_str()))
                .await
            {
                Some(kept) => kept,
                None => continue,
            };
            if entry.file_type.is_dir() {
                dir_children.push((child_path, entry));
            } else {
                file_children.push((child_path, entry));
            }
        }

        let cmp = |a: &(PathBuf, &KopiaEntry), b: &(PathBuf, &KopiaEntry)| -> std::cmp::Ordering {
            match sort {
                NameAsc => a.0.cmp_ascii_case_insensitive(&b.0),
                NameDesc => b.0.cmp_ascii_case_insensitive(&a.0),
                SizeAsc | PhysicalSizeAsc => a.1.size.cmp(&b.1.size),
                SizeDesc | PhysicalSizeDesc => b.1.size.cmp(&a.1.size),
                ModifiedAsc | CreatedAsc => a.1.mtime.cmp(&b.1.mtime),
                ModifiedDesc | CreatedDesc => b.1.mtime.cmp(&a.1.mtime),
            }
        };

        dir_children.sort_unstable_by(&cmp);
        file_children.sort_unstable_by(&cmp);

        let total_entries = dir_children.len() + file_children.len();
        let merged = dir_children.into_iter().chain(file_children);

        let target: Vec<(PathBuf, &KopiaEntry)> = if let Some(per_page) = per_page {
            let start = page.saturating_sub(1) * per_page;
            merged.skip(start).take(per_page).collect()
        } else {
            merged.collect()
        };

        let mut entries = Vec::with_capacity(target.len());
        for (child_path, entry) in target {
            entries.push(Self::directory_entry(&child_path, entry, None));
        }

        Ok(DirectoryListing {
            total_entries,
            entries,
        })
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let base = path.as_ref().to_path_buf();
        let mut flat: Vec<(FileType, PathBuf, String)> = Vec::new();

        if let Ok(oid) = self.resolve_dir_oid_blocking(&base) {
            self.flatten_walk_blocking(base, oid, &is_ignored, &mut flat)?;
        }

        struct TreeWalk {
            items: std::vec::IntoIter<(FileType, PathBuf)>,
        }

        impl DirectoryWalk for TreeWalk {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.items.next().map(Ok)
            }
        }

        let items: Vec<(FileType, PathBuf)> = flat.into_iter().map(|(ft, p, _)| (ft, p)).collect();

        Ok(Box::new(TreeWalk {
            items: items.into_iter(),
        }))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let base = path.as_ref().to_path_buf();
        let mut flat: Vec<(FileType, PathBuf, String)> = Vec::new();

        if let Ok(oid) = self.resolve_dir_oid(&base).await {
            self.flatten_walk(base, oid, &is_ignored, &mut flat).await?;
        }

        struct TreeWalk {
            items: std::vec::IntoIter<(FileType, PathBuf)>,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryWalk for TreeWalk {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.items.next().map(Ok)
            }
        }

        let items: Vec<(FileType, PathBuf)> = flat.into_iter().map(|(ft, p, _)| (ft, p)).collect();

        Ok(Box::new(TreeWalk {
            items: items.into_iter(),
        }))
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        struct KopiaDirStreamWalk {
            entry_wanted_notifier: Arc<tokio::sync::Notify>,
            entry_channel_rx: tokio::sync::mpsc::Receiver<
                Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>,
            >,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryStreamWalk for KopiaDirStreamWalk {
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

        let base = path.as_ref().to_path_buf();
        let base_oid = match self.resolve_dir_oid(&base).await {
            Ok(oid) => Some(oid),
            Err(err) => {
                tracing::warn!(
                    base = %base.display(),
                    "kopia stream walk could not resolve directory oid: {:?}",
                    err,
                );
                None
            }
        };

        let entry_wanted_notifier = Arc::new(tokio::sync::Notify::new());
        let (entry_channel_tx, entry_channel_rx) = tokio::sync::mpsc::channel(1);

        if let Some(base_oid) = base_oid {
            let entry_wanted_notifier = Arc::clone(&entry_wanted_notifier);
            let config_file = self.config_file.clone();
            let remote = Arc::clone(&self.remote);

            crate::spawn_handled(async move {
                tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                    let runtime = tokio::runtime::Handle::current();

                    let child = KopiaBackup::get_std_command(&config_file, &remote)
                        .arg("restore")
                        .arg(base_oid.as_ref())
                        .arg("/dev/stdout")
                        .arg("--mode")
                        .arg("tar")
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()?;
                    let stdout = child
                        .stdout
                        .ok_or_else(|| anyhow::anyhow!("kopia restore produced no stdout"))?;

                    let mut subtar = tar::Archive::new(stdout);
                    let entries = subtar.entries()?;

                    for entry in entries {
                        let mut entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();
                        if relative.as_os_str().is_empty() || relative.as_os_str() == "." {
                            continue;
                        }

                        let file_type = match header.entry_type() {
                            tar::EntryType::Directory => FileType::Dir,
                            tar::EntryType::Symlink => FileType::Symlink,
                            tar::EntryType::Regular => FileType::File,
                            _ => continue,
                        };

                        let Some(entry_path) = (is_ignored)(file_type, base.join(&relative)) else {
                            continue;
                        };

                        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
                        entry_channel_tx.blocking_send(Ok((
                            file_type,
                            entry_path,
                            Box::new(reader) as AsyncReadableFileStream,
                        )))?;

                        let mut writer = tokio_util::io::SyncIoBridge::new(writer);
                        crate::io::copy(&mut entry, &mut writer)?;
                        writer.shutdown()?;

                        runtime.block_on(entry_wanted_notifier.notified());
                    }

                    entry_wanted_notifier.notify_one();
                    Ok(())
                })
                .await??;

                Ok::<_, anyhow::Error>(())
            });
        }

        entry_wanted_notifier.notify_one();

        Ok(Box::new(KopiaDirStreamWalk {
            entry_wanted_notifier,
            entry_channel_rx,
        }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let entry = self.lookup_entry_blocking(path.as_ref())?;
        if !entry.file_type.is_file() {
            return Err(Self::not_found());
        }

        let reader = self.open_object(&entry.oid)?;

        Ok(FileRead {
            size: entry.size,
            total_size: entry.size,
            reader_range: None,
            reader: Box::new(reader),
        })
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let entry = self.lookup_entry(path.as_ref()).await?;
        if !entry.file_type.is_file() {
            return Err(Self::not_found());
        }

        let child = KopiaBackup::get_tokio_command(&self.config_file, &self.remote)
            .arg("show")
            .arg(&entry.oid)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let reader = child
            .stdout
            .ok_or_else(|| anyhow::anyhow!("kopia show produced no stdout"))?;

        Ok(AsyncFileRead {
            size: entry.size,
            total_size: entry.size,
            reader_range: None,
            reader: Box::new(reader),
        })
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let entry = self.lookup_entry_blocking(path.as_ref())?;
        if !entry.file_type.is_symlink() {
            return Err(Self::not_found());
        }

        let mut reader = self.open_object(&entry.oid)?;
        let mut target = String::new();
        reader.read_to_string(&mut target)?;
        Ok(PathBuf::from(target))
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let entry = self.lookup_entry(path.as_ref()).await?;
        if !entry.file_type.is_symlink() {
            return Err(Self::not_found());
        }

        let output = KopiaBackup::get_tokio_command(&self.config_file, &self.remote)
            .arg("show")
            .arg(&entry.oid)
            .stderr(std::process::Stdio::null())
            .output()
            .await?;
        if !output.status.success() {
            return Err(Self::not_found());
        }

        Ok(PathBuf::from(
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error> {
        let base_path = path.as_ref().to_path_buf();
        let base_oid = match self.resolve_dir_oid(&base_path).await {
            Ok(oid) => oid,
            Err(_) => return Err(Self::not_found()),
        };

        let threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;
        let config_file = self.config_file.clone();
        let remote = Arc::clone(&self.remote);
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new(reader);

        let spawn_restore = move || -> Result<std::process::ChildStdout, anyhow::Error> {
            let child = KopiaBackup::get_std_command(&config_file, &remote)
                .arg("restore")
                .arg(base_oid.as_ref())
                .arg("/dev/stdout")
                .arg("--mode")
                .arg("tar")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            child
                .stdout
                .ok_or_else(|| anyhow::anyhow!("kopia restore produced no stdout"))
        };

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let stdout = spawn_restore()?;

                    let writer = tokio_util::io::SyncIoBridge::new(writer);
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    let mut subtar = tar::Archive::new(stdout);
                    let entries = subtar.entries()?;

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    for entry in entries {
                        let mut entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();
                        if relative.as_os_str().is_empty() || relative.as_os_str() == "." {
                            continue;
                        }

                        let file_type = match header.entry_type() {
                            tar::EntryType::Directory => FileType::Dir,
                            tar::EntryType::Symlink => FileType::Symlink,
                            tar::EntryType::Regular => FileType::File,
                            _ => continue,
                        };

                        let absolute_path = base_path.join(&relative);
                        if (is_ignored)(file_type, absolute_path).is_none() {
                            continue;
                        }

                        let mode =
                            header
                                .mode()
                                .unwrap_or(if file_type.is_dir() { 0o755 } else { 0o644 });
                        let size = header.size().unwrap_or(0);

                        let mut options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .unix_permissions(mode)
                                .large_file(size >= u32::MAX as u64);

                        if let Ok(mtime) = header.mtime()
                            && let Some(mtime) = chrono::DateTime::from_timestamp(mtime as i64, 0)
                        {
                            options =
                                options.last_modified_time(zip::DateTime::from_date_and_time(
                                    mtime.year() as u16,
                                    mtime.month() as u8,
                                    mtime.day() as u8,
                                    mtime.hour() as u8,
                                    mtime.minute() as u8,
                                    mtime.second() as u8,
                                )?);
                        }

                        match file_type {
                            FileType::Dir => {
                                zip.add_directory(relative.to_string_lossy(), options)?;
                            }
                            FileType::File => {
                                zip.start_file(relative.to_string_lossy(), options)?;
                                progress.increment_files();

                                loop {
                                    let bytes_read = entry.read_uninterrupted(&mut read_buffer)?;
                                    if crate::unlikely(bytes_read == 0) {
                                        break;
                                    }
                                    zip.safe_write_all(&read_buffer, bytes_read)?;
                                    progress.increment_bytes(bytes_read as u64);
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
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let stdout = spawn_restore()?;

                    let writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        threads,
                    )?;
                    let mut tar = tar::Builder::new(writer);

                    let mut subtar = tar::Archive::new(stdout);
                    let entries = subtar.entries()?;

                    for entry in entries {
                        let entry = entry?;
                        let mut header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();
                        if relative.as_os_str().is_empty() || relative.as_os_str() == "." {
                            continue;
                        }

                        let file_type = match header.entry_type() {
                            tar::EntryType::Directory => FileType::Dir,
                            tar::EntryType::Symlink => FileType::Symlink,
                            tar::EntryType::Regular => FileType::File,
                            _ => continue,
                        };

                        let absolute_path = base_path.join(&relative);
                        if (is_ignored)(file_type, absolute_path).is_none() {
                            continue;
                        }

                        if file_type.is_file() {
                            let reader = progress.counting_reader(entry);
                            tar.append_data(&mut header, relative, reader)?;
                            progress.increment_files();
                        } else {
                            tar.append_data(&mut header, relative, std::io::empty())?;
                            if file_type.is_symlink() {
                                progress.increment_files();
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
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported archive format for kopia backups: {}",
                    archive_format.extension()
                ));
            }
        }

        Ok(reader)
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
