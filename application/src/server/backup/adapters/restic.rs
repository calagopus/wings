use crate::{
    io::{
        SafeSliceExt, SafeWriteExt, UninterruptedReadExt,
        compression::{CompressionLevel, writer::CompressionWriter},
    },
    models::DirectoryEntry,
    remote::backups::{RawServerBackup, ResticBackupConfiguration},
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
    utils::{CmpExt, PortablePermissions, StdoutTakeExt, TokioStdoutTakeExt},
};
use chrono::{Datelike, Timelike};
use compact_str::{CompactString, ToCompactString};
use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use serde::Deserialize;
use serde_default::DefaultFromSerde;
use std::{
    collections::HashMap,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{io::AsyncBufReadExt, process::Command, sync::RwLock};

type ResticBackupCache =
    RwLock<HashMap<uuid::Uuid, (ResticSnapshot, Arc<ResticBackupConfiguration>)>>;
static RESTIC_BACKUP_CACHE: LazyLock<ResticBackupCache> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

const RESTIC_STDERR_CAPTURE_LIMIT: usize = 8 * 1024;
const MAX_TREE_DEPTH: usize = 1024;
const MAX_BROWSE_ENTRIES: usize = 10_000_000;

#[derive(Debug, Deserialize)]
struct ResticSnapshot {
    short_id: String,
    tags: Vec<compact_str::CompactString>,
    paths: Vec<compact_str::CompactString>,
    #[serde(default)]
    summary: ResticSnapshotSummary,
}

#[derive(Debug, Deserialize, DefaultFromSerde)]
struct ResticSnapshotSummary {
    #[serde(default)]
    total_bytes_processed: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ResticEntryType {
    File,
    Dir,
    Symlink,
}

#[derive(Deserialize)]
pub struct ResticDirectoryEntry {
    r#type: ResticEntryType,
    path: PathBuf,
    mode: u32,
    size: Option<u64>,
    mtime: chrono::DateTime<chrono::Utc>,
}

struct ResticFileMeta {
    file_type: FileType,
    mode: u32,
    size: u64,
    mtime: chrono::DateTime<chrono::Utc>,
}

#[derive(Default)]
pub struct ResticTreeNode {
    size: u64,
    mtime: chrono::DateTime<chrono::Utc>,
    mode: u32,
    has_explicit_entry: bool,
    dirs: thin_vec::ThinVec<(CompactString, ResticTreeNode)>,
    files: thin_vec::ThinVec<(CompactString, ResticFileMeta)>,
}

// drops the tree iteratively, recursive dropping would overflow the stack on deeply nested trees
impl Drop for ResticTreeNode {
    fn drop(&mut self) {
        while let Some((_, mut node)) = self.dirs.pop() {
            self.dirs.append(&mut node.dirs);
        }
    }
}

impl ResticTreeNode {
    fn build(entries: Vec<ResticDirectoryEntry>) -> Self {
        let mut root = ResticTreeNode::default();

        for entry in entries {
            root.insert(entry);
        }
        root.sort_files();
        root.aggregate_sizes();
        root
    }

    fn insert(&mut self, entry: ResticDirectoryEntry) {
        let mut components: Vec<&str> = Vec::new();
        for component in entry.path.components() {
            let Component::Normal(name) = component else {
                return;
            };
            let Some(name) = name.to_str() else {
                return;
            };

            components.push(name);
        }

        if components.is_empty() || components.len() > MAX_TREE_DEPTH {
            return;
        }

        match entry.r#type {
            ResticEntryType::Dir => {
                let node = self.upsert_dir_path(&components);
                node.has_explicit_entry = true;
                node.mtime = entry.mtime;
                node.mode = entry.mode;
            }
            ResticEntryType::File | ResticEntryType::Symlink => {
                let (leaf, parents) = match components.split_last() {
                    Some(v) => v,
                    None => return,
                };

                let parent = self.upsert_dir_path(parents);
                let meta = ResticFileMeta {
                    file_type: match entry.r#type {
                        ResticEntryType::File => FileType::File,
                        ResticEntryType::Symlink => FileType::Symlink,
                        ResticEntryType::Dir => FileType::Dir,
                    },
                    mode: entry.mode,
                    size: entry.size.unwrap_or(0),
                    mtime: entry.mtime,
                };

                parent.files.push((leaf.to_compact_string(), meta));
            }
        }
    }

    fn sort_files(&mut self) {
        self.files.reverse();
        self.files.sort_by(|(a, _), (b, _)| a.cmp(b));
        self.files.dedup_by(|(a, _), (b, _)| a == b);
        for (_, child) in self.dirs.iter_mut() {
            child.sort_files();
        }
    }

    fn upsert_dir_path(&mut self, components: &[&str]) -> &mut ResticTreeNode {
        let mut current = self;
        for name in components {
            let idx = match current.dirs.binary_search_by(|(n, _)| n.as_str().cmp(name)) {
                Ok(idx) => idx,
                Err(idx) => {
                    current
                        .dirs
                        .insert(idx, (name.to_compact_string(), ResticTreeNode::default()));
                    idx
                }
            };
            // SAFETY: `idx` is guaranteed to be a valid index into `current.dirs` due to the logic above.
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

    fn lookup_dir(&self, path: &Path) -> Option<&ResticTreeNode> {
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

    fn lookup_file(&self, path: &Path) -> Option<&ResticFileMeta> {
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

pub struct ResticBackup {
    uuid: uuid::Uuid,
    short_id: String,
    total_bytes_processed: u64,

    config: Arc<crate::config::Config>,
    server_path: PathBuf,
    configuration: Arc<ResticBackupConfiguration>,
}

impl ResticBackup {
    pub fn get_restic_cache_dir(config: &crate::config::Config) -> String {
        config.resolve_as_str(|cfg| &cfg.system.backup_directory) + "/.cache/restic"
    }

    fn spawn_stderr_capture(
        stderr: tokio::process::ChildStderr,
    ) -> tokio::task::JoinHandle<String> {
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stderr);
            let mut output = String::new();
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        if output.len() < RESTIC_STDERR_CAPTURE_LIMIT {
                            output.push_str(&line);
                        }
                    }
                    Err(_) => break,
                }
            }

            output
        })
    }
}

#[async_trait::async_trait]
impl BackupFindExt for ResticBackup {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error> {
        if RESTIC_BACKUP_CACHE.read().await.contains_key(&uuid) {
            return Ok(true);
        }

        if tokio::fs::metadata(
            state
                .config
                .resolve_as_path(|cfg| &cfg.system.backups.restic.password_file),
        )
        .await
        .is_ok()
        {
            let config = state.config.load();
            let output = match Command::new("restic")
                .envs(&config.system.backups.restic.environment)
                .arg("--json")
                .arg("--no-lock")
                .arg("--repo")
                .arg(&*config.system.backups.restic.repository.as_str(&config))
                .arg("--password-file")
                .arg(&*config.system.backups.restic.password_file.as_str(&config))
                .arg("--cache-dir")
                .arg(Self::get_restic_cache_dir(&state.config))
                .arg("snapshots")
                .output()
                .await
            {
                Ok(output) => output,
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "failed to check restic backup existence: {:#?}",
                        err
                    ));
                }
            };

            if output.status.success() {
                let snapshots: Vec<ResticSnapshot> =
                    serde_json::from_slice(&output.stdout).unwrap_or_default();
                let configuration = {
                    let config = state.config.load();

                    Arc::new(ResticBackupConfiguration {
                        repository: config
                            .system
                            .backups
                            .restic
                            .repository
                            .as_str(&config)
                            .into(),
                        password_file: Some(
                            config
                                .system
                                .backups
                                .restic
                                .password_file
                                .as_str(&config)
                                .into(),
                        ),
                        retry_lock_seconds: config.system.backups.restic.retry_lock_seconds,
                        environment: config.system.backups.restic.environment.clone(),
                    })
                };

                let mut found = false;
                let mut cache = RESTIC_BACKUP_CACHE.write().await;
                for snapshot in snapshots {
                    let snapshot_uuid = match snapshot.tags.first() {
                        Some(tag) => match uuid::Uuid::parse_str(tag) {
                            Ok(uuid) => uuid,
                            Err(_) => continue,
                        },
                        _ => continue,
                    };

                    if snapshot_uuid == uuid {
                        found = true;
                    }

                    cache.insert(snapshot_uuid, (snapshot, Arc::clone(&configuration)));
                }
                drop(cache);

                if found {
                    return Ok(true);
                }
            }
        }

        if let Ok(configuration) = state.config.client.backup_restic_configuration(uuid).await {
            let output = match Command::new("restic")
                .envs(&configuration.environment)
                .arg("--json")
                .arg("--no-lock")
                .arg("--repo")
                .arg(&configuration.repository)
                .arg("--cache-dir")
                .arg(Self::get_restic_cache_dir(&state.config))
                .arg("snapshots")
                .output()
                .await
            {
                Ok(output) => output,
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "failed to check restic backup existence: {:#?}",
                        err
                    ));
                }
            };

            if output.status.success() {
                let snapshots: Vec<ResticSnapshot> =
                    serde_json::from_slice(&output.stdout).unwrap_or_default();
                let configuration = Arc::new(configuration.clone());

                let mut found = false;
                let mut cache = RESTIC_BACKUP_CACHE.write().await;
                for snapshot in snapshots {
                    let snapshot_uuid = match snapshot.tags.first() {
                        Some(tag) => match uuid::Uuid::parse_str(tag) {
                            Ok(uuid) => uuid,
                            Err(_) => continue,
                        },
                        _ => continue,
                    };

                    if snapshot_uuid == uuid {
                        found = true;
                    }

                    cache.insert(snapshot_uuid, (snapshot, Arc::clone(&configuration)));
                }
                drop(cache);

                if found {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        if let Some((snapshot, configuration)) = RESTIC_BACKUP_CACHE.read().await.get(&uuid) {
            return Ok(Some(Backup::Restic(ResticBackup {
                uuid,
                short_id: snapshot.short_id.clone(),
                total_bytes_processed: snapshot.summary.total_bytes_processed,
                config: Arc::clone(&state.config),
                server_path: match snapshot.paths.first() {
                    Some(path) => PathBuf::from(path),
                    None => {
                        return Err(anyhow::anyhow!(
                            "no paths found in restic snapshot for uuid: {}",
                            uuid
                        ));
                    }
                },
                configuration: Arc::clone(configuration),
            })));
        }

        if tokio::fs::metadata(
            state
                .config
                .resolve_as_path(|cfg| &cfg.system.backups.restic.password_file),
        )
        .await
        .is_ok()
        {
            let config = state.config.load();
            let output = match Command::new("restic")
                .envs(&config.system.backups.restic.environment)
                .arg("--json")
                .arg("--no-lock")
                .arg("--repo")
                .arg(&*config.system.backups.restic.repository.as_str(&config))
                .arg("--password-file")
                .arg(&*config.system.backups.restic.password_file.as_str(&config))
                .arg("--cache-dir")
                .arg(Self::get_restic_cache_dir(&state.config))
                .arg("snapshots")
                .output()
                .await
            {
                Ok(output) => output,
                Err(err) => {
                    return Err(anyhow::anyhow!("failed to find restic backup: {:?}", err));
                }
            };

            if output.status.success() {
                let snapshots: Vec<ResticSnapshot> =
                    serde_json::from_slice(&output.stdout).unwrap_or_default();
                let configuration = {
                    let config = state.config.load();

                    Arc::new(ResticBackupConfiguration {
                        repository: config
                            .system
                            .backups
                            .restic
                            .repository
                            .as_str(&config)
                            .into(),
                        password_file: Some(
                            config
                                .system
                                .backups
                                .restic
                                .password_file
                                .as_str(&config)
                                .into(),
                        ),
                        retry_lock_seconds: config.system.backups.restic.retry_lock_seconds,
                        environment: config.system.backups.restic.environment.clone(),
                    })
                };

                let mut backup = None;
                let mut cache = RESTIC_BACKUP_CACHE.write().await;
                for snapshot in snapshots {
                    let snapshot_uuid = match snapshot.tags.first() {
                        Some(tag) => match uuid::Uuid::parse_str(tag) {
                            Ok(uuid) => uuid,
                            Err(_) => continue,
                        },
                        _ => continue,
                    };

                    if snapshot_uuid == uuid {
                        backup = Some(ResticBackup {
                            uuid,
                            short_id: snapshot.short_id.clone(),
                            total_bytes_processed: snapshot.summary.total_bytes_processed,
                            config: Arc::clone(&state.config),
                            server_path: match snapshot.paths.first() {
                                Some(path) => PathBuf::from(path),
                                None => {
                                    return Err(anyhow::anyhow!(
                                        "no paths found in restic snapshot for uuid: {}",
                                        uuid
                                    ));
                                }
                            },
                            configuration: Arc::clone(&configuration),
                        });
                    }

                    cache.insert(snapshot_uuid, (snapshot, Arc::clone(&configuration)));
                }
                drop(cache);

                if let Some(backup) = backup {
                    return Ok(Some(Backup::Restic(backup)));
                }
            }
        }

        if let Ok(configuration) = state.config.client.backup_restic_configuration(uuid).await {
            let output = match Command::new("restic")
                .envs(&configuration.environment)
                .arg("--json")
                .arg("--no-lock")
                .arg("--repo")
                .arg(&configuration.repository)
                .arg("--cache-dir")
                .arg(Self::get_restic_cache_dir(&state.config))
                .arg("snapshots")
                .output()
                .await
            {
                Ok(output) => output,
                Err(err) => {
                    return Err(anyhow::anyhow!("failed to find restic backup: {:?}", err));
                }
            };

            if output.status.success() {
                let snapshots: Vec<ResticSnapshot> =
                    serde_json::from_slice(&output.stdout).unwrap_or_default();
                let configuration = Arc::new(configuration.clone());

                let mut backup = None;
                let mut cache = RESTIC_BACKUP_CACHE.write().await;
                for snapshot in snapshots {
                    let snapshot_uuid = match snapshot.tags.first() {
                        Some(tag) => match uuid::Uuid::parse_str(tag) {
                            Ok(uuid) => uuid,
                            Err(_) => continue,
                        },
                        _ => continue,
                    };

                    if snapshot_uuid == uuid {
                        backup = Some(ResticBackup {
                            uuid,
                            short_id: snapshot.short_id.clone(),
                            total_bytes_processed: snapshot.summary.total_bytes_processed,
                            config: Arc::clone(&state.config),
                            server_path: match snapshot.paths.first() {
                                Some(path) => PathBuf::from(path),
                                None => {
                                    return Err(anyhow::anyhow!(
                                        "no paths found in restic snapshot for uuid: {}",
                                        uuid
                                    ));
                                }
                            },
                            configuration: Arc::clone(&configuration),
                        });
                    }

                    cache.insert(snapshot_uuid, (snapshot, Arc::clone(&configuration)));
                }
                drop(cache);

                if let Some(backup) = backup {
                    return Ok(Some(Backup::Restic(backup)));
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl BackupCreateExt for ResticBackup {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        _ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let mut excluded_paths = Vec::new();
        for line in ignore_raw.lines() {
            excluded_paths.push("--exclude");
            excluded_paths.push(line);
        }

        let (mut child, configuration) = if tokio::fs::metadata(
            server
                .app_state
                .config
                .resolve_as_path(|cfg| &cfg.system.backups.restic.password_file),
        )
        .await
        .is_ok()
        {
            let config = server.app_state.config.load();

            (
                Command::new("restic")
                    .envs(&config.system.backups.restic.environment)
                    .arg("--json")
                    .arg("--repo")
                    .arg(&*config.system.backups.restic.repository.as_str(&config))
                    .arg("--password-file")
                    .arg(&*config.system.backups.restic.password_file.as_str(&config))
                    .arg("--cache-dir")
                    .arg(Self::get_restic_cache_dir(&server.app_state.config))
                    .arg("--retry-lock")
                    .arg(format!(
                        "{}s",
                        config.system.backups.restic.retry_lock_seconds
                    ))
                    .arg("backup")
                    .arg(&server.filesystem.base_path)
                    .args(&excluded_paths)
                    .arg("--tag")
                    .arg(uuid.to_string())
                    .arg("--group-by")
                    .arg("tags")
                    .arg("--limit-download")
                    .arg((config.system.backups.read_limit.as_kib()).to_compact_string())
                    .arg("--limit-upload")
                    .arg((config.system.backups.write_limit.as_kib()).to_compact_string())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?,
                ResticBackupConfiguration {
                    repository: config
                        .system
                        .backups
                        .restic
                        .repository
                        .as_str(&config)
                        .into(),
                    password_file: Some(
                        config
                            .system
                            .backups
                            .restic
                            .password_file
                            .as_str(&config)
                            .into(),
                    ),
                    retry_lock_seconds: config.system.backups.restic.retry_lock_seconds,
                    environment: config.system.backups.restic.environment.clone(),
                },
            )
        } else {
            let configuration = server
                .app_state
                .config
                .client
                .backup_restic_configuration(uuid)
                .await?;

            (
                Command::new("restic")
                    .envs(&configuration.environment)
                    .arg("--json")
                    .arg("--repo")
                    .arg(&configuration.repository)
                    .arg("--cache-dir")
                    .arg(Self::get_restic_cache_dir(&server.app_state.config))
                    .arg("--retry-lock")
                    .arg(format!("{}s", configuration.retry_lock_seconds))
                    .arg("backup")
                    .arg(&server.filesystem.base_path)
                    .args(&excluded_paths)
                    .arg("--tag")
                    .arg(uuid.to_string())
                    .arg("--group-by")
                    .arg("tags")
                    .arg("--limit-download")
                    .arg(
                        (server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .read_limit
                            .as_kib())
                        .to_compact_string(),
                    )
                    .arg("--limit-upload")
                    .arg(
                        (server
                            .app_state
                            .config
                            .load()
                            .system
                            .backups
                            .write_limit
                            .as_kib())
                        .to_compact_string(),
                    )
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?,
                configuration,
            )
        };

        let mut line_reader = tokio::io::BufReader::new(child.take_stdout()?).lines();

        let mut snapshot_id = None;
        let mut total_bytes_processed = 0;
        let mut total_files_processed = 0;

        while let Ok(Some(line)) = line_reader.next_line().await {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&line) {
                if json.get("message_type").and_then(|v| v.as_str()) == Some("status") {
                    let bytes_done = json.get("bytes_done").and_then(|v| v.as_u64()).unwrap_or(0);
                    let total_bytes = json
                        .get("total_bytes")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    progress.store_bytes(bytes_done);
                    total.store(total_bytes, Ordering::Relaxed);

                    let files_done = json.get("files_done").and_then(|v| v.as_u64()).unwrap_or(0);
                    progress.store_files(files_done);
                } else if json.get("message_type").and_then(|v| v.as_str()) == Some("summary") {
                    total_bytes_processed = json
                        .get("total_bytes_processed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    total_files_processed = json
                        .get("total_files_processed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    progress.store_files(total_files_processed);

                    snapshot_id = json
                        .get("snapshot_id")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create Restic backup for {}: {}",
                server.filesystem.base_path.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        if let Some(snapshot_id) = &snapshot_id {
            let mut cache = RESTIC_BACKUP_CACHE.write().await;
            cache.insert(
                uuid,
                (
                    ResticSnapshot {
                        short_id: snapshot_id.clone(),
                        tags: vec![uuid.to_compact_string()],
                        paths: vec![server.filesystem.base_path.to_string_lossy().into()],
                        summary: ResticSnapshotSummary {
                            total_bytes_processed,
                        },
                    },
                    Arc::new(configuration),
                ),
            );
        }

        Ok(RawServerBackup {
            checksum: snapshot_id.unwrap_or_else(|| "unknown".to_string()),
            checksum_type: "restic".into(),
            size: total_bytes_processed,
            files: total_files_processed,
            successful: true,
            browsable: true,
            streaming: true,
            parts: vec![],
        })
    }
}

#[async_trait::async_trait]
impl BackupExt for ResticBackup {
    #[inline]
    fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    async fn download(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        _range: Option<ByteRange>,
    ) -> Result<crate::response::ApiResponse, anyhow::Error> {
        let compression_level = state.config.load().system.backups.compression_level;
        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

        match archive_format {
            StreamableArchiveFormat::Zip => {
                let child = tokio::task::block_in_place(|| {
                    std::process::Command::new("restic")
                        .envs(&self.configuration.environment)
                        .arg("--json")
                        .arg("--no-lock")
                        .arg("--repo")
                        .arg(&self.configuration.repository)
                        .args(self.configuration.password())
                        .arg("--cache-dir")
                        .arg(Self::get_restic_cache_dir(&state.config))
                        .arg("dump")
                        .arg(format!("{}:{}", self.short_id, self.server_path.display()))
                        .arg("/")
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                })?;

                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = tokio_util::io::SyncIoBridge::new(writer);
                    let mut archive = zip::ZipWriter::new_stream(writer);

                    let mut subtar = tar::Archive::new(child.into_stdout()?);
                    let entries = subtar.entries()?;

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    for entry in entries {
                        let mut entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?;

                        let mut options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .unix_permissions(header.mode()?)
                                .large_file(header.size()? >= u32::MAX as u64);
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
                let child = tokio::task::block_in_place(|| {
                    std::process::Command::new("restic")
                        .envs(&self.configuration.environment)
                        .arg("--json")
                        .arg("--no-lock")
                        .arg("--repo")
                        .arg(&self.configuration.repository)
                        .args(self.configuration.password())
                        .arg("--cache-dir")
                        .arg(Self::get_restic_cache_dir(&self.config))
                        .arg("dump")
                        .arg(format!("{}:{}", self.short_id, self.server_path.display()))
                        .arg("/")
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                })?;

                let file_compression_threads = self.config.load().api.file_compression_threads;
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let mut writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;

                    if let Err(err) = crate::io::copy(&mut child.into_stdout()?, &mut writer) {
                        tracing::error!(
                            "failed to compress tar archive for restic backup: {}",
                            err
                        );
                    }

                    let mut inner = writer.finish()?;
                    inner.flush()?;
                    inner.shutdown()?;

                    Ok(())
                });
            }
            f if f.is_itaf() => {
                let child = tokio::task::block_in_place(|| {
                    std::process::Command::new("restic")
                        .envs(&self.configuration.environment)
                        .arg("--json")
                        .arg("--no-lock")
                        .arg("--repo")
                        .arg(&self.configuration.repository)
                        .args(self.configuration.password())
                        .arg("--cache-dir")
                        .arg(Self::get_restic_cache_dir(&self.config))
                        .arg("dump")
                        .arg(format!("{}:{}", self.short_id, self.server_path.display()))
                        .arg("/")
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                })?;

                let file_compression_threads = self.config.load().api.file_compression_threads;
                crate::spawn_blocking_handled(move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;
                    let mut itaf_enc = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;

                    let mut dir_stack = Vec::new();
                    let mut restic_tar = tar::Archive::new(child.into_stdout()?);
                    let entries = restic_tar.entries()?;

                    for entry in entries {
                        let entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();

                        if relative.as_os_str() == "." {
                            continue;
                        }

                        let components: Vec<_> = relative
                            .components()
                            .filter_map(|c| match c {
                                std::path::Component::Normal(s) => Some(s.to_string_lossy()),
                                _ => None,
                            })
                            .collect();
                        let Some(name) = components.last() else {
                            continue;
                        };

                        let is_dir = header.entry_type() == tar::EntryType::Directory;
                        let parent = components.get_slice(..components.len() - 1)?;

                        let mode = header.mode().unwrap_or(if is_dir { 0o755 } else { 0o644 });
                        let mtime = header
                            .mtime()
                            .map(|t| std::time::UNIX_EPOCH + std::time::Duration::from_secs(t))
                            .unwrap_or_else(|_| std::time::SystemTime::now());
                        let meta = Metadata {
                            uid: 0,
                            gid: 0,
                            mode,
                            modified: mtime,
                        };

                        let shared = dir_stack
                            .iter()
                            .zip(parent.iter())
                            .take_while(|(a, b)| a == b)
                            .count();
                        while dir_stack.len() > shared {
                            itaf_enc.exit_dir()?;
                            dir_stack.pop();
                        }

                        for component in parent.get_slice(shared..)? {
                            itaf_enc.enter_dir(
                                component,
                                &Metadata {
                                    uid: 0,
                                    gid: 0,
                                    mode: 0o755,
                                    modified: std::time::SystemTime::now(),
                                },
                            )?;
                            dir_stack.push(component.to_compact_string());
                        }

                        match header.entry_type() {
                            tar::EntryType::Directory => {
                                itaf_enc.enter_dir(name, &meta)?;
                                dir_stack.push(name.to_compact_string());
                            }
                            tar::EntryType::Regular => {
                                let size = header.size().unwrap_or(0);
                                let mut reader =
                                    crate::io::fixed_reader::FixedReader::new_with_fixed_bytes(
                                        entry,
                                        size as usize,
                                    );

                                itaf_enc.add_file(name, &meta, size, &mut reader)?;
                            }
                            tar::EntryType::Symlink => {
                                let link =
                                    entry.link_name().unwrap_or_default().unwrap_or_default();
                                let target = link.to_string_lossy();
                                if itaf::spec::validate_name(name).is_ok() {
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
                tracing::error!(
                    "unsupported archive format for restic backup download: {}",
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
        total.store(self.total_bytes_processed, Ordering::Relaxed);

        let mut child = Command::new("restic")
            .envs(&self.configuration.environment)
            .arg("--json")
            .arg("--no-lock")
            .arg("--repo")
            .arg(&self.configuration.repository)
            .args(self.configuration.password())
            .arg("--cache-dir")
            .arg(Self::get_restic_cache_dir(&server.app_state.config))
            .arg("restore")
            .arg(format!("{}:{}", self.short_id, self.server_path.display()))
            .arg("--target")
            .arg(&server.filesystem.base_path)
            .arg("--limit-download")
            .arg(
                (server
                    .app_state
                    .config
                    .load()
                    .system
                    .backups
                    .read_limit
                    .as_kib())
                .to_compact_string(),
            )
            .arg("-vv")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child.take_stdout()?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("No stderr available"))?;
        let mut line_reader = tokio::io::BufReader::new(stdout).lines();

        let stderr_task = Self::spawn_stderr_capture(stderr);

        while let Ok(Some(line)) = line_reader.next_line().await {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&line)
                && json.get("message_type").and_then(|v| v.as_str()) == Some("verbose_status")
            {
                let Some(item) = json.get("item").and_then(|v| v.as_str()) else {
                    continue;
                };
                let size = json.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

                if size == 0 {
                    continue;
                }

                progress.store_bytes(size);
                progress.increment_files();

                server.log_daemon(compact_str::format_compact!("(restoring): {}", item));
            }
        }

        let status = child.wait().await?;
        let stderr_output = stderr_task.await.unwrap_or_default();

        if !status.success() {
            let mut message = compact_str::CompactString::from("failed to restore restic backup");
            if !stderr_output.is_empty() {
                message.push_str(":\n");
                message.push_str(stderr_output.trim_end());
            }
            return Err(anyhow::anyhow!("{}", message));
        }

        server.filesystem.rerun_disk_checker();

        Ok(())
    }

    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        let output = Command::new("restic")
            .envs(&self.configuration.environment)
            .arg("--repo")
            .arg(&self.configuration.repository)
            .args(self.configuration.password())
            .arg("--cache-dir")
            .arg(Self::get_restic_cache_dir(&self.config))
            .arg("--retry-lock")
            .arg(format!("{}s", self.configuration.retry_lock_seconds))
            .arg("forget")
            .arg(&self.short_id)
            .arg("--group-by")
            .arg("tags")
            .arg("--prune")
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to delete restic backup: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut cache = RESTIC_BACKUP_CACHE.write().await;
        cache.remove(&self.uuid);

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
        let mut child = Command::new("restic")
            .envs(&self.configuration.environment)
            .arg("--json")
            .arg("--repo")
            .arg(&self.configuration.repository)
            .args(self.configuration.password())
            .arg("--cache-dir")
            .arg(Self::get_restic_cache_dir(&self.config))
            .arg("--retry-lock")
            .arg(format!("{}s", self.configuration.retry_lock_seconds))
            .arg("ls")
            .arg(format!("{}:{}", self.short_id, self.server_path.display()))
            .arg("/")
            .arg("--recursive")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("No stderr available"))?;

        let stderr_task = Self::spawn_stderr_capture(stderr);

        let mut entries = Vec::new();
        let mut truncated = false;

        if let Some(stdout) = child.stdout.take() {
            let mut line_reader = tokio::io::BufReader::new(stdout).lines();

            while let Ok(Some(line)) = line_reader.next_line().await {
                if line.is_empty() {
                    continue;
                }

                if entries.len() >= MAX_BROWSE_ENTRIES {
                    if !truncated {
                        truncated = true;

                        tracing::warn!(
                            "restic snapshot listing exceeds {MAX_BROWSE_ENTRIES} entries, truncating backup browse tree"
                        );
                    }

                    continue;
                }

                if let Ok(mut entry) = serde_json::from_str::<ResticDirectoryEntry>(&line) {
                    entry.path = entry
                        .path
                        .strip_prefix(Path::new("/"))
                        .unwrap_or(&entry.path)
                        .to_owned();

                    entries.push(entry);
                }
            }
        }

        let status = child.wait().await?;
        let stderr_out = stderr_task.await.unwrap_or_default();

        if !status.success() {
            tracing::error!(
                "failed to list Restic snapshot for browsing: {}",
                stderr_out.trim()
            );
        }

        let tree = tokio::task::block_in_place(|| ResticTreeNode::build(entries));

        Ok(Arc::new(VirtualResticBackup {
            server: server.clone(),
            short_id: self.short_id.clone(),
            server_path: self.server_path.clone(),
            configuration: Arc::clone(&self.configuration),
            tree: Arc::new(tree),
        }))
    }
}

#[async_trait::async_trait]
impl BackupCleanExt for ResticBackup {
    async fn clean(
        _server: &crate::server::Server,
        _uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub struct VirtualResticBackup {
    pub server: crate::server::Server,
    pub short_id: String,
    pub server_path: PathBuf,
    pub configuration: Arc<ResticBackupConfiguration>,
    pub tree: Arc<ResticTreeNode>,
}

impl VirtualResticBackup {
    fn directory_entry_from_dir_node(path: &Path, node: &ResticTreeNode) -> DirectoryEntry {
        let detected_mime = MimeCacheValue::directory();
        let mode = if node.mode != 0 { node.mode } else { 0o755 };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(mode),
            mode_bits: compact_str::format_compact!("{:o}", mode & 0o777),
            size: node.size,
            size_physical: node.size,
            editable: false,
            inner_editable: false,
            directory: true,
            file: false,
            symlink: false,
            r#virtual: true,
            mime: detected_mime.mime,
            modified: node.mtime,
            created: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
        }
    }

    fn directory_entry_from_file_meta(
        path: &Path,
        meta: &ResticFileMeta,
        buffer: Option<&[u8]>,
    ) -> DirectoryEntry {
        let detected_mime = if meta.file_type.is_symlink() {
            MimeCacheValue::symlink()
        } else if meta.file_type.is_file() && meta.size == 0 {
            MimeCacheValue::text()
        } else {
            crate::utils::detect_mime_type(path, buffer)
        };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(meta.mode),
            mode_bits: compact_str::format_compact!("{:o}", meta.mode & 0o777),
            size: meta.size,
            size_physical: meta.size,
            editable: meta.file_type.is_file() && detected_mime.valid_utf8,
            inner_editable: meta.file_type.is_file() && detected_mime.valid_inner_utf8,
            directory: false,
            file: meta.file_type.is_file(),
            symlink: meta.file_type.is_symlink(),
            r#virtual: true,
            mime: detected_mime.mime,
            modified: meta.mtime,
            created: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
        }
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualResticBackup {
    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let path_ref = path.as_ref();

        if path_ref == Path::new("") || path_ref == Path::new("/") {
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(0o755),
                size: 0,
                modified: None,
                created: None,
            });
        }

        if let Some(node) = self.tree.lookup_dir(path_ref) {
            let mode = if node.mode != 0 { node.mode } else { 0o755 };
            let modified = if node.has_explicit_entry {
                Some(node.mtime.into())
            } else {
                None
            };
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(mode),
                size: 0,
                modified,
                created: None,
            });
        }

        if let Some(meta) = self.tree.lookup_file(path_ref) {
            return Ok(FileMetadata {
                file_type: meta.file_type,
                permissions: PortablePermissions::from_mode_file(meta.mode),
                size: meta.size,
                modified: Some(meta.mtime.into()),
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
        let path_ref = path.as_ref();

        if let Some(node) = self.tree.lookup_dir(path_ref) {
            return Ok(Self::directory_entry_from_dir_node(path_ref, node));
        }
        if let Some(meta) = self.tree.lookup_file(path_ref) {
            return Ok(Self::directory_entry_from_file_meta(path_ref, meta, None));
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
        let path_ref = path.as_ref();

        if let Some(node) = self.tree.lookup_dir(path_ref) {
            return Ok(Self::directory_entry_from_dir_node(path_ref, node));
        }
        if let Some(meta) = self.tree.lookup_file(path_ref) {
            return Ok(Self::directory_entry_from_file_meta(
                path_ref,
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
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        use crate::models::DirectorySortingMode::*;

        let path = path.as_ref().to_path_buf();
        let node = match self.tree.lookup_dir(&path) {
            Some(n) => n,
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
                node: &'a ResticTreeNode,
            },
            File {
                path: PathBuf,
                meta: &'a ResticFileMeta,
            },
        }

        let mut dir_children: Vec<Child<'_>> = Vec::new();
        let mut file_children: Vec<Child<'_>> = Vec::new();

        for (name, child_node) in node.dirs.iter() {
            let child_path = match is_ignored
                .call_async(FileType::Dir, path.join(name.as_str()))
                .await
            {
                Some(kept) => kept,
                None => continue,
            };
            dir_children.push(Child::Dir {
                path: child_path,
                node: child_node,
            });
        }
        for (name, meta) in node.files.iter() {
            let child_path = match is_ignored
                .call_async(meta.file_type, path.join(name.as_str()))
                .await
            {
                Some(kept) => kept,
                None => continue,
            };
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
            let start = (page - 1) * per_page;
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

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let start = self.tree.lookup_dir(path.as_ref());
        let mut flat: Vec<(FileType, PathBuf)> = Vec::new();

        if let Some(start) = start {
            fn walk(
                node: &ResticTreeNode,
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

        impl DirectoryWalk for TreeWalk {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.items.next().map(Ok)
            }
        }

        Ok(Box::new(TreeWalk {
            items: flat.into_iter(),
        }))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let start = self.tree.lookup_dir(path.as_ref());
        let mut flat: Vec<(FileType, PathBuf)> = Vec::new();

        if let Some(start) = start {
            fn walk(
                node: &ResticTreeNode,
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
        impl AsyncDirectoryWalk for TreeWalk {
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
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        struct ResticDirStreamWalk {
            entry_wanted_notifier: Arc<tokio::sync::Notify>,
            entry_channel_rx: tokio::sync::mpsc::Receiver<
                Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>,
            >,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryStreamWalk for ResticDirStreamWalk {
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

        let root_path = path.as_ref().to_path_buf();
        let mut top_entries: Vec<(FileType, PathBuf)> = Vec::new();
        if let Some(node) = self.tree.lookup_dir(&root_path) {
            for (name, _child) in node.dirs.iter() {
                top_entries.push((FileType::Dir, root_path.join(name.as_str())));
            }
            for (name, meta) in node.files.iter() {
                top_entries.push((meta.file_type, root_path.join(name.as_str())));
            }
        }

        let entry_wanted_notifier = Arc::new(tokio::sync::Notify::new());
        let (entry_channel_tx, entry_channel_rx) = tokio::sync::mpsc::channel(1);

        crate::spawn_handled({
            let entry_wanted_notifier = Arc::clone(&entry_wanted_notifier);
            let configuration = Arc::clone(&self.configuration);
            let config = self.server.app_state.config.clone();
            let short_id = self.short_id.clone();
            let server_path = self.server_path.clone();
            let is_ignored = is_ignored.clone();

            async move {
                let mut skip_notifier = false;
                for (file_type, entry_path) in top_entries {
                    if !skip_notifier {
                        entry_wanted_notifier.notified().await;
                    } else {
                        skip_notifier = false;
                    }

                    if let Some(path) = is_ignored.call_async(file_type, entry_path.clone()).await {
                        let full_path = server_path.join(&entry_path);

                        if file_type.is_dir() {
                            let child = tokio::task::block_in_place(|| {
                                std::process::Command::new("restic")
                                    .envs(&configuration.environment)
                                    .arg("--json")
                                    .arg("--no-lock")
                                    .arg("--repo")
                                    .arg(&configuration.repository)
                                    .args(configuration.password())
                                    .arg("--cache-dir")
                                    .arg(ResticBackup::get_restic_cache_dir(&config))
                                    .arg("dump")
                                    .arg(format!("{}:{}", short_id, full_path.display()))
                                    .arg("/")
                                    .stdout(std::process::Stdio::piped())
                                    .stderr(std::process::Stdio::null())
                                    .spawn()
                            })?;

                            let entry_channel_tx = entry_channel_tx.clone();
                            let entry_wanted_notifier = Arc::clone(&entry_wanted_notifier);
                            let is_ignored = is_ignored.clone();
                            tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                                let runtime = tokio::runtime::Handle::current();
                                let mut restic_tar = tar::Archive::new(child.into_stdout()?);
                                let entries = restic_tar.entries()?;

                                for entry in entries {
                                    let mut entry = entry?;
                                    let header = entry.header().clone();
                                    let relative = path.join(entry.path()?);

                                    let file_type = match header.entry_type() {
                                        tar::EntryType::Directory => FileType::Dir,
                                        tar::EntryType::Regular => FileType::File,
                                        tar::EntryType::Symlink => FileType::Symlink,
                                        _ => continue,
                                    };

                                    let Some(relative) = (is_ignored)(file_type, relative) else {
                                        continue;
                                    };

                                    let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);

                                    entry_channel_tx.blocking_send(Ok((
                                        file_type,
                                        relative,
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
                        } else {
                            let child = Command::new("restic")
                                .envs(&configuration.environment)
                                .arg("--json")
                                .arg("--no-lock")
                                .arg("--repo")
                                .arg(&configuration.repository)
                                .args(configuration.password())
                                .arg("--cache-dir")
                                .arg(ResticBackup::get_restic_cache_dir(&config))
                                .arg("dump")
                                .arg(format!("{}:{}", short_id, full_path.display()))
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::null())
                                .spawn()?;

                            entry_channel_tx
                                .send(Ok((
                                    file_type,
                                    path,
                                    Box::new(child.into_stdout()?) as AsyncReadableFileStream,
                                )))
                                .await?;
                        }
                    } else {
                        skip_notifier = true;
                        continue;
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        });

        entry_wanted_notifier.notify_one();

        Ok(Box::new(ResticDirStreamWalk {
            entry_wanted_notifier,
            entry_channel_rx,
        }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let entry = self.metadata(path)?;

        if !entry.file_type.is_file() {
            return Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            )));
        }

        let full_path = self.server_path.join(path);

        let child = std::process::Command::new("restic")
            .envs(&self.configuration.environment)
            .arg("--json")
            .arg("--no-lock")
            .arg("--repo")
            .arg(&self.configuration.repository)
            .args(self.configuration.password())
            .arg("--cache-dir")
            .arg(ResticBackup::get_restic_cache_dir(
                &self.server.app_state.config,
            ))
            .arg("dump")
            .arg(&self.short_id)
            .arg(full_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        Ok(FileRead {
            size: entry.size,
            total_size: entry.size,
            reader_range: None,
            reader: Box::new(child.into_stdout()?),
        })
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        _range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let entry = self.async_metadata(path).await?;

        if !entry.file_type.is_file() {
            return Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            )));
        }

        let full_path = self.server_path.join(path);

        let child = Command::new("restic")
            .envs(&self.configuration.environment)
            .arg("--json")
            .arg("--no-lock")
            .arg("--repo")
            .arg(&self.configuration.repository)
            .args(self.configuration.password())
            .arg("--cache-dir")
            .arg(ResticBackup::get_restic_cache_dir(
                &self.server.app_state.config,
            ))
            .arg("dump")
            .arg(&self.short_id)
            .arg(full_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        Ok(AsyncFileRead {
            size: entry.size,
            total_size: entry.size,
            reader_range: None,
            reader: Box::new(child.into_stdout()?),
        })
    }

    fn read_symlink(
        &self,
        _path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        Err(anyhow::anyhow!(
            "Symlink reading is not supported for Restic backups"
        ))
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.read_symlink(path)
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error> {
        let entry = self.async_metadata(&path).await?;

        if !entry.file_type.is_dir() {
            return Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            )));
        }

        let full_path = self.server_path.join(path);
        let path = path.as_ref().to_path_buf();

        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new(reader);

        let configuration = self.configuration.clone();
        let config = self.server.app_state.config.clone();
        let short_id = self.short_id.clone();
        let file_compression_threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;

        let spawn_restic = move || {
            std::process::Command::new("restic")
                .envs(&configuration.environment)
                .arg("--json")
                .arg("--no-lock")
                .arg("--repo")
                .arg(&configuration.repository)
                .args(configuration.password())
                .arg("--cache-dir")
                .arg(ResticBackup::get_restic_cache_dir(&config))
                .arg("dump")
                .arg(format!("{}:{}", short_id, full_path.display()))
                .arg("/")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
        };

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let mut child = spawn_restic()?;

                    let writer = tokio_util::io::SyncIoBridge::new(writer);
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    let mut restic_tar = tar::Archive::new(child.take_stdout()?);
                    let entries = restic_tar.entries()?;

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];
                    for entry in entries {
                        let mut entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();

                        let file_type = match header.entry_type() {
                            tar::EntryType::Directory => FileType::Dir,
                            tar::EntryType::Regular => FileType::File,
                            tar::EntryType::Symlink => FileType::Symlink,
                            _ => continue,
                        };

                        let absolute_path = path.join(&relative);
                        if (is_ignored)(file_type, absolute_path).is_none() {
                            continue;
                        }

                        let mut options: zip::write::FileOptions<'_, ()> =
                            zip::write::FileOptions::default()
                                .compression_level(
                                    Some(compression_level.to_deflate_level() as i64),
                                )
                                .unix_permissions(header.mode()?)
                                .large_file(header.size()? >= u32::MAX as u64);

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
                                zip.add_directory(relative.to_string_lossy(), options)?;
                            }
                            tar::EntryType::Regular => {
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
                            _ => continue,
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
                    let mut child = spawn_restic()?;

                    let writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;
                    let mut tar = tar::Builder::new(writer);

                    let mut restic_tar = tar::Archive::new(child.take_stdout()?);
                    let entries = restic_tar.entries()?;

                    for entry in entries {
                        let entry = entry?;
                        let mut header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();

                        let file_type = match header.entry_type() {
                            tar::EntryType::Directory => FileType::Dir,
                            tar::EntryType::Regular => FileType::File,
                            tar::EntryType::Symlink => FileType::Symlink,
                            _ => continue,
                        };

                        let absolute_path = path.join(&relative);
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
            f if f.is_itaf() => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let mut child = spawn_restic()?;

                    let writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;
                    let mut itaf_enc = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;

                    let mut dir_stack = Vec::new();
                    let mut restic_tar = tar::Archive::new(child.take_stdout()?);
                    let entries = restic_tar.entries()?;

                    for entry in entries {
                        let entry = entry?;
                        let header = entry.header().clone();
                        let relative = entry.path()?.to_path_buf();

                        if relative.as_os_str() == "." {
                            continue;
                        }

                        let file_type = match header.entry_type() {
                            tar::EntryType::Directory => FileType::Dir,
                            tar::EntryType::Regular => FileType::File,
                            tar::EntryType::Symlink => FileType::Symlink,
                            _ => continue,
                        };

                        let absolute_path = path.join(&relative);
                        if (is_ignored)(file_type, absolute_path).is_none() {
                            continue;
                        }

                        let components: Vec<_> = relative
                            .components()
                            .filter_map(|c| match c {
                                std::path::Component::Normal(s) => Some(s.to_string_lossy()),
                                _ => None,
                            })
                            .collect();
                        let Some(name) = components.last() else {
                            continue;
                        };

                        let is_dir = file_type.is_dir();
                        let parent = components.get_slice(..components.len() - 1)?;

                        let mode = header.mode().unwrap_or(if is_dir { 0o755 } else { 0o644 });
                        let mtime = header
                            .mtime()
                            .map(|t| std::time::UNIX_EPOCH + std::time::Duration::from_secs(t))
                            .unwrap_or_else(|_| std::time::SystemTime::now());
                        let meta = Metadata {
                            uid: 0,
                            gid: 0,
                            mode,
                            modified: mtime,
                        };

                        let shared = dir_stack
                            .iter()
                            .zip(parent.iter())
                            .take_while(|(a, b)| a == b)
                            .count();
                        while dir_stack.len() > shared {
                            itaf_enc.exit_dir()?;
                            dir_stack.pop();
                        }

                        for component in parent.get_slice(shared..)? {
                            itaf_enc.enter_dir(
                                component,
                                &Metadata {
                                    uid: 0,
                                    gid: 0,
                                    mode: 0o755,
                                    modified: std::time::SystemTime::now(),
                                },
                            )?;
                            dir_stack.push(component.to_compact_string());
                        }

                        match file_type {
                            FileType::Dir => {
                                itaf_enc.enter_dir(name, &meta)?;
                                dir_stack.push(name.to_compact_string());
                            }
                            FileType::File => {
                                let size = header.size().unwrap_or(0);
                                let reader = progress.counting_reader(entry);
                                let mut reader =
                                    crate::io::fixed_reader::FixedReader::new_with_fixed_bytes(
                                        reader,
                                        size as usize,
                                    );

                                itaf_enc.add_file(name, &meta, size, &mut reader)?;
                                progress.increment_files();
                            }
                            FileType::Symlink => {
                                let link =
                                    entry.link_name().unwrap_or_default().unwrap_or_default();
                                let target = link.to_string_lossy();
                                if itaf::spec::validate_name(name).is_ok() {
                                    itaf_enc.add_symlink(name, &target, false, &meta)?;
                                    progress.increment_files();
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
                tracing::error!(
                    "unsupported archive format for restic backup archive: {}",
                    archive_format.extension()
                );
            }
        }

        Ok(reader)
    }

    async fn async_read_dir_files_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_paths: Vec<PathBuf>,
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FallibleSimplexReader, anyhow::Error> {
        let entry = self.async_metadata(&path).await?;

        if !entry.file_type.is_dir() {
            return Err(anyhow::anyhow!(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found"
            )));
        }

        let full_path = self.server_path.join(path);
        let path = path.as_ref().to_path_buf();

        let (reader, writer) = tokio::io::simplex(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new(reader);

        let configuration = self.configuration.clone();
        let config = self.server.app_state.config.clone();
        let short_id = self.short_id.clone();
        let file_compression_threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;

        let spawn_restic = move |is_dir: bool, path: &Path| {
            std::process::Command::new("restic")
                .envs(&configuration.environment)
                .arg("--json")
                .arg("--no-lock")
                .arg("--repo")
                .arg(&configuration.repository)
                .args(configuration.password())
                .arg("--cache-dir")
                .arg(ResticBackup::get_restic_cache_dir(&config))
                .arg("dump")
                .args(if is_dir {
                    vec![
                        format!("{}:{}", short_id, full_path.join(path).display()),
                        "/".to_string(),
                    ]
                } else {
                    vec![short_id.clone(), full_path.join(path).display().to_string()]
                })
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
        };

        enum ResolvedEntry {
            Dir {
                path: PathBuf,
            },
            File {
                path: PathBuf,
                mode: u32,
                size: u64,
                mtime: chrono::DateTime<chrono::Utc>,
            },
        }

        let mut resolved: Vec<ResolvedEntry> = Vec::with_capacity(file_paths.len());
        for entry_path in &file_paths {
            if self.tree.lookup_dir(entry_path).is_some() {
                resolved.push(ResolvedEntry::Dir {
                    path: entry_path.clone(),
                });
            } else if let Some(meta) = self.tree.lookup_file(entry_path)
                && meta.file_type.is_file()
            {
                resolved.push(ResolvedEntry::File {
                    path: entry_path.clone(),
                    mode: meta.mode,
                    size: meta.size,
                    mtime: meta.mtime,
                });
            }
        }

        match archive_format {
            StreamableArchiveFormat::Zip => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let writer = tokio_util::io::SyncIoBridge::new(writer);
                    let mut zip = zip::ZipWriter::new_stream(writer);

                    let mut read_buffer = vec![0; crate::BUFFER_SIZE];

                    for resolved_entry in resolved {
                        match resolved_entry {
                            ResolvedEntry::Dir { path: entry_path } => {
                                let mut child = spawn_restic(true, &entry_path)?;

                                let mut restic_tar = tar::Archive::new(child.take_stdout()?);
                                let entries = restic_tar.entries()?;

                                for entry in entries {
                                    let mut entry = entry?;
                                    let header = entry.header().clone();
                                    let relative = entry_path.join(entry.path()?);

                                    let file_type = match header.entry_type() {
                                        tar::EntryType::Directory => FileType::Dir,
                                        tar::EntryType::Regular => FileType::File,
                                        tar::EntryType::Symlink => FileType::Symlink,
                                        _ => continue,
                                    };

                                    let absolute_path = path.join(&relative);
                                    if (is_ignored)(file_type, absolute_path).is_none() {
                                        continue;
                                    }

                                    let mut options: zip::write::FileOptions<'_, ()> =
                                        zip::write::FileOptions::default()
                                            .compression_level(Some(
                                                compression_level.to_deflate_level() as i64,
                                            ))
                                            .unix_permissions(header.mode()?)
                                            .large_file(header.size()? >= u32::MAX as u64);

                                    if let Ok(mtime) = header.mtime()
                                        && let Some(mtime) =
                                            chrono::DateTime::from_timestamp(mtime as i64, 0)
                                    {
                                        options = options.last_modified_time(
                                            zip::DateTime::from_date_and_time(
                                                mtime.year() as u16,
                                                mtime.month() as u8,
                                                mtime.day() as u8,
                                                mtime.hour() as u8,
                                                mtime.minute() as u8,
                                                mtime.second() as u8,
                                            )?,
                                        );
                                    }

                                    match header.entry_type() {
                                        tar::EntryType::Directory => {
                                            zip.add_directory(relative.to_string_lossy(), options)?;
                                        }
                                        tar::EntryType::Regular => {
                                            zip.start_file(relative.to_string_lossy(), options)?;
                                            progress.increment_files();

                                            loop {
                                                let bytes_read =
                                                    entry.read_uninterrupted(&mut read_buffer)?;
                                                if crate::unlikely(bytes_read == 0) {
                                                    break;
                                                }

                                                zip.safe_write_all(&read_buffer, bytes_read)?;
                                                progress.increment_bytes(bytes_read as u64);
                                            }
                                        }
                                        _ => continue,
                                    }
                                }
                            }
                            ResolvedEntry::File {
                                path: entry_path,
                                mode,
                                size,
                                mtime,
                            } => {
                                let mut child = spawn_restic(false, &entry_path)?;

                                let options: zip::write::FileOptions<'_, ()> =
                                    zip::write::FileOptions::default()
                                        .compression_level(Some(
                                            compression_level.to_deflate_level() as i64,
                                        ))
                                        .unix_permissions(mode)
                                        .large_file(size >= u32::MAX as u64)
                                        .last_modified_time(zip::DateTime::from_date_and_time(
                                            mtime.year() as u16,
                                            mtime.month() as u8,
                                            mtime.day() as u8,
                                            mtime.hour() as u8,
                                            mtime.minute() as u8,
                                            mtime.second() as u8,
                                        )?);

                                zip.start_file(entry_path.to_string_lossy(), options)?;
                                progress.increment_files();

                                let mut restic_file = child.take_stdout()?;

                                loop {
                                    let bytes_read =
                                        restic_file.read_uninterrupted(&mut read_buffer)?;
                                    if crate::unlikely(bytes_read == 0) {
                                        break;
                                    }

                                    zip.safe_write_all(&read_buffer, bytes_read)?;
                                    progress.increment_bytes(bytes_read as u64);
                                }
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
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;
                    let mut tar = tar::Builder::new(writer);

                    for resolved_entry in resolved {
                        match resolved_entry {
                            ResolvedEntry::Dir { path: entry_path } => {
                                let mut child = spawn_restic(true, &entry_path)?;

                                let mut restic_tar = tar::Archive::new(child.take_stdout()?);
                                let entries = restic_tar.entries()?;

                                for entry in entries {
                                    let entry = entry?;
                                    let mut header = entry.header().clone();
                                    let relative = entry.path()?.to_path_buf();

                                    let file_type = match header.entry_type() {
                                        tar::EntryType::Directory => FileType::Dir,
                                        tar::EntryType::Regular => FileType::File,
                                        tar::EntryType::Symlink => FileType::Symlink,
                                        _ => continue,
                                    };

                                    let absolute_path = path.join(&relative);
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
                            }
                            ResolvedEntry::File {
                                path: entry_path,
                                mode,
                                size,
                                mtime,
                            } => {
                                let mut child = spawn_restic(false, &entry_path)?;

                                let mut header = tar::Header::new_gnu();
                                header.set_path(&entry_path)?;
                                header.set_size(size);
                                header.set_mode(mode);
                                header.set_mtime(mtime.timestamp() as u64);
                                header.set_entry_type(tar::EntryType::Regular);
                                header.set_cksum();

                                let reader = progress.counting_reader(child.take_stdout()?);
                                tar.append_data(&mut header, &entry_path, reader)?;
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
            f if f.is_itaf() => {
                crate::spawn_blocking_signalled(signal, move || -> Result<(), anyhow::Error> {
                    let writer = CompressionWriter::new(
                        tokio_util::io::SyncIoBridge::new(writer),
                        f.compression_format(),
                        compression_level,
                        file_compression_threads,
                    )?;
                    let mut itaf_enc = ItafEncoder::new(
                        writer,
                        EncoderOptions {
                            base_timestamp: None,
                            crc_enabled: true,
                        },
                    )?;

                    let mut dir_stack = Vec::new();

                    resolved.sort_unstable_by(|a, b| {
                        let pa = match a {
                            ResolvedEntry::Dir { path } => path.as_path(),
                            ResolvedEntry::File { path, .. } => path.as_path(),
                        };
                        let pb = match b {
                            ResolvedEntry::Dir { path } => path.as_path(),
                            ResolvedEntry::File { path, .. } => path.as_path(),
                        };
                        pa.cmp(pb)
                    });

                    for resolved_entry in resolved {
                        match resolved_entry {
                            ResolvedEntry::Dir { path: entry_path } => {
                                let components: Vec<_> = entry_path
                                    .components()
                                    .filter_map(|c| match c {
                                        std::path::Component::Normal(s) => {
                                            Some(s.to_string_lossy())
                                        }
                                        _ => None,
                                    })
                                    .collect();
                                let Some(name) = components.last() else {
                                    continue;
                                };

                                let parent = components.get_slice(..components.len() - 1)?;

                                let shared = dir_stack
                                    .iter()
                                    .zip(parent.iter())
                                    .take_while(|(a, b)| a == b)
                                    .count();
                                while dir_stack.len() > shared {
                                    itaf_enc.exit_dir()?;
                                    dir_stack.pop();
                                }

                                for component in parent.get_slice(shared..)? {
                                    itaf_enc.enter_dir(
                                        component,
                                        &Metadata {
                                            uid: 0,
                                            gid: 0,
                                            mode: 0o755,
                                            modified: std::time::SystemTime::now(),
                                        },
                                    )?;
                                    dir_stack.push(component.to_compact_string());
                                }

                                itaf_enc.enter_dir(
                                    name,
                                    &Metadata {
                                        uid: 0,
                                        gid: 0,
                                        mode: 0o755,
                                        modified: std::time::SystemTime::now(),
                                    },
                                )?;
                                dir_stack.push(name.to_compact_string());

                                let base_depth = dir_stack.len();
                                let mut child = spawn_restic(true, &entry_path)?;
                                let mut restic_tar = tar::Archive::new(child.take_stdout()?);
                                let entries = restic_tar.entries()?;

                                for entry in entries {
                                    let entry = entry?;
                                    let header = entry.header().clone();
                                    let relative = entry.path()?.to_path_buf();

                                    if relative.as_os_str() == "." {
                                        continue;
                                    }

                                    let file_type = match header.entry_type() {
                                        tar::EntryType::Directory => FileType::Dir,
                                        tar::EntryType::Regular => FileType::File,
                                        tar::EntryType::Symlink => FileType::Symlink,
                                        _ => continue,
                                    };

                                    let absolute_path = path.join(&entry_path).join(&relative);
                                    if (is_ignored)(file_type, absolute_path).is_none() {
                                        continue;
                                    }

                                    let inner_components: Vec<_> = relative
                                        .components()
                                        .filter_map(|c| match c {
                                            std::path::Component::Normal(s) => {
                                                Some(s.to_string_lossy())
                                            }
                                            _ => None,
                                        })
                                        .collect();
                                    let Some(inner_name) = inner_components.last() else {
                                        continue;
                                    };

                                    let inner_parent =
                                        inner_components.get_slice(..inner_components.len() - 1)?;

                                    let shared = dir_stack
                                        .get_slice(base_depth..)?
                                        .iter()
                                        .zip(inner_parent.iter())
                                        .take_while(|(a, b)| a == b)
                                        .count();
                                    while dir_stack.len() > base_depth + shared {
                                        itaf_enc.exit_dir()?;
                                        dir_stack.pop();
                                    }

                                    for component in inner_parent.get_slice(shared..)? {
                                        itaf_enc.enter_dir(
                                            component,
                                            &Metadata {
                                                uid: 0,
                                                gid: 0,
                                                mode: 0o755,
                                                modified: std::time::SystemTime::now(),
                                            },
                                        )?;
                                        dir_stack.push(component.to_compact_string());
                                    }

                                    let is_dir = file_type.is_dir();
                                    let mode =
                                        header.mode().unwrap_or(if is_dir { 0o755 } else { 0o644 });
                                    let mtime = header
                                        .mtime()
                                        .map(|t| {
                                            std::time::UNIX_EPOCH
                                                + std::time::Duration::from_secs(t)
                                        })
                                        .unwrap_or_else(|_| std::time::SystemTime::now());
                                    let meta = Metadata {
                                        uid: 0,
                                        gid: 0,
                                        mode,
                                        modified: mtime,
                                    };

                                    match file_type {
                                        FileType::Dir => {
                                            itaf_enc.enter_dir(inner_name, &meta)?;
                                            dir_stack.push(inner_name.to_compact_string());
                                        }
                                        FileType::File => {
                                            let size = header.size().unwrap_or(0);
                                            let reader = progress.counting_reader(entry);
                                            let mut reader = crate::io::fixed_reader::FixedReader::new_with_fixed_bytes(
                                                reader,
                                                size as usize,
                                            );

                                            itaf_enc.add_file(
                                                inner_name,
                                                &meta,
                                                size,
                                                &mut reader,
                                            )?;
                                            progress.increment_files();
                                        }
                                        FileType::Symlink => {
                                            let link = entry
                                                .link_name()
                                                .unwrap_or_default()
                                                .unwrap_or_default();
                                            let target = link.to_string_lossy();
                                            if itaf::spec::validate_name(inner_name).is_ok() {
                                                itaf_enc.add_symlink(
                                                    inner_name, &target, false, &meta,
                                                )?;
                                                progress.increment_files();
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            ResolvedEntry::File {
                                path: entry_path,
                                mode,
                                size,
                                mtime,
                            } => {
                                let components: Vec<compact_str::CompactString> = entry_path
                                    .components()
                                    .filter_map(|c| match c {
                                        std::path::Component::Normal(s) => {
                                            Some(s.to_string_lossy().into())
                                        }
                                        _ => None,
                                    })
                                    .collect();
                                let Some(file_name) = components.last() else {
                                    continue;
                                };

                                let parent = components.get_slice(..components.len() - 1)?;

                                let shared = dir_stack
                                    .iter()
                                    .zip(parent.iter())
                                    .take_while(|(a, b)| a == b)
                                    .count();
                                while dir_stack.len() > shared {
                                    itaf_enc.exit_dir()?;
                                    dir_stack.pop();
                                }

                                for component in parent.get_slice(shared..)? {
                                    itaf_enc.enter_dir(
                                        component,
                                        &Metadata {
                                            uid: 0,
                                            gid: 0,
                                            mode: 0o755,
                                            modified: std::time::SystemTime::now(),
                                        },
                                    )?;
                                    dir_stack.push(component.clone());
                                }

                                let meta = Metadata {
                                    uid: 0,
                                    gid: 0,
                                    mode,
                                    modified: mtime.into(),
                                };

                                let mut child = spawn_restic(false, &entry_path)?;
                                let reader = progress.counting_reader(child.take_stdout()?);
                                let mut reader =
                                    crate::io::fixed_reader::FixedReader::new_with_fixed_bytes(
                                        reader,
                                        size as usize,
                                    );

                                itaf_enc.add_file(file_name, &meta, size, &mut reader)?;
                                progress.increment_files();
                            }
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
                tracing::error!(
                    "unsupported archive format for restic backup files archive: {}",
                    archive_format.extension()
                );
            }
        }

        Ok(reader)
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
