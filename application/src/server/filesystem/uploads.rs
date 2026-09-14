use compact_str::ToCompactString;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
};
use tokio::sync::RwLock;
use utoipa::ToSchema;

pub const PART_SUFFIX: &str = ".upload-part";

const NAME_MAX: usize = 255;
const INACTIVE_RETENTION: chrono::Duration = chrono::Duration::hours(24);

pub fn part_path(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy();
    if name.len() + PART_SUFFIX.len() > NAME_MAX {
        return None;
    }

    let name = format!("{name}{PART_SUFFIX}");

    Some(match path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    })
}

pub fn target_name(name: &str) -> Option<&str> {
    name.strip_suffix(PART_SUFFIX)
        .filter(|target| !target.is_empty())
}

pub fn ignore_match_path(path: &Path) -> std::borrow::Cow<'_, Path> {
    match path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(target_name)
    {
        Some(target) => std::borrow::Cow::Owned(path.with_file_name(target)),
        None => std::borrow::Cow::Borrowed(path),
    }
}

fn file_name(path: &Path) -> compact_str::CompactString {
    path.file_name()
        .map(|name| name.to_string_lossy().to_compact_string())
        .unwrap_or_default()
}

pub struct Upload {
    pub target: PathBuf,
    pub part: PathBuf,

    pub user: uuid::Uuid,
    pub user_name: Option<compact_str::CompactString>,
    pub resumable: bool,
    pub started: chrono::DateTime<chrono::Utc>,

    total: AtomicU64,
    uploaded: AtomicU64,
    updated: AtomicI64,
    active: AtomicBool,
}

impl Upload {
    #[inline]
    pub fn set_progress(&self, uploaded: u64) {
        self.uploaded.store(uploaded, Ordering::Relaxed);
        self.updated
            .store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
    }

    #[inline]
    pub fn set_total(&self, total: Option<u64>) {
        self.total.store(total.unwrap_or(0), Ordering::Relaxed);
    }

    #[inline]
    fn deactivate(&self) {
        self.active.store(false, Ordering::Relaxed);
        self.updated
            .store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
    }

    fn updated_at(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(self.updated.load(Ordering::Relaxed))
            .unwrap_or(self.started)
    }

    fn entry(&self, filesystem: &super::cap::CapFilesystem) -> UploadEntry {
        let target = filesystem.relative_path(&self.target);
        let total = self.total.load(Ordering::Relaxed);

        UploadEntry {
            name: file_name(&self.part),
            target_name: file_name(&self.target),
            directory: target
                .parent()
                .map(|parent| parent.to_string_lossy().to_compact_string())
                .unwrap_or_default(),
            user: Some(self.user),
            user_name: self.user_name.clone(),
            uploaded: self.uploaded.load(Ordering::Relaxed),
            total: if total == 0 { None } else { Some(total) },
            resumable: self.resumable,
            active: self.active.load(Ordering::Relaxed),
            started: Some(self.started),
            updated: Some(self.updated_at()),
        }
    }
}

pub struct UploadGuard {
    upload: Arc<Upload>,
    uploads: Arc<RwLock<HashMap<PathBuf, Arc<Upload>>>>,
    key: PathBuf,
    armed: bool,
}

impl UploadGuard {
    #[inline]
    pub fn set_progress(&self, uploaded: u64) {
        self.upload.set_progress(uploaded);
    }

    /// Forgets the upload now that its staging file has been renamed onto the final name.
    pub async fn complete(mut self) {
        self.armed = false;
        self.uploads.write().await.remove(&self.key);
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if self.armed {
            self.upload.deactivate();
        }
    }
}

#[derive(Clone, ToSchema, Serialize)]
pub struct UploadEntry {
    pub name: compact_str::CompactString,
    pub target_name: compact_str::CompactString,
    pub directory: compact_str::CompactString,

    pub user: Option<uuid::Uuid>,
    pub user_name: Option<compact_str::CompactString>,

    pub uploaded: u64,
    pub total: Option<u64>,
    pub resumable: bool,
    pub active: bool,

    pub started: Option<chrono::DateTime<chrono::Utc>>,
    pub updated: Option<chrono::DateTime<chrono::Utc>>,
}

impl UploadEntry {
    pub fn orphan(name: &str, directory: &str, uploaded: u64) -> Self {
        Self {
            target_name: target_name(name).unwrap_or(name).to_compact_string(),
            name: name.to_compact_string(),
            directory: directory.to_compact_string(),
            user: None,
            user_name: None,
            uploaded,
            total: None,
            resumable: false,
            active: false,
            started: None,
            updated: None,
        }
    }
}

pub struct NewUpload<'a> {
    pub target: &'a Path,
    pub part: &'a Path,
    pub user: uuid::Uuid,
    pub user_name: Option<compact_str::CompactString>,
    pub total: Option<u64>,
    pub uploaded: u64,
    pub resumable: bool,
}

pub struct UploadManager {
    uploads: Arc<RwLock<HashMap<PathBuf, Arc<Upload>>>>,
    sender: tokio::sync::broadcast::Sender<crate::server::websocket::WebsocketMessage>,
    broadcasting: Arc<AtomicBool>,
}

impl UploadManager {
    pub fn new(
        sender: tokio::sync::broadcast::Sender<crate::server::websocket::WebsocketMessage>,
    ) -> Self {
        Self {
            uploads: Arc::new(RwLock::new(HashMap::new())),
            sender,
            broadcasting: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts tracking an upload streaming into `part`, or picks the existing record back up
    /// when a resumable upload continues with its next slice.
    pub async fn register(
        &self,
        new: NewUpload<'_>,
        filesystem: &super::cap::CapFilesystem,
    ) -> UploadGuard {
        let NewUpload {
            target,
            part,
            user,
            user_name,
            total,
            uploaded,
            resumable,
        } = new;

        let key = filesystem.relative_path(part);
        let now = chrono::Utc::now();

        Self::prune(&self.uploads, filesystem).await;

        let mut uploads = self.uploads.write().await;
        let upload = match uploads.get(&key) {
            // a staging file abandoned by one user and picked up by another changes hands, so the
            // new upload is attributed to - and cancellable by - whoever is actually writing it
            Some(existing) if existing.user == user => {
                existing.active.store(true, Ordering::Relaxed);
                existing.set_total(total);
                existing.set_progress(uploaded);

                Arc::clone(existing)
            }
            _ => {
                let upload = Arc::new(Upload {
                    target: target.to_path_buf(),
                    part: part.to_path_buf(),
                    user,
                    user_name,
                    resumable,
                    started: now,
                    total: AtomicU64::new(total.unwrap_or(0)),
                    uploaded: AtomicU64::new(uploaded),
                    updated: AtomicI64::new(now.timestamp_millis()),
                    active: AtomicBool::new(true),
                });

                uploads.insert(key.clone(), Arc::clone(&upload));
                upload
            }
        };

        let broadcast = !self.broadcasting.swap(true, Ordering::AcqRel);
        drop(uploads);

        if broadcast {
            self.spawn_broadcast(filesystem);
        }

        UploadGuard {
            upload,
            uploads: Arc::clone(&self.uploads),
            key,
            armed: true,
        }
    }

    /// Drops records whose staging file is gone - removed or renamed through the file API, over
    /// SFTP, or by the server process itself - along with ones that went inactive long enough ago
    /// to count as abandoned. Active records are left alone: their file is being written into
    /// right now, and unlinking it does not make the write stop.
    async fn prune(
        uploads: &RwLock<HashMap<PathBuf, Arc<Upload>>>,
        filesystem: &super::cap::CapFilesystem,
    ) {
        let now = chrono::Utc::now();
        let candidates: Vec<(PathBuf, Arc<Upload>, i64)> = uploads
            .read()
            .await
            .iter()
            .filter(|(_, upload)| !upload.active.load(Ordering::Relaxed))
            .map(|(key, upload)| {
                (
                    key.clone(),
                    Arc::clone(upload),
                    upload.updated.load(Ordering::Relaxed),
                )
            })
            .collect();

        let mut dead = Vec::new();
        for (key, upload, updated) in candidates {
            // only a missing file counts, never an unreadable one - a closed or uninitialized
            // filesystem errors on every path, and would otherwise retire every record at once
            let gone = now.signed_duration_since(upload.updated_at()) >= INACTIVE_RETENTION
                || matches!(filesystem.async_metadata(&key).await,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound);

            if gone {
                dead.push((key, upload, updated));
            }
        }

        if dead.is_empty() {
            return;
        }

        let mut uploads = uploads.write().await;
        for (key, upload, updated) in dead {
            // a registration may have replaced or resumed the record while we were statting
            if uploads.get(&key).is_some_and(|current| {
                Arc::ptr_eq(current, &upload)
                    && current.updated.load(Ordering::Relaxed) == updated
                    && !current.active.load(Ordering::Relaxed)
            }) {
                uploads.remove(&key);
            }
        }
    }

    pub async fn forget(&self, part: &Path, filesystem: &super::cap::CapFilesystem) {
        self.uploads
            .write()
            .await
            .remove(&filesystem.relative_path(part));
    }

    pub async fn owner(
        &self,
        part: &Path,
        filesystem: &super::cap::CapFilesystem,
    ) -> Option<uuid::Uuid> {
        self.uploads
            .read()
            .await
            .get(&filesystem.relative_path(part))
            .map(|upload| upload.user)
    }

    pub async fn entries(&self, filesystem: &super::cap::CapFilesystem) -> Vec<UploadEntry> {
        self.uploads
            .read()
            .await
            .values()
            .map(|upload| upload.entry(filesystem))
            .collect()
    }

    pub async fn in_directory(
        &self,
        directory: &Path,
        filesystem: &super::cap::CapFilesystem,
    ) -> Vec<UploadEntry> {
        Self::prune(&self.uploads, filesystem).await;

        let directory = filesystem.relative_path(directory);

        self.uploads
            .read()
            .await
            .iter()
            .filter(|(key, _)| key.parent() == Some(directory.as_path()))
            .map(|(_, upload)| upload.entry(filesystem))
            .collect()
    }

    fn spawn_broadcast(&self, filesystem: &super::cap::CapFilesystem) {
        let uploads = Arc::clone(&self.uploads);
        let broadcasting = Arc::clone(&self.broadcasting);
        let sender = self.sender.clone();
        let filesystem = filesystem.clone();

        tokio::spawn(async move {
            loop {
                Self::prune(&uploads, &filesystem).await;

                let (entries, active) = {
                    // write, not read: this is the only thing serializing the store below
                    // against the swap in register, which runs under the same lock
                    let tracked = uploads.write().await;
                    let entries: Vec<UploadEntry> = tracked
                        .values()
                        .map(|upload| upload.entry(&filesystem))
                        .collect();
                    let active = entries.iter().any(|entry| entry.active);

                    if !active {
                        broadcasting.store(false, Ordering::Release);
                    }

                    (entries, active)
                };

                sender
                    .send(
                        crate::server::websocket::WebsocketMessage::builder(
                            crate::server::websocket::WebsocketEvent::ServerFileUploads,
                        )
                        .structured_arg(&entries)
                        .build(),
                    )
                    .ok();

                if !active {
                    break;
                }

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{routes::AppState, server::Server};

    fn with_server<F, Fut>(f: F)
    where
        F: FnOnce(Server) -> Fut,
        Fut: Future<Output = ()>,
    {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir().expect("failed to create temp dir");
            let state = AppState::mock();
            state
                .config
                .mutate_in_place_for_testing()
                .system
                .data_directory =
                crate::config::SystemPath::new(temp.path().to_string_lossy().into_owned());

            let server = Server::mock(uuid::Uuid::new_v4(), Arc::clone(&state));
            server.filesystem.disk_checker.abort();

            let root = server.filesystem.base_path.to_path_buf();
            std::fs::create_dir_all(&root).expect("failed to create server root");
            let cap = super::super::cap::CapFilesystem::new(&root)
                .await
                .expect("failed to open server root");
            server
                .filesystem
                .inner
                .store(Some(cap.get_inner().expect("failed to get inner")));

            f(server).await;
        });
    }

    async fn register_upload(server: &Server, target: &str) -> UploadGuard {
        register_upload_as(server, target, uuid::Uuid::new_v4()).await
    }

    /// Registers an upload the way a route does, staging file included: [`UploadManager::prune`]
    /// retires a record whose staging file is not on disk, so a fixture without one would never
    /// survive its own guard being dropped.
    async fn register_upload_as(server: &Server, target: &str, user: uuid::Uuid) -> UploadGuard {
        let target = server.filesystem.base_path.join(target);
        let part = part_path(&target).expect("staging path");

        if let Some(parent) = part.parent() {
            std::fs::create_dir_all(parent).expect("failed to create staging parent");
        }
        std::fs::write(&part, b"").expect("failed to create staging file");

        server
            .filesystem
            .uploads
            .register(
                NewUpload {
                    target: &target,
                    part: &part,
                    user,
                    user_name: Some("ada".into()),
                    total: Some(100),
                    uploaded: 0,
                    resumable: true,
                },
                &server.filesystem,
            )
            .await
    }

    #[test]
    fn part_path_appends_the_suffix() {
        assert_eq!(
            part_path(Path::new("/plugins/server.jar")),
            Some(PathBuf::from("/plugins/server.jar.upload-part"))
        );
    }

    #[test]
    fn part_path_rejects_a_name_that_cannot_carry_the_suffix() {
        let fits = "a".repeat(NAME_MAX - PART_SUFFIX.len());
        assert!(part_path(&PathBuf::from("/").join(&fits)).is_some());

        let overflows = "a".repeat(NAME_MAX - PART_SUFFIX.len() + 1);
        assert!(part_path(&PathBuf::from("/").join(&overflows)).is_none());
    }

    /// A staging name that cannot be turned back into its target is a deny-list hole, since
    /// [`ignore_match_path`] matches the recovered target rather than the staging name.
    #[test]
    fn part_path_round_trips_through_target_name() {
        for target in ["server.jar", "sérvér.jar", "a.b.upload-part.jar"] {
            let path = part_path(&PathBuf::from("/plugins").join(target)).expect("staging path");
            let name = path.file_name().expect("file name").to_string_lossy();

            assert_eq!(target_name(&name), Some(target));
        }
    }

    #[test]
    fn target_name_round_trips() {
        assert_eq!(target_name("server.jar.upload-part"), Some("server.jar"));
        assert_eq!(target_name("server.jar"), None);
        assert_eq!(target_name(PART_SUFFIX), None);
    }

    #[test]
    fn a_registered_upload_is_reported_as_active() {
        with_server(|server| async move {
            let _guard = register_upload(&server, "plugins/server.jar").await;

            let directory = server.filesystem.base_path.join("plugins");
            let entries = server
                .filesystem
                .uploads
                .in_directory(&directory, &server.filesystem)
                .await;

            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name, "server.jar.upload-part");
            assert_eq!(entries[0].target_name, "server.jar");
            assert_eq!(entries[0].directory, "plugins");
            assert_eq!(entries[0].user_name.as_deref(), Some("ada"));
            assert_eq!(entries[0].total, Some(100));
            assert!(entries[0].active);
        });
    }

    #[test]
    fn dropping_the_guard_leaves_an_inactive_record() {
        with_server(|server| async move {
            let guard = register_upload(&server, "plugins/server.jar").await;
            guard.upload.set_progress(40);
            drop(guard);

            let directory = server.filesystem.base_path.join("plugins");
            let entries = server
                .filesystem
                .uploads
                .in_directory(&directory, &server.filesystem)
                .await;

            assert_eq!(entries.len(), 1);
            assert!(!entries[0].active);
            assert_eq!(entries[0].uploaded, 40);
        });
    }

    #[test]
    fn completing_an_upload_forgets_it() {
        with_server(|server| async move {
            register_upload(&server, "plugins/server.jar")
                .await
                .complete()
                .await;

            let directory = server.filesystem.base_path.join("plugins");
            assert!(
                server
                    .filesystem
                    .uploads
                    .in_directory(&directory, &server.filesystem)
                    .await
                    .is_empty()
            );
        });
    }

    /// Nothing tells the manager that a staging file was deleted or renamed out from under it -
    /// over SFTP, or by the server process - so an inactive record has to answer for its own file.
    #[test]
    fn a_record_whose_staging_file_vanished_is_pruned() {
        with_server(|server| async move {
            let guard = register_upload(&server, "plugins/server.jar").await;
            drop(guard);

            let target = server.filesystem.base_path.join("plugins/server.jar");
            std::fs::remove_file(part_path(&target).expect("staging path"))
                .expect("failed to remove staging file");

            let directory = server.filesystem.base_path.join("plugins");
            assert!(
                server
                    .filesystem
                    .uploads
                    .in_directory(&directory, &server.filesystem)
                    .await
                    .is_empty()
            );
        });
    }

    #[test]
    fn an_active_record_outlives_its_staging_file() {
        with_server(|server| async move {
            let _guard = register_upload(&server, "plugins/server.jar").await;

            let target = server.filesystem.base_path.join("plugins/server.jar");
            std::fs::remove_file(part_path(&target).expect("staging path"))
                .expect("failed to remove staging file");

            let directory = server.filesystem.base_path.join("plugins");
            let entries = server
                .filesystem
                .uploads
                .in_directory(&directory, &server.filesystem)
                .await;

            assert_eq!(entries.len(), 1);
            assert!(entries[0].active);
        });
    }

    /// An unreadable filesystem answers every path with an error, so treating anything but a
    /// missing file as gone would retire every record the first time one is closed.
    #[test]
    fn an_unreadable_filesystem_prunes_nothing() {
        with_server(|server| async move {
            drop(register_upload(&server, "plugins/server.jar").await);
            server.filesystem.close();

            let directory = server.filesystem.base_path.join("plugins");
            assert_eq!(
                server
                    .filesystem
                    .uploads
                    .in_directory(&directory, &server.filesystem)
                    .await
                    .len(),
                1
            );
        });
    }

    #[test]
    fn a_staging_file_picked_up_by_another_user_changes_hands() {
        with_server(|server| async move {
            let ada = uuid::Uuid::new_v4();
            let grace = uuid::Uuid::new_v4();

            drop(register_upload_as(&server, "plugins/server.jar", ada).await);
            let _guard = register_upload_as(&server, "plugins/server.jar", grace).await;

            let target = server.filesystem.base_path.join("plugins/server.jar");
            let part = part_path(&target).expect("staging path");

            assert_eq!(
                server
                    .filesystem
                    .uploads
                    .owner(&part, &server.filesystem)
                    .await,
                Some(grace)
            );
        });
    }

    #[test]
    fn an_untracked_staging_file_has_no_owner() {
        with_server(|server| async move {
            let target = server.filesystem.base_path.join("plugins/server.jar");
            let part = part_path(&target).expect("staging path");

            assert!(
                server
                    .filesystem
                    .uploads
                    .owner(&part, &server.filesystem)
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn a_discarded_upload_is_forgotten() {
        with_server(|server| async move {
            let _guard = register_upload(&server, "plugins/server.jar").await;

            let target = server.filesystem.base_path.join("plugins/server.jar");
            let part = part_path(&target).expect("staging path");
            server
                .filesystem
                .uploads
                .forget(&part, &server.filesystem)
                .await;

            let directory = server.filesystem.base_path.join("plugins");
            assert!(
                server
                    .filesystem
                    .uploads
                    .in_directory(&directory, &server.filesystem)
                    .await
                    .is_empty()
            );
        });
    }

    #[test]
    fn entries_span_every_directory() {
        with_server(|server| async move {
            let _plugins = register_upload(&server, "plugins/server.jar").await;
            let _mods = register_upload(&server, "mods/other.jar").await;

            let mut entries = server.filesystem.uploads.entries(&server.filesystem).await;
            entries.sort_by(|a, b| a.directory.cmp(&b.directory));

            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].directory, "mods");
            assert_eq!(entries[1].directory, "plugins");
        });
    }

    #[test]
    fn uploads_are_scoped_to_their_own_directory() {
        with_server(|server| async move {
            let _plugins = register_upload(&server, "plugins/server.jar").await;
            let _mods = register_upload(&server, "mods/other.jar").await;

            let directory = server.filesystem.base_path.join("plugins");
            let entries = server
                .filesystem
                .uploads
                .in_directory(&directory, &server.filesystem)
                .await;

            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].target_name, "server.jar");
        });
    }

    #[test]
    fn a_staging_file_is_matched_as_its_target() {
        assert_eq!(
            ignore_match_path(Path::new("/plugins/server.jar.upload-part")),
            std::borrow::Cow::Owned::<Path>(PathBuf::from("/plugins/server.jar"))
        );
        assert_eq!(
            ignore_match_path(Path::new("/plugins/server.jar")),
            std::borrow::Cow::Borrowed(Path::new("/plugins/server.jar"))
        );
    }
}
