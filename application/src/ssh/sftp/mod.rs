use crate::{
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        filesystem::{RenameParents, cap::FileType},
        permissions::Permission,
    },
    utils::PortablePermissions,
};
use cap_std::fs::{Metadata, OpenOptions};
use parking_lot::Mutex;
use positioned_io::{ReadAt, WriteAt};
use russh_sftp::protocol::{
    Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use serde_json::json;
use std::{
    collections::HashMap,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

mod extended;

pub struct FileHandle {
    _guard: super::limiter::SshLimiterHandleGuard,
    path: PathBuf,

    file: Arc<Mutex<crate::server::filesystem::file::ServerFile>>,
    append: bool,

    diff_track: bool,
    diff_before: Option<Vec<u8>>,
    diff_dirty: bool,
}

pub struct DirHandle {
    _guard: super::limiter::SshLimiterHandleGuard,
    path: Arc<Path>,

    dir: Arc<Mutex<crate::server::filesystem::cap::ReadDir>>,

    consumed: Arc<AtomicU64>,
}

pub enum ServerHandle {
    File(FileHandle),
    Dir(DirHandle),
}

impl ServerHandle {
    #[inline]
    fn path(&self) -> &Path {
        match self {
            ServerHandle::File(handle) => &handle.path,
            ServerHandle::Dir(handle) => &handle.path,
        }
    }
}

pub struct SftpSession {
    pub limiter: Arc<super::limiter::SshLimiter>,
    pub state: State,
    pub server: crate::server::Server,

    pub user_ip: std::net::IpAddr,
    pub user_uuid: uuid::Uuid,

    pub handle_id: u64,
    pub handles: HashMap<compact_str::CompactString, ServerHandle>,
}

impl SftpSession {
    #[inline]
    fn convert_entry(path: &Path, metadata: Metadata, target_metadata: Option<Metadata>) -> File {
        let mut attrs = FileAttributes {
            size: Some(metadata.len()),
            atime: None,
            mtime: Some(
                metadata
                    .modified()
                    .map(|t| {
                        t.into_std()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
                    .as_secs() as u32,
            ),
            permissions: Some(PortablePermissions::from(metadata.permissions()).mode() as u32),
            ..Default::default()
        };

        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;

            match rustix::fs::FileType::from_raw_mode(metadata.mode() as _) {
                rustix::fs::FileType::RegularFile => attrs.set_regular(true),
                rustix::fs::FileType::Directory => attrs.set_dir(true),
                rustix::fs::FileType::Symlink => attrs.set_symlink(true),
                rustix::fs::FileType::BlockDevice => attrs.set_block(true),
                rustix::fs::FileType::CharacterDevice => attrs.set_character(true),
                rustix::fs::FileType::Fifo => attrs.set_fifo(true),
                _ => {}
            }

            if let Some(target_metadata) = target_metadata {
                match rustix::fs::FileType::from_raw_mode(target_metadata.mode() as _) {
                    rustix::fs::FileType::RegularFile => attrs.set_regular(true),
                    rustix::fs::FileType::Directory => attrs.set_dir(true),
                    rustix::fs::FileType::BlockDevice => attrs.set_block(true),
                    rustix::fs::FileType::CharacterDevice => attrs.set_character(true),
                    rustix::fs::FileType::Fifo => attrs.set_fifo(true),
                    _ => {}
                }
            }
        }
        #[cfg(not(unix))]
        {
            if metadata.is_file() {
                attrs.set_regular(true);
            } else if metadata.is_dir() {
                attrs.set_dir(true);
            } else if metadata.file_type().is_symlink() {
                attrs.set_symlink(true);
            }

            if let Some(target_metadata) = target_metadata {
                if target_metadata.is_file() {
                    attrs.set_regular(true);
                } else if target_metadata.is_dir() {
                    attrs.set_dir(true);
                }
            }
        }

        File::new(
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string()),
            attrs,
        )
    }

    #[inline]
    fn next_handle_id(&mut self) -> compact_str::CompactString {
        let id = self.handle_id;
        self.handle_id += 1;

        compact_str::format_compact!("{id:x}")
    }

    #[inline]
    fn has_permission(&self, permission: Permission) -> bool {
        self.server
            .user_permissions
            .has_permission(self.user_uuid, permission)
    }

    #[inline]
    async fn async_is_ignored(&self, path: &Path, file_type: FileType) -> bool {
        Self::async_is_ignored_server(&self.server, self.user_uuid, path, file_type).await
    }

    #[inline]
    fn is_ignored_server(
        server: &crate::server::Server,
        user_uuid: uuid::Uuid,
        path: &Path,
        file_type: FileType,
    ) -> bool {
        if Self::is_ignored_root(path) {
            return false;
        }

        server.filesystem.is_ignored(path, file_type)
            || server
                .user_permissions
                .is_ignored(server, user_uuid, path, file_type)
    }

    #[inline]
    async fn async_is_ignored_server(
        server: &crate::server::Server,
        user_uuid: uuid::Uuid,
        path: &Path,
        file_type: FileType,
    ) -> bool {
        if Self::is_ignored_root(path) {
            return false;
        }

        server.filesystem.async_is_ignored(path, file_type).await
            || server
                .user_permissions
                .async_is_ignored(server, user_uuid, path, file_type)
                .await
    }

    #[inline]
    fn is_ignored_root(path: &Path) -> bool {
        path == Path::new("/") || path == Path::new(".") || path == Path::new("")
    }

    #[inline]
    fn allow_action(&self) -> bool {
        self.server.locked_state().is_none()
            && self
                .server
                .user_permissions
                .has_permission(self.user_uuid, Permission::FileSftp)
    }
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    #[inline]
    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<russh_sftp::protocol::Version, Self::Error> {
        Ok(russh_sftp::protocol::Version {
            version: russh_sftp::protocol::VERSION,
            extensions: HashMap::from([
                ("check-file".to_string(), "1".to_string()),
                ("copy-file".to_string(), "1".to_string()),
                ("space-available".to_string(), "6".to_string()),
                ("limits@openssh.com".to_string(), "1".to_string()),
                ("statvfs@openssh.com".to_string(), "2".to_string()),
                ("hardlink@openssh.com".to_string(), "1".to_string()),
                ("fsync@openssh.com".to_string(), "1".to_string()),
                ("lsetstat@openssh.com".to_string(), "1".to_string()),
                (
                    "users-groups-by-id@openssh.com".to_string(),
                    "1".to_string(),
                ),
                ("posix-rename@openssh.com".to_string(), "1".to_string()),
            ]),
        })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        if let Some(ServerHandle::File(handle)) = self.handles.remove(handle.as_str())
            && handle.diff_track
            && handle.diff_dirty
        {
            let file_size_cap = self.state.config.load().system.file_history.file_size_cap;
            let diff_key = handle.path.to_string_lossy().to_string();

            match self
                .server
                .filesystem
                .async_read_to_vec(&handle.path, file_size_cap.saturating_add(1) as usize)
                .await
            {
                Ok(after) if after.len() as u64 <= file_size_cap => {
                    if let Err(err) = self
                        .server
                        .diff
                        .record_edit(&diff_key, handle.diff_before, after, Some(self.user_uuid))
                        .await
                    {
                        tracing::warn!(
                            server = %self.server.uuid,
                            path = %diff_key,
                            "diff: sftp record_edit failed: {err:#}"
                        );
                    }
                }
                Ok(_) => {
                    tracing::debug!(
                        server = %self.server.uuid,
                        path = %diff_key,
                        "diff: sftp post-write content exceeds file_size_cap; not recorded"
                    );
                }
                Err(err) => {
                    tracing::debug!(
                        server = %self.server.uuid,
                        path = %diff_key,
                        "diff: sftp failed to read post-edit content: {err}"
                    );
                }
            }
        }

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        if path == "/.." || path == "." || path == "/" {
            return Ok(Name {
                id,
                files: vec![File::dummy("/".to_string())],
            });
        }

        if let Ok(path) = self.server.filesystem.async_canonicalize(&path).await {
            Ok(Name {
                id,
                files: vec![File::dummy(format!("/{}", path.display()))],
            })
        } else {
            Ok(Name {
                id,
                files: vec![File::dummy(format!(
                    "/{}",
                    self.server
                        .filesystem
                        .relative_path(Path::new(&path))
                        .display()
                ))],
            })
        }
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.handles.len()
            >= self
                .state
                .config
                .load()
                .system
                .sftp
                .limits
                .max_handles_per_channel
        {
            return Err(StatusCode::Failure);
        }

        if !self.has_permission(Permission::FileRead) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = match self.server.filesystem.async_canonicalize(&path).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if self.async_is_ignored(&path, FileType::Dir).await {
            return Err(StatusCode::NoSuchFile);
        }

        let dir = match tokio::task::spawn_blocking({
            let server = self.server.clone();
            let path = path.clone();

            move || server.filesystem.read_dir(path)
        })
        .await
        {
            Ok(Ok(dir)) => dir,
            _ => return Err(StatusCode::NoSuchFile),
        };

        let handle = self.next_handle_id();

        self.handles.insert(
            handle.clone(),
            ServerHandle::Dir(DirHandle {
                _guard: self
                    .limiter
                    .open_handle()
                    .map_err(|_| StatusCode::Failure)?,
                path: Arc::from(path),
                dir: Arc::new(Mutex::new(dir)),
                consumed: Arc::new(AtomicU64::new(0)),
            }),
        );

        Ok(Handle {
            id,
            handle: handle.into(),
        })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        let handle = match self.handles.get_mut(handle.as_str()) {
            Some(ServerHandle::Dir(handle)) => handle,
            _ => return Err(StatusCode::NoSuchFile),
        };

        if handle.consumed.load(Ordering::Relaxed)
            >= self.state.config.load().system.sftp.directory_entry_limit
        {
            return Err(StatusCode::Eof);
        }

        let files = tokio::task::spawn_blocking({
            let server = self.server.clone();
            let user_uuid = self.user_uuid;
            let state = self.state.clone();
            let path = Arc::clone(&handle.path);
            let dir = Arc::clone(&handle.dir);
            let consumed = Arc::clone(&handle.consumed);

            move || {
                let mut files = Vec::new();
                let mut dir = dir.lock();

                loop {
                    let file = match dir.next_entry() {
                        Some(Ok((_, file))) => file,
                        _ => {
                            if files.is_empty() {
                                return Err(StatusCode::Eof);
                            }

                            break;
                        }
                    };

                    let path = path.join(file);
                    let metadata = match server.filesystem.symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };

                    if Self::is_ignored_server(
                        &server,
                        user_uuid,
                        &path,
                        metadata.file_type().into(),
                    ) {
                        continue;
                    }

                    let target_metadata = if metadata.is_symlink() {
                        server.filesystem.metadata(&path).ok()
                    } else {
                        None
                    };

                    files.push(Self::convert_entry(&path, metadata, target_metadata));
                    let prev_consumed = consumed.fetch_add(1, Ordering::Relaxed);

                    if prev_consumed + 1 >= state.config.load().system.sftp.directory_entry_limit
                        || files.len()
                            >= state.config.load().system.sftp.directory_entry_send_amount
                    {
                        tracing::debug!(
                            "{} entries sent early in sftp readdir ({} total)",
                            files.len(),
                            prev_consumed + 1,
                        );

                        break;
                    }
                }

                Ok::<_, StatusCode>(files)
            }
        })
        .await
        .map_err(|_| StatusCode::Failure)??;

        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileDelete) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = match self.server.filesystem.async_canonicalize(&filename).await {
            Ok(path) => path,
            Err(_) => PathBuf::from(filename),
        };

        if let Ok(metadata) = self.server.filesystem.async_symlink_metadata(&path).await {
            if metadata.is_dir() {
                return Err(StatusCode::NoSuchFile);
            }

            if self
                .async_is_ignored(&path, metadata.file_type().into())
                .await
            {
                return Err(StatusCode::NoSuchFile);
            }

            let before = {
                let config = self.state.config.load();
                let history = &config.system.file_history;
                let cap = history.file_size_cap;

                if history.enabled && metadata.len() > 0 && metadata.len() <= cap {
                    drop(config);
                    match self
                        .server
                        .filesystem
                        .async_read_to_vec(&path, cap.saturating_add(1) as usize)
                        .await
                    {
                        Ok(content) if content.len() as u64 <= cap => Some(content),
                        _ => None,
                    }
                } else {
                    None
                }
            };

            if self.server.filesystem.truncate_path(&path).await.is_err() {
                return Err(StatusCode::NoSuchFile);
            }

            if let Err(err) = self
                .server
                .diff
                .forget_file(&path.to_string_lossy(), before)
                .await
            {
                tracing::error!("failed to forget file from diff storage: {:?}", err);
            }

            self.server.activity.log_activity(Activity {
                event: ActivityEvent::SftpDelete,
                user: Some(self.user_uuid),
                ip: Some(self.user_ip),
                metadata: Some(json!({
                    "files": [self.server.filesystem.relative_path(&path)],
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileDelete) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = match self.server.filesystem.async_canonicalize(&path).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if let Ok(metadata) = self.server.filesystem.async_symlink_metadata(&path).await {
            if !metadata.is_dir() {
                return Err(StatusCode::NoSuchFile);
            }

            if self.async_is_ignored(&path, FileType::Dir).await {
                return Err(StatusCode::NoSuchFile);
            }

            if path != self.server.filesystem.base_path
                && self.server.filesystem.truncate_path(&path).await.is_err()
            {
                return Err(StatusCode::NoSuchFile);
            }

            self.server.activity.log_activity(Activity {
                event: ActivityEvent::SftpDelete,
                user: Some(self.user_uuid),
                ip: Some(self.user_ip),
                metadata: Some(json!({
                    "files": [self.server.filesystem.relative_path(&path)],
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileCreate) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = Path::new(&path);

        if self.async_is_ignored(path, FileType::Dir).await {
            return Err(StatusCode::NoSuchFile);
        }
        if self
            .server
            .filesystem
            .async_symlink_metadata(&path)
            .await
            .is_ok()
        {
            return Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            });
        }

        if self
            .server
            .filesystem
            .async_create_dir(&path)
            .await
            .is_err()
        {
            return Err(StatusCode::NoSuchFile);
        }

        if let Err(err) = self.server.filesystem.async_chown_path(path).await {
            tracing::warn!("failed to chown new directory: {:?}", err);
        }
        if let Some(permissions) = attrs.permissions
            && self
                .server
                .filesystem
                .async_set_permissions(&path, PortablePermissions::from_mode_dir(permissions))
                .await
                .is_err()
        {
            return Err(StatusCode::Failure);
        }

        self.server.activity.log_activity(Activity {
            event: ActivityEvent::SftpCreateDirectory,
            user: Some(self.user_uuid),
            ip: Some(self.user_ip),
            metadata: Some(json!({
                "files": [self.server.filesystem.relative_path(path)],
            })),
            schedule: None,
            timestamp: chrono::Utc::now(),
        });

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        old_path: String,
        new_path: String,
    ) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileUpdate) {
            return Err(StatusCode::PermissionDenied);
        }

        let old_path = match self.server.filesystem.async_canonicalize(&old_path).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };
        let new_path = PathBuf::from(new_path);

        let old_metadata = match self
            .server
            .filesystem
            .async_symlink_metadata(&old_path)
            .await
        {
            Ok(metadata) => metadata,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if self
            .server
            .filesystem
            .async_symlink_metadata(&new_path)
            .await
            .is_ok()
            || self
                .async_is_ignored(&old_path, old_metadata.file_type().into())
                .await
            || self
                .async_is_ignored(&new_path, old_metadata.file_type().into())
                .await
        {
            return Err(StatusCode::Failure);
        }

        let activity = Activity {
            event: ActivityEvent::SftpRename,
            user: Some(self.user_uuid),
            ip: Some(self.user_ip),
            metadata: Some(json!({
                "files": [
                    {
                        "from": self.server.filesystem.relative_path(&old_path),
                        "to": self.server.filesystem.relative_path(&new_path),
                    }
                ],
            })),
            schedule: None,
            timestamp: chrono::Utc::now(),
        };

        if self
            .server
            .filesystem
            .rename_path(
                &old_path,
                &new_path,
                if self.has_permission(Permission::FileCreate) {
                    RenameParents::Create
                } else {
                    RenameParents::Require
                },
            )
            .await
            .is_err()
        {
            return Err(StatusCode::NoSuchFile);
        }

        let new_path = self.server.filesystem.diff_key(&new_path).await;
        let new_key = new_path.to_string_lossy().to_string();
        let replaced = match self
            .server
            .diff
            .rename_file(&old_path.to_string_lossy(), &new_key)
            .await
        {
            Ok(replaced) => replaced,
            Err(err) => {
                tracing::error!("failed to rename file in diff storage: {:?}", err);
                None
            }
        };

        if let Some(before) = replaced {
            let file_size_cap = self.state.config.load().system.file_history.file_size_cap;

            match self
                .server
                .filesystem
                .async_read_to_vec(&new_path, file_size_cap.saturating_add(1) as usize)
                .await
            {
                Ok(after) if after.len() as u64 <= file_size_cap => {
                    if let Err(err) = self
                        .server
                        .diff
                        .record_edit(&new_key, before, after, Some(self.user_uuid))
                        .await
                    {
                        tracing::warn!(
                            server = %self.server.uuid,
                            path = %new_key,
                            "diff: sftp record_edit on replace failed: {err:#}"
                        );
                    }
                }
                Ok(_) => {
                    tracing::debug!(
                        server = %self.server.uuid,
                        path = %new_key,
                        "diff: sftp replace content exceeds file_size_cap; not recorded"
                    );
                }
                Err(err) => {
                    tracing::debug!(
                        server = %self.server.uuid,
                        path = %new_key,
                        "diff: sftp failed to read replaced content: {err}"
                    );
                }
            }
        }

        self.server.activity.log_activity(activity);

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileUpdate) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = match self.server.filesystem.async_canonicalize(&path).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if path.components().next().is_none() {
            return Err(StatusCode::NoSuchFile);
        }

        let metadata = match self.server.filesystem.async_symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if self
            .async_is_ignored(&path, metadata.file_type().into())
            .await
        {
            return Err(StatusCode::NoSuchFile);
        }

        if let Some(permissions) = attrs.permissions {
            let permissions = if metadata.is_dir() {
                PortablePermissions::from_mode_dir(permissions)
            } else {
                PortablePermissions::from_mode_file(permissions)
            };
            self.server
                .filesystem
                .async_set_permissions(&path, permissions)
                .await
                .map_err(|_| StatusCode::Failure)?;
        }

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        let handle = match self.handles.get(handle.as_str()) {
            Some(ServerHandle::File(handle)) => handle,
            _ => return Err(StatusCode::NoSuchFile),
        };

        self.setstat(id, handle.path.to_string_lossy().to_string(), attrs)
            .await
    }

    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileRead) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = match self.server.filesystem.async_canonicalize(&path).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        let metadata = match self.server.filesystem.async_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if self
            .async_is_ignored(&path, metadata.file_type().into())
            .await
        {
            return Err(StatusCode::NoSuchFile);
        }

        let file = Self::convert_entry(&path, metadata, None);

        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: file.attrs,
        })
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        let handle = match self.handles.get(handle.as_str()) {
            Some(handle) => handle,
            None => return Err(StatusCode::NoSuchFile),
        };

        self.stat(id, handle.path().to_string_lossy().to_string())
            .await
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileRead) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = Path::new(&path);

        let metadata = match self.server.filesystem.async_symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if self
            .async_is_ignored(path, metadata.file_type().into())
            .await
        {
            return Err(StatusCode::NoSuchFile);
        }

        let target_metadata = if metadata.is_symlink() {
            self.server.filesystem.async_metadata(path).await.ok()
        } else {
            None
        };

        let file = Self::convert_entry(path, metadata, target_metadata);

        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: file.attrs,
        })
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileRead) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = match self.server.filesystem.async_read_link(&path).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        let metadata = match self.server.filesystem.async_symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if self
            .async_is_ignored(&path, metadata.file_type().into())
            .await
        {
            return Err(StatusCode::NoSuchFile);
        }

        let target_metadata = if metadata.is_symlink() {
            self.server.filesystem.async_metadata(&path).await.ok()
        } else {
            None
        };

        let file = Self::convert_entry(&path, metadata, target_metadata);

        Ok(Name {
            id,
            files: vec![file],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if !self.has_permission(Permission::FileCreate) {
            return Err(StatusCode::PermissionDenied);
        }

        if linkpath == targetpath {
            return Err(StatusCode::NoSuchFile);
        }

        let linkpath = PathBuf::from(linkpath);
        let targetpath = match self.server.filesystem.async_canonicalize(&targetpath).await {
            Ok(path) => path,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        let metadata = match self
            .server
            .filesystem
            .async_symlink_metadata(&targetpath)
            .await
        {
            Ok(metadata) => metadata,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        if !metadata.is_file()
            || self
                .async_is_ignored(&targetpath, metadata.file_type().into())
                .await
            || self.async_is_ignored(&linkpath, FileType::File).await
        {
            return Err(StatusCode::NoSuchFile);
        }

        if self
            .server
            .filesystem
            .async_symlink(&targetpath, &linkpath)
            .await
            .is_err()
        {
            return Err(StatusCode::Failure);
        }

        if let Err(err) = self.server.filesystem.async_chown_path(&targetpath).await {
            tracing::warn!("failed to chown new symlink: {:?}", err);
        }

        self.server.activity.log_activity(Activity {
            event: ActivityEvent::SftpCreate,
            user: Some(self.user_uuid),
            ip: Some(self.user_ip),
            metadata: Some(json!({
                "files": [self.server.filesystem.relative_path(&linkpath)],
            })),
            schedule: None,
            timestamp: chrono::Utc::now(),
        });

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: russh_sftp::protocol::OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        if self.handles.len()
            >= self
                .state
                .config
                .load()
                .system
                .sftp
                .limits
                .max_handles_per_channel
        {
            return Err(StatusCode::Failure);
        }

        if (pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND))
            && !self.has_permission(Permission::FileUpdate)
        {
            return Err(StatusCode::PermissionDenied);
        }
        if pflags.contains(OpenFlags::CREATE) && !self.has_permission(Permission::FileCreate) {
            return Err(StatusCode::PermissionDenied);
        }
        if pflags.contains(OpenFlags::TRUNCATE) && !self.has_permission(Permission::FileDelete) {
            return Err(StatusCode::PermissionDenied);
        }
        if pflags.contains(OpenFlags::READ) && !self.has_permission(Permission::FileReadContent) {
            return Err(StatusCode::PermissionDenied);
        }

        let path = self.server.filesystem.diff_key(Path::new(&filename)).await;

        let pre_size = match self.server.filesystem.async_symlink_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(StatusCode::NoSuchFile);
                }

                Some(metadata.len())
            }
            Err(_) => {
                if !pflags.contains(OpenFlags::CREATE) {
                    return Err(StatusCode::NoSuchFile);
                }

                None
            }
        };

        if self.async_is_ignored(&path, FileType::File).await {
            return Err(StatusCode::NoSuchFile);
        }

        let is_write = pflags.contains(OpenFlags::WRITE)
            || pflags.contains(OpenFlags::APPEND)
            || pflags.contains(OpenFlags::CREATE)
            || pflags.contains(OpenFlags::TRUNCATE);

        if is_write && self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        let (history_enabled, file_size_cap) = {
            let config = self.state.config.load();
            (
                config.system.file_history.enabled,
                config.system.file_history.file_size_cap,
            )
        };

        let mut diff_track = is_write
            && history_enabled
            && matches!(pre_size, Some(size) if size > 0 && size <= file_size_cap);

        let diff_before = if diff_track {
            match self
                .server
                .filesystem
                .async_read_to_vec(&path, (file_size_cap + 1) as usize)
                .await
            {
                Ok(before) if before.len() as u64 <= file_size_cap => Some(before),
                Ok(_) => {
                    diff_track = false;
                    None
                }
                Err(err) => {
                    tracing::debug!(
                        server = %self.server.uuid,
                        path = %path.display(),
                        "diff: sftp failed to read pre-edit content: {err}"
                    );
                    diff_track = false;
                    None
                }
            }
        } else {
            None
        };

        let mut activity_event = None;
        if pflags.contains(OpenFlags::TRUNCATE) || pflags.contains(OpenFlags::CREATE) {
            activity_event = Some(ActivityEvent::SftpCreate);
        } else if pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND) {
            activity_event = Some(ActivityEvent::SftpWrite);
        } else if pflags.contains(OpenFlags::READ)
            && self.state.config.load().system.sftp.activity.log_file_reads
        {
            activity_event = Some(ActivityEvent::SftpRead);
        }

        let file = tokio::task::spawn_blocking({
            let server = self.server.clone();
            let path = path.clone();

            move || {
                let mut open_options = OpenOptions::new();
                if pflags.contains(OpenFlags::READ) {
                    open_options.read(true);
                }
                if pflags.contains(OpenFlags::WRITE) {
                    open_options.write(true);
                }
                if pflags.contains(OpenFlags::APPEND) {
                    open_options.append(true);
                }
                if pflags.contains(OpenFlags::CREATE) {
                    if pflags.contains(OpenFlags::EXCLUDE) {
                        open_options.create_new(true);
                    } else {
                        open_options.create(true);
                    }
                }
                if pflags.contains(OpenFlags::TRUNCATE) {
                    open_options.truncate(true);
                }

                let file = server.filesystem.open_with(&path, open_options)?;
                let initial_size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);

                let mut file = crate::server::filesystem::file::ServerFile::new_file(
                    server.clone(),
                    &path,
                    file,
                    initial_size,
                )
                .map_err(std::io::Error::other)?;

                if pflags.contains(OpenFlags::APPEND) {
                    file.seek(SeekFrom::End(0))?;
                }

                Ok::<_, std::io::Error>(file)
            }
        })
        .await
        .map_err(|_| StatusCode::Failure)?
        .map_err(|_| StatusCode::Failure)?;

        if pflags.contains(OpenFlags::CREATE)
            && let Err(err) = self.server.filesystem.async_chown_path(&path).await
        {
            tracing::warn!("failed to chown new file: {:?}", err);
        }

        let path_components = self.server.filesystem.path_to_components(&path);

        if let Some(event) = activity_event {
            self.server.activity.log_activity(Activity {
                event,
                user: Some(self.user_uuid),
                ip: Some(self.user_ip),
                metadata: Some(json!({
                    "files": [self.server.filesystem.relative_path(&path)],
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }

        if pflags.contains(OpenFlags::TRUNCATE)
            && let Some(old) = pre_size.filter(|&s| s > 0)
            && let Some(parent_components) = path_components.get(0..path_components.len() - 1)
        {
            self.server
                .filesystem
                .async_allocate_in_path_iterator(parent_components, -(old as i64), true)
                .await;
        }

        let handle = self.next_handle_id();

        self.handles.insert(
            handle.clone(),
            ServerHandle::File(FileHandle {
                _guard: self
                    .limiter
                    .open_handle()
                    .map_err(|_| StatusCode::Failure)?,
                path,
                file: Arc::new(Mutex::new(file)),
                append: pflags.contains(OpenFlags::APPEND),
                diff_track,
                diff_before,
                diff_dirty: false,
            }),
        );

        Ok(Handle {
            id,
            handle: handle.into(),
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        let handle = match self.handles.get_mut(handle.as_str()) {
            Some(ServerHandle::File(handle)) => handle,
            _ => return Err(StatusCode::NoSuchFile),
        };

        let data = tokio::task::spawn_blocking({
            let file = Arc::clone(&handle.file);

            move || -> Result<Vec<u8>, std::io::Error> {
                let mut data = vec![0; len.min(256 * 1024) as usize];
                let bytes_read = file.lock().read_at(offset, &mut data)?;

                data.truncate(bytes_read);
                data.shrink_to_fit();
                Ok(data)
            }
        })
        .await
        .map_err(|_| StatusCode::Failure)?
        .map_err(|_| StatusCode::Failure)?;

        if data.is_empty() {
            return Err(StatusCode::Eof);
        }

        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if !self.allow_action() {
            return Err(StatusCode::PermissionDenied);
        }

        let handle = match self.handles.get_mut(handle.as_str()) {
            Some(ServerHandle::File(handle)) => handle,
            _ => return Err(StatusCode::NoSuchFile),
        };

        if self.state.config.load().system.sftp.read_only {
            return Err(StatusCode::PermissionDenied);
        }

        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(StatusCode::BadMessage);
        }

        tokio::task::spawn_blocking({
            let file = Arc::clone(&handle.file);
            let append = handle.append;

            move || {
                let mut file = file.lock();

                if append {
                    file.write_all(&data)
                } else {
                    file.write_all_at(offset, &data)
                }
            }
        })
        .await
        .map_err(|_| StatusCode::Failure)?
        .map_err(|_| StatusCode::Failure)?;

        handle.diff_dirty = true;

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn extended(
        &mut self,
        id: u32,
        command: String,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Packet, Self::Error> {
        extended::handle_extended(self, id, command, data).await
    }
}
