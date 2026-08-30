use crate::{
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        filesystem::RenameParents,
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
    path::{Path, PathBuf},
    sync::Arc,
};

mod extended;

pub struct FileHandle {
    _guard: super::limiter::SshLimiterHandleGuard,
    path: PathBuf,
    path_components: Vec<String>,

    file: Arc<Mutex<std::fs::File>>,
    known_size: u64,
    append: bool,

    diff_track: bool,
    diff_before: Option<Vec<u8>>,
    diff_dirty: bool,
}

pub struct DirHandle {
    _guard: super::limiter::SshLimiterHandleGuard,
    path: PathBuf,

    dir: crate::server::filesystem::cap::AsyncReadDir,

    consumed: u64,
}

pub enum ServerHandle {
    File(FileHandle),
    Dir(DirHandle),
}

impl ServerHandle {
    #[inline]
    fn path(&self) -> &Path {
        match self {
            ServerHandle::File(handle) => handle.path.as_path(),
            ServerHandle::Dir(handle) => handle.path.as_path(),
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
            permissions: Some(PortablePermissions::from(metadata.permissions()).mode),
            ..Default::default()
        };

        #[cfg(unix)]
        {
            match rustix::fs::FileType::from_raw_mode(
                PortablePermissions::from(metadata.permissions()).mode,
            ) {
                rustix::fs::FileType::RegularFile => attrs.set_regular(true),
                rustix::fs::FileType::Directory => attrs.set_dir(true),
                rustix::fs::FileType::Symlink => attrs.set_symlink(true),
                rustix::fs::FileType::BlockDevice => attrs.set_block(true),
                rustix::fs::FileType::CharacterDevice => attrs.set_character(true),
                rustix::fs::FileType::Fifo => attrs.set_fifo(true),
                _ => {}
            }

            if let Some(target_metadata) = target_metadata {
                match rustix::fs::FileType::from_raw_mode(
                    PortablePermissions::from(target_metadata.permissions()).mode,
                ) {
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
    fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        Self::is_ignored_server(&self.server, self.user_uuid, path, is_dir)
    }

    #[inline]
    fn is_ignored_server(
        server: &crate::server::Server,
        user_uuid: uuid::Uuid,
        path: &Path,
        is_dir: bool,
    ) -> bool {
        if path == Path::new("/") || path == Path::new(".") || path == Path::new("") {
            return false;
        }

        server.filesystem.is_ignored(path, is_dir)
            || server.user_permissions.is_ignored(user_uuid, path, is_dir)
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

        if self.is_ignored(&path, true) {
            return Err(StatusCode::NoSuchFile);
        }

        let dir = match self.server.filesystem.async_read_dir(&path).await {
            Ok(dir) => dir,
            Err(_) => return Err(StatusCode::NoSuchFile),
        };

        let handle = self.next_handle_id();

        self.handles.insert(
            handle.clone(),
            ServerHandle::Dir(DirHandle {
                _guard: self
                    .limiter
                    .open_handle()
                    .map_err(|_| StatusCode::Failure)?,
                path,
                dir,
                consumed: 0,
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

        if handle.consumed >= self.state.config.load().system.sftp.directory_entry_limit {
            return Err(StatusCode::Eof);
        }

        let mut files = Vec::new();

        loop {
            let file = match handle.dir.next_entry().await {
                Some(Ok((_, file))) => file,
                _ => {
                    if files.is_empty() {
                        return Err(StatusCode::Eof);
                    }

                    break;
                }
            };

            let path = handle.path.join(file);
            let metadata = match self.server.filesystem.async_symlink_metadata(&path).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if Self::is_ignored_server(&self.server, self.user_uuid, &path, metadata.is_dir()) {
                continue;
            }

            let target_metadata = if metadata.is_symlink() {
                self.server.filesystem.async_metadata(&path).await.ok()
            } else {
                None
            };

            files.push(Self::convert_entry(&path, metadata, target_metadata));
            handle.consumed += 1;

            if handle.consumed >= self.state.config.load().system.sftp.directory_entry_limit
                || files.len()
                    >= self
                        .state
                        .config
                        .load()
                        .system
                        .sftp
                        .directory_entry_send_amount
            {
                tracing::debug!(
                    "{} entries sent early in sftp readdir ({} total)",
                    files.len(),
                    handle.consumed,
                );

                break;
            }
        }

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

            if self.is_ignored(&path, metadata.is_dir()) {
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

            if self.is_ignored(&path, true) {
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

        if self.is_ignored(path, true) {
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
                .async_set_permissions(&path, PortablePermissions::from_mode(permissions))
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
            || self.is_ignored(&old_path, old_metadata.is_dir())
            || self.is_ignored(&new_path, old_metadata.is_dir())
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

        let new_path = self.server.filesystem.relative_path(&new_path);
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

        if self.is_ignored(&path, metadata.is_dir()) {
            return Err(StatusCode::NoSuchFile);
        }

        if let Some(permissions) = attrs.permissions {
            self.server
                .filesystem
                .async_set_permissions(&path, PortablePermissions::from_mode(permissions))
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

        if self.is_ignored(&path, metadata.is_dir()) {
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

        if self.is_ignored(path, metadata.is_dir()) {
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

        if self.is_ignored(&path, metadata.is_dir()) {
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
            || self.is_ignored(&targetpath, metadata.is_dir())
            || self.is_ignored(&linkpath, false)
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

        let path = match self.server.filesystem.async_canonicalize(&filename).await {
            Ok(path) => path,
            Err(_) => PathBuf::from(filename.strip_prefix("/").unwrap_or(&filename)),
        };

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

        if self.is_ignored(&path, false) {
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

                server.filesystem.open_with(path, open_options)
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
                path_components,
                file: Arc::new(Mutex::new(file)),
                known_size: if pflags.contains(OpenFlags::TRUNCATE) {
                    0
                } else {
                    pre_size.unwrap_or(0)
                },
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

        let end = offset.saturating_add(data.len() as u64);
        let delta = if handle.append {
            data.len() as i64
        } else {
            end.saturating_sub(handle.known_size) as i64
        };

        if !self
            .server
            .filesystem
            .async_allocate_in_path_iterator(
                handle
                    .path_components
                    .get(0..handle.path_components.len() - 1)
                    .ok_or(StatusCode::Failure)?,
                delta,
                false,
            )
            .await
        {
            return Err(StatusCode::Failure);
        }

        match tokio::task::spawn_blocking({
            let file = Arc::clone(&handle.file);

            move || file.lock().write_all_at(offset, &data)
        })
        .await
        {
            Ok(Ok(())) => (),
            Ok(Err(_)) => {
                self.server
                    .filesystem
                    .async_allocate_in_path_iterator(
                        handle
                            .path_components
                            .get(0..handle.path_components.len() - 1)
                            .ok_or(StatusCode::Failure)?,
                        -delta,
                        true,
                    )
                    .await;
                return Err(StatusCode::Failure);
            }
            Err(_) => {
                self.server
                    .filesystem
                    .async_allocate_in_path_iterator(
                        handle
                            .path_components
                            .get(0..handle.path_components.len() - 1)
                            .ok_or(StatusCode::Failure)?,
                        -delta,
                        true,
                    )
                    .await;
                return Err(StatusCode::Failure);
            }
        }

        handle.diff_dirty = true;
        if !handle.append {
            handle.known_size = handle.known_size.max(end);
        }

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
