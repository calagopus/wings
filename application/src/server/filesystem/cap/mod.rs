use crate::{
    io::{
        SafeSliceExt,
        abort::{AbortGuard, AbortListener},
    },
    utils::{PortablePermissions, PortablePermissionsApplier},
};
use arc_swap::ArcSwapOption;
use cap_std::fs::{Metadata, OpenOptions};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod utils;
pub use utils::{AsyncReadDir, AsyncWalkDir, FileType, ReadDir, WalkDir, WalkEntry};

#[derive(Debug, Clone)]
pub struct CapFilesystem {
    pub base_path: Arc<Path>,
    pub(super) inner: Arc<ArcSwapOption<cap_std::fs::Dir>>,
}

impl CapFilesystem {
    pub async fn new(base_path: &Path) -> Result<Self, std::io::Error> {
        let base_path: Arc<Path> = Arc::from(base_path);

        let inner = tokio::task::spawn_blocking({
            let base_path = base_path.clone();

            move || cap_std::fs::Dir::open_ambient_dir(&*base_path, cap_std::ambient_authority())
        })
        .await??;

        Ok(Self {
            base_path,
            inner: Arc::new(ArcSwapOption::new(Some(Arc::new(inner)))),
        })
    }

    pub fn new_uninitialized(base_path: &Path) -> Self {
        Self {
            base_path: Arc::from(base_path),
            inner: Arc::new(ArcSwapOption::empty()),
        }
    }

    pub fn get_virtual(
        &self,
        server: crate::server::Server,
    ) -> crate::server::filesystem::virtualfs::cap::VirtualCapFilesystem {
        crate::server::filesystem::virtualfs::cap::VirtualCapFilesystem {
            inner: self.clone(),
            server,
            is_primary_server_fs: false,
            is_writable: false,
            is_ignored: None,
        }
    }

    #[inline]
    pub fn is_uninitialized(&self) -> bool {
        self.inner.load().is_none()
    }

    /// Closes the inner fd, preventing any further operations from succeeding.
    #[inline]
    pub fn close(&self) {
        self.inner.store(None);
    }

    #[inline]
    pub fn get_inner(&self) -> Result<Arc<cap_std::fs::Dir>, std::io::Error> {
        self.inner
            .load_full()
            .ok_or_else(|| std::io::Error::other("filesystem not initialized"))
    }

    #[inline]
    pub fn resolve_path(path: &Path) -> PathBuf {
        let mut result = PathBuf::new();

        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    if !result.as_os_str().is_empty()
                        && result.components().next_back() != Some(std::path::Component::RootDir)
                    {
                        result.pop();
                    }
                }
                std::path::Component::CurDir => {}
                _ => {
                    result.push(component);
                }
            }
        }

        result
    }

    #[inline]
    pub fn relative_path(&self, path: &Path) -> PathBuf {
        Self::resolve_path(if let Ok(path) = path.strip_prefix(&*self.base_path) {
            path
        } else if let Ok(path) = path.strip_prefix("/") {
            path
        } else {
            path
        })
    }

    pub fn resolve_symlink_contents(link: &Path, target: &Path) -> (PathBuf, PathBuf) {
        let link = Self::resolve_path(link.strip_prefix("/").unwrap_or(link));
        let directory = link.parent().unwrap_or(Path::new(""));

        let resolved = match target.strip_prefix("/") {
            Ok(target) => Self::resolve_path(target),
            Err(_) => Self::resolve_path(&directory.join(target)),
        };

        let mut directory_components = directory.components().peekable();
        let mut resolved_components = resolved.components().peekable();
        while let (Some(directory_component), Some(resolved_component)) =
            (directory_components.peek(), resolved_components.peek())
        {
            if directory_component != resolved_component {
                break;
            }

            directory_components.next();
            resolved_components.next();
        }

        let mut contents = PathBuf::new();
        for _ in directory_components {
            contents.push("..");
        }
        for component in resolved_components {
            contents.push(component);
        }

        if contents.as_os_str().is_empty() {
            contents.push(".");
        }

        (contents, resolved)
    }

    pub async fn async_create_dir(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        tokio::task::spawn_blocking(move || inner.create_dir(path)).await??;

        Ok(())
    }

    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.create_dir(path)?;

        Ok(())
    }

    pub async fn async_create_dir_all(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        tokio::task::spawn_blocking(move || inner.create_dir_all(path)).await??;

        Ok(())
    }

    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.create_dir_all(path)?;

        Ok(())
    }

    pub async fn async_remove_dir_all(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let self_clone = self.clone();
        tokio::task::spawn_blocking(move || self_clone.remove_dir_all(path)).await??;

        Ok(())
    }

    pub fn remove_dir_all(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());
        let inner = self.get_inner()?;

        let mut first_error = None;
        let mut failed: u64 = 0;
        let mut record = |err: std::io::Error| {
            failed += 1;
            if first_error.is_none() {
                first_error = Some(err);
            }
        };

        let mut walker = WalkDir::new(self.clone(), path.clone())?.reversed();
        let mut cleared_parent: Option<PathBuf> = None;

        while let Some(entry) = walker.next_entry() {
            match entry {
                Ok(entry) => {
                    if let Err(err) = Self::remove_entry(
                        &inner,
                        &entry.path,
                        entry.file_type(),
                        &mut cleared_parent,
                    ) {
                        record(err);
                    }
                }
                Err(err) => record(err),
            }
        }

        if !path.as_os_str().is_empty()
            && let Err(err) = Self::remove_entry(&inner, &path, FileType::Dir, &mut cleared_parent)
        {
            record(err);
        }

        match first_error {
            Some(err) => {
                tracing::warn!(
                    path = %path.display(),
                    "failed to remove {} entr{} while removing directory: {:#?}",
                    failed,
                    if failed == 1 { "y" } else { "ies" },
                    err
                );

                Err(err)
            }
            None => Ok(()),
        }
    }

    fn remove_entry(
        inner: &cap_std::fs::Dir,
        path: &Path,
        file_type: FileType,
        cleared_parent: &mut Option<PathBuf>,
    ) -> Result<(), std::io::Error> {
        fn remove(
            inner: &cap_std::fs::Dir,
            path: &Path,
            is_dir: bool,
        ) -> Result<(), std::io::Error> {
            if is_dir {
                inner.remove_dir(path)
            } else {
                inner.remove_file(path)
            }
        }

        let is_dir = file_type.is_dir();
        let err = match remove(inner, path, is_dir) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => err,
            Err(err) => return Err(err),
        };

        #[cfg(target_os = "linux")]
        {
            if Self::clear_inode_flags(inner, path, file_type).is_ok()
                && remove(inner, path, is_dir).is_ok()
            {
                return Ok(());
            }

            if let Some(parent) = path.parent()
                && cleared_parent.as_deref() != Some(parent)
            {
                let cleared = if parent.as_os_str().is_empty() {
                    Self::clear_flags_on_fd(inner).is_ok()
                } else {
                    Self::clear_inode_flags(inner, parent, FileType::Dir).is_ok()
                };

                if cleared {
                    *cleared_parent = Some(parent.to_path_buf());

                    if remove(inner, path, is_dir).is_ok() {
                        return Ok(());
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cleared_parent;

        Err(err)
    }

    #[cfg(target_os = "linux")]
    fn clear_flags_on_fd<Fd: std::os::fd::AsFd>(fd: Fd) -> Result<(), std::io::Error> {
        let mask = rustix::fs::IFlags::IMMUTABLE | rustix::fs::IFlags::APPEND;

        let current = rustix::fs::ioctl_getflags(&fd)?;
        if current.intersects(mask) {
            rustix::fs::ioctl_setflags(&fd, current & !mask)?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn clear_inode_flags(
        inner: &cap_std::fs::Dir,
        path: &Path,
        file_type: FileType,
    ) -> Result<(), std::io::Error> {
        match file_type {
            FileType::Dir => Self::clear_flags_on_fd(inner.open_dir(path)?),
            FileType::File => Self::clear_flags_on_fd(inner.open(path)?),
            _ => Ok(()),
        }
    }

    pub async fn async_remove_file(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        tokio::task::spawn_blocking(move || inner.remove_file(path)).await??;

        Ok(())
    }

    pub fn remove_file(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.remove_file(path)?;

        Ok(())
    }

    pub async fn async_rename(
        &self,
        from: impl AsRef<Path>,
        to_dir: &CapFilesystem,
        to: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let from = self.relative_path(from.as_ref());
        let to = self.relative_path(to.as_ref());

        let inner = self.get_inner()?;
        let to_inner = to_dir.get_inner()?;
        tokio::task::spawn_blocking(move || inner.rename(from, &to_inner, to)).await??;

        Ok(())
    }

    pub fn rename(
        &self,
        from: impl AsRef<Path>,
        to_dir: &CapFilesystem,
        to: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let from = self.relative_path(from.as_ref());
        let to = self.relative_path(to.as_ref());

        let inner = self.get_inner()?;
        let to_inner = to_dir.get_inner()?;
        inner.rename(from, &to_inner, to)?;

        Ok(())
    }

    pub async fn async_metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(tokio::fs::metadata(&*self.base_path).await?)
        } else {
            let inner = self.get_inner()?;

            tokio::task::spawn_blocking(move || inner.metadata(path)).await??
        };

        Ok(metadata)
    }

    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(std::fs::metadata(&*self.base_path)?)
        } else {
            let inner = self.get_inner()?;

            inner.metadata(path)?
        };

        Ok(metadata)
    }

    pub async fn async_symlink_metadata(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Metadata, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(
                tokio::fs::symlink_metadata(&*self.base_path).await?,
            )
        } else {
            let inner = self.get_inner()?;

            tokio::task::spawn_blocking(move || inner.symlink_metadata(path)).await??
        };

        Ok(metadata)
    }

    pub fn symlink_metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(std::fs::symlink_metadata(&*self.base_path)?)
        } else {
            let inner = self.get_inner()?;

            inner.symlink_metadata(path)?
        };

        Ok(metadata)
    }

    pub async fn async_canonicalize(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PathBuf, std::io::Error> {
        let path = self.relative_path(path.as_ref());
        if path.components().next().is_none() {
            return Ok(path);
        }

        let inner = self.get_inner()?;
        let canonicalized = tokio::task::spawn_blocking(move || inner.canonicalize(path)).await??;

        Ok(canonicalized)
    }

    pub fn canonicalize(&self, path: impl AsRef<Path>) -> Result<PathBuf, std::io::Error> {
        let path = self.relative_path(path.as_ref());
        if path.components().next().is_none() {
            return Ok(path);
        }

        let inner = self.get_inner()?;
        let canonicalized = inner.canonicalize(path)?;

        Ok(canonicalized)
    }

    pub async fn async_read_link(&self, path: impl AsRef<Path>) -> Result<PathBuf, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let link = tokio::task::spawn_blocking(move || inner.read_link(path)).await??;

        Ok(link)
    }

    pub fn read_link(&self, path: impl AsRef<Path>) -> Result<PathBuf, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let link = inner.read_link(path)?;

        Ok(link)
    }

    pub fn read_link_contents(&self, path: impl AsRef<Path>) -> Result<PathBuf, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let link_contents = inner.read_link_contents(path)?;

        Ok(link_contents)
    }

    pub async fn async_read_to_string(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<String, std::io::Error> {
        let content = self.async_read_to_vec(path, limit).await?;

        String::from_utf8(content)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    pub async fn async_read_to_vec(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let mut file = self.async_open(path).await?;
        let mut content = Vec::new();

        let mut buffer = vec![0; crate::BUFFER_SIZE];
        loop {
            let bytes_read = file.read(&mut buffer).await?;

            if crate::unlikely(bytes_read == 0) {
                break;
            }

            content.extend_from_slice(buffer.get_slice(..bytes_read)?);

            if crate::unlikely(content.len() >= limit) {
                content.truncate(limit);
                break;
            }
        }

        Ok(content)
    }

    pub async fn async_open(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = tokio::task::spawn_blocking(move || inner.open(path)).await??;

        Ok(tokio::fs::File::from_std(file.into_std()))
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<std::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = inner.open(path)?;

        Ok(file.into_std())
    }

    pub async fn async_open_with(
        &self,
        path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = tokio::task::spawn_blocking(move || inner.open_with(path, &options)).await??;

        Ok(tokio::fs::File::from_std(file.into_std()))
    }

    pub fn open_with(
        &self,
        path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<std::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = inner.open_with(path, &options)?;

        Ok(file.into_std())
    }

    pub async fn async_write(
        &self,
        path: impl AsRef<Path>,
        data: impl AsRef<[u8]>,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let mut file = self.async_create(path).await?;
        file.write_all(data.as_ref()).await?;
        file.sync_all().await?;

        Ok(())
    }

    pub async fn async_create(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = tokio::task::spawn_blocking(move || inner.create(path)).await??;

        Ok(tokio::fs::File::from_std(file.into_std()))
    }

    pub fn create(&self, path: impl AsRef<Path>) -> Result<std::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = inner.create(path)?;

        Ok(file.into_std())
    }

    pub async fn async_quota_copy(
        &self,
        path: impl AsRef<Path>,
        destination_path: impl AsRef<Path>,
        destination_server: &crate::server::Server,
        progress: Option<&Arc<AtomicU64>>,
    ) -> Result<u64, std::io::Error> {
        let (guard, listener) = AbortGuard::new();

        let bytes_copied = tokio::task::spawn_blocking({
            let self_clone = self.clone();
            let destination_server = destination_server.clone();
            let path = path.as_ref().to_owned();
            let destination_path = destination_path.as_ref().to_owned();
            let progress = progress.cloned();

            move || {
                self_clone.quota_copy(
                    &path,
                    &destination_path,
                    &destination_server,
                    progress.as_ref(),
                    listener,
                )
            }
        })
        .await??;

        drop(guard);

        Ok(bytes_copied)
    }

    pub fn quota_copy(
        &self,
        path: impl AsRef<Path>,
        destination_path: impl AsRef<Path>,
        destination_server: &crate::server::Server,
        progress: Option<&Arc<AtomicU64>>,
        listener: AbortListener,
    ) -> Result<u64, std::io::Error> {
        let path = self.relative_path(path.as_ref());
        let destination_path = destination_server
            .filesystem
            .relative_path(destination_path.as_ref());

        let Some(destination_parent) = destination_path.parent() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Destination path has no parent",
            ));
        };

        let destination_metadata = destination_server
            .filesystem
            .metadata(&destination_path)
            .ok();
        if let Some(metadata) = &destination_metadata
            && !metadata.is_file()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Destination path exists and is not a file",
            ));
        }

        let mut reader = self.open(&path)?;
        let mut writer = destination_server.filesystem.create(&destination_path)?;

        if let Some(destination_metadata) = &destination_metadata {
            destination_server.filesystem.allocate_in_path(
                destination_parent,
                -(destination_metadata.len() as i64),
                false,
            );
        }

        let mut cached_allocation_progress = 0;

        let bytes_copied = crate::io::copy_file_progress(
            &mut reader,
            &mut writer,
            |bytes_read| {
                if let Some(progress) = progress {
                    progress.fetch_add(bytes_read as u64, Ordering::Relaxed);
                }
                cached_allocation_progress += bytes_read as i64;

                if cached_allocation_progress >= super::file::ALLOCATION_THRESHOLD {
                    if !destination_server.filesystem.allocate_in_path(
                        destination_parent,
                        cached_allocation_progress,
                        false,
                    ) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::StorageFull,
                            "Failed to allocate space",
                        ));
                    }

                    cached_allocation_progress = 0;
                }

                Ok(())
            },
            listener,
        )?;

        if cached_allocation_progress > 0
            && !destination_server.filesystem.allocate_in_path(
                destination_parent,
                cached_allocation_progress,
                false,
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "Failed to allocate space",
            ));
        }

        Ok(bytes_copied)
    }

    pub async fn async_set_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: PortablePermissions,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        if path.components().next().is_none() {
            if let Some(permissions) = permissions.into_std_permissions() {
                tokio::fs::set_permissions(&*self.base_path, permissions).await?;
            }
        } else {
            let inner = self.get_inner()?;

            if let Some(permissions) = permissions.into_std_permissions() {
                tokio::task::spawn_blocking(move || {
                    inner.set_permissions(path, cap_std::fs::Permissions::from_std(permissions))
                })
                .await??;
            } else {
                tokio::task::spawn_blocking(move || {
                    let file = inner.open(&path)?;
                    file.apply_permissions(permissions)
                })
                .await??;
            }
        }

        Ok(())
    }

    pub fn set_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: PortablePermissions,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        if path.components().next().is_none() {
            if let Some(permissions) = permissions.into_std_permissions() {
                std::fs::set_permissions(&*self.base_path, permissions)?;
            }
        } else {
            let inner = self.get_inner()?;

            if let Some(permissions) = permissions.into_std_permissions() {
                inner.set_permissions(path, cap_std::fs::Permissions::from_std(permissions))?;
            } else {
                let file = inner.open(&path)?;
                file.apply_permissions(permissions)?;
            }
        }

        Ok(())
    }

    pub async fn async_set_symlink_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: PortablePermissions,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        if path.components().next().is_none() {
            if let Some(permissions) = permissions.into_std_permissions() {
                tokio::fs::set_permissions(&*self.base_path, permissions).await?;
            }
        } else {
            let inner = self.get_inner()?;

            #[cfg(unix)]
            tokio::task::spawn_blocking(move || {
                use std::os::fd::AsFd;

                rustix::fs::chmodat(
                    inner.as_fd(),
                    path,
                    rustix::fs::Mode::from_raw_mode(permissions.mode() as _),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
            })
            .await??;
            #[cfg(not(unix))]
            tokio::task::spawn_blocking(move || {
                let file = inner.open(&path)?;
                file.apply_permissions(permissions)
            })
            .await??;
        }

        Ok(())
    }

    pub async fn async_set_times(
        &self,
        path: impl AsRef<Path>,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;

            let path = self.relative_path(path.as_ref());
            let inner = self.get_inner()?;

            let elapsed_modification = modification_time
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "modification time is before UNIX_EPOCH",
                    )
                })?;
            let elapsed_access = access_time
                .unwrap_or_else(std::time::SystemTime::now)
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "access time is before UNIX_EPOCH",
                    )
                })?;

            let times = rustix::fs::Timestamps {
                last_modification: elapsed_modification.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "modification time is too large",
                    )
                })?,
                last_access: elapsed_access.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "access time is too large",
                    )
                })?,
            };

            tokio::task::spawn_blocking(move || {
                rustix::fs::utimensat(
                    inner.as_fd(),
                    path,
                    &times,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
            })
            .await??;

            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path = self.relative_path(path.as_ref());
            let inner = self.get_inner()?;

            let mut times = std::fs::FileTimes::new().set_modified(modification_time);
            if let Some(atime) = access_time {
                times = times.set_accessed(atime);
            }

            tokio::task::spawn_blocking(move || {
                let file = inner.open(path)?.into_std();

                file.set_times(times)
            })
            .await??;

            Ok(())
        }
    }

    pub fn set_times(
        &self,
        path: impl AsRef<Path>,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;

            let path = self.relative_path(path.as_ref());
            let inner = self.get_inner()?;

            let elapsed_modification = modification_time
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "modification time is before UNIX_EPOCH",
                    )
                })?;
            let elapsed_access = access_time
                .unwrap_or_else(std::time::SystemTime::now)
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "access time is before UNIX_EPOCH",
                    )
                })?;

            let times = rustix::fs::Timestamps {
                last_modification: elapsed_modification.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "modification time is too large",
                    )
                })?,
                last_access: elapsed_access.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "access time is too large",
                    )
                })?,
            };

            rustix::fs::utimensat(
                inner.as_fd(),
                path,
                &times,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;

            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path = self.relative_path(path.as_ref());
            let inner = self.get_inner()?;

            let mut times = std::fs::FileTimes::new().set_modified(modification_time);
            if let Some(atime) = access_time {
                times = times.set_accessed(atime);
            }

            let file = inner.open(path)?.into_std();
            file.set_times(times)?;

            Ok(())
        }
    }

    pub async fn async_symlink(
        &self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.get_inner()?;
        #[cfg(unix)]
        tokio::task::spawn_blocking(move || inner.symlink(target, link)).await??;
        #[cfg(windows)]
        tokio::task::spawn_blocking(move || {
            let metadata = inner.metadata(&target)?;
            if metadata.is_dir() {
                inner.symlink_dir(target, link)
            } else {
                inner.symlink_file(target, link)
            }
        })
        .await??;

        Ok(())
    }

    pub fn symlink(
        &self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.get_inner()?;

        #[cfg(unix)]
        inner.symlink(target, link)?;
        #[cfg(windows)]
        {
            let metadata = inner.metadata(&target)?;
            if metadata.is_dir() {
                inner.symlink_dir(target, link)?;
            } else {
                inner.symlink_file(target, link)?;
            }
        }

        Ok(())
    }

    pub async fn async_symlink_contents(
        &self,
        contents: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let contents = contents.as_ref().to_path_buf();
        let link = self.relative_path(link.as_ref());

        let inner = self.get_inner()?;
        #[cfg(unix)]
        tokio::task::spawn_blocking(move || inner.symlink(contents, link)).await??;
        #[cfg(windows)]
        tokio::task::spawn_blocking(move || {
            let target =
                Self::resolve_path(&link.parent().unwrap_or(Path::new("")).join(&contents));

            let metadata = inner.metadata(&target)?;
            if metadata.is_dir() {
                inner.symlink_dir(contents, link)
            } else {
                inner.symlink_file(contents, link)
            }
        })
        .await??;

        Ok(())
    }

    pub async fn async_hard_link(
        &self,
        target: impl AsRef<Path>,
        dst_dir: &CapFilesystem,
        link: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.get_inner()?;
        let dst_inner = dst_dir.get_inner()?;
        tokio::task::spawn_blocking(move || inner.hard_link(target, &dst_inner, link)).await??;

        Ok(())
    }

    pub fn hard_link(
        &self,
        target: impl AsRef<Path>,
        dst_dir: &CapFilesystem,
        link: impl AsRef<Path>,
    ) -> Result<(), std::io::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.get_inner()?;
        let dst_inner = dst_dir.get_inner()?;
        inner.hard_link(target, &dst_inner, link)?;

        Ok(())
    }

    pub async fn async_read_dir_all(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Vec<String>, std::io::Error> {
        let mut read_dir = self.async_read_dir(path).await?;

        let mut names = Vec::new();
        while let Some(Ok((_, entry))) = read_dir.next_entry().await {
            names.push(entry);
        }

        Ok(names)
    }

    pub async fn async_read_dir(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<AsyncReadDir, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let read_dir = tokio::task::spawn_blocking(move || {
            if path.components().next().is_none() {
                inner.entries()
            } else {
                inner.read_dir(path)
            }
        })
        .await??;

        Ok(AsyncReadDir(
            Some(read_dir),
            Some(VecDeque::with_capacity(128)),
        ))
    }

    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<ReadDir, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;

        Ok(ReadDir(if path.components().next().is_none() {
            inner.entries()?
        } else {
            inner.read_dir(path)?
        }))
    }

    pub async fn async_walk_dir(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<AsyncWalkDir, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        AsyncWalkDir::new(self.clone(), path).await
    }

    pub fn walk_dir(&self, path: impl AsRef<Path>) -> Result<WalkDir, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        WalkDir::new(self.clone(), path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // resolve_path

    #[test]
    fn resolve_path_strips_current_dir_components() {
        assert_eq!(
            CapFilesystem::resolve_path(Path::new("./a/./b")),
            PathBuf::from("a/b")
        );
    }

    #[test]
    fn resolve_path_collapses_parent_dir_components() {
        assert_eq!(
            CapFilesystem::resolve_path(Path::new("a/b/../c")),
            PathBuf::from("a/c")
        );
    }

    #[test]
    fn resolve_path_clamps_parent_dir_escapes() {
        assert_eq!(
            CapFilesystem::resolve_path(Path::new("../../etc/passwd")),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(
            CapFilesystem::resolve_path(Path::new("a/../../../etc/passwd")),
            PathBuf::from("etc/passwd")
        );
    }

    #[test]
    fn resolve_path_clamps_parent_dir_escapes_below_root() {
        assert_eq!(
            CapFilesystem::resolve_path(Path::new("/../../etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
    }

    #[test]
    fn resolve_path_leaves_plain_relative_paths_untouched() {
        assert_eq!(
            CapFilesystem::resolve_path(Path::new("plugins/config.yml")),
            PathBuf::from("plugins/config.yml")
        );
    }

    // resolve_symlink_contents

    #[test]
    fn resolve_symlink_contents_resolves_relative_targets_next_to_the_link() {
        assert_eq!(
            CapFilesystem::resolve_symlink_contents(
                Path::new("plugins/Foo.jar"),
                Path::new("Foo-1.0.jar")
            ),
            (
                PathBuf::from("Foo-1.0.jar"),
                PathBuf::from("plugins/Foo-1.0.jar")
            )
        );
    }

    #[test]
    fn resolve_symlink_contents_resolves_absolute_targets_from_the_root() {
        assert_eq!(
            CapFilesystem::resolve_symlink_contents(
                Path::new("/plugins/Foo.jar"),
                Path::new("/plugins/Foo-1.0.jar")
            ),
            (
                PathBuf::from("Foo-1.0.jar"),
                PathBuf::from("plugins/Foo-1.0.jar")
            )
        );
    }

    #[test]
    fn resolve_symlink_contents_walks_up_to_targets_outside_the_link_directory() {
        assert_eq!(
            CapFilesystem::resolve_symlink_contents(
                Path::new("plugins/nested/Foo.jar"),
                Path::new("/mods/Foo-1.0.jar")
            ),
            (
                PathBuf::from("../../mods/Foo-1.0.jar"),
                PathBuf::from("mods/Foo-1.0.jar")
            )
        );
    }

    #[test]
    fn resolve_symlink_contents_clamps_targets_escaping_the_root() {
        assert_eq!(
            CapFilesystem::resolve_symlink_contents(
                Path::new("plugins/Foo.jar"),
                Path::new("../../../etc/passwd")
            ),
            (PathBuf::from("../etc/passwd"), PathBuf::from("etc/passwd"))
        );
    }

    #[test]
    fn resolve_symlink_contents_points_at_directories_above_the_link() {
        assert_eq!(
            CapFilesystem::resolve_symlink_contents(Path::new("plugins/here"), Path::new(".")),
            (PathBuf::from("."), PathBuf::from("plugins"))
        );
        assert_eq!(
            CapFilesystem::resolve_symlink_contents(Path::new("plugins/here"), Path::new("..")),
            (PathBuf::from(".."), PathBuf::from(""))
        );
    }

    // reversed walk + remove_dir_all

    fn temp_filesystem() -> (tempfile::TempDir, CapFilesystem) {
        let dir = tempfile::tempdir().unwrap();
        let inner =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();

        let filesystem = CapFilesystem {
            base_path: Arc::from(dir.path()),
            inner: Arc::new(ArcSwapOption::new(Some(Arc::new(inner)))),
        };

        (dir, filesystem)
    }

    #[test]
    fn walk_dir_reversed_yields_children_before_parents() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/deep.txt"), "x").unwrap();
        std::fs::write(dir.path().join("a/shallow.txt"), "x").unwrap();

        let mut seen = Vec::new();
        let mut walker = filesystem.walk_dir("").unwrap().reversed();
        while let Some(entry) = walker.next_entry() {
            seen.push(entry.unwrap().path);
        }

        let index = |p: &str| seen.iter().position(|s| s == Path::new(p)).unwrap();

        // every directory lands after everything nested inside it
        assert!(index("a/b/deep.txt") < index("a/b"));
        assert!(index("a/b") < index("a"));
        assert!(index("a/shallow.txt") < index("a"));

        // the walk root itself is never emitted, matching the pre-order walker
        assert!(!seen.iter().any(|s| s.as_os_str().is_empty()));
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn symlink_contents_are_written_verbatim() {
        tokio_test::block_on(async {
            let (dir, filesystem) = temp_filesystem();
            std::fs::create_dir_all(dir.path().join("plugins")).unwrap();
            std::fs::write(dir.path().join("Foo-1.0.jar"), "x").unwrap();

            let (contents, target) = CapFilesystem::resolve_symlink_contents(
                Path::new("plugins/Foo.jar"),
                Path::new("/Foo-1.0.jar"),
            );

            filesystem
                .async_symlink_contents(&contents, "plugins/Foo.jar")
                .await
                .unwrap();

            assert_eq!(target, PathBuf::from("Foo-1.0.jar"));
            assert_eq!(
                std::fs::read_link(dir.path().join("plugins/Foo.jar")).unwrap(),
                PathBuf::from("../Foo-1.0.jar")
            );
            assert_eq!(
                std::fs::read(dir.path().join("plugins/Foo.jar")).unwrap(),
                b"x"
            );
        });
    }

    #[test]
    fn remove_dir_all_removes_nested_tree() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("tree/nested")).unwrap();
        std::fs::write(dir.path().join("tree/nested/file.txt"), "x").unwrap();
        std::fs::write(dir.path().join("keep.txt"), "x").unwrap();

        filesystem.remove_dir_all("tree").unwrap();

        assert!(!dir.path().join("tree").exists());
        assert!(dir.path().join("keep.txt").exists());
    }

    #[test]
    fn remove_dir_all_with_empty_path_clears_contents_but_keeps_root() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/file.txt"), "x").unwrap();
        std::fs::write(dir.path().join("top.txt"), "x").unwrap();

        filesystem.remove_dir_all("").unwrap();

        assert!(dir.path().exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn remove_dir_all_unlinks_symlinks_without_following_them() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("outside")).unwrap();
        std::fs::write(dir.path().join("outside/keep.txt"), "x").unwrap();
        std::fs::create_dir(dir.path().join("tree")).unwrap();
        std::os::unix::fs::symlink("../outside", dir.path().join("tree/link")).unwrap();

        filesystem.remove_dir_all("tree").unwrap();

        assert!(!dir.path().join("tree").exists());
        assert!(dir.path().join("outside/keep.txt").exists());
    }

    /// Reproduces the failure this retry exists for: a `chattr +i` file makes every
    /// unlink in the tree return `EPERM`. Needs root and `CAP_LINUX_IMMUTABLE`, so it
    /// skips itself where the flag cannot be set.
    #[test]
    #[cfg(target_os = "linux")]
    fn remove_dir_all_clears_immutable_flag_to_delete() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("tree")).unwrap();
        let locked = dir.path().join("tree/locked.txt");
        std::fs::write(&locked, "x").unwrap();

        let set = std::process::Command::new("chattr")
            .arg("+i")
            .arg(&locked)
            .status();
        if !matches!(set, Ok(status) if status.success()) {
            eprintln!("skipping: cannot set the immutable flag here");
            return;
        }

        // sanity: the flag really does block deletion
        assert_eq!(
            std::fs::remove_file(&locked).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        let result = filesystem.remove_dir_all("tree");

        if result.is_err() {
            std::process::Command::new("chattr")
                .arg("-i")
                .arg(&locked)
                .status()
                .ok();
        }

        result.unwrap();
        assert!(!dir.path().join("tree").exists());
    }

    // canonicalize

    #[test]
    fn canonicalize_resolves_symlink_to_target() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("config")).unwrap();
        std::fs::write(dir.path().join("config/secret.yml"), b"x").unwrap();
        filesystem.symlink("config/secret.yml", "link.yml").unwrap();

        assert_eq!(
            filesystem.canonicalize("link.yml").unwrap(),
            PathBuf::from("config/secret.yml")
        );
    }

    #[test]
    fn canonicalize_errors_on_missing_path() {
        let (_d, filesystem) = temp_filesystem();

        assert!(filesystem.canonicalize("nope.txt").is_err());
    }

    #[test]
    fn canonicalize_returns_empty_path_untouched() {
        let (_d, filesystem) = temp_filesystem();

        assert_eq!(filesystem.canonicalize("").unwrap(), PathBuf::from(""));
    }
}
