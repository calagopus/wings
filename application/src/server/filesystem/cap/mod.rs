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
    borrow::Cow,
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod utils;
pub use utils::{AsyncReadDir, AsyncWalkDir, FileType, ListingDir, ReadDir, WalkDir, WalkEntry};

#[cfg(target_os = "linux")]
pub fn proc_fd_path(fd: &impl std::os::fd::AsRawFd) -> PathBuf {
    Path::new("/proc/self/fd").join(fd.as_raw_fd().to_string())
}

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

    /// Borrows `path` when it is already relative and free of `.` / `..` components,
    /// which is the case for every path the listing pipeline builds from a resolved root.
    #[inline]
    pub fn relative_path_cow<'a>(&self, path: &'a Path) -> Cow<'a, Path> {
        let path = path
            .strip_prefix(&*self.base_path)
            .or_else(|_| path.strip_prefix("/"))
            .unwrap_or(path);

        if path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            Cow::Borrowed(path)
        } else {
            Cow::Owned(Self::resolve_path(path))
        }
    }

    #[inline]
    pub fn relative_path(&self, path: &Path) -> PathBuf {
        self.relative_path_cow(path).into_owned()
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

    pub async fn async_remove_dir_all(
        &self,
        path: impl AsRef<Path>,
        threads: usize,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let self_clone = self.clone();
        tokio::task::spawn_blocking(move || self_clone.remove_dir_all(path, threads)).await??;

        Ok(())
    }

    pub fn remove_dir_all(
        &self,
        path: impl AsRef<Path>,
        threads: usize,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let state = Arc::new(parking_lot::Mutex::new(RemoveDirAllState::default()));
        let pool = crate::threading::build_pool(threads).map_err(std::io::Error::other)?;

        let dir = if path.as_os_str().is_empty() {
            inner.try_clone()?
        } else {
            inner.open_dir(&path)?
        };

        pool.in_place_scope(|scope| Self::remove_dir_contents(scope, Arc::new(dir), &state));

        let mut state = state.lock();

        if !path.as_os_str().is_empty()
            && let Err(err) =
                Self::remove_entry(&inner, &path, FileType::Dir, &mut state.cleared_parent)
        {
            state.record(err);
        }

        match state.first_error.take() {
            Some(err) => {
                tracing::warn!(
                    path = %path.display(),
                    "failed to remove {} entr{} while removing directory: {:#?}",
                    state.failed,
                    if state.failed == 1 { "y" } else { "ies" },
                    err
                );

                Err(err)
            }
            None => Ok(()),
        }
    }

    /// Removes everything inside `dir`. One task owns one directory and unlinks
    /// through that directory's own handle, so no two threads work on the same
    /// directory and nothing is resolved from the sandbox root again; a directory
    /// is removed once the tasks for its subdirectories are done. A subdirectory
    /// is only opened once its task runs, so queued tasks hold no descriptors and
    /// wide trees cannot run the process out of them.
    fn remove_dir_contents<'scope>(
        scope: &rayon::Scope<'scope>,
        dir: Arc<cap_std::fs::Dir>,
        state: &'scope Arc<parking_lot::Mutex<RemoveDirAllState>>,
    ) {
        let entries = match dir.entries() {
            Ok(entries) => entries,
            Err(err) => {
                state.lock().record(err);
                return;
            }
        };

        let mut cleared_dir = false;

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    state.lock().record(err);
                    continue;
                }
            };

            let mut file_type = entry.file_type().map_or(FileType::Unknown, FileType::from);
            if matches!(file_type, FileType::Unknown) {
                file_type = entry
                    .metadata()
                    .map_or(FileType::Unknown, |metadata| metadata.file_type().into());
            }

            if file_type.is_dir() {
                let parent = Arc::clone(&dir);

                scope.spawn(move |_| {
                    let sub = match entry.open_dir() {
                        Ok(sub) => Arc::new(sub),
                        Err(err) => {
                            state.lock().record(err);
                            return;
                        }
                    };

                    rayon::scope(|scope| Self::remove_dir_contents(scope, sub, state));

                    if let Err(err) = entry.remove_dir()
                        && !(err.kind() == std::io::ErrorKind::PermissionDenied
                            && Self::remove_dir_after_clearing_flags(&parent, &entry.file_name()))
                    {
                        state.lock().record(err);
                    }
                });

                continue;
            }

            if let Err(err) = entry.remove_file() {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    let name = entry.file_name();

                    #[cfg(target_os = "linux")]
                    if Self::clear_inode_flags(&dir, Path::new(&name), file_type).is_ok()
                        && dir.remove_file(&name).is_ok()
                    {
                        continue;
                    }

                    #[cfg(target_os = "linux")]
                    if !cleared_dir {
                        cleared_dir = true;

                        if Self::clear_flags_on_fd(&dir).is_ok() && dir.remove_file(&name).is_ok() {
                            continue;
                        }
                    }

                    #[cfg(not(target_os = "linux"))]
                    let _ = (&name, &mut cleared_dir);
                }

                state.lock().record(err);
            }
        }
    }

    fn remove_dir_after_clearing_flags(parent: &cap_std::fs::Dir, name: &std::ffi::OsStr) -> bool {
        #[cfg(target_os = "linux")]
        {
            (Self::clear_inode_flags(parent, Path::new(name), FileType::Dir).is_ok()
                && parent.remove_dir(name).is_ok())
                || (Self::clear_flags_on_fd(parent).is_ok() && parent.remove_dir(name).is_ok())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (parent, name);
            false
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

    pub async fn async_remove_dir(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        tokio::task::spawn_blocking(move || {
            Self::remove_entry(&inner, &path, FileType::Dir, &mut None)
        })
        .await??;

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

            tokio::task::spawn_blocking(move || Self::stat_beneath(&inner, &path)).await??
        };

        Ok(metadata)
    }

    pub fn symlink_metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(std::fs::symlink_metadata(&*self.base_path)?)
        } else {
            let inner = self.get_inner()?;

            Self::stat_beneath(&inner, &path)?
        };

        Ok(metadata)
    }

    /// Stats a path relative to `inner`, keeping the birth time on every target.
    ///
    /// `cap-primitives` only reaches its `statx` fast path for a single-component
    /// no-follow stat; anything deeper falls back to `O_PATH` + `File::metadata`.
    /// On glibc that still carries a birth time, so the stat goes straight
    /// through. `std` only implements `statx` for `target_env = "gnu"`, so on
    /// musl the deeper path loses `created` entirely, and opening the parent
    /// first is what keeps the fast path reachable.
    #[cfg(target_env = "gnu")]
    fn stat_beneath(inner: &cap_std::fs::Dir, path: &Path) -> Result<Metadata, std::io::Error> {
        inner.symlink_metadata(path)
    }

    #[cfg(not(target_env = "gnu"))]
    fn stat_beneath(inner: &cap_std::fs::Dir, path: &Path) -> Result<Metadata, std::io::Error> {
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                inner.open_dir(parent)?.symlink_metadata(name)
            }
            _ => inner.symlink_metadata(path),
        }
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

    /// Canonicalizes every directory component while leaving the final component
    /// untouched, so paths that do not exist yet still resolve.
    pub async fn async_canonicalize_parent(&self, path: impl AsRef<Path>) -> PathBuf {
        self.async_try_canonicalize_parent(path.as_ref())
            .await
            .unwrap_or_else(|_| self.relative_path(path.as_ref()))
    }

    /// Like [`Self::async_canonicalize_parent`], but fails instead of falling back
    /// to the unresolved path when a directory cannot be resolved for any reason
    /// other than not existing yet.
    pub async fn async_try_canonicalize_parent(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PathBuf, std::io::Error> {
        let path = path.as_ref().to_path_buf();

        let self_clone = self.clone();
        let path =
            tokio::task::spawn_blocking(move || self_clone.try_canonicalize_parent(path)).await??;

        Ok(path)
    }

    /// Canonicalizes every directory component while leaving the final component
    /// untouched. Directories that do not exist yet are kept as given beneath the
    /// deepest one that does.
    pub fn try_canonicalize_parent(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PathBuf, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let mut ancestor = path.as_path();
        while let Some(parent) = ancestor.parent() {
            match self.canonicalize(parent) {
                Ok(resolved) => {
                    return Ok(resolved.join(path.strip_prefix(parent).unwrap_or(&path)));
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => ancestor = parent,
                Err(err) => return Err(err),
            }
        }

        Ok(path)
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

    /// Path of an opened file relative to the root, as the kernel resolved it when the
    /// file was opened, so swapping symlinks after the open cannot change the answer.
    #[cfg(target_os = "linux")]
    pub fn opened_relative_path(&self, file: &std::fs::File) -> Result<PathBuf, std::io::Error> {
        use std::os::unix::fs::MetadataExt;

        let root = std::fs::read_link(proc_fd_path(&self.get_inner()?))?;
        let opened = std::fs::read_link(proc_fd_path(file))?;
        if file.metadata()?.nlink() == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }

        opened
            .strip_prefix(&root)
            .map(Path::to_path_buf)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::NotFound))
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

        let mut buffer = crate::io::mem_buffer(crate::BUFFER_SIZE);
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

    #[cfg(target_os = "linux")]
    pub async fn async_connect_unix(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(tokio::net::UnixStream, PathBuf), std::io::Error> {
        use cap_std::fs::OpenOptionsExt;
        use std::os::unix::fs::FileTypeExt;

        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let filesystem = self.clone();
        let (file, opened_path) = tokio::task::spawn_blocking(move || {
            let file = inner
                .open_with(
                    path,
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(rustix::fs::OFlags::PATH.bits() as i32),
                )?
                .into_std();

            if !file.metadata()?.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a socket",
                ));
            }

            let opened_path = filesystem.opened_relative_path(&file)?;

            Ok::<_, std::io::Error>((file, opened_path))
        })
        .await??;

        let stream = tokio::net::UnixStream::connect(proc_fd_path(&file)).await?;

        Ok((stream, opened_path))
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

    pub async fn async_create_with_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: Option<PortablePermissions>,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = tokio::task::spawn_blocking(move || {
            let file = inner.create(path)?;
            if let Some(permissions) = permissions {
                file.apply_permissions(permissions)?;
            }

            Ok::<_, std::io::Error>(file)
        })
        .await??;

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
        permissions: Option<PortablePermissions>,
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
                    permissions,
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
        permissions: Option<PortablePermissions>,
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
        if let Some(permissions) = permissions {
            writer.apply_permissions(permissions)?;
        }
        destination_server.filesystem.chown_file(&writer)?;

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
        let path = path.as_ref().to_path_buf();

        let self_clone = self.clone();
        tokio::task::spawn_blocking(move || {
            self_clone.set_times(path, modification_time, access_time)
        })
        .await??;

        Ok(())
    }

    pub fn set_times(
        &self,
        path: impl AsRef<Path>,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), std::io::Error> {
        #[cfg(target_os = "linux")]
        {
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

            Self::utimensat_beneath(&inner, &path, &times)?;

            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
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

    /// Runs `op` on the last component of `path` relative to its parent
    /// directory, which is opened beneath `inner` so in-root symlinks in the
    /// parent are followed and escapes are refused. The last component is
    /// never followed, except when the path ends in `/` or `/.`: then the
    /// whole path is opened as a directory and `op` acts on it through
    /// `AT_EMPTY_PATH`. An empty path acts on `inner` itself the same way.
    #[cfg(target_os = "linux")]
    fn at_parent<T>(
        inner: &cap_std::fs::Dir,
        path: &Path,
        op: impl FnOnce(
            std::os::fd::BorrowedFd<'_>,
            &Path,
            rustix::fs::AtFlags,
        ) -> rustix::io::Result<T>,
    ) -> Result<T, std::io::Error> {
        use std::os::fd::AsFd;

        let bytes = path.as_os_str().as_encoded_bytes();
        let (dir, name, flags) = if bytes.is_empty() {
            (None, Path::new(""), rustix::fs::AtFlags::EMPTY_PATH)
        } else if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
            (
                Some(inner.open_dir(path)?),
                Path::new(""),
                rustix::fs::AtFlags::EMPTY_PATH,
            )
        } else {
            let Some(name) = path.file_name() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path has no final component",
                ));
            };
            let dir = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => Some(inner.open_dir(parent)?),
                _ => None,
            };

            (dir, Path::new(name), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        };

        Ok(op(
            dir.as_ref().map_or(inner.as_fd(), AsFd::as_fd),
            name,
            flags,
        )?)
    }

    #[cfg(target_os = "linux")]
    fn utimensat_beneath(
        inner: &cap_std::fs::Dir,
        path: &Path,
        times: &rustix::fs::Timestamps,
    ) -> Result<(), std::io::Error> {
        Self::at_parent(inner, path, |fd, name, flags| {
            // Linux before 5.8 rejects AT_EMPTY_PATH here with EINVAL.
            match rustix::fs::utimensat(fd, name, times, flags) {
                Err(rustix::io::Errno::INVAL)
                    if flags.contains(rustix::fs::AtFlags::EMPTY_PATH) => {}
                result => return result,
            }

            match rustix::fs::utimensat(
                rustix::fs::CWD,
                proc_fd_path(&fd),
                times,
                rustix::fs::AtFlags::empty(),
            ) {
                Err(rustix::io::Errno::NOENT) => {
                    rustix::fs::utimensat(fd, ".", times, rustix::fs::AtFlags::empty())
                }
                result => result,
            }
        })
    }

    #[cfg(target_os = "linux")]
    pub async fn async_lchown(
        &self,
        path: impl AsRef<Path>,
        uid: rustix::fs::Uid,
        gid: rustix::fs::Gid,
    ) -> Result<(), std::io::Error> {
        let path = path.as_ref().to_path_buf();

        let self_clone = self.clone();
        tokio::task::spawn_blocking(move || self_clone.lchown(path, uid, gid)).await??;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn lchown(
        &self,
        path: impl AsRef<Path>,
        uid: rustix::fs::Uid,
        gid: rustix::fs::Gid,
    ) -> Result<(), std::io::Error> {
        let path = self.relative_path_cow(path.as_ref());
        let inner = self.get_inner()?;

        Self::at_parent(&inner, &path, |fd, name, flags| {
            rustix::fs::chownat(fd, name, Some(uid), Some(gid), flags)
        })
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

    pub fn open_listing_dir(&self, path: impl AsRef<Path>) -> Result<ListingDir, std::io::Error> {
        // Without openat2, cap-std resolves paths itself: a trailing slash would
        // make it an O_PATH open getdents cannot read, and our O_DIRECTORY
        // flag hides a final symlink from it. Ending in `/.` makes the last
        // real component an intermediate one, which cap-std follows safely,
        // before `.` is opened with the proper flags.
        let mut path = self.relative_path(path.as_ref());
        path.push(".");

        let inner = self.get_inner()?;

        #[cfg(target_os = "linux")]
        let dir = {
            use cap_std::fs::OpenOptionsExt;

            let file = inner.open_with(
                &path,
                OpenOptions::new()
                    .read(true)
                    .custom_flags(rustix::fs::OFlags::DIRECTORY.bits() as i32),
            )?;

            cap_std::fs::Dir::from_std_file(file.into_std())
        };
        #[cfg(not(target_os = "linux"))]
        let dir = inner.open_dir(&path)?;

        Ok(ListingDir(dir))
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

#[derive(Default)]
struct RemoveDirAllState {
    first_error: Option<std::io::Error>,
    failed: u64,
    cleared_parent: Option<PathBuf>,
}

impl RemoveDirAllState {
    fn record(&mut self, err: std::io::Error) {
        self.failed += 1;
        self.first_error.get_or_insert(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::filesystem::virtualfs::{DirectoryWalkFilterFn, IsIgnoredFn};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

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

    // relative_path_cow

    #[test]
    fn relative_path_cow_borrows_normalized_paths() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;

            for (input, expected) in [
                ("plugins/config.yml", "plugins/config.yml"),
                ("/plugins/config.yml", "plugins/config.yml"),
                ("", ""),
                ("/", ""),
            ] {
                let resolved = fs.relative_path_cow(Path::new(input));

                assert!(matches!(resolved, Cow::Borrowed(_)), "{input}");
                assert_eq!(resolved.as_ref(), Path::new(expected), "{input}");
            }

            let inside = temp.path().join("plugins/config.yml");
            let resolved = fs.relative_path_cow(&inside);
            assert!(matches!(resolved, Cow::Borrowed(_)));
            assert_eq!(resolved.as_ref(), Path::new("plugins/config.yml"));

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn relative_path_cow_resolves_dot_components() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;

            for (input, expected) in [
                ("./a/./b", "a/b"),
                ("a/../b", "b"),
                ("../../etc/passwd", "etc/passwd"),
                ("//nested/.", "nested"),
                ("nested/", "nested"),
            ] {
                let resolved = fs.relative_path_cow(Path::new(input));

                assert_eq!(resolved.as_ref(), Path::new(expected), "{input}");
                assert_eq!(
                    resolved.as_ref(),
                    fs.relative_path(Path::new(input)),
                    "{input}"
                );
            }

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
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

    // stat_beneath

    #[test]
    fn nested_stats_keep_their_birth_time() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            // `created` only goes missing for paths below the root, so check a
            // nested stat against a single-component one rather than just
            // asserting it is present
            let temp = tempfile::tempdir()?;
            std::fs::create_dir_all(temp.path().join("plugins/nested"))?;
            std::fs::write(temp.path().join("plugins/nested/config.yml"), b"a: 1")?;
            std::fs::write(temp.path().join("root.yml"), b"a: 1")?;

            let filesystem = CapFilesystem::new(temp.path()).await?;

            let shallow = filesystem.symlink_metadata("root.yml")?;
            let nested = filesystem.symlink_metadata("plugins/nested/config.yml")?;

            assert!(
                shallow.created().is_ok(),
                "single-component stat lost its birth time"
            );
            assert!(
                nested.created().is_ok(),
                "nested stat lost its birth time: the statx path was missed"
            );

            let nested = filesystem
                .async_symlink_metadata("plugins/nested/config.yml")
                .await?;
            assert!(
                nested.created().is_ok(),
                "nested async stat lost its birth time"
            );

            Ok(())
        })
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
    fn walk_dir_reversed_completes_children_before_removing_parents() {
        for threads in [1, 4] {
            for parallel in [false, true] {
                for filtered in [false, true] {
                    let (dir, filesystem) = temp_filesystem();
                    std::fs::create_dir_all(dir.path().join("a/b/empty")).unwrap();
                    std::fs::create_dir(dir.path().join("skip")).unwrap();
                    for index in 0..crate::threading::WALK_BATCH_SIZE * 2 + 1 {
                        std::fs::write(dir.path().join(format!("a/b/{index}")), "x").unwrap();
                    }
                    std::fs::write(dir.path().join("a/shallow"), "x").unwrap();

                    let remove = Arc::new({
                        let filesystem = filesystem.clone();
                        move |entry: WalkEntry| -> Result<(), anyhow::Error> {
                            if entry.file_type().is_dir() {
                                filesystem.get_inner()?.remove_dir(&entry.path)?;
                            } else {
                                std::thread::sleep(std::time::Duration::from_millis(1));
                                filesystem.get_inner()?.remove_file(&entry.path)?;
                            }
                            Ok(())
                        }
                    });
                    let filter = filtered.then(|| {
                        DirectoryWalkFilterFn::from(|_, path: &Path| path != Path::new("skip"))
                    });

                    let mut walker = filesystem.walk_dir("").unwrap().reversed();
                    if parallel {
                        walker.run_parallel(threads, filter, remove)
                    } else {
                        walker.run_multithreaded_filtered(threads, filter, remove)
                    }
                    .unwrap();

                    assert!(!dir.path().join("a").exists());
                    assert_eq!(dir.path().join("skip").exists(), filtered);
                    assert!(dir.path().is_dir());
                }
            }
        }
    }

    #[test]
    fn walk_dir_reversed_stops_before_parents_on_callback_error() {
        for fail_directory in [false, true] {
            let (dir, filesystem) = temp_filesystem();
            std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
            std::fs::write(dir.path().join("a/b/file"), "x").unwrap();

            let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let result = filesystem
                .walk_dir("")
                .unwrap()
                .reversed()
                .run_multithreaded(
                    2,
                    Arc::new({
                        let seen = Arc::clone(&seen);
                        move |entry: WalkEntry| {
                            seen.lock().push(entry.path.clone());
                            if entry.file_type().is_dir() == fail_directory {
                                anyhow::bail!("callback failed");
                            }
                            Ok(())
                        }
                    }),
                );

            assert_eq!(result.unwrap_err().to_string(), "callback failed");
            let expected = if fail_directory {
                vec![PathBuf::from("a/b/file"), PathBuf::from("a/b")]
            } else {
                vec![PathBuf::from("a/b/file")]
            };
            assert_eq!(*seen.lock(), expected);
        }
    }

    #[test]
    fn walk_dir_reversed_can_continue_after_directory_read_error() {
        let (dir, filesystem) = temp_filesystem();
        for parent in ["tree/a", "tree/b", "tree/c"] {
            std::fs::create_dir_all(dir.path().join(parent)).unwrap();
            std::fs::write(dir.path().join(parent).join("file"), "x").unwrap();
        }

        let skipped = Arc::new(parking_lot::Mutex::new(None));
        let mut walker = filesystem
            .walk_dir("tree")
            .unwrap()
            .reversed()
            .with_is_ignored(IsIgnoredFn::from({
                let skipped = Arc::clone(&skipped);
                move |file_type: FileType, path: PathBuf| {
                    if file_type.is_dir() {
                        let mut skipped = skipped.lock();
                        if skipped.is_none() {
                            *skipped = Some(path);
                            return Some(PathBuf::from("tree/missing"));
                        }
                    }
                    Some(path)
                }
            }));

        let mut errors = Vec::new();
        walker
            .run_multithreaded_with_error_handler(
                2,
                None,
                Arc::new({
                    let filesystem = filesystem.clone();
                    move |entry: WalkEntry| -> Result<(), anyhow::Error> {
                        if entry.file_type().is_dir() {
                            filesystem.get_inner()?.remove_dir(&entry.path)?;
                        } else {
                            filesystem.get_inner()?.remove_file(&entry.path)?;
                        }
                        Ok(())
                    }
                }),
                |err| {
                    errors.push(err);
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind(), std::io::ErrorKind::NotFound);
        let skipped = skipped.lock().clone().unwrap();
        assert!(dir.path().join(skipped).join("file").exists());
        assert_eq!(
            std::fs::read_dir(dir.path().join("tree")).unwrap().count(),
            1
        );
    }

    #[test]
    fn async_walk_dir_reversed_completes_children_before_removing_parents() {
        tokio_test::block_on(async {
            for threads in [0, 1, 4] {
                let (dir, filesystem) = temp_filesystem();
                std::fs::create_dir_all(dir.path().join("a/b/empty")).unwrap();
                for index in 0..crate::threading::WALK_BATCH_SIZE * 2 + 1 {
                    std::fs::write(dir.path().join(format!("a/b/{index}")), "x").unwrap();
                }
                std::fs::write(dir.path().join("a/shallow"), "x").unwrap();

                let mut walker = filesystem.async_walk_dir("").await.unwrap().reversed();
                let remove = Arc::new({
                    let filesystem = filesystem.clone();
                    move |entry: WalkEntry| {
                        let filesystem = filesystem.clone();
                        async move {
                            if entry.file_type().is_dir() {
                                filesystem.get_inner()?.remove_dir(&entry.path)?;
                            } else {
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                                filesystem.get_inner()?.remove_file(&entry.path)?;
                            }
                            Ok(())
                        }
                    }
                });

                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    walker.run_multithreaded(threads, remove),
                )
                .await
                .unwrap()
                .unwrap();

                assert!(dir.path().is_dir());
                assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
            }
        });
    }

    #[test]
    fn async_walk_dir_reversed_stops_before_parents_on_callback_error() {
        tokio_test::block_on(async {
            for fail_directory in [false, true] {
                let (dir, filesystem) = temp_filesystem();
                std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
                std::fs::write(dir.path().join("a/b/file"), "x").unwrap();

                let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
                let result = filesystem
                    .async_walk_dir("")
                    .await
                    .unwrap()
                    .reversed()
                    .run_multithreaded(
                        2,
                        Arc::new({
                            let seen = Arc::clone(&seen);
                            move |entry: WalkEntry| {
                                let seen = Arc::clone(&seen);
                                async move {
                                    tokio::task::yield_now().await;
                                    seen.lock().push(entry.path.clone());
                                    if entry.file_type().is_dir() == fail_directory {
                                        anyhow::bail!("callback failed");
                                    }
                                    Ok(())
                                }
                            }
                        }),
                    )
                    .await;

                assert_eq!(result.unwrap_err().to_string(), "callback failed");
                let expected = if fail_directory {
                    vec![PathBuf::from("a/b/file"), PathBuf::from("a/b")]
                } else {
                    vec![PathBuf::from("a/b/file")]
                };
                assert_eq!(*seen.lock(), expected);
            }
        });
    }

    #[test]
    fn async_walk_dir_reversed_allows_sibling_subtrees_to_progress() {
        tokio_test::block_on(async {
            let (dir, filesystem) = temp_filesystem();
            for name in ["a", "b"] {
                std::fs::create_dir(dir.path().join(name)).unwrap();
                std::fs::write(dir.path().join(name).join("file"), "x").unwrap();
            }

            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let mut walker = filesystem.async_walk_dir("").await.unwrap().reversed();
            let remove = Arc::new(move |entry: WalkEntry| {
                let filesystem = filesystem.clone();
                let barrier = Arc::clone(&barrier);
                async move {
                    if entry.file_type().is_dir() {
                        filesystem.get_inner()?.remove_dir(&entry.path)?;
                    } else {
                        barrier.wait().await;
                        filesystem.get_inner()?.remove_file(&entry.path)?;
                    }
                    Ok(())
                }
            });

            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                walker.run_multithreaded(2, remove),
            )
            .await
            .unwrap()
            .unwrap();

            assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        });
    }

    #[test]
    fn async_walk_dir_reversed_stops_before_parents_on_callback_panic() {
        tokio_test::block_on(async {
            for panic_before_future in [false, true] {
                let (dir, filesystem) = temp_filesystem();
                std::fs::create_dir(dir.path().join("a")).unwrap();
                std::fs::write(dir.path().join("a/file"), "x").unwrap();

                let directories = Arc::new(AtomicUsize::new(0));
                let result = filesystem
                    .async_walk_dir("")
                    .await
                    .unwrap()
                    .reversed()
                    .run_multithreaded(
                        1,
                        Arc::new({
                            let directories = Arc::clone(&directories);
                            move |entry: WalkEntry| {
                                assert!(!panic_before_future || entry.file_type().is_dir());
                                let directories = Arc::clone(&directories);
                                async move {
                                    assert!(entry.file_type().is_dir());
                                    directories.fetch_add(1, Ordering::Relaxed);
                                    Ok(())
                                }
                            }
                        }),
                    )
                    .await;

                assert!(
                    result
                        .unwrap_err()
                        .downcast_ref::<tokio::task::JoinError>()
                        .unwrap()
                        .is_panic()
                );
                assert_eq!(directories.load(Ordering::Relaxed), 0);
            }
        });
    }

    #[test]
    fn async_walk_dir_reversed_drains_more_than_the_pending_limit() {
        tokio_test::block_on(async {
            let (dir, filesystem) = temp_filesystem();
            std::fs::create_dir(dir.path().join("a")).unwrap();
            for index in 0..crate::threading::WALK_IN_FLIGHT_LIMIT + 1 {
                std::fs::create_dir(dir.path().join(format!("a/{index}"))).unwrap();
            }

            let count = Arc::new(AtomicUsize::new(0));
            let mut walker = filesystem.async_walk_dir("").await.unwrap().reversed();
            let visit = Arc::new({
                let count = Arc::clone(&count);
                move |_| {
                    let count = Arc::clone(&count);
                    async move {
                        tokio::task::yield_now().await;
                        count.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                }
            });

            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                walker.run_multithreaded(1, visit),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(
                count.load(Ordering::Relaxed),
                crate::threading::WALK_IN_FLIGHT_LIMIT + 2
            );
        });
    }

    #[test]
    fn async_walk_dir_reversed_drains_callbacks_after_read_error() {
        tokio_test::block_on(async {
            let (dir, filesystem) = temp_filesystem();
            for name in ["a", "b"] {
                std::fs::create_dir(dir.path().join(name)).unwrap();
                std::fs::write(dir.path().join(name).join("file"), "x").unwrap();
            }

            let directories = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(tokio::sync::Notify::new());
            let mut walker = filesystem
                .async_walk_dir("")
                .await
                .unwrap()
                .reversed()
                .with_is_ignored(IsIgnoredFn::new(|_, path| Some(path), {
                    let directories = Arc::clone(&directories);
                    let started = Arc::clone(&started);
                    move |file_type: FileType, path| {
                        let directories = Arc::clone(&directories);
                        let started = Arc::clone(&started);
                        async move {
                            if file_type.is_dir()
                                && directories.fetch_add(1, Ordering::Relaxed) == 1
                            {
                                // a spawned callback gives up if an error is already
                                // recorded, so the first directory's file has to be
                                // inside its callback before this one fails to open
                                started.notified().await;

                                return Some(PathBuf::from("missing"));
                            }
                            Some(path)
                        }
                    }
                }));

            let release = Arc::new(tokio::sync::Notify::new());
            let completed = Arc::new(AtomicBool::new(false));
            let walk = walker.run_multithreaded(
                2,
                Arc::new({
                    let started = Arc::clone(&started);
                    let release = Arc::clone(&release);
                    let completed = Arc::clone(&completed);
                    move |entry: WalkEntry| {
                        let started = Arc::clone(&started);
                        let release = Arc::clone(&release);
                        let completed = Arc::clone(&completed);
                        async move {
                            if entry.file_type().is_dir() {
                                return Ok(());
                            }

                            started.notify_one();
                            release.notified().await;
                            completed.store(true, Ordering::Relaxed);
                            Ok(())
                        }
                    }
                }),
            );
            tokio::pin!(walk);

            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(250), &mut walk)
                    .await
                    .is_err()
            );
            assert!(!completed.load(Ordering::Relaxed));

            release.notify_one();
            let err = walk.await.unwrap_err();
            assert_eq!(
                err.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::NotFound
            );
            assert!(completed.load(Ordering::Relaxed));
        });
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
    fn canonicalize_parent_resolves_symlinked_directories_but_not_the_leaf() {
        tokio_test::block_on(async {
            let (dir, filesystem) = temp_filesystem();
            std::fs::create_dir(dir.path().join("config")).unwrap();
            std::fs::write(dir.path().join("config/secrets.yml"), "x").unwrap();
            std::os::unix::fs::symlink("config", dir.path().join("s")).unwrap();
            std::os::unix::fs::symlink("config/secrets.yml", dir.path().join("link.yml")).unwrap();

            // the deny-list bypass: a symlinked parent no longer hides the real name
            assert_eq!(
                filesystem.async_canonicalize_parent("s/secrets.yml").await,
                PathBuf::from("config/secrets.yml")
            );

            // a leaf that does not exist yet still resolves through its parent
            assert_eq!(
                filesystem.async_canonicalize_parent("s/new.yml").await,
                PathBuf::from("config/new.yml")
            );

            // the final component is left alone, so lstat still describes the link
            assert_eq!(
                filesystem.async_canonicalize_parent("link.yml").await,
                PathBuf::from("link.yml")
            );

            // paths without a parent, and escapes, are unchanged by the resolution
            assert_eq!(
                filesystem.async_canonicalize_parent("/top.yml").await,
                PathBuf::from("top.yml")
            );
            assert_eq!(
                filesystem
                    .async_canonicalize_parent("../../etc/passwd")
                    .await,
                PathBuf::from("etc/passwd")
            );
        });
    }

    #[test]
    fn remove_dir_all_removes_nested_tree() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("tree/nested")).unwrap();
        std::fs::write(dir.path().join("tree/nested/file.txt"), "x").unwrap();
        std::fs::write(dir.path().join("keep.txt"), "x").unwrap();

        filesystem.remove_dir_all("tree", 2).unwrap();

        assert!(!dir.path().join("tree").exists());
        assert!(dir.path().join("keep.txt").exists());
    }

    #[test]
    fn remove_dir_all_handles_multiple_batches_in_nested_directories() {
        tokio_test::block_on(async {
            for threads in [0, 1, 2, 4] {
                for asynchronous in [false, true] {
                    let (dir, filesystem) = temp_filesystem();
                    for parent in ["tree/a", "tree/a/b", "tree/c"] {
                        std::fs::create_dir_all(dir.path().join(parent).join("empty")).unwrap();
                        for index in 0..crate::threading::WALK_BATCH_SIZE * 2 + 1 {
                            std::fs::write(dir.path().join(parent).join(index.to_string()), "x")
                                .unwrap();
                        }
                    }
                    std::fs::write(dir.path().join("keep"), "x").unwrap();

                    if asynchronous {
                        filesystem
                            .async_remove_dir_all("tree", threads)
                            .await
                            .unwrap();
                    } else {
                        filesystem.remove_dir_all("tree", threads).unwrap();
                    }

                    assert!(!dir.path().join("tree").exists());
                    assert!(dir.path().join("keep").exists());
                }
            }
        });
    }

    #[test]
    fn remove_dir_all_with_empty_path_clears_contents_but_keeps_root() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/file.txt"), "x").unwrap();
        std::fs::write(dir.path().join("top.txt"), "x").unwrap();

        filesystem.remove_dir_all("", 2).unwrap();

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

        filesystem.remove_dir_all("tree", 2).unwrap();

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

        let result = filesystem.remove_dir_all("tree", 2);

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

    // ListingDir

    fn listing_entries(listing: &ListingDir) -> Vec<(FileType, String)> {
        let mut entries = Vec::new();
        listing
            .for_each_entry(|file_type, name| {
                entries.push((file_type, name));
                Ok::<_, std::io::Error>(())
            })
            .unwrap();
        entries.sort_by(|a, b| a.1.cmp(&b.1));

        entries
    }

    fn entry_names(listing: &ListingDir) -> Vec<String> {
        listing_entries(listing)
            .into_iter()
            .map(|(_, name)| name)
            .collect()
    }

    #[test]
    fn listing_dir_root_lists_every_entry_once_without_dot_entries() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("plugins")).unwrap();
        for index in 0..300 {
            std::fs::write(dir.path().join(format!("file-{index}")), "x").unwrap();
        }

        let mut expected: Vec<String> = (0..300).map(|index| format!("file-{index}")).collect();
        expected.push("plugins".to_string());
        expected.sort();

        for root in ["", "/"] {
            let listing = filesystem.open_listing_dir(root).unwrap();
            assert_eq!(entry_names(&listing), expected, "{root:?}");
        }
    }

    #[test]
    fn listing_dir_rejects_files_and_missing_paths() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::write(dir.path().join("file.txt"), "x").unwrap();

        assert!(filesystem.open_listing_dir("file.txt").is_err());
        assert!(filesystem.open_listing_dir("missing").is_err());
        assert!(filesystem.open_listing_dir("missing/nested").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn listing_dir_cannot_escape_the_root() {
        let (dir, filesystem) = temp_filesystem();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "x").unwrap();
        std::fs::write(dir.path().join("inside"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("absolute")).unwrap();
        let relative = Path::new("..").join(outside.path().file_name().unwrap());
        std::os::unix::fs::symlink(&relative, dir.path().join("relative")).unwrap();

        for path in [
            PathBuf::from(".."),
            PathBuf::from("../.."),
            relative.clone(),
            PathBuf::from("absolute"),
            PathBuf::from("relative"),
        ] {
            if let Ok(listing) = filesystem.open_listing_dir(&path) {
                assert!(
                    !entry_names(&listing).contains(&"secret".to_string()),
                    "{path:?} escaped the root"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn listing_dir_reports_entry_types_without_following_symlinks() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        std::fs::write(dir.path().join("file"), "x").unwrap();
        std::os::unix::fs::symlink("dir", dir.path().join("dir_link")).unwrap();
        std::os::unix::fs::symlink("file", dir.path().join("file_link")).unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("dangling_link")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.path().join("fifo"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let listing = filesystem.open_listing_dir("").unwrap();
        let entries = listing_entries(&listing);

        let names: Vec<&str> = entries.iter().map(|(_, name)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "dangling_link",
                "dir",
                "dir_link",
                "fifo",
                "file",
                "file_link"
            ]
        );
        for (file_type, name) in &entries {
            let expected = match name.as_str() {
                "dir" => matches!(file_type, FileType::Dir),
                "file" => matches!(file_type, FileType::File),
                "fifo" => matches!(file_type, FileType::Unknown),
                _ => matches!(file_type, FileType::Symlink),
            };
            assert!(expected, "{name}: {file_type:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn listing_dir_converts_non_utf8_names_lossily() {
        use std::os::unix::ffi::OsStrExt;

        let (dir, filesystem) = temp_filesystem();
        let raw = b"bad-\xff\xfe.txt";
        std::fs::write(dir.path().join(std::ffi::OsStr::from_bytes(raw)), "x").unwrap();

        let listing = filesystem.open_listing_dir("").unwrap();
        let entries = listing_entries(&listing);

        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].0, FileType::File));
        assert_eq!(entries[0].1, String::from_utf8_lossy(raw));
    }

    #[test]
    fn listing_dir_stops_at_the_first_visitor_error() {
        let (dir, filesystem) = temp_filesystem();
        for index in 0..10 {
            std::fs::write(dir.path().join(format!("file-{index}")), "x").unwrap();
        }

        let listing = filesystem.open_listing_dir("").unwrap();
        let mut visited = 0;
        let result = listing.for_each_entry(|_, name| {
            visited += 1;
            if visited == 3 {
                Err(anyhow::anyhow!("stop at {name}"))
            } else {
                Ok(())
            }
        });

        assert_eq!(visited, 3);
        assert!(result.unwrap_err().to_string().starts_with("stop at file-"));
    }

    #[cfg(unix)]
    #[test]
    fn listing_dir_symlink_metadata_does_not_follow_symlinks() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        std::fs::write(dir.path().join("dir/file"), "hello").unwrap();
        std::os::unix::fs::symlink("file", dir.path().join("dir/link")).unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("dir/dangling")).unwrap();

        let listing = filesystem.open_listing_dir("dir").unwrap();

        let file = listing.symlink_metadata("file").unwrap();
        assert!(file.is_file());
        assert_eq!(file.len(), 5);
        assert!(listing.symlink_metadata("link").unwrap().is_symlink());
        assert!(listing.symlink_metadata("dangling").unwrap().is_symlink());
        assert!(listing.symlink_metadata("missing").is_err());
    }

    #[test]
    fn listing_dir_keeps_resolving_after_the_directory_is_renamed() {
        use std::io::Read;

        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("before")).unwrap();
        std::fs::write(dir.path().join("before/file"), "hello").unwrap();

        let listing = filesystem.open_listing_dir("before").unwrap();
        std::fs::rename(dir.path().join("before"), dir.path().join("after")).unwrap();
        std::fs::create_dir(dir.path().join("before")).unwrap();

        assert_eq!(listing.symlink_metadata("file").unwrap().len(), 5);

        let mut content = String::new();
        listing
            .open(std::ffi::OsStr::new("file"))
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "hello");
    }

    // lchown

    #[cfg(target_os = "linux")]
    fn owner(path: impl AsRef<Path>) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(path).unwrap();
        (metadata.uid(), metadata.gid())
    }

    #[cfg(target_os = "linux")]
    fn mtime(path: impl AsRef<Path>) -> i64 {
        use std::os::unix::fs::MetadataExt;

        std::fs::symlink_metadata(path).unwrap().mtime()
    }

    #[cfg(target_os = "linux")]
    const NEW_OWNER: (u32, u32) = (4242, 4243);

    #[cfg(target_os = "linux")]
    fn new_owner() -> (rustix::fs::Uid, rustix::fs::Gid) {
        (
            rustix::fs::Uid::from_raw(NEW_OWNER.0),
            rustix::fs::Gid::from_raw(NEW_OWNER.1),
        )
    }

    #[cfg(target_os = "linux")]
    const NEW_MTIME: i64 = 1_000_000;

    #[cfg(target_os = "linux")]
    fn new_mtime() -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(NEW_MTIME as u64)
    }

    #[cfg(target_os = "linux")]
    fn make_fifo(path: impl AsRef<Path>) {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path.as_ref(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lchown_refuses_parents_that_escape_the_root() {
        let (dir, filesystem) = temp_filesystem();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let (uid, gid) = new_owner();
        let victim_before = owner(outside.path().join("victim"));
        let outside_before = owner(outside.path());

        for path in ["link/victim", "link/", "link/."] {
            assert!(filesystem.lchown(path, uid, gid).is_err(), "{path}");
        }

        assert_eq!(owner(outside.path().join("victim")), victim_before);
        assert_eq!(owner(outside.path()), outside_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn lchown_with_trailing_separator_changes_the_directory() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::create_dir(dir.path().join("b")).unwrap();
        let (uid, gid) = new_owner();

        filesystem.lchown("a/", uid, gid).unwrap();
        filesystem.lchown("b/.", uid, gid).unwrap();

        assert_eq!(owner(dir.path().join("a")), NEW_OWNER);
        assert_eq!(owner(dir.path().join("b")), NEW_OWNER);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn lchown_changes_leaf_symlinks_and_fifos_without_following() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::write(dir.path().join("target"), "x").unwrap();
        std::os::unix::fs::symlink("target", dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("dangling")).unwrap();
        make_fifo(dir.path().join("fifo"));
        let (uid, gid) = new_owner();
        let target_before = owner(dir.path().join("target"));

        for path in ["link", "dangling", "fifo"] {
            filesystem.lchown(path, uid, gid).unwrap();
            assert_eq!(owner(dir.path().join(path)), NEW_OWNER, "{path}");
        }

        assert_eq!(owner(dir.path().join("target")), target_before);
        assert!(!dir.path().join("missing").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn lchown_follows_in_root_symlinked_parents() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/f"), "x").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("alias")).unwrap();
        let (uid, gid) = new_owner();

        filesystem.lchown("alias/f", uid, gid).unwrap();

        assert_eq!(owner(dir.path().join("real/f")), NEW_OWNER);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn lchown_trailing_separator_on_symlink_changes_its_directory() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
        let (uid, gid) = new_owner();
        let link_before = owner(dir.path().join("link"));

        filesystem.lchown("link/", uid, gid).unwrap();

        assert_eq!(owner(dir.path().join("real")), NEW_OWNER);
        assert_eq!(owner(dir.path().join("link")), link_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn lchown_on_the_root_changes_the_base_directory() {
        let (dir, filesystem) = temp_filesystem();
        let (uid, gid) = new_owner();
        let (before_uid, before_gid) = owner(dir.path());
        let reset = || std::os::unix::fs::chown(dir.path(), Some(before_uid), Some(before_gid));

        for path in ["", "/", "."] {
            filesystem.lchown(path, uid, gid).unwrap();
            assert_eq!(owner(dir.path()), NEW_OWNER, "{path}");
            reset().unwrap();

            tokio_test::block_on(filesystem.async_lchown(path, uid, gid)).unwrap();
            assert_eq!(owner(dir.path()), NEW_OWNER, "async {path}");
            reset().unwrap();
        }
    }

    // set_times

    #[cfg(target_os = "linux")]
    #[test]
    fn set_times_refuses_parents_that_escape_the_root() {
        let (dir, filesystem) = temp_filesystem();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let victim_before = mtime(outside.path().join("victim"));
        let outside_before = mtime(outside.path());

        for path in ["link/victim", "link/", "link/."] {
            assert!(
                filesystem.set_times(path, new_mtime(), None).is_err(),
                "{path}"
            );
            assert!(
                tokio_test::block_on(filesystem.async_set_times(path, new_mtime(), None)).is_err(),
                "async {path}"
            );
        }

        assert_eq!(mtime(outside.path().join("victim")), victim_before);
        assert_eq!(mtime(outside.path()), outside_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_times_with_trailing_separator_changes_the_directory() {
        let (dir, filesystem) = temp_filesystem();
        for name in ["a", "b", "c", "d"] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
        }

        filesystem.set_times("a/", new_mtime(), None).unwrap();
        filesystem
            .set_times("b/.", new_mtime(), Some(new_mtime()))
            .unwrap();
        tokio_test::block_on(async {
            filesystem.async_set_times("c/", new_mtime(), None).await?;
            filesystem.async_set_times("d/.", new_mtime(), None).await
        })
        .unwrap();

        for name in ["a", "b", "c", "d"] {
            assert_eq!(mtime(dir.path().join(name)), NEW_MTIME, "{name}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_times_changes_leaf_symlinks_and_fifos_without_following() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::write(dir.path().join("target"), "x").unwrap();
        std::os::unix::fs::symlink("target", dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("dangling")).unwrap();
        make_fifo(dir.path().join("fifo"));
        let target_before = mtime(dir.path().join("target"));

        for path in ["link", "dangling", "fifo"] {
            filesystem.set_times(path, new_mtime(), None).unwrap();
            assert_eq!(mtime(dir.path().join(path)), NEW_MTIME, "{path}");
        }

        assert_eq!(mtime(dir.path().join("target")), target_before);
        assert!(!dir.path().join("missing").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_times_follows_in_root_symlinked_parents() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/f"), "x").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("alias")).unwrap();

        tokio_test::block_on(filesystem.async_set_times("alias/f", new_mtime(), None)).unwrap();

        assert_eq!(mtime(dir.path().join("real/f")), NEW_MTIME);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_times_trailing_separator_on_symlink_changes_its_directory() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
        let link_before = mtime(dir.path().join("link"));

        filesystem.set_times("link/", new_mtime(), None).unwrap();

        assert_eq!(mtime(dir.path().join("real")), NEW_MTIME);
        assert_eq!(mtime(dir.path().join("link")), link_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_times_on_the_root_changes_the_base_directory() {
        let (dir, filesystem) = temp_filesystem();
        let later = new_mtime() + std::time::Duration::from_secs(1);

        for path in ["", "/", "."] {
            filesystem.set_times(path, new_mtime(), None).unwrap();
            assert_eq!(mtime(dir.path()), NEW_MTIME, "{path}");

            tokio_test::block_on(filesystem.async_set_times(path, later, None)).unwrap();
            assert_eq!(mtime(dir.path()), NEW_MTIME + 1, "async {path}");
        }
    }

    // WalkEntry::lchown

    #[cfg(target_os = "linux")]
    fn walk_entry(filesystem: &CapFilesystem, dir: &str, name: &str) -> WalkEntry {
        let mut walk = filesystem.walk_dir(dir).unwrap();
        while let Some(entry) = walk.next_entry() {
            let entry = entry.unwrap();
            if entry.name() == name {
                return entry;
            }
        }
        panic!("{name} not found in {dir}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn walk_entry_lchown_changes_the_entry_without_following_symlinks() {
        let (dir, filesystem) = temp_filesystem();
        std::fs::create_dir(dir.path().join("tree")).unwrap();
        std::fs::write(dir.path().join("tree/f"), "x").unwrap();
        std::fs::write(dir.path().join("tree/target"), "x").unwrap();
        std::os::unix::fs::symlink("target", dir.path().join("tree/link")).unwrap();
        let (uid, gid) = new_owner();
        let target_before = owner(dir.path().join("tree/target"));

        walk_entry(&filesystem, "tree", "f")
            .lchown(uid, gid)
            .unwrap();
        walk_entry(&filesystem, "tree", "link")
            .lchown(uid, gid)
            .unwrap();

        assert_eq!(owner(dir.path().join("tree/f")), NEW_OWNER);
        assert_eq!(owner(dir.path().join("tree/link")), NEW_OWNER);
        assert_eq!(owner(dir.path().join("tree/target")), target_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn walk_entry_lchown_stays_bound_to_the_listed_directory() {
        let (dir, filesystem) = temp_filesystem();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), "x").unwrap();
        let (uid, gid) = new_owner();
        let outside_before = owner(outside.path().join("f"));

        for swap_to_outside in [false, true] {
            let tree = dir.path().join("tree");
            let moved = dir.path().join("moved");
            std::fs::create_dir(&tree).unwrap();
            std::fs::write(tree.join("f"), "x").unwrap();

            let entry = walk_entry(&filesystem, "tree", "f");
            std::fs::rename(&tree, &moved).unwrap();
            if swap_to_outside {
                std::os::unix::fs::symlink(outside.path(), &tree).unwrap();
            } else {
                std::fs::create_dir(&tree).unwrap();
                std::fs::write(tree.join("f"), "x").unwrap();
            }
            let replacement_before = owner(tree.join("f"));

            entry.lchown(uid, gid).unwrap();

            assert_eq!(owner(moved.join("f")), NEW_OWNER);
            assert_eq!(owner(tree.join("f")), replacement_before);

            std::fs::remove_dir_all(&moved).unwrap();
            if swap_to_outside {
                std::fs::remove_file(&tree).unwrap();
            } else {
                std::fs::remove_dir_all(&tree).unwrap();
            }
        }

        assert_eq!(owner(outside.path().join("f")), outside_before);
    }

    // async_connect_unix

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_round_trips_bytes_and_reports_relative_path() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;
            let listener = std::os::unix::net::UnixListener::bind(temp.path().join("s.sock"))?;

            let (mut stream, path) = fs.async_connect_unix("/s.sock").await?;
            assert_eq!(path, PathBuf::from("s.sock"));

            let (mut accepted, _) = listener.accept()?;
            stream.write_all(b"ping").await?;
            stream.flush().await?;
            let mut buf = [0; 4];
            std::io::Read::read_exact(&mut accepted, &mut buf)?;
            assert_eq!(&buf, b"ping");

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_reports_symlink_target_path() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;
            std::fs::create_dir(temp.path().join("sub"))?;
            let listener =
                std::os::unix::net::UnixListener::bind(temp.path().join("sub/real.sock"))?;
            std::os::unix::fs::symlink("sub/real.sock", temp.path().join("link.sock"))?;

            let (_stream, path) = fs.async_connect_unix("link.sock").await?;
            assert_eq!(path, PathBuf::from("sub/real.sock"));
            listener.accept()?;

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_cannot_escape_the_root() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let outside = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;
            let listener = std::os::unix::net::UnixListener::bind(outside.path().join("s.sock"))?;
            listener.set_nonblocking(true)?;
            std::os::unix::fs::symlink(
                outside.path().join("s.sock"),
                temp.path().join("absolute"),
            )?;
            let relative = Path::new("..")
                .join(outside.path().file_name().unwrap())
                .join("s.sock");
            std::os::unix::fs::symlink(&relative, temp.path().join("relative"))?;

            for path in [
                Path::new("absolute"),
                Path::new("relative"),
                relative.as_path(),
            ] {
                let err = fs.async_connect_unix(path).await.unwrap_err();
                assert!(
                    matches!(
                        err.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::NotADirectory
                    ),
                    "{path:?}: {err:?}"
                );
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "{path:?} reached the outside listener"
                );
            }

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_rejects_regular_file() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;
            std::fs::write(temp.path().join("file"), "x")?;

            let err = fs.async_connect_unix("file").await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_reports_missing_socket() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;

            for path in ["missing.sock", "missing/s.sock"] {
                let err = fs.async_connect_unix(path).await.unwrap_err();
                assert!(
                    matches!(
                        err.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::NotADirectory
                    ),
                    "{path}: {err:?}"
                );
            }

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_refuses_stale_socket() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;
            drop(std::os::unix::net::UnixListener::bind(
                temp.path().join("s.sock"),
            )?);

            let err = fs.async_connect_unix("s.sock").await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn async_connect_unix_is_not_limited_by_sun_path_length() {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            let fs = CapFilesystem::new(temp.path()).await?;
            let deep = Path::new(&"a".repeat(60)).join("b".repeat(60));
            std::fs::create_dir_all(temp.path().join(&deep))?;
            // bind at a short path, then move the socket inode past the sun_path limit
            let listener = std::os::unix::net::UnixListener::bind(temp.path().join("s.sock"))?;
            std::fs::rename(
                temp.path().join("s.sock"),
                temp.path().join(&deep).join("s.sock"),
            )?;
            assert!(temp.path().join(&deep).join("s.sock").as_os_str().len() > 108);

            let (mut stream, path) = fs.async_connect_unix(deep.join("s.sock")).await?;
            assert_eq!(path, deep.join("s.sock"));

            let (mut accepted, _) = listener.accept()?;
            stream.write_all(b"ping").await?;
            stream.flush().await?;
            let mut buf = [0; 4];
            std::io::Read::read_exact(&mut accepted, &mut buf)?;
            assert_eq!(&buf, b"ping");

            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    }
}
