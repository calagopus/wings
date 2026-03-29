use crate::{
    io::abort::{AbortGuard, AbortListener},
    utils::PortableModeExt,
};
use cap_std::fs::{Metadata, OpenOptions};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    os::fd::AsFd,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

mod utils;
pub use utils::{AsyncReadDir, AsyncWalkDir, FileType, ReadDir, WalkDir};

#[derive(Debug, Clone)]
pub struct CapFilesystem {
    pub base_path: Arc<PathBuf>,
    pub(super) inner: Arc<RwLock<Option<Arc<cap_std::fs::Dir>>>>,
}

impl CapFilesystem {
    pub async fn new(base_path: PathBuf) -> Result<Self, std::io::Error> {
        let base_path = Arc::new(base_path);

        let inner = tokio::task::spawn_blocking({
            let base_path = base_path.clone();

            move || cap_std::fs::Dir::open_ambient_dir(&*base_path, cap_std::ambient_authority())
        })
        .await??;

        Ok(Self {
            base_path,
            inner: Arc::new(RwLock::new(Some(Arc::new(inner)))),
        })
    }

    pub fn new_uninitialized(base_path: PathBuf) -> Self {
        Self {
            base_path: Arc::new(base_path),
            inner: Arc::new(RwLock::new(None)),
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
    pub async fn is_uninitialized(&self) -> bool {
        self.inner.read().await.is_none()
    }

    #[inline]
    pub async fn async_get_inner(&self) -> Result<Arc<cap_std::fs::Dir>, anyhow::Error> {
        let inner = self.inner.read().await;

        inner
            .clone()
            .ok_or_else(|| anyhow::anyhow!("filesystem not initialized"))
    }

    async fn async_refresh_inner(&self) -> Result<Arc<cap_std::fs::Dir>, anyhow::Error> {
        let base_path = self.base_path.clone();
        let inner = tokio::task::spawn_blocking(move || {
            cap_std::fs::Dir::open_ambient_dir(&*base_path, cap_std::ambient_authority())
        })
        .await??;

        let inner = Arc::new(inner);
        *self.inner.write().await = Some(inner.clone());

        Ok(inner)
    }

    #[inline]
    pub fn get_inner(&self) -> Result<Arc<cap_std::fs::Dir>, anyhow::Error> {
        let inner = self.inner.blocking_read();

        inner
            .clone()
            .ok_or_else(|| anyhow::anyhow!("filesystem not initialized"))
    }

    fn refresh_inner(&self) -> Result<Arc<cap_std::fs::Dir>, anyhow::Error> {
        let inner = Arc::new(cap_std::fs::Dir::open_ambient_dir(
            &*self.base_path,
            cap_std::ambient_authority(),
        )?);

        *self.inner.blocking_write() = Some(inner.clone());

        Ok(inner)
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

    pub async fn async_create_dir_all(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.create_dir_all(path)).await??;

        Ok(())
    }

    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.create_dir_all(path)?;

        Ok(())
    }

    pub async fn async_create_dir(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.create_dir(path)).await??;

        Ok(())
    }

    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.create_dir(path)?;

        Ok(())
    }

    pub async fn async_remove_dir(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.remove_dir(path)).await??;

        Ok(())
    }

    pub fn remove_dir(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.remove_dir(path)?;

        Ok(())
    }

    pub async fn async_remove_dir_all(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        let res = tokio::task::spawn_blocking({
            let inner = inner.clone();
            let path = path.clone();
            move || inner.remove_dir_all(path)
        })
        .await?;

        match res {
            Ok(()) => {}
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "remove_dir_all failed, refreshing filesystem handle and retrying"
                );

                let inner = self.async_refresh_inner().await?;
                let retry = tokio::task::spawn_blocking({
                    let inner = inner.clone();
                    let path = path.clone();
                    move || inner.remove_dir_all(path)
                })
                .await?;

                match retry {
                    Ok(()) => {}
                    Err(retry_err) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %retry_err,
                            "remove_dir_all retry failed, falling back to std::fs::remove_dir_all"
                        );

                        let absolute_path = self.base_path.join(&path);
                        tokio::task::spawn_blocking(move || std::fs::remove_dir_all(absolute_path))
                            .await??;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn remove_dir_all(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        if let Err(err) = inner.remove_dir_all(path.clone()) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "remove_dir_all failed, refreshing filesystem handle and retrying"
            );

            let inner = self.refresh_inner()?;
            if let Err(retry_err) = inner.remove_dir_all(path.clone()) {
                tracing::warn!(
                    path = %path.display(),
                    error = %retry_err,
                    "remove_dir_all retry failed, falling back to std::fs::remove_dir_all"
                );

                std::fs::remove_dir_all(self.base_path.join(&path))?;
            }
        }

        Ok(())
    }

    pub async fn async_remove_file(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.remove_file(path)).await??;

        Ok(())
    }

    pub fn remove_file(&self, path: impl AsRef<Path>) -> Result<(), anyhow::Error> {
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
    ) -> Result<(), anyhow::Error> {
        let from = self.relative_path(from.as_ref());
        let to = self.relative_path(to.as_ref());

        let inner = self.async_get_inner().await?;
        let to_inner = to_dir.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.rename(from, &to_inner, to)).await??;

        Ok(())
    }

    pub fn rename(
        &self,
        from: impl AsRef<Path>,
        to_dir: &CapFilesystem,
        to: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
        let from = self.relative_path(from.as_ref());
        let to = self.relative_path(to.as_ref());

        let inner = self.get_inner()?;
        let to_inner = to_dir.get_inner()?;
        inner.rename(from, &to_inner, to)?;

        Ok(())
    }

    pub async fn async_metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(tokio::fs::metadata(&*self.base_path).await?)
        } else {
            let inner = self.async_get_inner().await?;
            let result =
                tokio::task::spawn_blocking({
                    let inner = inner.clone();
                    let path = path.clone();

                    move || inner.metadata(path)
                })
                .await?;

            match result {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "metadata failed, refreshing filesystem handle and retrying"
                    );

                    let inner = self.async_refresh_inner().await?;
                    tokio::task::spawn_blocking(move || inner.metadata(path)).await??
                }
            }
        };

        Ok(metadata)
    }

    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(std::fs::metadata(&*self.base_path)?)
        } else {
            let inner = self.get_inner()?;
            match inner.metadata(path.clone()) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "metadata failed, refreshing filesystem handle and retrying"
                    );

                    let inner = self.refresh_inner()?;
                    inner.metadata(path)?
                }
            }
        };

        Ok(metadata)
    }

    pub async fn async_symlink_metadata(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Metadata, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(
                tokio::fs::symlink_metadata(&*self.base_path).await?,
            )
        } else {
            let inner = self.async_get_inner().await?;
            let result =
                tokio::task::spawn_blocking({
                    let inner = inner.clone();
                    let path = path.clone();

                    move || inner.symlink_metadata(path)
                })
                .await?;

            match result {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "symlink_metadata failed, refreshing filesystem handle and retrying"
                    );

                    let inner = self.async_refresh_inner().await?;
                    tokio::task::spawn_blocking(move || inner.symlink_metadata(path)).await??
                }
            }
        };

        Ok(metadata)
    }

    pub fn symlink_metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let metadata = if path.components().next().is_none() {
            cap_std::fs::Metadata::from_just_metadata(std::fs::symlink_metadata(&*self.base_path)?)
        } else {
            let inner = self.get_inner()?;
            match inner.symlink_metadata(path.clone()) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "symlink_metadata failed, refreshing filesystem handle and retrying"
                    );

                    let inner = self.refresh_inner()?;
                    inner.symlink_metadata(path)?
                }
            }
        };

        Ok(metadata)
    }

    pub async fn async_canonicalize(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = self.relative_path(path.as_ref());
        if path.components().next().is_none() {
            return Ok(path);
        }

        let inner = self.async_get_inner().await?;
        let canonicalized = tokio::task::spawn_blocking(move || inner.canonicalize(path)).await??;

        Ok(canonicalized)
    }

    pub fn canonicalize(&self, path: impl AsRef<Path>) -> Result<PathBuf, anyhow::Error> {
        let path = self.relative_path(path.as_ref());
        if path.components().next().is_none() {
            return Ok(path);
        }

        let inner = self.get_inner()?;
        let canonicalized = inner.canonicalize(path)?;

        Ok(canonicalized)
    }

    pub async fn async_read_link(&self, path: impl AsRef<Path>) -> Result<PathBuf, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        let link = tokio::task::spawn_blocking(move || inner.read_link(path)).await??;

        Ok(link)
    }

    pub fn read_link(&self, path: impl AsRef<Path>) -> Result<PathBuf, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let link = inner.read_link(path)?;

        Ok(link)
    }

    pub async fn async_read_link_contents(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        let link_contents =
            tokio::task::spawn_blocking(move || inner.read_link_contents(path)).await??;

        Ok(link_contents)
    }

    pub fn read_link_contents(&self, path: impl AsRef<Path>) -> Result<PathBuf, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let link_contents = inner.read_link_contents(path)?;

        Ok(link_contents)
    }

    pub async fn async_read_to_string(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<String, anyhow::Error> {
        let content = self.async_read_to_vec(path, limit).await?;

        Ok(String::from_utf8(content)?)
    }

    pub fn read_to_string(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<String, anyhow::Error> {
        let content = self.read_to_vec(path, limit)?;

        Ok(String::from_utf8(content)?)
    }

    pub async fn async_read_to_vec(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let mut file = self.async_open(path).await?;
        let mut content = Vec::new();

        let mut buf = vec![0; crate::BUFFER_SIZE];
        loop {
            let bytes_read = file.read(&mut buf).await?;

            if crate::unlikely(bytes_read == 0) {
                break;
            }

            content.extend_from_slice(&buf[..bytes_read]);

            if crate::unlikely(content.len() >= limit) {
                content.truncate(limit);
                break;
            }
        }

        Ok(content)
    }

    pub fn read_to_vec(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let mut file = self.open(path)?;
        let mut content = Vec::new();

        let mut buf = vec![0; crate::BUFFER_SIZE];
        loop {
            let bytes_read = file.read(&mut buf)?;

            if crate::unlikely(bytes_read == 0) {
                break;
            }

            content.extend_from_slice(&buf[..bytes_read]);

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
    ) -> Result<tokio::fs::File, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        let file = tokio::task::spawn_blocking(move || inner.open(path)).await??;

        Ok(tokio::fs::File::from_std(file.into_std()))
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<std::fs::File, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = inner.open(path)?;

        Ok(file.into_std())
    }

    pub async fn async_open_with(
        &self,
        path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<tokio::fs::File, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        let file = tokio::task::spawn_blocking(move || inner.open_with(path, &options)).await??;

        Ok(tokio::fs::File::from_std(file.into_std()))
    }

    pub fn open_with(
        &self,
        path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<std::fs::File, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = inner.open_with(path, &options)?;

        Ok(file.into_std())
    }

    pub async fn async_write(
        &self,
        path: impl AsRef<Path>,
        data: impl AsRef<[u8]>,
    ) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let mut file = self.async_create(path).await?;
        file.write_all(data.as_ref()).await?;
        file.sync_all().await?;

        Ok(())
    }

    pub fn write(
        &self,
        path: impl AsRef<Path>,
        data: impl AsRef<[u8]>,
    ) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let mut file = self.create(path)?;
        file.write_all(data.as_ref())?;
        file.sync_all()?;

        Ok(())
    }

    pub async fn async_create(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<tokio::fs::File, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.async_get_inner().await?;
        let file = tokio::task::spawn_blocking(move || inner.create(path)).await??;

        Ok(tokio::fs::File::from_std(file.into_std()))
    }

    pub fn create(&self, path: impl AsRef<Path>) -> Result<std::fs::File, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        let file = inner.create(path)?;

        Ok(file.into_std())
    }

    pub async fn async_copy(
        &self,
        from: impl AsRef<Path>,
        to_dir: &CapFilesystem,
        to: impl AsRef<Path>,
    ) -> Result<u64, anyhow::Error> {
        let from = self.relative_path(from.as_ref());
        let to = self.relative_path(to.as_ref());

        let inner = self.async_get_inner().await?;
        let to_inner = to_dir.async_get_inner().await?;
        let bytes_copied =
            tokio::task::spawn_blocking(move || inner.copy(from, &to_inner, to)).await??;

        Ok(bytes_copied)
    }

    pub fn copy(
        &self,
        from: impl AsRef<Path>,
        to_dir: &CapFilesystem,
        to: impl AsRef<Path>,
    ) -> Result<u64, anyhow::Error> {
        let from = self.relative_path(from.as_ref());
        let to = self.relative_path(to.as_ref());

        let inner = self.get_inner()?;
        let to_inner = to_dir.get_inner()?;
        let bytes_copied = inner.copy(from, &to_inner, to)?;

        Ok(bytes_copied)
    }

    pub async fn async_quota_copy(
        &self,
        path: impl AsRef<Path>,
        destination_path: impl AsRef<Path>,
        destination_server: &crate::server::Server,
        progress: Option<&Arc<AtomicU64>>,
    ) -> Result<u64, anyhow::Error> {
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
    ) -> Result<u64, anyhow::Error> {
        let path = self.relative_path(path.as_ref());
        let destination_path = destination_server
            .filesystem
            .relative_path(destination_path.as_ref());

        let mut reader = self.open(&path)?;
        let mut writer = destination_server.filesystem.create(&destination_path)?;

        let Some(destination_parent) = destination_path.parent() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Destination path has no parent",
            )
            .into());
        };

        let mut cached_allocation_progress = 0i64;

        let bytes_copied = crate::io::copy_file_progress(
            &mut reader,
            &mut writer,
            |bytes_read| {
                if let Some(progress) = progress {
                    progress.fetch_add(bytes_read as u64, Ordering::Relaxed);
                }
                cached_allocation_progress += bytes_read as i64;

                if cached_allocation_progress >= super::writer::ALLOCATION_THRESHOLD {
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
            )
            .into());
        }

        Ok(bytes_copied)
    }

    pub async fn async_set_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: cap_std::fs::Permissions,
    ) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        if path.components().next().is_none() {
            tokio::fs::set_permissions(
                &*self.base_path,
                std::fs::Permissions::from_portable_mode(permissions.mode()),
            )
            .await?;
        } else {
            let inner = self.async_get_inner().await?;

            tokio::task::spawn_blocking(move || inner.set_permissions(path, permissions)).await??;
        }

        Ok(())
    }

    pub fn set_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: cap_std::fs::Permissions,
    ) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        let inner = self.get_inner()?;
        inner.set_permissions(path, permissions)?;

        Ok(())
    }

    pub async fn async_set_symlink_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: cap_std::fs::Permissions,
    ) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        if path.components().next().is_none() {
            tokio::fs::set_permissions(
                &*self.base_path,
                std::fs::Permissions::from_portable_mode(permissions.mode()),
            )
            .await?;
        } else {
            let inner = self.async_get_inner().await?;

            tokio::task::spawn_blocking(move || {
                rustix::fs::chmodat(
                    inner.as_fd(),
                    path,
                    rustix::fs::Mode::from_raw_mode(permissions.mode()),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
            })
            .await??;
        }

        Ok(())
    }

    pub fn set_symlink_permissions(
        &self,
        path: impl AsRef<Path>,
        permissions: cap_std::fs::Permissions,
    ) -> Result<(), anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        if path.components().next().is_none() {
            std::fs::set_permissions(
                &*self.base_path,
                std::fs::Permissions::from_portable_mode(permissions.mode()),
            )?;
        } else {
            let inner = self.get_inner()?;

            #[cfg(unix)]
            rustix::fs::chmodat(
                inner.as_fd(),
                path,
                rustix::fs::Mode::from_raw_mode(permissions.mode()),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            #[cfg(not(unix))]
            self.set_permissions(path, permissions)?;
        }

        Ok(())
    }

    pub async fn async_set_times(
        &self,
        path: impl AsRef<Path>,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error> {
        #[cfg(unix)]
        {
            let path = self.relative_path(path.as_ref());
            let inner = self.async_get_inner().await?;

            let elapsed_modification = modification_time.duration_since(std::time::UNIX_EPOCH)?;
            let elapsed_access = access_time
                .unwrap_or_else(std::time::SystemTime::now)
                .duration_since(std::time::UNIX_EPOCH)?;

            let times = rustix::fs::Timestamps {
                last_modification: elapsed_modification.try_into()?,
                last_access: elapsed_access.try_into()?,
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
            let inner = self.async_get_inner().await?;

            let mut times = std::fs::FileTimes::new();
            times.set_modified(modification_time);
            if let Some(atime) = access_time {
                times.set_accessed(atime);
            }

            let mut file = tokio::task::spawn_blocking(move || {
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
    ) -> Result<(), anyhow::Error> {
        #[cfg(unix)]
        {
            let path = self.relative_path(path.as_ref());
            let inner = self.get_inner()?;

            let elapsed_modification = modification_time.duration_since(std::time::UNIX_EPOCH)?;
            let elapsed_access = access_time
                .unwrap_or_else(std::time::SystemTime::now)
                .duration_since(std::time::UNIX_EPOCH)?;

            let times = rustix::fs::Timestamps {
                last_modification: elapsed_modification.try_into()?,
                last_access: elapsed_access.try_into()?,
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

            let mut times = std::fs::FileTimes::new();
            times.set_modified(modification_time);
            if let Some(atime) = access_time {
                times.set_accessed(atime);
            }

            let mut file = inner.open(path)?.into_std();
            file.set_times(times)?;

            Ok(())
        }
    }

    pub async fn async_symlink(
        &self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.symlink(target, link)).await??;

        Ok(())
    }

    pub fn symlink(
        &self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.get_inner()?;

        #[cfg(unix)]
        {
            inner.symlink(target, link)?;
        }
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

    pub async fn async_hard_link(
        &self,
        target: impl AsRef<Path>,
        dst_dir: &CapFilesystem,
        link: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
        let target = self.relative_path(target.as_ref());
        let link = self.relative_path(link.as_ref());

        let inner = self.async_get_inner().await?;
        let dst_inner = dst_dir.async_get_inner().await?;
        tokio::task::spawn_blocking(move || inner.hard_link(target, &dst_inner, link)).await??;

        Ok(())
    }

    pub fn hard_link(
        &self,
        target: impl AsRef<Path>,
        dst_dir: &CapFilesystem,
        link: impl AsRef<Path>,
    ) -> Result<(), anyhow::Error> {
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
    ) -> Result<Vec<String>, anyhow::Error> {
        let mut read_dir = self.async_read_dir(path).await?;

        let mut names = Vec::new();
        while let Some(Ok((_, entry))) = read_dir.next_entry().await {
            names.push(entry);
        }

        Ok(names)
    }

    pub fn read_dir_all(&self, path: impl AsRef<Path>) -> Result<Vec<String>, anyhow::Error> {
        let mut read_dir = self.read_dir(path)?;

        let mut names = Vec::new();
        while let Some(Ok((_, entry))) = read_dir.next_entry() {
            names.push(entry);
        }

        Ok(names)
    }

    pub async fn async_read_dir(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<AsyncReadDir, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        Ok(if path.components().next().is_none() {
            AsyncReadDir::Tokio(utils::AsyncTokioReadDir(
                tokio::fs::read_dir(&*self.base_path).await?,
            ))
        } else {
            let inner = self.async_get_inner().await?;

            AsyncReadDir::Cap(utils::AsyncCapReadDir(
                Some(tokio::task::spawn_blocking(move || inner.read_dir(path)).await??),
                Some(VecDeque::with_capacity(32)),
            ))
        })
    }

    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<ReadDir, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        Ok(if path.components().next().is_none() {
            ReadDir::Std(utils::StdReadDir(std::fs::read_dir(&*self.base_path)?))
        } else {
            let inner = self.get_inner()?;

            ReadDir::Cap(utils::CapReadDir(inner.read_dir(path)?))
        })
    }

    pub async fn async_walk_dir(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<AsyncWalkDir, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        AsyncWalkDir::new(self.clone(), path).await
    }

    pub fn walk_dir(&self, path: impl AsRef<Path>) -> Result<WalkDir, anyhow::Error> {
        let path = self.relative_path(path.as_ref());

        WalkDir::new(self.clone(), path)
    }
}
