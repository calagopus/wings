use crate::utils::{PortablePermissions, PortablePermissionsApplier};
use positioned_io::{ReadAt, WriteAt};
use std::{
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::SystemTime,
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const ALLOCATION_THRESHOLD: i64 = 1024 * 1024; // 1 MiB

pub struct ServerFile {
    server: crate::server::Server,
    parent: Vec<String>,
    file: Option<std::fs::File>,
    ignorant: bool,
    accumulated_bytes: i64,
    modified: Option<SystemTime>,
    current_position: u64,
    highest_position: u64,
}

fn open_destination(
    server: &crate::server::Server,
    destination: &Path,
    permissions: Option<PortablePermissions>,
) -> Result<(std::fs::File, u64), anyhow::Error> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);

    let file = server.filesystem.open_with(destination, options)?;
    let previous_size = file
        .metadata()
        .ok()
        .filter(|metadata| metadata.is_file())
        .map_or(0, |metadata| metadata.len());
    if previous_size > 0 {
        file.set_len(0)?;
    }

    if let Some(permissions) = permissions {
        file.apply_permissions(permissions)?;
    }

    server.filesystem.chown_file(&file)?;

    Ok((file, previous_size))
}

impl ServerFile {
    pub fn new(
        server: crate::server::Server,
        destination: &Path,
        permissions: Option<PortablePermissions>,
        modified: Option<SystemTime>,
    ) -> Result<Self, anyhow::Error> {
        let parent_path = destination.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Destination has no parent",
            )
        })?;

        let parent = server
            .filesystem
            .path_to_components(&server.filesystem.relative_path(parent_path));

        let (file, previous_size) = open_destination(&server, destination, permissions)?;

        Ok(Self {
            server,
            parent,
            file: Some(file),
            ignorant: false,
            accumulated_bytes: -(previous_size as i64),
            modified,
            current_position: 0,
            highest_position: 0,
        })
    }

    /// Wraps an already opened file, accounting only for what is written past
    /// `initial_size`.
    ///
    /// Positions are counted from this handle, not from the file, so `initial_size`
    /// must be `0` for an `O_APPEND` handle: writes there land at the end of the file
    /// while the handle's own position starts at zero, and any other value would leave
    /// that many appended bytes uncharged.
    pub fn new_file(
        server: crate::server::Server,
        destination: &Path,
        file: std::fs::File,
        initial_size: u64,
    ) -> Result<Self, anyhow::Error> {
        let parent_path = destination.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Destination has no parent",
            )
        })?;

        let parent = server
            .filesystem
            .path_to_components(&server.filesystem.relative_path(parent_path));

        Ok(Self {
            server,
            parent,
            file: Some(file),
            ignorant: false,
            accumulated_bytes: 0,
            modified: None,
            current_position: 0,
            highest_position: initial_size,
        })
    }

    /// Skip Disk Limit Checks
    pub fn ignorant(mut self) -> Self {
        self.ignorant = true;
        self
    }

    pub fn sync_all(&mut self) -> std::io::Result<()> {
        self.allocate_accumulated()?;

        let Some(file) = self.file.as_ref() else {
            return Err(std::io::Error::other("file is not available"));
        };

        file.sync_all()
    }

    fn allocate_accumulated(&mut self) -> std::io::Result<()> {
        if self.accumulated_bytes != 0 {
            if !self.server.filesystem.allocate_in_path_iterator(
                &self.parent,
                self.accumulated_bytes,
                self.ignorant,
            ) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "Failed to allocate space",
                ));
            }

            self.accumulated_bytes = 0;
        }

        Ok(())
    }
}

impl Write for ServerFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        let written = file.write(buf)?;

        self.current_position += written as u64;

        if crate::likely(self.current_position > self.highest_position) {
            let additional_space = (self.current_position - self.highest_position) as i64;
            self.accumulated_bytes += additional_space;
            self.highest_position = self.current_position;
        }

        if crate::unlikely(self.accumulated_bytes >= ALLOCATION_THRESHOLD) {
            self.allocate_accumulated()?;
        }

        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.allocate_accumulated()?;

        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        Write::flush(file)
    }
}

impl Seek for ServerFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.allocate_accumulated()?;

        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        let new_pos = file.seek(pos)?;

        self.current_position = new_pos;

        Ok(new_pos)
    }
}

impl Read for ServerFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        file.read(buf)
    }
}

impl ReadAt for ServerFile {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(file) = self.file.as_ref() else {
            return Err(std::io::Error::other("file is not available"));
        };

        file.read_at(pos, buf)
    }
}

impl WriteAt for ServerFile {
    fn write_at(&mut self, pos: u64, buf: &[u8]) -> std::io::Result<usize> {
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        let written = file.write_at(pos, buf)?;
        let end = pos.saturating_add(written as u64);

        if crate::likely(end > self.highest_position) {
            self.accumulated_bytes = self
                .accumulated_bytes
                .saturating_add(i64::try_from(end - self.highest_position).unwrap_or(i64::MAX));
            self.highest_position = end;
        }

        if crate::unlikely(self.accumulated_bytes >= ALLOCATION_THRESHOLD) {
            self.allocate_accumulated()?;
        }

        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.allocate_accumulated()?;

        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        Write::flush(file)
    }
}

impl Drop for ServerFile {
    fn drop(&mut self) {
        if self.accumulated_bytes != 0 {
            let server = self.server.clone();
            let parent = self.parent.clone();
            let bytes = self.accumulated_bytes;
            let ignorant = self.ignorant;
            self.accumulated_bytes = 0;

            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(async move {
                    server
                        .filesystem
                        .async_allocate_in_path_iterator(&parent, bytes, ignorant)
                        .await;
                });
            } else {
                server
                    .filesystem
                    .allocate_in_path_iterator(&parent, bytes, ignorant);
            }
        }

        if let Some(modified) = self.modified
            && let Some(file) = self.file.take()
        {
            file.set_modified(modified).ok();
        }
    }
}

pub struct AsyncServerFile {
    server: crate::server::Server,
    parent: Vec<String>,
    file: Option<tokio::fs::File>,
    ignorant: bool,
    accumulated_bytes: i64,
    allocating_bytes: i64,
    modified: Option<SystemTime>,
    allocation_in_progress: Option<Pin<Box<dyn Future<Output = bool> + Send>>>,
    current_position: u64,
    highest_position: u64,
}

impl AsyncServerFile {
    pub async fn new(
        server: crate::server::Server,
        destination: &Path,
        permissions: Option<PortablePermissions>,
        modified: Option<SystemTime>,
    ) -> Result<Self, anyhow::Error> {
        let parent_path = destination.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Destination has no parent",
            )
        })?;

        let parent = server
            .filesystem
            .path_to_components(&server.filesystem.relative_path(parent_path));

        let (file, previous_size) = tokio::task::spawn_blocking({
            let server = server.clone();
            let destination = destination.to_path_buf();

            move || open_destination(&server, &destination, permissions)
        })
        .await??;
        let file = tokio::fs::File::from_std(file);

        Ok(Self {
            server,
            parent,
            file: Some(file),
            ignorant: false,
            accumulated_bytes: -(previous_size as i64),
            allocating_bytes: 0,
            modified,
            allocation_in_progress: None,
            current_position: 0,
            highest_position: 0,
        })
    }

    /// Async counterpart of [`ServerFile::new_file`], with the same `initial_size`
    /// requirement for `O_APPEND` handles.
    pub fn new_file(
        server: crate::server::Server,
        destination: &Path,
        file: tokio::fs::File,
        initial_size: u64,
    ) -> Result<Self, anyhow::Error> {
        let parent_path = destination.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Destination has no parent",
            )
        })?;

        let parent = server
            .filesystem
            .path_to_components(&server.filesystem.relative_path(parent_path));

        Ok(Self {
            server,
            parent,
            file: Some(file),
            ignorant: false,
            accumulated_bytes: 0,
            allocating_bytes: 0,
            modified: None,
            allocation_in_progress: None,
            current_position: 0,
            highest_position: initial_size,
        })
    }

    /// Skip Disk Limit Checks
    #[allow(dead_code)]
    pub fn ignorant(mut self) -> Self {
        self.ignorant = true;
        self
    }

    fn start_allocation(&mut self) {
        if crate::likely(self.accumulated_bytes != 0 && self.allocation_in_progress.is_none()) {
            let server = self.server.clone();
            let parent = self.parent.clone();
            let bytes = self.accumulated_bytes;
            let ignorant = self.ignorant;

            self.allocation_in_progress = Some(Box::pin(async move {
                server
                    .filesystem
                    .async_allocate_in_path_iterator(&parent, bytes, ignorant)
                    .await
            }));

            self.allocating_bytes = bytes;
            self.accumulated_bytes = 0;
        }
    }

    fn poll_allocation(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(fut) = &mut self.allocation_in_progress {
            match fut.as_mut().poll(cx) {
                Poll::Ready(true) => {
                    self.allocation_in_progress = None;
                    self.allocating_bytes = 0;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(false) => {
                    self.allocation_in_progress = None;
                    self.accumulated_bytes += self.allocating_bytes;
                    self.allocating_bytes = 0;
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::StorageFull,
                        "Failed to allocate space",
                    )))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for AsyncServerFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.poll_allocation(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let Some(file) = self.file.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("file is not available")));
        };

        let result = Pin::new(file).poll_write(cx, buf);

        if let Poll::Ready(Ok(written)) = &result {
            let written = *written as u64;
            self.current_position += written;

            if self.current_position > self.highest_position {
                let additional_space = (self.current_position - self.highest_position) as i64;
                self.accumulated_bytes += additional_space;
                self.highest_position = self.current_position;
            }

            if self.accumulated_bytes >= ALLOCATION_THRESHOLD {
                self.start_allocation();
            }
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_allocation(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        if crate::likely(self.accumulated_bytes != 0) {
            self.start_allocation();

            match self.poll_allocation(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let Some(file) = self.file.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("file is not available")));
        };

        Pin::new(file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_allocation(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        if crate::likely(self.accumulated_bytes != 0) {
            self.start_allocation();

            match self.poll_allocation(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let Some(file) = self.file.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("file is not available")));
        };

        Pin::new(file).poll_shutdown(cx)
    }
}

impl AsyncSeek for AsyncServerFile {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        if crate::unlikely(self.accumulated_bytes != 0) {
            self.start_allocation();
        }

        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("file is not available"));
        };

        Pin::new(file).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        match self.poll_allocation(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let Some(file) = self.file.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("file is not available")));
        };

        let result = Pin::new(file).poll_complete(cx);

        if let Poll::Ready(Ok(new_pos)) = &result {
            self.current_position = *new_pos;
        }

        result
    }
}

impl AsyncRead for AsyncServerFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(file) = self.file.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("file is not available")));
        };

        Pin::new(file).poll_read(cx, buf)
    }
}

impl Drop for AsyncServerFile {
    fn drop(&mut self) {
        let leftover = self.accumulated_bytes + self.allocating_bytes;
        if leftover != 0 {
            let server = self.server.clone();
            let parent = self.parent.clone();
            let ignorant = self.ignorant;

            tokio::spawn(async move {
                server
                    .filesystem
                    .async_allocate_in_path_iterator(&parent, leftover, ignorant)
                    .await;
            });
        }

        if let Some(mut file) = self.file.take() {
            let modified = self.modified;

            tokio::spawn(async move {
                file.flush().await.ok();

                if let Some(modified) = modified {
                    let file = file.into_std().await;

                    crate::spawn_blocking_handled(move || file.set_modified(modified));
                }
            });
        }
    }
}
