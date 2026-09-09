use std::{
    io::{Read, Write},
    ops::{Bound, RangeBounds},
};
use tokio::io::AsyncWriteExt;

pub mod abort;
pub mod compression;
pub mod counting_reader;
pub mod counting_writer;
pub mod fallible_reader;
pub mod fixed_reader;
pub mod hash_reader;
pub mod limited_reader;
pub mod limited_writer;
pub mod line_buffer;
pub mod pipe;
pub mod range_reader;
pub mod tail;

const KERNEL_COPY_BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub fn copy(
    reader: &mut (impl ?Sized + Read),
    writer: &mut (impl ?Sized + Write),
) -> std::io::Result<()> {
    let mut buffer = vec![0; crate::BUFFER_SIZE];

    copy_shared(&mut buffer, reader, writer)
}

pub fn copy_shared(
    buffer: &mut [u8],
    reader: &mut (impl ?Sized + Read),
    writer: &mut (impl ?Sized + Write),
) -> std::io::Result<()> {
    loop {
        let bytes_read = reader.read_uninterrupted(buffer)?;

        if crate::unlikely(bytes_read == 0) {
            break;
        }

        writer.safe_write_all(buffer, bytes_read)?;
    }

    Ok(())
}

#[cfg(unix)]
pub fn copy_file_progress(
    reader: &mut (impl std::os::fd::AsFd + Read + ?Sized),
    writer: &mut (impl std::os::fd::AsFd + Write + ?Sized),
    mut progress: impl FnMut(usize) -> Result<(), std::io::Error>,
    listener: abort::AbortListener,
) -> Result<u64, std::io::Error> {
    let mut total_copied = 0;

    loop {
        if listener.is_aborted() {
            return Err(std::io::Error::other("Operation aborted"));
        }

        #[cfg(target_os = "linux")]
        let result = rustix::fs::copy_file_range(
            reader.as_fd(),
            None,
            writer.as_fd(),
            None,
            KERNEL_COPY_BUFFER_SIZE,
        );
        #[cfg(not(target_os = "linux"))]
        let result = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "copy_file_range is not supported on this platform",
        ));

        match result {
            Ok(0) => break,
            Ok(bytes_copied) => {
                total_copied += bytes_copied as u64;
                progress(bytes_copied)?;
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::CrossesDevices | std::io::ErrorKind::Unsupported => {
                    let mut buffer = vec![0; crate::BUFFER_SIZE];

                    loop {
                        if listener.is_aborted() {
                            return Err(std::io::Error::other("Operation aborted"));
                        }

                        let bytes_read = reader.read_uninterrupted(&mut buffer)?;
                        if crate::unlikely(bytes_read == 0) {
                            break;
                        }

                        writer.safe_write_all(&buffer, bytes_read)?;

                        total_copied += bytes_read as u64;
                        progress(bytes_read)?;
                    }

                    break;
                }
                _ => return Err(err.into()),
            },
        }
    }

    Ok(total_copied)
}

#[cfg(not(unix))]
pub fn copy_file_progress(
    reader: &mut (impl Read + ?Sized),
    writer: &mut (impl Write + ?Sized),
    mut progress: impl FnMut(usize) -> Result<(), std::io::Error>,
    listener: abort::AbortListener,
) -> Result<u64, std::io::Error> {
    let mut total_copied = 0;
    let mut buffer = vec![0; crate::BUFFER_SIZE];

    loop {
        if listener.is_aborted() {
            return Err(std::io::Error::other("Operation aborted"));
        }

        let bytes_read = reader.read_uninterrupted(&mut buffer)?;
        if crate::unlikely(bytes_read == 0) {
            break;
        }

        writer.safe_write_all(&buffer, bytes_read)?;

        total_copied += bytes_read as u64;
        progress(bytes_read)?;
    }

    Ok(total_copied)
}

pub trait WriteSeek: Write + std::io::Seek {}
impl<T: Write + std::io::Seek> WriteSeek for T {}
pub trait AsyncWriteSeek: tokio::io::AsyncWrite + tokio::io::AsyncSeek + Unpin {}
impl<T: tokio::io::AsyncWrite + tokio::io::AsyncSeek + Unpin> AsyncWriteSeek for T {}
pub trait ReadWriteSeek: Read + Write + std::io::Seek {}
impl<T: Read + Write + std::io::Seek> ReadWriteSeek for T {}
pub trait AsyncReadWriteSeek:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + tokio::io::AsyncSeek + Unpin
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + tokio::io::AsyncSeek + Unpin>
    AsyncReadWriteSeek for T
{
}

pub trait SafeWriteExt: Write {
    fn safe_write_all(&mut self, buf: &[u8], start_bytes: usize) -> std::io::Result<()> {
        if crate::unlikely(start_bytes > buf.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "start_bytes exceeds buffer length",
            ));
        }

        // SAFETY: Check ensures start_bytes is within buffer bounds
        unsafe { self.write_all(buf.get_unchecked(..start_bytes)) }
    }
}
impl<T: Write + ?Sized> SafeWriteExt for T {}
pub trait SafeAsyncWriteExt: tokio::io::AsyncWrite + Unpin {
    async fn safe_write_all(&mut self, buf: &[u8], start_bytes: usize) -> std::io::Result<()> {
        if crate::unlikely(start_bytes > buf.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "start_bytes exceeds buffer length",
            ));
        }

        // SAFETY: Check ensures start_bytes is within buffer bounds
        unsafe { self.write_all(buf.get_unchecked(..start_bytes)).await }
    }
}
impl<T: tokio::io::AsyncWrite + Unpin + ?Sized> SafeAsyncWriteExt for T {}

pub trait SafeDigestExt: sha2::Digest {
    fn safe_update(&mut self, buf: &[u8], start_bytes: usize) -> std::io::Result<()> {
        if crate::unlikely(start_bytes > buf.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "start_bytes exceeds buffer length",
            ));
        }

        // SAFETY: Check ensures start_bytes is within buffer bounds
        unsafe { self.update(buf.get_unchecked(..start_bytes)) };

        Ok(())
    }
}
impl<T: sha2::Digest + ?Sized> SafeDigestExt for T {}

fn resolve_range(range: impl RangeBounds<usize>, len: usize) -> std::io::Result<(usize, usize)> {
    let start = match range.start_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n.saturating_add(1),
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&n) => n.saturating_add(1),
        Bound::Excluded(&n) => n,
        Bound::Unbounded => len,
    };

    if crate::unlikely(start > end) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "range start exceeds range end",
        ));
    }

    if crate::unlikely(end > len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "range end exceeds slice length",
        ));
    }

    Ok((start, end))
}

pub trait SafeSliceExt<T>: AsRef<[T]> {
    fn get_slice(&self, range: impl RangeBounds<usize>) -> std::io::Result<&[T]> {
        let slice = self.as_ref();
        let (start, end) = resolve_range(range, slice.len())?;

        // SAFETY: resolve_range guarantees start <= end <= slice.len()
        Ok(unsafe { slice.get_unchecked(start..end) })
    }
}
impl<T, Tr: AsRef<[T]> + ?Sized> SafeSliceExt<T> for Tr {}

pub trait SafeSliceMutExt<T>: AsMut<[T]> {
    fn get_slice_mut(&mut self, range: impl RangeBounds<usize>) -> std::io::Result<&mut [T]> {
        let slice = self.as_mut();
        let (start, end) = resolve_range(range, slice.len())?;

        // SAFETY: resolve_range guarantees start <= end <= slice.len()
        Ok(unsafe { slice.get_unchecked_mut(start..end) })
    }
}
impl<T, Tr: AsMut<[T]> + ?Sized> SafeSliceMutExt<T> for Tr {}

pub trait UninterruptedReadExt: Read {
    fn read_uninterrupted(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.read(buf) {
                Ok(bytes_read) => return Ok(bytes_read),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
    }
}
impl<T: Read + ?Sized> UninterruptedReadExt for T {}
