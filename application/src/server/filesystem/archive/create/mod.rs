use crate::io::{
    counting_reader::{AsyncCountingReader, CountingReader},
    counting_writer::CountingWriter,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::AsyncRead;

mod itaf;
mod pxar;
mod seven_zip;
mod tar;
mod zip;

pub use itaf::*;
pub use pxar::*;
pub use seven_zip::*;
pub use tar::*;
pub use zip::*;

#[derive(Clone, Default)]
pub struct ArchiveProgress {
    bytes_processed: Option<Arc<AtomicU64>>,
    files_processed: Option<Arc<AtomicU64>>,
}

impl ArchiveProgress {
    #[inline]
    pub fn new(bytes_processed: Arc<AtomicU64>, files_processed: Arc<AtomicU64>) -> Self {
        Self {
            bytes_processed: Some(bytes_processed),
            files_processed: Some(files_processed),
        }
    }

    #[inline]
    pub fn increment_bytes(&self, bytes: u64) {
        if let Some(bytes_processed) = &self.bytes_processed {
            bytes_processed.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn store_bytes(&self, bytes: u64) {
        if let Some(bytes_processed) = &self.bytes_processed {
            bytes_processed.store(bytes, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn increment_files(&self) {
        if let Some(files_processed) = &self.files_processed {
            files_processed.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn store_files(&self, files: u64) {
        if let Some(files_processed) = &self.files_processed {
            files_processed.store(files, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn without_bytes(&self) -> Self {
        Self {
            bytes_processed: None,
            files_processed: self.files_processed.clone(),
        }
    }

    #[inline]
    pub fn clone_bytes(&self) -> Option<Arc<AtomicU64>> {
        self.bytes_processed.clone()
    }

    #[inline]
    pub fn clone_files(&self) -> Option<Arc<AtomicU64>> {
        self.files_processed.clone()
    }

    #[inline]
    pub fn counting_reader<R: std::io::Read>(&self, reader: R) -> CountingReader<R> {
        let counter = self
            .bytes_processed
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));

        CountingReader::new_with_bytes_read(reader, counter)
    }

    #[inline]
    pub fn counting_writer<W: std::io::Write>(&self, writer: W) -> CountingWriter<W> {
        let counter = self
            .bytes_processed
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));

        CountingWriter::new_with_bytes_written(writer, counter)
    }

    #[inline]
    pub fn async_counting_reader<R: AsyncRead + Unpin>(&self, reader: R) -> AsyncCountingReader<R> {
        let counter = self
            .bytes_processed
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));

        AsyncCountingReader::new_with_bytes_read(reader, counter)
    }
}
