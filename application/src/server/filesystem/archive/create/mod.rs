use crate::{
    io::{
        counting_reader::{AsyncCountingReader, CountingReader},
        counting_writer::CountingWriter,
    },
    server::filesystem::{
        cap::{CapFilesystem, FileType},
        virtualfs::IsIgnoredFn,
    },
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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

fn walk_sources(
    filesystem: &CapFilesystem,
    base: &Path,
    sources: impl IntoIterator<Item = impl AsRef<Path>>,
    is_ignored: &IsIgnoredFn,
    mut visit: impl FnMut(&Path, &Path, &cap_std::fs::Metadata) -> Result<(), anyhow::Error>,
) -> Result<(), anyhow::Error> {
    for source in sources {
        let relative = source.as_ref();
        let source = base.join(relative);

        let source_metadata = match filesystem.symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(err) => {
                tracing::debug!(path = %source.display(), "skipping source while creating archive, failed to read metadata: {err:#}");
                continue;
            }
        };

        let file_type: FileType = source_metadata.file_type().into();
        let verdict = (is_ignored)(file_type, source);
        let kept = verdict.is_kept();
        let Some(source) = verdict.reachable(file_type) else {
            continue;
        };

        if kept {
            visit(relative, &source, &source_metadata)?;
        }

        if !source_metadata.is_dir() {
            continue;
        }

        let mut walker = filesystem
            .walk_dir(&source)?
            .with_is_ignored(is_ignored.clone());

        while let Some(entry) = walker.next_entry() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    tracing::debug!(
                        "failed to read directory entry while creating archive: {err:#}"
                    );
                    break;
                }
            };

            let Ok(relative) = entry.path.strip_prefix(base) else {
                continue;
            };

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %entry.path.display(), "skipping entry while creating archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            visit(relative, &entry.path, &metadata)?;
        }
    }

    Ok(())
}

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
