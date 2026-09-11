use super::ArchiveProgress;
use crate::{
    io::{
        SafeSliceExt, SafeSliceMutExt,
        abort::{AbortGuard, AbortListener, AbortReader, AbortWriter},
        compression::CompressionLevel,
        fixed_reader::FixedReader,
    },
    server::filesystem::{cap::CapFilesystem, virtualfs::IsIgnoredFn},
    utils::PortablePermissions,
};
use chrono::{Datelike, Timelike};
use positioned_io::ReadAt;
use std::{
    collections::BTreeMap,
    io::{Cursor, Seek, Write},
    path::{Path, PathBuf},
};

pub struct CreateZipOptions {
    pub compression_level: CompressionLevel,
    pub threads: usize,
}

const BATCH_BYTES: u64 = 1024 * 1024;
/// Caps the entries a batch holds, since empty files never reach [`BATCH_BYTES`].
const BATCH_ENTRIES: usize = 1024;
const MAX_IN_FLIGHT_BATCHES: usize = 256;
/// A file this large gets a batch to itself.
const STANDALONE_BYTES: u64 = 256 * 1024;
/// A file this large is streamed by the merger instead of buffered.
const DIRECT_BYTES: u64 = 64 * 1024 * 1024;
/// Below this the probe costs more than the compression it saves.
const PROBE_MIN_BYTES: u64 = 96 * 1024;
const PROBE_SAMPLE_BYTES: usize = 32 * 1024;

pub async fn create_zip<W: Write + Seek + Send + 'static>(
    filesystem: CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: CreateZipOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = AbortWriter::new(destination, listener.clone());
        let pipeline = Pipeline::new(
            zip::ZipWriter::new(writer),
            filesystem,
            progress,
            listener,
            &options,
        )?;

        let archive = pipeline.write(base, sources, is_ignored)?;
        let mut inner = archive.finish()?.into_inner();
        inner.flush()?;

        Ok(inner)
    })
    .await?
}

pub async fn create_zip_streaming<W: Write + Send + 'static>(
    filesystem: CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: CreateZipOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = AbortWriter::new(destination, listener.clone());
        let pipeline = Pipeline::new(
            zip::ZipWriter::new_stream(writer),
            filesystem,
            progress,
            listener,
            &options,
        )?;

        let archive = pipeline.write(base, sources, is_ignored)?;
        let mut inner = archive.finish()?.into_inner().into_inner();
        inner.flush()?;

        Ok(inner)
    })
    .await?
}

/// Ceiling on input bytes submitted to workers but not yet merged.
fn window_bytes(threads: usize) -> u64 {
    const PER_THREAD: u64 = 32 * 1024 * 1024;
    const MAX: u64 = 256 * 1024 * 1024;

    (threads as u64 * PER_THREAD).clamp(DIRECT_BYTES, MAX)
}

enum EntryKind {
    Directory,
    File,
    Symlink { target: String },
}

struct Entry {
    name: String,
    path: PathBuf,
    kind: EntryKind,
    len: u64,
    mode: u32,
    mtime: Option<zip::DateTime>,
}

impl Entry {
    fn from_metadata(
        filesystem: &CapFilesystem,
        relative: &Path,
        path: PathBuf,
        metadata: &cap_std::fs::Metadata,
    ) -> Option<Self> {
        let kind = if metadata.is_dir() {
            EntryKind::Directory
        } else if metadata.is_file() {
            EntryKind::File
        } else {
            EntryKind::Symlink {
                target: filesystem
                    .read_link_contents(&path)
                    .ok()?
                    .to_string_lossy()
                    .into_owned(),
            }
        };

        let mtime = metadata.modified().ok().and_then(|mtime| {
            let mtime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from(mtime.into_std());

            zip::DateTime::from_date_and_time(
                mtime.year() as u16,
                mtime.month() as u8,
                mtime.day() as u8,
                mtime.hour() as u8,
                mtime.minute() as u8,
                mtime.second() as u8,
            )
            .ok()
        });

        Some(Self {
            name: relative.to_string_lossy().into_owned(),
            path,
            kind,
            len: metadata.len(),
            mode: PortablePermissions::from(metadata.permissions()).mode() as u32,
            mtime,
        })
    }

    fn options(
        &self,
        method: zip::CompressionMethod,
        level: Option<i64>,
    ) -> zip::write::FileOptions<'static, ()> {
        let mut options: zip::write::FileOptions<'static, ()> = zip::write::FileOptions::default()
            .compression_method(method)
            .compression_level(level)
            .unix_permissions(self.mode)
            .large_file(true);

        if let Some(mtime) = self.mtime {
            options = options.last_modified_time(mtime);
        }

        options
    }

    fn deflated(&self, level: i64) -> zip::write::FileOptions<'static, ()> {
        self.options(zip::CompressionMethod::Deflated, Some(level))
    }

    fn stored(&self) -> zip::write::FileOptions<'static, ()> {
        self.options(zip::CompressionMethod::Stored, None)
    }
}

/// Fills `buffer` from `offset` without moving the file cursor.
fn read_sample(file: &std::fs::File, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut read = 0;

    while read < buffer.len() {
        match file.read_at(offset + read as u64, buffer.get_slice_mut(read..)?) {
            Ok(0) => break,
            Ok(bytes_read) => read += bytes_read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(read)
}

/// Decides whether an entry's contents are worth handing to deflate.
fn is_incompressible(
    file: &std::fs::File,
    len: u64,
    read_buffer: &mut [u8],
) -> std::io::Result<bool> {
    if len < PROBE_MIN_BYTES {
        return Ok(false);
    }

    let sample = PROBE_SAMPLE_BYTES as u64;
    let offsets = [0, len / 2 - sample / 2, len - sample];
    let read_buffer = read_buffer.get_slice_mut(..PROBE_SAMPLE_BYTES.min(read_buffer.len()))?;

    for offset in offsets {
        let read = read_sample(file, offset, read_buffer)?;

        if !crate::io::compression::looks_incompressible(read_buffer.get_slice(..read)?) {
            return Ok(false);
        }
    }

    Ok(true)
}

type BatchArchive = zip::ZipArchive<Cursor<Vec<u8>>>;

#[derive(Clone)]
struct EntryWriter {
    filesystem: CapFilesystem,
    progress: ArchiveProgress,
    listener: AbortListener,
    level: i64,
}

impl EntryWriter {
    fn write_file<Z: Write + Seek>(
        &self,
        archive: &mut zip::ZipWriter<Z>,
        entry: &Entry,
        read_buffer: &mut [u8],
    ) -> Result<(), anyhow::Error> {
        let file = self.filesystem.open(&entry.path)?;

        let options = if is_incompressible(&file, entry.len, read_buffer).unwrap_or(false) {
            entry.stored()
        } else {
            entry.deflated(self.level)
        };

        let reader = AbortReader::new(file, self.listener.clone());
        let reader = self.progress.counting_reader(reader);
        let mut reader = FixedReader::new_with_fixed_bytes(reader, entry.len as usize);

        archive.start_file(&entry.name, options)?;
        crate::io::copy_shared(read_buffer, &mut reader, archive)?;
        self.progress.increment_files();

        Ok(())
    }

    fn write_entry<Z: Write + Seek>(
        &self,
        archive: &mut zip::ZipWriter<Z>,
        entry: &Entry,
        read_buffer: &mut [u8],
    ) -> Result<(), anyhow::Error> {
        match &entry.kind {
            EntryKind::Directory => {
                archive.add_directory(&entry.name, entry.deflated(self.level))?;
                self.progress.increment_bytes(entry.len);
            }
            EntryKind::File => {
                self.write_file(archive, entry, read_buffer)?;
            }
            EntryKind::Symlink { target } => {
                archive.add_symlink(&entry.name, target, entry.deflated(self.level))?;
                self.progress.increment_bytes(entry.len);
                self.progress.increment_files();
            }
        }

        Ok(())
    }

    fn compress_batch(&self, batch: Vec<Entry>, bytes: u64) -> Result<BatchArchive, anyhow::Error> {
        let capacity = bytes as usize + batch.len() * 128;
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::with_capacity(capacity)));
        let mut read_buffer = vec![0; crate::BUFFER_SIZE];

        for entry in batch {
            if self.listener.is_aborted() {
                return Err(anyhow::anyhow!("operation aborted"));
            }

            self.write_entry(&mut archive, &entry, &mut read_buffer)?;
        }

        Ok(archive.finish_into_readable()?)
    }
}

struct CompressedBatch {
    index: usize,
    bytes: u64,
    result: Result<BatchArchive, anyhow::Error>,
}

struct Pipeline<Z: Write + Seek> {
    archive: zip::ZipWriter<Z>,
    writer: EntryWriter,

    pool: rayon::ThreadPool,
    sender: std::sync::mpsc::Sender<CompressedBatch>,
    receiver: std::sync::mpsc::Receiver<CompressedBatch>,

    batch: Vec<Entry>,
    batch_bytes: u64,
    pending: BTreeMap<usize, (u64, BatchArchive)>,
    submitted: usize,
    merged: usize,

    in_flight: u64,
    window: u64,

    read_buffer: Vec<u8>,
}

impl<Z: Write + Seek> Pipeline<Z> {
    fn new(
        archive: zip::ZipWriter<Z>,
        filesystem: CapFilesystem,
        progress: ArchiveProgress,
        listener: AbortListener,
        options: &CreateZipOptions,
    ) -> Result<Self, anyhow::Error> {
        let threads = crate::threading::resolve_threads(options.threads);
        let (sender, receiver) = std::sync::mpsc::channel();

        Ok(Self {
            archive,
            writer: EntryWriter {
                filesystem,
                progress,
                listener,
                level: options.compression_level.to_deflate_level() as i64,
            },
            pool: crate::threading::build_pool(threads)?,
            sender,
            receiver,
            batch: Vec::new(),
            batch_bytes: 0,
            pending: BTreeMap::new(),
            submitted: 0,
            merged: 0,
            in_flight: 0,
            window: window_bytes(threads),
            read_buffer: vec![0; crate::BUFFER_SIZE],
        })
    }

    fn push(&mut self, entry: Entry) -> Result<(), anyhow::Error> {
        if matches!(entry.kind, EntryKind::File) && entry.len >= DIRECT_BYTES {
            self.submit()?;
            self.drain(self.submitted)?;

            return self
                .writer
                .write_entry(&mut self.archive, &entry, &mut self.read_buffer);
        }

        let standalone = matches!(entry.kind, EntryKind::File) && entry.len >= STANDALONE_BYTES;

        if standalone {
            self.submit()?;
        }

        self.batch_bytes += entry.len;
        self.batch.push(entry);

        if standalone || self.batch_bytes >= BATCH_BYTES || self.batch.len() >= BATCH_ENTRIES {
            self.submit()?;
        }

        Ok(())
    }

    fn submit(&mut self) -> Result<(), anyhow::Error> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let bytes = self.batch_bytes;

        while self.merged < self.submitted
            && (self.in_flight + bytes > self.window
                || self.submitted - self.merged >= MAX_IN_FLIGHT_BATCHES)
        {
            self.receive()?;
        }

        let batch = std::mem::take(&mut self.batch);
        self.batch_bytes = 0;
        let index = self.submitted;
        self.submitted += 1;
        self.in_flight += bytes;

        let writer = self.writer.clone();
        let sender = self.sender.clone();

        self.pool.spawn(move || {
            let result = writer.compress_batch(batch, bytes);

            // a pipeline that gave up on an earlier error is already gone
            sender
                .send(CompressedBatch {
                    index,
                    bytes,
                    result,
                })
                .ok();
        });

        Ok(())
    }

    fn receive(&mut self) -> Result<(), anyhow::Error> {
        let batch = self
            .receiver
            .recv()
            .map_err(|_| anyhow::anyhow!("zip worker disconnected"))?;

        self.pending
            .insert(batch.index, (batch.bytes, batch.result?));

        while let Some((bytes, batch_archive)) = self.pending.remove(&self.merged) {
            self.in_flight = self.in_flight.saturating_sub(bytes);
            self.merged += 1;
            self.archive.merge_archive(batch_archive)?;
        }

        Ok(())
    }

    fn drain(&mut self, until: usize) -> Result<(), anyhow::Error> {
        while self.merged < until {
            self.receive()?;
        }

        Ok(())
    }

    fn write(
        mut self,
        base: PathBuf,
        sources: Vec<impl AsRef<Path>>,
        is_ignored: IsIgnoredFn,
    ) -> Result<zip::ZipWriter<Z>, anyhow::Error> {
        for source in sources {
            let relative = source.as_ref();
            let source = base.join(relative);

            let source_metadata = match self.writer.filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    tracing::debug!(path = %source.display(), "skipping source while creating zip archive, failed to read metadata: {err:#}");
                    continue;
                }
            };

            let Some(source) = (is_ignored)(source_metadata.file_type().into(), source) else {
                continue;
            };

            if source_metadata.is_dir() {
                if let Some(entry) = Entry::from_metadata(
                    &self.writer.filesystem,
                    relative,
                    source.clone(),
                    &source_metadata,
                ) {
                    self.push(entry)?;
                }

                let mut walker = self
                    .writer
                    .filesystem
                    .walk_dir(source)?
                    .with_is_ignored(is_ignored.clone());

                while let Some(entry) = walker.next_entry() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            tracing::debug!(
                                "failed to read directory entry while creating zip archive: {err:#}"
                            );
                            break;
                        }
                    };

                    let path = &entry.path;

                    let relative = match path.strip_prefix(&base) {
                        Ok(path) => path,
                        Err(_) => continue,
                    };

                    let metadata = match entry.metadata() {
                        Ok(metadata) => metadata,
                        Err(err) => {
                            tracing::debug!(path = %path.display(), "skipping entry while creating zip archive, failed to read metadata: {err:#}");
                            continue;
                        }
                    };

                    if let Some(entry) = Entry::from_metadata(
                        &self.writer.filesystem,
                        relative,
                        path.clone(),
                        &metadata,
                    ) {
                        self.push(entry)?;
                    }
                }
            } else if let Some(entry) =
                Entry::from_metadata(&self.writer.filesystem, relative, source, &source_metadata)
            {
                self.push(entry)?;
            }
        }

        self.finish()
    }

    fn finish(mut self) -> Result<zip::ZipWriter<Z>, anyhow::Error> {
        self.submit()?;
        self.drain(self.submitted)?;

        Ok(self.archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn random(len: usize) -> Vec<u8> {
        let mut state = 0x7ee0u64;

        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn text(len: usize) -> Vec<u8> {
        std::iter::repeat(b"level_spawn=true player_ticks=4096\n".iter().copied())
            .flatten()
            .take(len)
            .collect()
    }

    fn build_tree(root: &Path) -> std::io::Result<HashMap<String, Vec<u8>>> {
        let mut expected = HashMap::new();

        std::fs::create_dir_all(root.join("tree/plugins"))?;
        std::fs::create_dir_all(root.join("tree/world/region"))?;
        std::fs::create_dir_all(root.join("tree/libraries"))?;

        for i in 0..40 {
            let name = format!("tree/plugins/config-{i:03}.yml");
            let data = text(4096);
            std::fs::write(root.join(&name), &data)?;
            expected.insert(name, data);
        }

        for i in 0..6 {
            let name = format!("tree/world/region/r.0.{i}.mca");
            let data = random(1024 * 1024);
            std::fs::write(root.join(&name), &data)?;
            expected.insert(name, data);
        }

        let name = "tree/libraries/library-0.jar".to_string();
        let data = random(3 * 1024 * 1024);
        std::fs::write(root.join(&name), &data)?;
        expected.insert(name, data);

        Ok(expected)
    }

    fn options(threads: usize) -> CreateZipOptions {
        CreateZipOptions {
            compression_level: CompressionLevel::BestSpeed,
            threads,
        }
    }

    fn zip_tree(root: &Path, threads: usize) -> Result<Vec<u8>, anyhow::Error> {
        tokio_test::block_on(async {
            let filesystem = CapFilesystem::new(root).await?;

            let archive = create_zip(
                filesystem,
                Cursor::new(Vec::new()),
                Path::new(""),
                vec!["tree"],
                ArchiveProgress::default(),
                IsIgnoredFn::default(),
                options(threads),
            )
            .await?;

            Ok(archive.into_inner())
        })
    }

    fn entries(bytes: Vec<u8>) -> Result<HashMap<String, Vec<u8>>, anyhow::Error> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        let mut seen = HashMap::new();

        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            if entry.is_dir() {
                continue;
            }

            let name = entry.name().to_string();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut data)?;

            if seen.insert(name.clone(), data).is_some() {
                anyhow::bail!("{name} appeared twice");
            }
        }

        Ok(seen)
    }

    // create_zip

    #[test]
    fn archive_contents_match_the_tree_at_every_thread_count() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        let expected = build_tree(temp.path())?;

        for threads in [1, 2, 4] {
            let seen = entries(zip_tree(temp.path(), threads)?)?;

            assert_eq!(
                seen.len(),
                expected.len(),
                "entry count mismatch with {threads} threads"
            );

            for (name, data) in &expected {
                assert_eq!(
                    seen.get(name),
                    Some(data),
                    "contents differ for {name} with {threads} threads"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn incompressible_entries_are_stored_and_text_is_deflated() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        build_tree(temp.path())?;

        let bytes = zip_tree(temp.path(), 2)?;
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;

        for index in 0..archive.len() {
            let entry = archive.by_index(index)?;
            if entry.is_dir() {
                continue;
            }

            let name = entry.name().to_string();
            let method = entry.compression();

            if name.ends_with(".mca") || name.ends_with(".jar") {
                assert_eq!(
                    method,
                    zip::CompressionMethod::Stored,
                    "{name} should have been stored"
                );
            } else {
                assert_eq!(
                    method,
                    zip::CompressionMethod::Deflated,
                    "{name} should have been deflated"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn archive_is_smaller_than_its_input() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        let expected = build_tree(temp.path())?;
        let total: usize = expected.values().map(Vec::len).sum();

        let bytes = zip_tree(temp.path(), 2)?;

        // deflating this tree produces an archive larger than its input
        assert!(
            bytes.len() < total,
            "archive {} is not smaller than its {total} bytes of input",
            bytes.len()
        );

        Ok(())
    }

    #[test]
    fn large_entries_bypass_the_worker_pool() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        std::fs::create_dir_all(temp.path().join("tree"))?;

        // over DIRECT_BYTES, so it is streamed rather than buffered
        let big = random(DIRECT_BYTES as usize + 4096);
        std::fs::write(temp.path().join("tree/before.yml"), text(8192))?;
        std::fs::write(temp.path().join("tree/world.mca"), &big)?;
        std::fs::write(temp.path().join("tree/after.yml"), text(8192))?;

        let seen = entries(zip_tree(temp.path(), 2)?)?;

        assert_eq!(
            seen.get("tree/world.mca"),
            Some(&big),
            "large entry did not round-trip"
        );

        for name in ["tree/before.yml", "tree/after.yml"] {
            assert_eq!(
                seen.get(name),
                Some(&text(8192)),
                "{name} did not round-trip"
            );
        }

        Ok(())
    }

    #[test]
    fn entries_survive_batch_boundaries() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        std::fs::create_dir_all(temp.path().join("tree"))?;

        // empty files add nothing to the byte window, only the entry count
        let count = BATCH_ENTRIES * 3;
        for i in 0..count {
            std::fs::write(temp.path().join(format!("tree/empty-{i:05}")), b"")?;
        }

        let seen = entries(zip_tree(temp.path(), 2)?)?;

        assert_eq!(
            seen.len(),
            count,
            "entries went missing across batch boundaries"
        );

        Ok(())
    }

    /// The merge rewrites local header offsets by hand, so a third-party reader
    /// is the check that matters, ours could share a bug. Skips itself where
    /// `unzip` is unavailable.
    #[test]
    fn external_unzip_accepts_the_archive() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        build_tree(temp.path())?;

        let bytes = zip_tree(temp.path(), 4)?;
        let path = temp.path().join("out.zip");
        std::fs::write(&path, &bytes)?;

        let output = match std::process::Command::new("unzip")
            .arg("-t")
            .arg(&path)
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                eprintln!("skipping external unzip check: {err}");
                return Ok(());
            }
        };

        assert!(
            output.status.success(),
            "unzip -t rejected the archive: {}",
            String::from_utf8_lossy(&output.stdout)
        );

        Ok(())
    }

    // create_zip_streaming

    #[test]
    fn streaming_archive_round_trips_without_a_seekable_destination() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        let expected = build_tree(temp.path())?;

        let bytes = tokio_test::block_on(async {
            let filesystem = CapFilesystem::new(temp.path()).await?;

            // a bare Vec is Write but not Seek, which is the whole point here
            create_zip_streaming(
                filesystem,
                Vec::new(),
                Path::new(""),
                vec!["tree"],
                ArchiveProgress::default(),
                IsIgnoredFn::default(),
                options(2),
            )
            .await
        })?;

        let seen = entries(bytes)?;

        assert_eq!(seen.len(), expected.len(), "entry count mismatch");

        for (name, data) in &expected {
            assert_eq!(seen.get(name), Some(data), "contents differ for {name}");
        }

        Ok(())
    }

    // window_bytes

    #[test]
    fn window_is_capped_regardless_of_thread_count() {
        // one batch must always fit, or reserving before the spawn could wait
        // on a worker that is never coming
        assert!(window_bytes(1) >= DIRECT_BYTES);

        assert_eq!(window_bytes(1), 64 * 1024 * 1024);
        assert_eq!(window_bytes(4), 128 * 1024 * 1024);
        assert_eq!(window_bytes(96), 256 * 1024 * 1024);
    }

    // is_incompressible

    #[test]
    fn probe_reads_do_not_disturb_the_entry_stream() -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("probe.bin");

        let mut read_buffer = vec![0; crate::BUFFER_SIZE];

        std::fs::write(&path, random(1024 * 1024))?;
        let mut file = std::fs::File::open(&path)?;
        assert!(is_incompressible(&file, 1024 * 1024, &mut read_buffer)?);
        assert_eq!(file.stream_position()?, 0, "probe left the cursor moved");

        std::fs::write(&path, text(1024 * 1024))?;
        let mut file = std::fs::File::open(&path)?;
        assert!(!is_incompressible(&file, 1024 * 1024, &mut read_buffer)?);
        assert_eq!(file.stream_position()?, 0, "probe left the cursor moved");

        let mut file = std::fs::File::open(&path)?;
        assert!(!is_incompressible(
            &file,
            PROBE_MIN_BYTES - 1,
            &mut read_buffer
        )?);
        assert_eq!(file.stream_position()?, 0, "probe left the cursor moved");

        std::fs::write(&path, random(1024 * 1024))?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(16 * 1024)?;
        let mut file = std::fs::File::open(&path)?;
        // leftovers a short sample must not be fooled into reading as its own
        read_buffer = random(crate::BUFFER_SIZE);
        assert!(!is_incompressible(&file, 1024 * 1024, &mut read_buffer)?);
        assert_eq!(file.stream_position()?, 0, "probe left the cursor moved");

        Ok(())
    }

    // EntryWriter::write_file

    #[test]
    fn a_shrunk_entry_keeps_the_bytes_that_survived() -> Result<(), anyhow::Error> {
        const SURVIVING: usize = 16 * 1024;

        let temp = tempfile::tempdir()?;
        let path = temp.path().join("shrunk.bin");

        let data = random(1024 * 1024);
        std::fs::write(&path, &data)?;
        let len = std::fs::metadata(&path)?.len();

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(SURVIVING as u64)?;

        let bytes = tokio_test::block_on(async {
            let filesystem = CapFilesystem::new(temp.path()).await?;
            let (_guard, listener) = AbortGuard::new();

            let entry = Entry {
                name: "shrunk.bin".to_string(),
                path: PathBuf::from("shrunk.bin"),
                kind: EntryKind::File,
                len,
                mode: 0o644,
                mtime: None,
            };

            let writer = EntryWriter {
                filesystem,
                progress: ArchiveProgress::default(),
                listener,
                level: 6,
            };

            let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let mut read_buffer = vec![0; crate::BUFFER_SIZE];

            writer.write_file(&mut archive, &entry, &mut read_buffer)?;

            Ok::<_, anyhow::Error>(archive.finish()?.into_inner())
        })?;

        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        let mut written = Vec::new();
        std::io::Read::read_to_end(&mut archive.by_index(0)?, &mut written)?;

        assert_eq!(
            written.len(),
            len as usize,
            "entry lost its declared length"
        );
        assert_eq!(
            written.get_slice(..SURVIVING)?,
            data.get_slice(..SURVIVING)?,
            "bytes still on disk were replaced with padding"
        );

        Ok(())
    }
}
