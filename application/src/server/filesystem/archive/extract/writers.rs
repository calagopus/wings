use super::super::create::ArchiveProgress;
use crate::{
    io::abort::AbortListener,
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    threading::{InFlightLimit, InFlightPermit, SharedError},
    utils::PortablePermissions,
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

const CHUNK_BYTES: usize = 1024 * 1024;
const IN_FLIGHT_CHUNKS: usize = 64;
/// Jobs queued per writer. Queued content is already bounded by the in-flight
/// chunk permits, so this only has to be deep enough that the reader can move on
/// to the next directory while a writer drains the previous one.
const WRITER_QUEUE_JOBS: usize = IN_FLIGHT_CHUNKS;

enum Content {
    Whole(Vec<u8>, InFlightPermit),
    Chunks(async_channel::Receiver<(Vec<u8>, InFlightPermit)>),
}

enum Job {
    File {
        path: PathBuf,
        content: Content,
        permissions: Option<PortablePermissions>,
        modified_time: Option<std::time::SystemTime>,
    },
    Symlink {
        path: PathBuf,
        link: PathBuf,
        modified_time: Option<std::time::SystemTime>,
    },
}

/// Picks the writer for an entry by its parent directory, so every file of a
/// directory is created by the same thread and writers do not serialize on the
/// directory's inode lock.
fn shard(path: &Path, shards: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    path.parent().unwrap_or(path).hash(&mut hasher);

    (hasher.finish() % shards.max(1) as u64) as usize
}

fn apply_job(
    destination_filesystem: &Arc<dyn VirtualWritableFilesystem>,
    progress: &ArchiveProgress,
    job: Job,
) -> Result<(), anyhow::Error> {
    match job {
        Job::File {
            path,
            content,
            permissions,
            modified_time,
        } => {
            let run = || -> Result<(), anyhow::Error> {
                let mut writer =
                    progress.counting_writer(destination_filesystem.create_file_with_metadata(
                        &path,
                        permissions,
                        modified_time,
                    )?);

                match content {
                    Content::Whole(data, _permit) => writer.write_all(&data)?,
                    Content::Chunks(chunks) => {
                        while let Ok((chunk, _permit)) = chunks.recv_blocking() {
                            writer.write_all(&chunk)?;
                        }
                    }
                }

                writer.flush()?;
                drop(writer);

                progress.increment_files();

                Ok(())
            };

            if let Err(err) = run() {
                tracing::debug!(
                    path = %path.display(),
                    "failed to extract file from archive: {:#?}",
                    err
                );

                return Err(err);
            }
        }
        Job::Symlink {
            path,
            link,
            modified_time,
        } => {
            if let Err(err) = destination_filesystem.create_symlink(&link, &path) {
                tracing::debug!(
                    path = %path.display(),
                    "failed to create symlink from archive: {:#?}",
                    err
                );
            } else if let Some(modified_time) = modified_time {
                destination_filesystem.set_times(&path, FileType::Symlink, modified_time, None)?;
            }
        }
    }

    Ok(())
}

/// Hands entries read from a sequential archive to a pool of writer threads.
pub struct Writers<'a> {
    senders: Vec<async_channel::Sender<Job>>,
    limit: Arc<InFlightLimit>,
    error: &'a SharedError<anyhow::Error>,
    destination_filesystem: &'a Arc<dyn VirtualWritableFilesystem>,
    last_parent: Option<PathBuf>,
}

impl Writers<'_> {
    #[inline]
    pub fn stopped(&self) -> bool {
        self.error.stopped()
    }

    /// Queues a file, reading its `size` bytes from `reader`. Returns `false` once
    /// the writers have shut down.
    pub fn file(
        &mut self,
        path: PathBuf,
        size: u64,
        permissions: Option<PortablePermissions>,
        modified_time: Option<std::time::SystemTime>,
        reader: &mut impl Read,
    ) -> Result<bool, anyhow::Error> {
        let Some(sender) = self.senders.get(shard(&path, self.senders.len())) else {
            return Ok(true);
        };

        if let Some(parent) = path.parent()
            && self.last_parent.as_deref() != Some(parent)
        {
            self.destination_filesystem.create_dir_all(&parent)?;
            self.last_parent = Some(parent.to_path_buf());
        }

        if size <= CHUNK_BYTES as u64 {
            let permit = self.limit.acquire();
            let mut data = Vec::with_capacity(size as usize);
            reader.read_to_end(&mut data)?;

            return Ok(sender
                .send_blocking(Job::File {
                    path,
                    content: Content::Whole(data, permit),
                    permissions,
                    modified_time,
                })
                .is_ok());
        }

        let (chunks, receiver) = async_channel::bounded(2);

        if sender
            .send_blocking(Job::File {
                path,
                content: Content::Chunks(receiver),
                permissions,
                modified_time,
            })
            .is_err()
        {
            return Ok(false);
        }

        loop {
            let permit = self.limit.acquire();
            let mut chunk = Vec::with_capacity(CHUNK_BYTES);

            if reader
                .by_ref()
                .take(CHUNK_BYTES as u64)
                .read_to_end(&mut chunk)?
                == 0
            {
                break;
            }

            if chunks.send_blocking((chunk, permit)).is_err() {
                break;
            }
        }

        Ok(true)
    }

    /// Queues a symlink. Returns `false` once the writers have shut down.
    pub fn symlink(
        &mut self,
        path: PathBuf,
        link: PathBuf,
        modified_time: Option<std::time::SystemTime>,
    ) -> bool {
        let Some(sender) = self.senders.get(shard(&path, self.senders.len())) else {
            return true;
        };

        sender
            .send_blocking(Job::Symlink {
                path,
                link,
                modified_time,
            })
            .is_ok()
    }
}

/// Runs `feed` with a pool of `threads` writers and waits for every queued entry
/// to be written.
pub fn with_writers<T>(
    threads: usize,
    destination_filesystem: &Arc<dyn VirtualWritableFilesystem>,
    progress: &ArchiveProgress,
    listener: &AbortListener,
    feed: impl FnOnce(&mut Writers) -> Result<T, anyhow::Error>,
) -> Result<T, anyhow::Error> {
    let threads = crate::threading::resolve_threads(threads);
    let error = SharedError::new();

    let result = std::thread::scope(|scope| {
        let mut senders = Vec::with_capacity(threads);

        for _ in 0..threads {
            let (sender, receiver) = async_channel::bounded::<Job>(WRITER_QUEUE_JOBS);
            senders.push(sender);

            let error = &error;

            scope.spawn(move || {
                while let Ok(job) = receiver.recv_blocking() {
                    if listener.is_aborted() || error.stopped() {
                        receiver.close();
                        continue;
                    }

                    if let Err(err) = apply_job(destination_filesystem, progress, job) {
                        error.fail(err);
                    }
                }
            });
        }

        let mut writers = Writers {
            senders,
            limit: InFlightLimit::new(IN_FLIGHT_CHUNKS),
            error: &error,
            destination_filesystem,
            last_parent: None,
        };

        feed(&mut writers)
    })?;

    if let Some(err) = error.take() {
        return Err(err);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // shard

    #[test]
    fn shard_is_stable_per_path() {
        for shards in [1usize, 2, 3, 4, 8] {
            for path in [
                "world/region/r.0.0.mca",
                "plugins/config.yml",
                "server.properties",
                "a",
                "nested/deep/deeper/file.bin",
            ] {
                let picked = shard(Path::new(path), shards);

                assert_eq!(
                    picked,
                    shard(Path::new(path), shards),
                    "{path} moved between writers"
                );
                assert!(
                    picked < shards,
                    "{path} picked a writer that does not exist"
                );
            }
        }
    }

    #[test]
    fn shard_keeps_a_directory_on_one_writer() {
        for shards in [2usize, 4, 8] {
            let writer = shard(Path::new("world/region/r.0.0.mca"), shards);

            for i in 0..64 {
                let path = format!("world/region/r.{}.{}.mca", i / 8, i % 8);

                assert_eq!(
                    shard(Path::new(&path), shards),
                    writer,
                    "{path} left its directory's writer"
                );
            }
        }
    }

    #[test]
    fn shard_spreads_directories_across_writers() {
        let mut paths = Vec::new();
        for i in 0..200 {
            paths.push(format!("world/region-{i}/r.0.0.mca"));
            paths.push(format!("plugins/plugin-{i:03}/config.yml"));
            paths.push(format!("libraries/library-{i}/library.jar"));
        }

        for shards in [2usize, 4, 8] {
            let mut counts = vec![0usize; shards];

            for path in &paths {
                if let Some(count) = counts.get_mut(shard(Path::new(path), shards)) {
                    *count += 1;
                }
            }

            // half of an even share, far looser than the measured spread
            let floor = paths.len() / shards / 2;

            assert!(
                counts.iter().all(|&count| count > floor),
                "uneven spread at {shards} shards: {counts:?}"
            );
        }
    }

    #[test]
    fn shard_survives_a_zero_thread_count() {
        assert_eq!(shard(Path::new("a.txt"), 0), 0);
    }
}
