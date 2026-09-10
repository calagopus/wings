use crate::server::filesystem::virtualfs::{DirectoryWalkFilterFn, IsIgnoredFn};
use parking_lot::RwLock;
use std::{
    borrow::Cow,
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{sync::Semaphore, task::JoinSet};

#[derive(Clone, Copy, Debug)]
pub enum FileType {
    File,
    Dir,
    Symlink,
    Unknown,
}

impl FileType {
    #[inline]
    pub fn from_is_dir(is_dir: bool) -> Self {
        if is_dir {
            FileType::Dir
        } else {
            FileType::File
        }
    }

    #[inline]
    pub fn is_file(self) -> bool {
        matches!(self, FileType::File)
    }

    #[inline]
    pub fn is_dir(self) -> bool {
        matches!(self, FileType::Dir)
    }

    #[inline]
    pub fn is_symlink(self) -> bool {
        matches!(self, FileType::Symlink)
    }
}

impl From<cap_std::fs::FileType> for FileType {
    fn from(ft: cap_std::fs::FileType) -> Self {
        match () {
            _ if ft.is_file() => FileType::File,
            _ if ft.is_dir() => FileType::Dir,
            _ if ft.is_symlink() => FileType::Symlink,
            _ => FileType::Unknown,
        }
    }
}

impl From<std::fs::FileType> for FileType {
    fn from(ft: std::fs::FileType) -> Self {
        match () {
            _ if ft.is_file() => FileType::File,
            _ if ft.is_dir() => FileType::Dir,
            _ if ft.is_symlink() => FileType::Symlink,
            _ => FileType::Unknown,
        }
    }
}

pub struct AsyncReadDir(
    pub Option<cap_std::fs::ReadDir>,
    pub Option<VecDeque<std::io::Result<cap_std::fs::DirEntry>>>,
);

impl AsyncReadDir {
    pub async fn next(&mut self) -> Option<std::io::Result<cap_std::fs::DirEntry>> {
        if let Some(buffer) = self.1.as_mut()
            && !buffer.is_empty()
        {
            return buffer.pop_front();
        }

        let mut read_dir = self.0.take()?;
        let mut buffer = self.1.take()?;

        match tokio::task::spawn_blocking(move || {
            for _ in 0..128 {
                if let Some(entry) = read_dir.next() {
                    buffer.push_back(entry);
                } else {
                    break;
                }
            }

            (buffer, read_dir)
        })
        .await
        {
            Ok((buffer, read_dir)) => {
                self.0 = Some(read_dir);
                self.1 = Some(buffer);

                self.1.as_mut()?.pop_front()
            }
            Err(_) => None,
        }
    }

    pub async fn next_entry(&mut self) -> Option<std::io::Result<(FileType, String)>> {
        Some(self.next().await?.map(|entry| name_and_type(&entry)))
    }
}

pub struct ReadDir(pub cap_std::fs::ReadDir);

impl ReadDir {
    pub fn next(&mut self) -> Option<std::io::Result<cap_std::fs::DirEntry>> {
        self.0.next()
    }

    pub fn next_entry(&mut self) -> Option<std::io::Result<(FileType, String)>> {
        Some(self.next()?.map(|entry| name_and_type(&entry)))
    }
}

pub fn name_and_type(entry: &cap_std::fs::DirEntry) -> (FileType, String) {
    (
        entry.file_type().map_or(FileType::Unknown, FileType::from),
        entry.file_name().to_string_lossy().to_string(),
    )
}

enum StatSource {
    Entry(cap_std::fs::DirEntry),
    Path(super::CapFilesystem),
}

pub struct WalkEntry {
    pub path: PathBuf,
    file_type: FileType,
    source: StatSource,
}

impl WalkEntry {
    #[inline]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    #[allow(dead_code)]
    pub fn name(&self) -> Cow<'_, str> {
        match self.path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => Cow::Borrowed(""),
        }
    }

    pub fn metadata(&self) -> Result<cap_std::fs::Metadata, std::io::Error> {
        match &self.source {
            StatSource::Entry(entry) => entry.metadata(),
            StatSource::Path(cap_filesystem) => cap_filesystem.symlink_metadata(&self.path),
        }
    }

    /// Opens the entry for reading relative to the directory it was listed from,
    /// which skips resolving the whole path from the sandbox root again.
    pub fn open(&self) -> Result<std::fs::File, std::io::Error> {
        match &self.source {
            StatSource::Entry(entry) => Ok(entry.open()?.into_std()),
            StatSource::Path(cap_filesystem) => cap_filesystem.open(&self.path),
        }
    }

    /// Unlinks the entry through the handle of the directory it was listed from,
    pub(super) fn remove(&self) -> Result<(), std::io::Error> {
        match &self.source {
            StatSource::Entry(entry) if self.file_type.is_dir() => entry.remove_dir(),
            StatSource::Entry(entry) => entry.remove_file(),
            StatSource::Path(cap_filesystem) if self.file_type.is_dir() => {
                cap_filesystem.get_inner()?.remove_dir(&self.path)
            }
            StatSource::Path(cap_filesystem) => cap_filesystem.remove_file(&self.path),
        }
    }

    pub async fn async_metadata(&self) -> Result<cap_std::fs::Metadata, std::io::Error> {
        match &self.source {
            StatSource::Entry(entry) => entry.metadata(),
            StatSource::Path(cap_filesystem) => {
                cap_filesystem.async_symlink_metadata(&self.path).await
            }
        }
    }
}

pub struct AsyncWalkDir {
    cap_filesystem: super::CapFilesystem,
    stack: Vec<(PathBuf, AsyncReadDir)>,
    is_ignored: IsIgnoredFn,
    reversed: bool,
}

impl AsyncWalkDir {
    pub async fn new(
        cap_filesystem: super::CapFilesystem,
        path: PathBuf,
    ) -> Result<Self, std::io::Error> {
        let read_dir = cap_filesystem.async_read_dir(&path).await?;

        Ok(Self {
            cap_filesystem,
            stack: vec![(path, read_dir)],
            is_ignored: IsIgnoredFn::default(),
            reversed: false,
        })
    }

    pub fn with_is_ignored(mut self, is_ignored: IsIgnoredFn) -> Self {
        self.is_ignored = is_ignored;
        self
    }

    /// Yields descendants before their directories. Multithreaded walks also wait
    /// for descendant callbacks to finish before invoking a directory callback.
    #[allow(dead_code)]
    pub fn reversed(mut self) -> Self {
        self.reversed = true;
        self
    }

    pub async fn next_entry(&mut self) -> Option<Result<WalkEntry, std::io::Error>> {
        'stack: while let Some((parent_path, read_dir)) = self.stack.last_mut() {
            match read_dir.next().await {
                Some(Ok(entry)) => {
                    let file_type = entry.file_type().map_or(FileType::Unknown, FileType::from);
                    let full_path = parent_path.join(entry.file_name());

                    let Some(full_path) = self.is_ignored.call_async(file_type, full_path).await
                    else {
                        continue 'stack;
                    };

                    if file_type.is_dir() {
                        match self.cap_filesystem.async_read_dir(&full_path).await {
                            Ok(dir) => self.stack.push((full_path.clone(), dir)),
                            Err(err) => return Some(Err(err)),
                        };

                        if self.reversed {
                            continue 'stack;
                        }
                    }

                    return Some(Ok(WalkEntry {
                        path: full_path,
                        file_type,
                        source: StatSource::Entry(entry),
                    }));
                }
                Some(Err(err)) => return Some(Err(err)),
                None => {
                    let (path, _) = self.stack.pop()?;

                    if self.reversed && !self.stack.is_empty() {
                        return Some(Ok(WalkEntry {
                            path,
                            file_type: FileType::Dir,
                            source: StatSource::Path(self.cap_filesystem.clone()),
                        }));
                    }
                }
            }
        }

        None
    }

    pub async fn run_multithreaded<
        F: Fn(WalkEntry) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), anyhow::Error>> + Send + 'static,
    >(
        &mut self,
        threads: usize,
        func: Arc<F>,
    ) -> Result<(), anyhow::Error> {
        let threads = crate::utils::resolve_threads(threads);
        let semaphore = Arc::new(Semaphore::new(threads));
        let pending = Arc::new(Semaphore::new(if self.reversed {
            crate::utils::WALK_IN_FLIGHT_LIMIT
        } else {
            threads
        }));
        let error = Arc::new(RwLock::new(None));
        let mut tasks = vec![JoinSet::new()];

        while let Some(entry) = self.next_entry().await {
            if crate::unlikely(error.read().is_some()) {
                break;
            }

            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    error.write().get_or_insert_with(|| err.into());
                    break;
                }
            };

            let directory = self.reversed && entry.file_type.is_dir();
            if self.reversed {
                // a reversed directory entry has already been popped by next_entry
                let depth = self.stack.len() + usize::from(directory);

                while tasks.len() < depth {
                    tasks.push(JoinSet::new());
                }
            }

            let children = if directory {
                tasks.pop().expect("completed directory has a task frame")
            } else {
                JoinSet::new()
            };

            let parent = tasks.last_mut().expect("walk root has a task frame");
            while let Some(result) = parent.try_join_next() {
                if let Err(err) = result {
                    error.write().get_or_insert_with(|| err.into());
                }
            }

            let permit = match Arc::clone(&pending).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            let semaphore = Arc::clone(&semaphore);
            let error = Arc::clone(&error);
            let func = Arc::clone(&func);

            parent.spawn(async move {
                let _pending = permit;

                finish_walk_tasks(children, &error).await;
                if crate::unlikely(error.read().is_some()) {
                    return;
                }

                let Ok(_permit) = semaphore.acquire_owned().await else {
                    return;
                };
                if crate::unlikely(error.read().is_some()) {
                    return;
                }

                if let Err(err) = func(entry).await {
                    error.write().get_or_insert(err);
                }
            });
        }

        for tasks in tasks.into_iter().rev() {
            finish_walk_tasks(tasks, &error).await;
        }

        if let Some(err) = error.write().take() {
            return Err(err);
        }

        Ok(())
    }
}

async fn finish_walk_tasks(mut tasks: JoinSet<()>, error: &RwLock<Option<anyhow::Error>>) {
    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result {
            error.write().get_or_insert_with(|| err.into());
        }
    }
}

pub struct WalkDir {
    cap_filesystem: super::CapFilesystem,
    stack: Vec<(PathBuf, ReadDir)>,
    is_ignored: IsIgnoredFn,
    reversed: bool,
}

impl WalkDir {
    pub fn new(
        cap_filesystem: super::CapFilesystem,
        path: PathBuf,
    ) -> Result<Self, std::io::Error> {
        let read_dir = cap_filesystem.read_dir(&path)?;

        Ok(Self {
            cap_filesystem,
            stack: vec![(path, read_dir)],
            is_ignored: IsIgnoredFn::default(),
            reversed: false,
        })
    }

    pub fn with_is_ignored(mut self, is_ignored: IsIgnoredFn) -> Self {
        self.is_ignored = is_ignored;
        self
    }

    /// Yields descendants before their directories. Multithreaded walks also wait
    /// for descendant callbacks to finish before invoking a directory callback.
    pub fn reversed(mut self) -> Self {
        self.reversed = true;
        self
    }

    pub fn next_entry(&mut self) -> Option<Result<WalkEntry, std::io::Error>> {
        'stack: while let Some((parent_path, read_dir)) = self.stack.last_mut() {
            match read_dir.next() {
                Some(Ok(entry)) => {
                    let file_type = entry.file_type().map_or(FileType::Unknown, FileType::from);
                    let full_path = parent_path.join(entry.file_name());

                    let Some(full_path) = (self.is_ignored)(file_type, full_path) else {
                        continue 'stack;
                    };

                    if file_type.is_dir() {
                        match self.cap_filesystem.read_dir(&full_path) {
                            Ok(dir) => self.stack.push((full_path.clone(), dir)),
                            Err(err) => return Some(Err(err)),
                        };

                        if self.reversed {
                            continue 'stack;
                        }
                    }

                    return Some(Ok(WalkEntry {
                        path: full_path,
                        file_type,
                        source: StatSource::Entry(entry),
                    }));
                }
                Some(Err(err)) => {
                    return Some(Err(err));
                }
                None => {
                    let (path, _) = self.stack.pop()?;

                    if self.reversed && !self.stack.is_empty() {
                        return Some(Ok(WalkEntry {
                            path,
                            file_type: FileType::Dir,
                            source: StatSource::Path(self.cap_filesystem.clone()),
                        }));
                    }
                }
            }
        }

        None
    }

    pub fn run_multithreaded<
        F: Fn(WalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static,
    >(
        &mut self,
        threads: usize,
        func: Arc<F>,
    ) -> Result<(), anyhow::Error> {
        self.run_multithreaded_filtered(threads, None, func)
    }

    pub fn run_multithreaded_filtered<
        F: Fn(WalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static,
    >(
        &mut self,
        threads: usize,
        filter: Option<DirectoryWalkFilterFn>,
        func: Arc<F>,
    ) -> Result<(), anyhow::Error> {
        self.run_multithreaded_with_error_handler(threads, filter, func, |err| Err(err.into()))
    }

    pub(super) fn run_multithreaded_with_error_handler<
        F: Fn(WalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static,
        E: FnMut(std::io::Error) -> Result<(), anyhow::Error>,
    >(
        &mut self,
        threads: usize,
        filter: Option<DirectoryWalkFilterFn>,
        func: Arc<F>,
        mut on_error: E,
    ) -> Result<(), anyhow::Error> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()?;
        let error = Arc::new(RwLock::new(None));
        let in_flight = crate::utils::InFlightLimit::new(
            crate::utils::WALK_IN_FLIGHT_LIMIT / crate::utils::WALK_BATCH_SIZE,
        );

        loop {
            let directory = pool.in_place_scope(|scope| {
                let mut directory = None;
                let mut batch = Vec::with_capacity(crate::utils::WALK_BATCH_SIZE);

                while let Some(entry) = self.next_entry() {
                    match entry {
                        Ok(entry) => {
                            if crate::unlikely(error.read().is_some()) {
                                break;
                            }

                            if let Some(filter) = &filter
                                && !filter(entry.file_type, &entry.path)
                            {
                                continue;
                            }

                            if self.reversed && entry.file_type.is_dir() {
                                directory = Some(entry);
                                break;
                            }

                            batch.push(entry);
                            if batch.len() < crate::utils::WALK_BATCH_SIZE {
                                continue;
                            }

                            let batch = std::mem::replace(
                                &mut batch,
                                Vec::with_capacity(crate::utils::WALK_BATCH_SIZE),
                            );
                            let permit = in_flight.acquire();

                            crate::utils::spawn_walk_batch(
                                scope,
                                Arc::clone(&error),
                                {
                                    let func = Arc::clone(&func);
                                    move |entry| func(entry)
                                },
                                permit,
                                batch,
                            );
                        }
                        Err(err) => {
                            if let Err(err) = on_error(err) {
                                error.write().get_or_insert(err);
                                break;
                            }
                        }
                    }
                }

                if !batch.is_empty() {
                    let permit = in_flight.acquire();

                    crate::utils::spawn_walk_batch(
                        scope,
                        Arc::clone(&error),
                        {
                            let func = Arc::clone(&func);
                            move |entry| func(entry)
                        },
                        permit,
                        batch,
                    );
                }

                directory
            });

            if let Some(err) = error.write().take() {
                return Err(err);
            }

            match directory {
                Some(entry) => func(entry)?,
                None => break,
            }
        }

        Ok(())
    }

    /// Reads directories as independent pool tasks instead of from one producer
    /// thread. Entries arrive in no particular order; a directory that fails to
    /// open fails the walk like the serial walker does. Only a fresh, pre-order
    /// walker can be split this way, anything else takes the serial path.
    pub fn run_parallel<F: Fn(WalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static>(
        &mut self,
        threads: usize,
        filter: Option<DirectoryWalkFilterFn>,
        func: Arc<F>,
    ) -> Result<(), anyhow::Error> {
        if self.reversed || self.stack.len() != 1 {
            return self.run_multithreaded_filtered(threads, filter, func);
        }

        let (root, root_read_dir) = self.stack.pop().expect("stack holds the root");
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()?;
        let context = ParallelWalkContext {
            cap_filesystem: self.cap_filesystem.clone(),
            is_ignored: self.is_ignored.clone(),
            filter,
            func,
            error: RwLock::new(None),
            stopped: AtomicBool::new(false),
            queued: AtomicUsize::new(0),
        };

        pool.in_place_scope(|scope| {
            parallel_walk_visit(scope, &context, root, Some(root_read_dir));
        });

        if let Some(err) = context.error.write().take() {
            return Err(err);
        }

        Ok(())
    }
}

struct ParallelWalkContext<F> {
    cap_filesystem: super::CapFilesystem,
    is_ignored: IsIgnoredFn,
    filter: Option<DirectoryWalkFilterFn>,
    func: Arc<F>,
    error: RwLock<Option<anyhow::Error>>,
    stopped: AtomicBool,
    queued: AtomicUsize,
}

impl<F: Fn(WalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static> ParallelWalkContext<F> {
    #[inline]
    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    fn fail(&self, err: anyhow::Error) {
        self.stopped.store(true, Ordering::Relaxed);

        self.error.write().get_or_insert(err);
    }

    fn process_batch(&self, batch: Vec<WalkEntry>) {
        for entry in batch {
            if crate::unlikely(self.stopped()) {
                return;
            }

            if let Err(err) = (self.func)(entry) {
                self.fail(err);
                return;
            }
        }
    }
}

fn parallel_walk_visit<'scope, F>(
    scope: &rayon::Scope<'scope>,
    context: &'scope ParallelWalkContext<F>,
    path: PathBuf,
    read_dir: Option<ReadDir>,
) where
    F: Fn(WalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static,
{
    if context.stopped() {
        return;
    }

    let mut read_dir = match read_dir {
        Some(read_dir) => read_dir,
        None => match context.cap_filesystem.read_dir(&path) {
            Ok(read_dir) => read_dir,
            Err(err) => return context.fail(err.into()),
        },
    };
    let queue_limit = crate::utils::WALK_IN_FLIGHT_LIMIT / crate::utils::WALK_BATCH_SIZE;
    let mut batch = Vec::with_capacity(crate::utils::WALK_BATCH_SIZE);

    while let Some(entry) = read_dir.next() {
        if context.stopped() {
            return;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => return context.fail(err.into()),
        };
        let file_type = entry.file_type().map_or(FileType::Unknown, FileType::from);
        let full_path = path.join(entry.file_name());

        let Some(full_path) = (context.is_ignored)(file_type, full_path) else {
            continue;
        };

        if file_type.is_dir() {
            let child = full_path.clone();
            scope.spawn(move |scope| parallel_walk_visit(scope, context, child, None));
        }

        if let Some(filter) = &context.filter
            && !filter(file_type, &full_path)
        {
            continue;
        }

        batch.push(WalkEntry {
            path: full_path,
            file_type,
            source: StatSource::Entry(entry),
        });
        if batch.len() < crate::utils::WALK_BATCH_SIZE {
            continue;
        }

        let batch = std::mem::replace(
            &mut batch,
            Vec::with_capacity(crate::utils::WALK_BATCH_SIZE),
        );
        if context.queued.load(Ordering::Relaxed) < queue_limit {
            context.queued.fetch_add(1, Ordering::Relaxed);
            scope.spawn(move |_| {
                context.process_batch(batch);
                context.queued.fetch_sub(1, Ordering::Relaxed);
            });
        } else {
            context.process_batch(batch);
        }
    }

    if !batch.is_empty() {
        context.process_batch(batch);
    }
}
