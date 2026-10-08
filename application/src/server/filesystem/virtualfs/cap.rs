use super::{
    AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, AsyncReadableFileStream,
    AsyncWritableSeekableFileStream, ByteRange, CheckedDirectoryListing, DirectoryListing,
    DirectoryWalkFilterFn, DirectoryWalkFn, FileMetadata, FileRead, FileType, IgnoreVerdict,
    IsIgnoredFn, VirtualWalkEntry, WritableSeekableFileStream, read_dir_checked,
};
use crate::{
    io::{abort::AbortListener, compression::CompressionLevel},
    models::DirectoryEntry,
    server::filesystem::{
        DirectoryEntryOptions, PreparedDirectoryEntry,
        archive::StreamableArchiveFormat,
        cap::ListingDir,
        listing::{ListingWork, check_aborted},
        virtualfs::{
            AsyncReadableWritableSeekableFileStream, DirectoryWalk,
            ReadableWritableSeekableFileStream,
        },
    },
    utils::{CmpExt, PortablePermissions, PortablePermissionsApplier},
};
use std::{
    cmp::Ordering,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;

fn group_window(start: usize, end: usize, len: usize) -> Option<Range<usize>> {
    let start = start.min(len);
    let end = end.min(len);

    if start >= end { None } else { Some(start..end) }
}

fn sort_window<T>(items: &mut [T], window: Range<usize>, cmp: impl Fn(&T, &T) -> Ordering) {
    if window.start >= window.end || window.end > items.len() {
        return;
    }

    if window.start == 0 && window.end == items.len() {
        items.sort_unstable_by(&cmp);
        return;
    }

    items.select_nth_unstable_by(window.end - 1, &cmp);
    if window.start > 0
        && window.start + 1 < window.end
        && let Some(prefix) = items.get_mut(..window.end - 1)
    {
        prefix.select_nth_unstable_by(window.start, &cmp);
    }

    if let Some(window) = items.get_mut(window) {
        window.sort_unstable_by(&cmp);
    }
}

struct StattedDirectoryEntry {
    path: PathBuf,
    parent: Option<Arc<ListingDir>>,
    metadata: cap_std::fs::Metadata,
}

/// A plain file whose modification time is stamped once the last write is done,
/// mirroring what `ServerFile` does for the primary server filesystem.
struct ModifiedOnClose {
    file: std::fs::File,
    modified: Option<std::time::SystemTime>,
}

impl std::io::Write for ModifiedOnClose {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.file, buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.file)
    }
}

impl Drop for ModifiedOnClose {
    fn drop(&mut self) {
        if let Some(modified) = self.modified {
            self.file.set_modified(modified).ok();
        }
    }
}

enum ListingResult<T, D = ()> {
    Complete(DirectoryListing),
    Pending {
        total_entries: usize,
        entries: Vec<T>,
        dir: D,
    },
}

#[derive(Clone)]
pub struct VirtualCapFilesystem {
    pub inner: crate::server::filesystem::cap::CapFilesystem,
    pub server: crate::server::Server,
    pub is_primary_server_fs: bool,
    pub is_writable: bool,
    pub is_ignored: Option<IsIgnoredFn>,
}

impl VirtualCapFilesystem {
    pub fn with_is_ignored(mut self, is_ignored: IsIgnoredFn) -> Self {
        if let Some(existing_is_ignored) = self.is_ignored {
            self.is_ignored = Some(existing_is_ignored.merge(is_ignored));
        } else {
            self.is_ignored = Some(is_ignored);
        }

        self
    }

    fn denied() -> anyhow::Error {
        anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        ))
    }

    pub fn check_ignored(
        &self,
        file_type: FileType,
        path: impl Into<PathBuf>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.into();
        let Some(is_ignored) = &self.is_ignored else {
            return Ok(path);
        };
        let Some(path) = (is_ignored)(file_type, path).keep() else {
            return Err(Self::denied());
        };

        Ok(path)
    }

    pub async fn async_check_ignored(
        &self,
        file_type: FileType,
        path: impl Into<PathBuf>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.into();
        let Some(is_ignored) = &self.is_ignored else {
            return Ok(path);
        };
        let Some(path) = is_ignored.call_async(file_type, path).await.keep() else {
            return Err(Self::denied());
        };

        Ok(path)
    }

    /// Like [`Self::check_ignored`], but a directory the filter only descends
    /// into stays reachable so the re-included entries beneath it can be listed
    /// and opened. Read paths use this; write paths keep the strict check.
    pub fn check_reachable(
        &self,
        file_type: FileType,
        path: impl Into<PathBuf>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.into();
        let Some(is_ignored) = &self.is_ignored else {
            return Ok(path);
        };
        let Some(path) = (is_ignored)(file_type, path).reachable(file_type) else {
            return Err(Self::denied());
        };

        Ok(path)
    }

    pub async fn async_check_reachable(
        &self,
        file_type: FileType,
        path: impl Into<PathBuf>,
    ) -> Result<PathBuf, anyhow::Error> {
        let path = path.into();
        let Some(is_ignored) = &self.is_ignored else {
            return Ok(path);
        };
        let Some(path) = is_ignored
            .call_async(file_type, path)
            .await
            .reachable(file_type)
        else {
            return Err(Self::denied());
        };

        Ok(path)
    }

    /// The deny filter symlink targets are checked against; only the primary
    /// server filesystem resolves them.
    fn link_filter(&self) -> Option<&IsIgnoredFn> {
        self.is_ignored
            .as_ref()
            .filter(|_| self.is_primary_server_fs)
    }

    /// `resolved` when it differs from `path` itself, so only paths that went
    /// through a symlink are checked again.
    fn diverged(&self, path: &Path, resolved: PathBuf) -> Option<PathBuf> {
        (resolved != self.inner.relative_path(path)).then_some(resolved)
    }

    fn check_resolved(&self, file_type: FileType, path: &Path) -> Result<PathBuf, anyhow::Error> {
        if self.link_filter().is_none() {
            return Ok(self.inner.relative_path(path));
        }

        let resolved = self.inner.canonicalize(path)?;
        match self.diverged(path, resolved) {
            Some(resolved) => self.check_reachable(file_type, resolved),
            None => Ok(self.inner.relative_path(path)),
        }
    }

    async fn async_check_resolved(
        &self,
        file_type: FileType,
        path: &Path,
    ) -> Result<PathBuf, anyhow::Error> {
        if self.link_filter().is_none() {
            return Ok(self.inner.relative_path(path));
        }

        let resolved = self.inner.async_canonicalize(path).await?;
        match self.diverged(path, resolved) {
            Some(resolved) => self.async_check_reachable(file_type, resolved).await,
            None => Ok(self.inner.relative_path(path)),
        }
    }

    fn check_opened(&self, path: &Path, file: &std::fs::File) -> Result<(), anyhow::Error> {
        if self.link_filter().is_none() {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        let resolved = self.inner.opened_relative_path(file)?;
        #[cfg(not(target_os = "linux"))]
        let resolved = {
            let _ = file;
            self.inner.canonicalize(path)?
        };
        if let Some(resolved) = self.diverged(path, resolved) {
            self.check_ignored(FileType::File, resolved)?;
        }

        Ok(())
    }

    /// The resolved path a write to `path` lands on, when that differs from `path`
    /// itself: its parent directories, and with `follow` the final component too. A
    /// dangling final symlink is refused when followed, since creating through it
    /// would land on a target never checked.
    fn written_target(&self, path: &Path, follow: bool) -> Result<Option<PathBuf>, anyhow::Error> {
        if self.link_filter().is_none() {
            return Ok(None);
        }

        let resolved = if !follow {
            self.inner.try_canonicalize_parent(path)?
        } else {
            match self.inner.canonicalize(path) {
                Ok(resolved) => resolved,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    if self
                        .inner
                        .symlink_metadata(path)
                        .is_ok_and(|metadata| metadata.is_symlink())
                    {
                        return Err(Self::denied());
                    }

                    self.inner.try_canonicalize_parent(path)?
                }
                Err(err) => return Err(err.into()),
            }
        };

        Ok(self.diverged(path, resolved))
    }

    async fn async_written_target(
        &self,
        path: &Path,
        follow: bool,
    ) -> Result<Option<PathBuf>, anyhow::Error> {
        if self.link_filter().is_none() {
            return Ok(None);
        }

        let resolved = if !follow {
            self.inner.async_try_canonicalize_parent(path).await?
        } else {
            match self.inner.async_canonicalize(path).await {
                Ok(resolved) => resolved,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    if self
                        .inner
                        .async_symlink_metadata(path)
                        .await
                        .is_ok_and(|metadata| metadata.is_symlink())
                    {
                        return Err(Self::denied());
                    }

                    self.inner.async_try_canonicalize_parent(path).await?
                }
                Err(err) => return Err(err.into()),
            }
        };

        Ok(self.diverged(path, resolved))
    }

    fn check_write(
        &self,
        file_type: FileType,
        path: &Path,
        follow: bool,
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_writable()?;
        let path = self.check_ignored(file_type, path)?;
        if let Some(resolved) = self.written_target(&path, follow)? {
            self.check_ignored(file_type, resolved)?;
        }

        Ok(path)
    }

    async fn async_check_write(
        &self,
        file_type: FileType,
        path: &Path,
        follow: bool,
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_writable()?;
        let path = self.async_check_ignored(file_type, path).await?;
        if let Some(resolved) = self.async_written_target(&path, follow).await? {
            self.async_check_ignored(file_type, resolved).await?;
        }

        Ok(path)
    }

    /// Like [`Self::check_write`] for a directory, but a directory the filter only
    /// descends into may still be created, so the re-included entries beneath it
    /// have somewhere to go.
    fn check_create_dir(&self, path: &Path) -> Result<PathBuf, anyhow::Error> {
        self.check_writable()?;
        let path = self.check_reachable(FileType::Dir, path)?;
        if let Some(resolved) = self.written_target(&path, true)? {
            self.check_reachable(FileType::Dir, resolved)?;
        }

        Ok(path)
    }

    async fn async_check_create_dir(&self, path: &Path) -> Result<PathBuf, anyhow::Error> {
        self.check_writable()?;
        let path = self.async_check_reachable(FileType::Dir, path).await?;
        if let Some(resolved) = self.async_written_target(&path, true).await? {
            self.async_check_reachable(FileType::Dir, resolved).await?;
        }

        Ok(path)
    }

    fn remap_walk_filter(deny: IsIgnoredFn, root: PathBuf, resolved_root: PathBuf) -> IsIgnoredFn {
        let resolve = move |path: &Path| {
            path.strip_prefix(&root)
                .ok()
                .map(|rest| resolved_root.join(rest))
        };
        let (sync_deny, async_deny) = (deny.clone(), deny);
        let (sync_resolve, async_resolve) = (resolve.clone(), resolve);

        IsIgnoredFn::new(
            move |file_type, path: PathBuf| match sync_resolve(&path) {
                Some(resolved) => sync_deny(file_type, resolved).with_path(path),
                None => IgnoreVerdict::Skip,
            },
            move |file_type, path: PathBuf| {
                let (deny, resolved) = (async_deny.clone(), async_resolve(&path));

                async move {
                    match resolved {
                        Some(resolved) => {
                            deny.call_async(file_type, resolved).await.with_path(path)
                        }
                        None => IgnoreVerdict::Skip,
                    }
                }
            },
        )
    }

    /// The filter a walk rooted at `path` runs with: the caller's, this filesystem's
    /// own, and for a symlinked root the latter applied to each entry's canonical
    /// path too, so the root's target cannot reach what its real name denies.
    fn walk_filter(
        &self,
        path: &Path,
        is_ignored: IsIgnoredFn,
    ) -> Result<IsIgnoredFn, anyhow::Error> {
        let Some(deny) = self.link_filter() else {
            return Ok(self.merge_filter(is_ignored));
        };

        let root = self.inner.relative_path(path);
        let resolved = self.inner.canonicalize(&root)?;
        let Some(resolved_root) = self.diverged(&root, resolved) else {
            return Ok(self.merge_filter(is_ignored));
        };

        self.check_reachable(FileType::Dir, resolved_root.clone())?;
        let remapped = Self::remap_walk_filter(deny.clone(), root, resolved_root);

        Ok(self.merge_filter(is_ignored.merge(remapped)))
    }

    async fn async_walk_filter(
        &self,
        path: &Path,
        is_ignored: IsIgnoredFn,
    ) -> Result<IsIgnoredFn, anyhow::Error> {
        let Some(deny) = self.link_filter() else {
            return Ok(self.merge_filter(is_ignored));
        };

        let root = self.inner.relative_path(path);
        let resolved = self.inner.async_canonicalize(&root).await?;
        let Some(resolved_root) = self.diverged(&root, resolved) else {
            return Ok(self.merge_filter(is_ignored));
        };

        self.async_check_reachable(FileType::Dir, resolved_root.clone())
            .await?;
        let remapped = Self::remap_walk_filter(deny.clone(), root, resolved_root);

        Ok(self.merge_filter(is_ignored.merge(remapped)))
    }

    fn merge_filter(&self, is_ignored: IsIgnoredFn) -> IsIgnoredFn {
        match &self.is_ignored {
            Some(existing) => existing.clone().merge(is_ignored),
            None => is_ignored,
        }
    }

    pub fn is_denied(&self, file_type: FileType, path: &Path) -> bool {
        self.check_ignored(file_type, path).is_err()
    }

    pub async fn async_is_denied(&self, file_type: FileType, path: &Path) -> bool {
        self.async_check_ignored(file_type, path).await.is_err()
    }

    #[inline]
    fn check_writable(&self) -> Result<(), anyhow::Error> {
        if !self.is_writable {
            Err(anyhow::anyhow!("filesystem is read-only"))
        } else {
            Ok(())
        }
    }

    fn stat_directory_entry(
        &self,
        dir: &Arc<ListingDir>,
        directory: &Path,
        name: String,
    ) -> Result<StattedDirectoryEntry, anyhow::Error> {
        let mut path = PathBuf::with_capacity(directory.as_os_str().len() + name.len() + 1);
        path.push(directory);
        path.push(&name);

        if cfg!(windows) {
            let metadata = self.inner.symlink_metadata(&path)?;

            return Ok(StattedDirectoryEntry {
                path,
                parent: None,
                metadata,
            });
        }

        let metadata = dir.symlink_metadata(&name)?;

        Ok(StattedDirectoryEntry {
            path,
            parent: metadata.is_file().then(|| Arc::clone(dir)),
            metadata,
        })
    }

    #[cfg(test)]
    fn prepare_statted_directory_entry(
        &self,
        statted: StattedDirectoryEntry,
    ) -> Result<PreparedDirectoryEntry, anyhow::Error> {
        let checked_path =
            self.check_ignored(statted.metadata.file_type().into(), &statted.path)?;

        let StattedDirectoryEntry {
            path,
            parent,
            metadata,
        } = statted;

        let mut prepared = self.server.filesystem.prepare_api_entry_cap_blocking(
            &self.inner,
            checked_path,
            metadata,
        );

        if prepared.metadata.is_file() && prepared.path == path {
            prepared.parent = parent;
        }

        Ok(prepared)
    }

    /// For entries the listing scan loop already passed through the merged ignore
    /// filter, keeping the path they were listed under.
    fn prepare_listed_directory_entry(
        &self,
        statted: StattedDirectoryEntry,
    ) -> PreparedDirectoryEntry {
        let StattedDirectoryEntry {
            path,
            parent,
            metadata,
        } = statted;

        let mut prepared =
            self.server
                .filesystem
                .prepare_api_entry_cap_blocking(&self.inner, path, metadata);

        if prepared.metadata.is_file() {
            prepared.parent = parent;
        }

        prepared
    }

    #[cfg(test)]
    fn prepare_directory_entry(
        &self,
        dir: &Arc<ListingDir>,
        directory: &Path,
        name: &str,
    ) -> Result<PreparedDirectoryEntry, anyhow::Error> {
        self.prepare_statted_directory_entry(self.stat_directory_entry(
            dir,
            directory,
            name.to_string(),
        )?)
    }

    fn select_prepared_entries(
        &self,
        entries: Vec<(bool, PreparedDirectoryEntry)>,
        sort: crate::models::DirectorySortingMode,
        per_page: Option<usize>,
        page: usize,
        listener: &AbortListener,
    ) -> Result<Vec<PreparedDirectoryEntry>, anyhow::Error> {
        use crate::models::DirectorySortingMode::*;

        if matches!(sort, NameAsc | NameDesc) {
            return Ok(entries.into_iter().map(|(_, entry)| entry).collect());
        }

        let options = DirectoryEntryOptions::server_fs(self.is_primary_server_fs);
        let mut keyed = Vec::with_capacity(entries.len());

        for (directory, prepared) in entries {
            check_aborted(listener)?;

            let key: i128 = match sort {
                SizeAsc | SizeDesc => self
                    .server
                    .filesystem
                    .prepared_entry_sort_size_blocking(&prepared, options)
                    .0
                    .into(),
                PhysicalSizeAsc | PhysicalSizeDesc => self
                    .server
                    .filesystem
                    .prepared_entry_sort_size_blocking(&prepared, options)
                    .1
                    .into(),
                ModifiedAsc | ModifiedDesc => prepared.modified_secs().into(),
                CreatedAsc | CreatedDesc => prepared.created_secs().into(),
                NameAsc | NameDesc => 0,
            };

            keyed.push((directory, key, prepared));
        }

        let ascending = matches!(sort, SizeAsc | PhysicalSizeAsc | ModifiedAsc | CreatedAsc);
        keyed.sort_by(|(a_dir, a_key, _), (b_dir, b_key, _)| {
            b_dir.cmp(a_dir).then_with(|| {
                if ascending {
                    a_key.cmp(b_key)
                } else {
                    b_key.cmp(a_key)
                }
            })
        });

        check_aborted(listener)?;

        let start = per_page.map_or(0, |per_page| {
            page.saturating_sub(1).saturating_mul(per_page)
        });

        Ok(keyed
            .into_iter()
            .skip(start)
            .take(per_page.unwrap_or(usize::MAX))
            .map(|(_, _, entry)| entry)
            .collect())
    }

    fn finish_prepared_entries(
        &self,
        prepared: Vec<PreparedDirectoryEntry>,
        listener: &AbortListener,
    ) -> Result<Vec<DirectoryEntry>, anyhow::Error> {
        let options = DirectoryEntryOptions::server_fs(self.is_primary_server_fs);
        let mut entries = Vec::with_capacity(prepared.len());

        for prepared in prepared {
            check_aborted(listener)?;

            entries.push(self.server.filesystem.finish_api_entry_cap_blocking(
                &self.inner,
                prepared,
                options,
            ));
        }

        Ok(entries)
    }

    fn finish_small_listing(
        &self,
        total_entries: usize,
        prepared: Vec<PreparedDirectoryEntry>,
        listener: &AbortListener,
    ) -> Result<ListingResult<PreparedDirectoryEntry>, anyhow::Error> {
        if prepared.len() > ListingWork::SMALL_LIMIT {
            return Ok(ListingResult::Pending {
                total_entries,
                entries: prepared,
                dir: (),
            });
        }

        Ok(ListingResult::Complete(DirectoryListing {
            total_entries,
            entries: self.finish_prepared_entries(prepared, listener)?,
        }))
    }

    /// Lists `path` with `is_ignored` already merged by [`Self::async_walk_filter`].
    ///
    /// With `checked`, a directory that cannot be opened or is not reachable
    /// yields `None` instead of an error, so the caller can classify it the way
    /// [`read_dir_checked`] does.
    async fn read_dir(
        &self,
        path: &Path,
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
        checked: bool,
    ) -> Result<Option<DirectoryListing>, anyhow::Error> {
        let path = self.inner.relative_path(path);
        let work = Arc::clone(&self.server.filesystem.app_state.listing_work);

        let initial = work
            .run({
                let this = self.clone();
                let path = path.clone();

                move |listener| {
                    use crate::models::DirectorySortingMode::*;

                    let mut directory_entries = Vec::new();
                    let mut other_entries = Vec::new();
                    let mut scratch = PathBuf::new();
                    let dir = match this.inner.open_listing_dir(&path) {
                        Ok(dir) => Arc::new(dir),
                        Err(_) if checked => return Ok(None),
                        Err(err) => return Err(err.into()),
                    };
                    if checked && this.check_reachable(FileType::Dir, &path).is_err() {
                        return Ok(None);
                    }

                    dir.for_each_entry(|file_type, name| -> Result<(), anyhow::Error> {
                        check_aborted(listener)?;

                        scratch.clear();
                        scratch.push(&path);
                        scratch.push(&name);
                        match is_ignored(file_type, std::mem::take(&mut scratch))
                            .reachable(file_type)
                        {
                            Some(kept) => scratch = kept,
                            None => return Ok(()),
                        }

                        if file_type.is_dir() {
                            directory_entries.push(name);
                        } else {
                            other_entries.push(name);
                        }

                        Ok(())
                    })?;

                    check_aborted(listener)?;

                    let total_entries = directory_entries.len() + other_entries.len();
                    let (directory_window, other_window) = if matches!(sort, NameAsc | NameDesc) {
                        let descending = matches!(sort, NameDesc);
                        let cmp = |a: &String, b: &String| {
                            let ordering = a.cmp_ascii_case_insensitive(b).then_with(|| a.cmp(b));
                            if descending {
                                ordering.reverse()
                            } else {
                                ordering
                            }
                        };

                        let start = per_page.map_or(0, |per_page| {
                            page.saturating_sub(1).saturating_mul(per_page)
                        });
                        let end =
                            per_page.map_or(usize::MAX, |per_page| start.saturating_add(per_page));

                        let directory_window = group_window(start, end, directory_entries.len());
                        if let Some(window) = directory_window.clone() {
                            sort_window(&mut directory_entries, window, cmp);
                        }

                        let other_window = group_window(
                            start.saturating_sub(directory_entries.len()),
                            end.saturating_sub(directory_entries.len()),
                            other_entries.len(),
                        );
                        if let Some(window) = other_window.clone() {
                            sort_window(&mut other_entries, window, cmp);
                        }

                        (
                            directory_window.unwrap_or(0..0),
                            other_window.unwrap_or(0..0),
                        )
                    } else {
                        (0..directory_entries.len(), 0..other_entries.len())
                    };

                    let candidates: Vec<_> = directory_entries
                        .into_iter()
                        .skip(directory_window.start)
                        .take(directory_window.len())
                        .map(|name| (true, name))
                        .chain(
                            other_entries
                                .into_iter()
                                .skip(other_window.start)
                                .take(other_window.len())
                                .map(|name| (false, name)),
                        )
                        .collect();

                    if candidates.len() > ListingWork::SMALL_LIMIT {
                        return Ok(Some(ListingResult::Pending {
                            total_entries,
                            entries: candidates,
                            dir,
                        }));
                    }

                    let mut prepared = Vec::with_capacity(candidates.len());
                    for (directory, name) in candidates {
                        check_aborted(listener)?;

                        if let Ok(statted) = this.stat_directory_entry(&dir, &path, name) {
                            prepared
                                .push((directory, this.prepare_listed_directory_entry(statted)));
                        }
                    }

                    let prepared =
                        this.select_prepared_entries(prepared, sort, per_page, page, listener)?;

                    Ok(Some(ListingResult::Complete(DirectoryListing {
                        total_entries,
                        entries: this.finish_prepared_entries(prepared, listener)?,
                    })))
                }
            })
            .await?;

        let Some(initial) = initial else {
            return Ok(None);
        };
        let (total_entries, candidates, dir) = match initial {
            ListingResult::Complete(listing) => return Ok(Some(listing)),
            ListingResult::Pending {
                total_entries,
                entries,
                dir,
            } => (total_entries, entries, dir),
        };

        let statted = work
            .map_ordered(candidates, {
                let this = self.clone();

                move |(directory, name)| (directory, this.stat_directory_entry(&dir, &path, name))
            })
            .await?;

        let selected = work
            .run({
                let this = self.clone();

                move |listener| {
                    let mut prepared = Vec::with_capacity(statted.len());

                    for (directory, statted) in statted {
                        check_aborted(listener)?;

                        let Ok(statted) = statted else { continue };
                        prepared.push((directory, this.prepare_listed_directory_entry(statted)));
                    }

                    let prepared =
                        this.select_prepared_entries(prepared, sort, per_page, page, listener)?;
                    this.finish_small_listing(total_entries, prepared, listener)
                }
            })
            .await?;

        let (total_entries, selected) = match selected {
            ListingResult::Complete(listing) => return Ok(Some(listing)),
            ListingResult::Pending {
                total_entries,
                entries,
                ..
            } => (total_entries, entries),
        };

        let entries = work
            .map_ordered(selected, {
                let this = self.clone();
                let options = DirectoryEntryOptions::server_fs(this.is_primary_server_fs);

                move |prepared| {
                    this.server.filesystem.finish_api_entry_cap_blocking(
                        &this.inner,
                        prepared,
                        options,
                    )
                }
            })
            .await?;

        Ok(Some(DirectoryListing {
            total_entries,
            entries,
        }))
    }
}

#[async_trait::async_trait]
impl super::VirtualReadableFilesystem for VirtualCapFilesystem {
    fn is_primary_server_fs(&self) -> bool {
        self.is_primary_server_fs
    }
    fn is_fast(&self) -> bool {
        true
    }
    fn is_writable(&self) -> bool {
        self.is_writable
    }

    fn backing_server(&self) -> &crate::server::Server {
        &self.server
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.metadata(path)?;
        let metadata: FileMetadata = metadata.into();

        self.check_reachable(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.async_metadata(path).await?;
        let metadata: FileMetadata = metadata.into();

        self.async_check_reachable(metadata.file_type, path.as_ref())
            .await?;

        Ok(metadata)
    }

    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.symlink_metadata(path)?;
        let metadata: FileMetadata = metadata.into();

        self.check_reachable(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;
        let metadata: FileMetadata = metadata.into();

        self.async_check_reachable(metadata.file_type, path.as_ref())
            .await?;

        Ok(metadata)
    }

    fn resolve_reachable(
        &self,
        file_type: FileType,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_resolved(file_type, path.as_ref())
    }
    async fn async_resolve_reachable(
        &self,
        file_type: FileType,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.async_check_resolved(file_type, path.as_ref()).await
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;

        let path = self
            .async_check_reachable(metadata.file_type().into(), path.as_ref())
            .await?;
        if let Some(resolved) = self.async_written_target(&path, false).await? {
            self.async_check_reachable(metadata.file_type().into(), resolved)
                .await?;
        }

        self.server
            .filesystem
            .to_api_entry_cap(
                &self.inner,
                path,
                metadata,
                DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            )
            .await
    }

    fn directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let metadata = self.inner.symlink_metadata(path)?;
        let path = self.check_reachable(metadata.file_type().into(), path.as_ref())?;

        Ok(self.server.filesystem.to_api_entry_buffer_blocking(
            path,
            &metadata,
            DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            Some(buffer),
            None,
            None,
        ))
    }
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let this = self.clone();
        let path = path.as_ref().to_path_buf();
        let buffer = buffer.to_owned();

        tokio::task::spawn_blocking(move || this.directory_entry_buffer(&path, &buffer)).await?
    }

    fn directory_entry_from_metadata(
        &self,
        path: &Path,
        metadata: &cap_std::fs::Metadata,
        buffer: Option<&[u8]>,
    ) -> Option<DirectoryEntry> {
        if metadata.is_dir() {
            return None;
        }

        Some(self.server.filesystem.to_api_file_entry_buffer(
            path.to_path_buf(),
            metadata,
            DirectoryEntryOptions::server_fs(self.is_primary_server_fs),
            buffer,
        ))
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        let is_ignored = self.async_walk_filter(path.as_ref(), is_ignored).await?;

        self.read_dir(path.as_ref(), per_page, page, is_ignored, sort, false)
            .await?
            .ok_or_else(|| anyhow::anyhow!("directory could not be listed"))
    }

    async fn async_read_dir_checked(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: crate::models::DirectorySortingMode,
    ) -> Result<CheckedDirectoryListing, anyhow::Error> {
        if self
            .inner
            .relative_path_cow(path.as_ref())
            .as_os_str()
            .is_empty()
        {
            return read_dir_checked(self, path, per_page, page, is_ignored, sort).await;
        }

        let merged = match self
            .async_walk_filter(path.as_ref(), is_ignored.clone())
            .await
        {
            Ok(merged) => merged,
            Err(_) => {
                let is_dir = self
                    .inner
                    .async_metadata(path.as_ref())
                    .await
                    .is_ok_and(|metadata| metadata.is_dir());

                return if is_dir {
                    Ok(CheckedDirectoryListing::NotFound)
                } else {
                    read_dir_checked(self, path, per_page, page, is_ignored, sort).await
                };
            }
        };

        if let Some(listing) = self
            .read_dir(path.as_ref(), per_page, page, merged, sort, true)
            .await?
        {
            return Ok(CheckedDirectoryListing::Listing(listing));
        }

        read_dir_checked(self, path, per_page, page, is_ignored, sort).await
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let is_ignored = self.walk_filter(path.as_ref(), is_ignored)?;
        let walk_dir = self.inner.walk_dir(path)?.with_is_ignored(is_ignored);

        struct IgnoreWalkDir {
            inner: crate::server::filesystem::cap::WalkDir,
        }

        impl DirectoryWalk for IgnoreWalkDir {
            fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.inner.next_entry().map(|res| {
                    res.map(|entry| (entry.file_type(), entry.path))
                        .map_err(|err| err.into())
                })
            }

            fn next_walk_entry(&mut self) -> Option<Result<VirtualWalkEntry, anyhow::Error>> {
                self.inner.next_entry().map(|res| {
                    res.map(VirtualWalkEntry::with_source)
                        .map_err(|err| err.into())
                })
            }

            fn run_parallel(
                &mut self,
                threads: usize,
                filter: Option<DirectoryWalkFilterFn>,
                func: DirectoryWalkFn,
            ) -> Result<(), anyhow::Error> {
                self.inner.run_parallel(
                    threads,
                    filter,
                    Arc::new(move |entry| func(VirtualWalkEntry::with_source(entry))),
                )
            }
        }

        Ok(Box::new(IgnoreWalkDir { inner: walk_dir }))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        let is_ignored = self.async_walk_filter(path.as_ref(), is_ignored).await?;
        let walk_dir = self
            .inner
            .async_walk_dir(path)
            .await?
            .with_is_ignored(is_ignored);

        struct IgnoreAsyncWalkDir {
            inner: crate::server::filesystem::cap::AsyncWalkDir,
        }

        #[async_trait::async_trait]
        impl AsyncDirectoryWalk for IgnoreAsyncWalkDir {
            async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
                self.inner.next_entry().await.map(|res| {
                    res.map(|entry| (entry.file_type(), entry.path))
                        .map_err(|err| err.into())
                })
            }

            async fn next_walk_entry(&mut self) -> Option<Result<VirtualWalkEntry, anyhow::Error>> {
                self.inner.next_entry().await.map(|res| {
                    res.map(VirtualWalkEntry::with_source)
                        .map_err(|err| err.into())
                })
            }
        }

        Ok(Box::new(IgnoreAsyncWalkDir { inner: walk_dir }))
    }

    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        let is_ignored = self.async_walk_filter(path.as_ref(), is_ignored).await?;
        let walk_dir = self
            .inner
            .async_walk_dir(path)
            .await?
            .with_is_ignored(is_ignored);

        struct IgnoreAsyncWalkDir<'a> {
            inner_fs: &'a crate::server::filesystem::cap::CapFilesystem,
            inner: crate::server::filesystem::cap::AsyncWalkDir,
        }

        #[async_trait::async_trait]
        impl<'a> AsyncDirectoryStreamWalk for IgnoreAsyncWalkDir<'a> {
            async fn next_entry(
                &mut self,
            ) -> Option<Result<(FileType, PathBuf, AsyncReadableFileStream), anyhow::Error>>
            {
                let entry = self.inner.next_entry().await?;

                let (file_type, path) = match entry {
                    Ok(entry) => (entry.file_type(), entry.path),
                    Err(err) => return Some(Err(err.into())),
                };

                let reader: AsyncReadableFileStream = if file_type.is_file() {
                    match self.inner_fs.async_open(&path).await {
                        Ok(file) => Box::new(file),
                        Err(_) => Box::new(tokio::io::empty()),
                    }
                } else {
                    Box::new(tokio::io::empty())
                };

                Some(Ok((file_type, path, reader)))
            }
        }

        Ok(Box::new(IgnoreAsyncWalkDir {
            inner_fs: &self.inner,
            inner: walk_dir,
        }))
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        let path = self.check_ignored(FileType::File, path.as_ref())?;
        let file = self.inner.open(&path)?;
        self.check_opened(&path, &file)?;

        Ok(FileRead::from_file(file, range)?)
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        let path = self
            .async_check_ignored(FileType::File, path.as_ref())
            .await?;

        let this = self.clone();
        let file = tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
            let file = this.inner.open(&path)?;
            this.check_opened(&path, &file)?;

            Ok(file)
        })
        .await??;

        Ok(AsyncFileRead::from_file(tokio::fs::File::from_std(file), range).await?)
    }

    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let path = self.check_ignored(FileType::Symlink, path.as_ref())?;
        let link_path = self.inner.read_link(&path)?;

        Ok(link_path)
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        let path = self
            .async_check_ignored(FileType::Symlink, path.as_ref())
            .await?;
        let link_path = self.inner.async_read_link(&path).await?;

        Ok(link_path)
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FalliblePipeReader, anyhow::Error> {
        let is_ignored = self.async_walk_filter(path.as_ref(), is_ignored).await?;
        let names = self.inner.async_read_dir_all(path).await?;
        let file_compression_threads = self
            .server
            .app_state
            .config
            .load()
            .api
            .file_compression_threads;
        let (reader, writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE);
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new(reader);

        tokio::spawn({
            let filesystem = self.inner.clone();
            let path = path.as_ref().to_path_buf();

            async move {
                let writer = writer.into_sync();

                match archive_format {
                    StreamableArchiveFormat::Zip => {
                        match crate::server::filesystem::archive::create::create_zip_streaming(
                            filesystem,
                            writer,
                            &path,
                            names,
                            progress,
                            is_ignored,
                            crate::server::filesystem::archive::create::CreateZipOptions {
                                compression_level,
                                threads: file_compression_threads,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                                signal.succeed();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create zip archive for cap vfs: {}",
                                    err
                                );
                                signal.fail(err);
                            }
                        }
                    }
                    f if f.is_tar() => {
                        match crate::server::filesystem::archive::create::create_tar(
                            filesystem,
                            writer,
                            &path,
                            names,
                            progress,
                            is_ignored,
                            crate::server::filesystem::archive::create::CreateTarOptions {
                                compression_type: archive_format.compression_format(),
                                compression_level,
                                threads: file_compression_threads,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                                signal.succeed();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create tar archive for cap vfs: {}",
                                    err
                                );
                                signal.fail(err);
                            }
                        }
                    }
                    f if f.is_itaf() => {
                        match crate::server::filesystem::archive::create::create_itaf(
                            filesystem,
                            writer,
                            &path,
                            names,
                            progress,
                            is_ignored,
                            crate::server::filesystem::archive::create::CreateItafOptions {
                                compression_type: archive_format.compression_format(),
                                compression_level,
                                threads: file_compression_threads,
                                crc_enabled: true,
                            },
                        )
                        .await
                        {
                            Ok(inner) => {
                                inner.into_inner().shutdown().await.ok();
                                signal.succeed();
                            }
                            Err(err) => {
                                tracing::error!(
                                    "failed to create itaf archive for cap vfs: {}",
                                    err
                                );
                                signal.fail(err);
                            }
                        }
                    }
                    _ => {
                        tracing::error!(
                            "unsupported archive format for cap vfs: {}",
                            archive_format.extension()
                        );
                        signal.fail(format!(
                            "unsupported archive format: {}",
                            archive_format.extension()
                        ));
                    }
                }
            }
        });

        Ok(reader)
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        self.inner.close();
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::VirtualWritableFilesystem for VirtualCapFilesystem {
    fn create_dir_all(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error> {
        let path = self.check_create_dir(path.as_ref())?;

        if self.is_primary_server_fs {
            self.server.filesystem.create_chowned_dir_all(&path)?;
        } else {
            self.inner.create_dir_all(&path)?;
        }

        Ok(())
    }
    async fn async_create_dir_all(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        let path = self.async_check_create_dir(path.as_ref()).await?;

        if self.is_primary_server_fs {
            self.server
                .filesystem
                .async_create_chowned_dir_all(&path)
                .await?;
        } else {
            self.inner.async_create_dir_all(&path).await?;
        }

        Ok(())
    }

    fn remove_dir_all(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error> {
        let path = self.check_write(FileType::Dir, path.as_ref(), false)?;

        let file_delete_threads = self.server.app_state.config.load().api.file_delete_threads;
        self.inner.remove_dir_all(path, file_delete_threads)?;

        Ok(())
    }

    async fn async_remove_dir_all(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        let path = self
            .async_check_write(FileType::Dir, path.as_ref(), false)
            .await?;

        let file_delete_threads = self.server.app_state.config.load().api.file_delete_threads;
        self.inner
            .async_remove_dir_all(path, file_delete_threads)
            .await?;

        Ok(())
    }

    fn remove_file(&self, path: &(dyn AsRef<Path> + Send + Sync)) -> Result<(), anyhow::Error> {
        let path = self.check_write(FileType::File, path.as_ref(), false)?;

        self.inner.remove_file(path)?;

        Ok(())
    }
    async fn async_remove_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        let path = self
            .async_check_write(FileType::File, path.as_ref(), false)
            .await?;

        self.inner.async_remove_file(path).await?;

        Ok(())
    }

    fn create_symlink(
        &self,
        original: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        let link = self.check_write(FileType::Symlink, link.as_ref(), false)?;
        let original = self.check_ignored(FileType::File, original.as_ref())?;

        self.inner.symlink(original, &link)?;
        if self.is_primary_server_fs {
            self.server.filesystem.chown_path(&link)?;
        }

        Ok(())
    }
    async fn async_create_symlink(
        &self,
        original: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        let link = self
            .async_check_write(FileType::Symlink, link.as_ref(), false)
            .await?;
        let original = self
            .async_check_ignored(FileType::File, original.as_ref())
            .await?;

        self.inner.async_symlink(original, &link).await?;
        if self.is_primary_server_fs {
            self.server.filesystem.async_chown_path(&link).await?;
        }

        Ok(())
    }

    async fn async_create_symlink_contents(
        &self,
        contents: &(dyn AsRef<Path> + Send + Sync),
        link: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<(), anyhow::Error> {
        let link = self
            .async_check_write(FileType::Symlink, link.as_ref(), false)
            .await?;

        self.inner
            .async_symlink_contents(contents.as_ref(), &link)
            .await?;
        if self.is_primary_server_fs {
            self.server.filesystem.async_chown_path(&link).await?;
        }

        Ok(())
    }

    fn create_seekable_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<WritableSeekableFileStream, anyhow::Error> {
        let path = self.check_write(FileType::File, path.as_ref(), true)?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::ServerFile::new_checked(
                self.server.clone(),
                &path,
                None,
                None,
                |file| self.check_opened(&path, file),
            )?;

            Ok(Box::new(file))
        } else {
            let file = self.inner.create(path)?;

            Ok(Box::new(file))
        }
    }
    fn create_file_with_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        permissions: Option<PortablePermissions>,
        modified: Option<std::time::SystemTime>,
    ) -> Result<super::WritableFileStream, anyhow::Error> {
        let path = self.check_write(FileType::File, path.as_ref(), true)?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::ServerFile::new_checked(
                self.server.clone(),
                &path,
                permissions,
                modified,
                |file| self.check_opened(&path, file),
            )?;

            Ok(Box::new(file))
        } else {
            let file = self.inner.create(path)?;
            if let Some(permissions) = permissions {
                file.apply_permissions(permissions)?;
            }

            Ok(Box::new(ModifiedOnClose { file, modified }))
        }
    }
    async fn async_create_file_with_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        permissions: Option<PortablePermissions>,
    ) -> Result<super::AsyncWritableFileStream, anyhow::Error> {
        let path = self
            .async_check_write(FileType::File, path.as_ref(), true)
            .await?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::AsyncServerFile::new_checked(
                self.server.clone(),
                &path,
                permissions,
                None,
                {
                    let this = self.clone();
                    let path = path.clone();

                    move |file| this.check_opened(&path, file)
                },
            )
            .await?;

            Ok(Box::new(file))
        } else {
            let file = self
                .inner
                .async_create_with_permissions(path, permissions)
                .await?;

            Ok(Box::new(file))
        }
    }
    async fn async_create_seekable_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<AsyncWritableSeekableFileStream, anyhow::Error> {
        let path = self
            .async_check_write(FileType::File, path.as_ref(), true)
            .await?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::AsyncServerFile::new_checked(
                self.server.clone(),
                &path,
                None,
                None,
                {
                    let this = self.clone();
                    let path = path.clone();

                    move |file| this.check_opened(&path, file)
                },
            )
            .await?;

            Ok(Box::new(file))
        } else {
            let file = self.inner.async_create(path).await?;

            Ok(Box::new(file))
        }
    }
    fn open_file_with_options(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        options: cap_std::fs::OpenOptions,
    ) -> Result<ReadableWritableSeekableFileStream, anyhow::Error> {
        let path = self.check_write(FileType::File, path.as_ref(), true)?;

        let file = self.inner.open_with(&path, options)?;
        self.check_opened(&path, &file)?;

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::ServerFile::new_file(
                self.server.clone(),
                &path,
                file,
                0,
            )?;

            Ok(Box::new(file))
        } else {
            Ok(Box::new(file))
        }
    }
    async fn async_open_file_with_options(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        options: cap_std::fs::OpenOptions,
    ) -> Result<AsyncReadableWritableSeekableFileStream, anyhow::Error> {
        let path = self
            .async_check_write(FileType::File, path.as_ref(), true)
            .await?;

        let this = self.clone();
        let (path, file) = tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
            let file = this.inner.open_with(&path, options)?;
            this.check_opened(&path, &file)?;

            Ok((path, file))
        })
        .await??;
        let file = tokio::fs::File::from_std(file);

        if self.is_primary_server_fs {
            let file = crate::server::filesystem::file::AsyncServerFile::new_file(
                self.server.clone(),
                &path,
                file,
                0,
            )?;

            Ok(Box::new(file))
        } else {
            Ok(Box::new(file))
        }
    }

    fn set_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        permissions: PortablePermissions,
    ) -> Result<(), anyhow::Error> {
        let path = self.check_write(file_type, path.as_ref(), !file_type.is_symlink())?;

        self.inner.set_permissions(path, permissions)?;

        Ok(())
    }
    async fn async_set_permissions(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        permissions: PortablePermissions,
    ) -> Result<(), anyhow::Error> {
        let path = self
            .async_check_write(file_type, path.as_ref(), !file_type.is_symlink())
            .await?;

        self.inner.async_set_permissions(path, permissions).await?;

        Ok(())
    }

    fn set_times(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error> {
        let path = self.check_write(file_type, path.as_ref(), !file_type.is_symlink())?;

        self.inner.set_times(path, modification_time, access_time)?;

        Ok(())
    }
    async fn async_set_times(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
        modification_time: std::time::SystemTime,
        access_time: Option<std::time::SystemTime>,
    ) -> Result<(), anyhow::Error> {
        let path = self
            .async_check_write(file_type, path.as_ref(), !file_type.is_symlink())
            .await?;

        self.inner
            .async_set_times(path, modification_time, access_time)
            .await?;

        Ok(())
    }

    fn rename(
        &self,
        from: &(dyn AsRef<Path> + Send + Sync),
        to: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
    ) -> Result<(), anyhow::Error> {
        let from = self.check_write(file_type, from.as_ref(), false)?;
        let to = self.check_write(file_type, to.as_ref(), false)?;

        self.inner.rename(from, &self.inner, to)?;

        Ok(())
    }
    async fn async_rename(
        &self,
        from: &(dyn AsRef<Path> + Send + Sync),
        to: &(dyn AsRef<Path> + Send + Sync),
        file_type: FileType,
    ) -> Result<(), anyhow::Error> {
        let from = self
            .async_check_write(file_type, from.as_ref(), false)
            .await?;
        let to = self
            .async_check_write(file_type, to.as_ref(), false)
            .await?;

        self.inner.async_rename(from, &self.inner, to).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::DirectorySortingMode::*,
        routes::State,
        server::{
            Server,
            filesystem::{
                Filesystem,
                cap::CapFilesystem,
                ignore_list::IgnoreList,
                usage::SpaceDelta,
                virtualfs::{VirtualReadableFilesystem, VirtualWritableFilesystem},
            },
        },
    };
    use std::time::Duration;

    const SORTS: [crate::models::DirectorySortingMode; 10] = [
        NameAsc,
        NameDesc,
        SizeAsc,
        SizeDesc,
        PhysicalSizeAsc,
        PhysicalSizeDesc,
        ModifiedAsc,
        ModifiedDesc,
        CreatedAsc,
        CreatedDesc,
    ];

    const EXTRA_FILES: [usize; 2] = [0, ListingWork::SMALL_LIMIT + 32];

    struct ListingFixture {
        state: State,
        server: Server,
        cap: CapFilesystem,
        fs: VirtualCapFilesystem,
        ignored: IsIgnoredFn,

        _temp: tempfile::TempDir,
    }

    impl ListingFixture {
        async fn new(extra_files: usize) -> Result<Self, anyhow::Error> {
            let (temp, server) = Server::mock_in_tempdir().await;

            let root = &server.filesystem.base_path;
            std::fs::create_dir(root.join("cached"))?;
            std::fs::create_dir(root.join("uncached"))?;
            std::fs::create_dir(root.join("nested"))?;
            std::fs::write(root.join("nested/data.bin"), b"nested text")?;

            for (name, contents) in [
                ("a.txt", b"hello".as_slice()),
                ("b.bin", b"\x00\xff\x01".as_slice()),
                ("empty.txt", b"".as_slice()),
                ("z.txt", b"last file".as_slice()),
                ("denied.txt", b"hidden".as_slice()),
                ("request-denied.txt", b"hidden".as_slice()),
            ] {
                std::fs::write(root.join(name), contents)?;
            }

            #[cfg(unix)]
            for (name, target) in [
                ("file-link", "a.txt"),
                ("dir-link", "cached"),
                ("broken-link", "missing"),
                ("denied-link", "denied.txt"),
                ("nested/parent-link", "../a.txt"),
                ("nested/denied-link", "../denied.txt"),
            ] {
                std::os::unix::fs::symlink(target, root.join(name))?;
            }

            for i in 0..extra_files {
                std::fs::write(root.join(format!("extra-{i:03}.txt")), b"same size")?;
            }

            let cap = server.filesystem.cap_filesystem.clone();
            server
                .filesystem
                .disk_usage
                .write()
                .await
                .update_size(Path::new("cached"), SpaceDelta::new(123, 4096));
            server.filesystem.update_ignored(&["denied.txt"]).await;

            let mut fs = cap
                .get_virtual(server.clone())
                .with_is_ignored(Filesystem::deny_filter(&server));
            fs.is_primary_server_fs = true;

            let ignored: IsIgnoredFn = IgnoreList::from_lines(["request-denied.txt"])?.into();

            Ok(Self {
                state: server.app_state.clone(),
                server,
                cap,
                fs,
                ignored,
                _temp: temp,
            })
        }

        async fn read_dir(
            &self,
            path: &str,
            per_page: Option<usize>,
            page: usize,
            sort: crate::models::DirectorySortingMode,
        ) -> Result<DirectoryListing, anyhow::Error> {
            self.read_dir_with(path, self.ignored.clone(), per_page, page, sort)
                .await
        }

        async fn read_dir_with(
            &self,
            path: &str,
            is_ignored: IsIgnoredFn,
            per_page: Option<usize>,
            page: usize,
            sort: crate::models::DirectorySortingMode,
        ) -> Result<DirectoryListing, anyhow::Error> {
            self.fs
                .async_read_dir(&path, per_page, page, is_ignored, sort)
                .await
        }
    }

    /// One blocking worker on purpose: a listing stage that waits on a second one deadlocks here
    /// instead of quietly passing.
    fn with_one_blocking_worker<F, Fut>(test: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), anyhow::Error>>,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("creating listing test runtime failed");

        let result =
            runtime.block_on(async { tokio::time::timeout(Duration::from_secs(30), test()).await });

        runtime.shutdown_timeout(Duration::from_secs(1));
        result
            .expect("listing stalled with one blocking worker")
            .expect("listing test failed");
    }

    #[cfg(unix)]
    fn read_sync(fs: &VirtualCapFilesystem, path: &str) -> Result<Vec<u8>, anyhow::Error> {
        let fs = fs.clone();
        let path = path.to_string();
        std::thread::spawn(move || {
            let mut file_read = fs.read_file(&path, None)?;
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut file_read.reader, &mut contents)?;
            Ok(contents)
        })
        .join()
        .expect("sync read worker panicked")
    }

    #[cfg(unix)]
    async fn read_async(fs: &VirtualCapFilesystem, path: &str) -> Result<Vec<u8>, anyhow::Error> {
        let mut file_read = fs.async_read_file(&path, None).await?;
        let mut contents = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file_read.reader, &mut contents).await?;
        Ok(contents)
    }

    #[cfg(unix)]
    fn is_not_found(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound)
        })
    }

    #[cfg(unix)]
    fn tar_entries(bytes: &[u8]) -> Result<Vec<(PathBuf, Vec<u8>)>, anyhow::Error> {
        let mut archive = tar::Archive::new(bytes);
        let mut entries = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.into_owned();
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut contents)?;
            entries.push((path, contents));
        }

        Ok(entries)
    }

    #[test]
    fn buffered_entries_match_async_lookup_without_runtime() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;

            for path in [
                "a.txt",
                "cached",
                "nested/data.bin",
                "denied.txt",
                "missing",
            ] {
                let filesystem = fixture.fs.clone();
                let sync = std::thread::spawn(move || {
                    assert!(tokio::runtime::Handle::try_current().is_err());
                    filesystem.directory_entry_buffer(&path, b"plain text")
                })
                .join()
                .expect("buffered entry worker panicked");
                let asynchronous = fixture
                    .fs
                    .async_directory_entry_buffer(&path, b"plain text")
                    .await;

                match (sync, asynchronous) {
                    (Ok(sync), Ok(asynchronous)) => {
                        assert_eq!(
                            serde_json::to_value(&sync)?,
                            serde_json::to_value(asynchronous)?
                        );
                        if path == "cached" {
                            assert_eq!((sync.size, sync.size_physical), (123, 4096));
                            assert_eq!(sync.mime, "inode/directory");
                        }
                    }
                    (Err(sync), Err(asynchronous)) => {
                        assert_eq!(sync.to_string(), asynchronous.to_string());
                    }
                    _ => panic!("sync and async buffered entries differ for {path}"),
                }
            }

            #[cfg(unix)]
            for path in ["file-link", "dir-link", "broken-link"] {
                let filesystem = fixture.fs.clone();
                let sync = std::thread::spawn(move || {
                    filesystem.directory_entry_buffer(&path, b"plain text")
                })
                .join()
                .expect("symlink entry worker panicked")?;
                let asynchronous = fixture
                    .fs
                    .async_directory_entry_buffer(&path, b"plain text")
                    .await?;
                assert!(sync.symlink);
                assert_eq!(
                    serde_json::to_value(sync)?,
                    serde_json::to_value(asynchronous)?
                );
            }

            Ok(())
        });
    }

    #[test]
    fn listing_applies_server_and_request_deny_filters() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    let listing = fixture.read_dir("", None, 1, sort).await?;
                    let names: Vec<_> = listing
                        .entries
                        .iter()
                        .map(|entry| entry.name.as_str())
                        .collect();

                    assert!(!names.contains(&"denied.txt"));
                    assert!(!names.contains(&"denied-link"));
                    assert!(!names.contains(&"request-denied.txt"));

                    assert!(names.contains(&"uncached"));
                    assert!(names.contains(&"a.txt"));

                    #[cfg(unix)]
                    for name in ["file-link", "dir-link", "broken-link"] {
                        assert!(names.contains(&name));
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn deny_filters_apply_identically_to_nested_and_unnormalized_listings() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::create_dir(root.join("hidden"))?;
            std::fs::write(root.join("hidden/inside.txt"), b"hidden")?;
            std::fs::write(root.join("nested/secret.log"), b"hidden")?;
            #[cfg(unix)]
            for (name, target) in [
                ("nested/linked.log", "data.bin"),
                ("nested/via-link", "secret.log"),
            ] {
                std::os::unix::fs::symlink(target, root.join(name))?;
            }
            fixture
                .server
                .filesystem
                .update_ignored(&["denied.txt", "hidden", "hidden/**", "*.log"])
                .await;

            fn names(listing: &DirectoryListing) -> Vec<String> {
                listing
                    .entries
                    .iter()
                    .map(|entry| entry.name.to_string())
                    .collect()
            }

            for sort in SORTS {
                let root_listing = fixture.read_dir("", None, 1, sort).await?;
                let root_names = names(&root_listing);
                for denied in ["denied.txt", "hidden", "request-denied.txt"] {
                    assert!(!root_names.iter().any(|name| name == denied), "{denied}");
                }
                #[cfg(unix)]
                assert!(!root_names.iter().any(|name| name == "denied-link"));
                assert!(root_names.iter().any(|name| name == "nested"));
                assert!(root_names.iter().any(|name| name == "a.txt"));
                assert_eq!(root_listing.total_entries, root_names.len());

                let hidden = fixture.read_dir("hidden", None, 1, sort).await?;
                assert!(hidden.entries.is_empty());
                assert_eq!(hidden.total_entries, 0);

                let nested = fixture.read_dir("nested", None, 1, sort).await?;
                let nested_names = names(&nested);
                assert!(nested_names.iter().any(|name| name == "data.bin"));
                assert!(!nested_names.iter().any(|name| name == "secret.log"));
                #[cfg(unix)]
                {
                    assert!(nested_names.iter().any(|name| name == "parent-link"));
                    assert!(!nested_names.iter().any(|name| name == "denied-link"));
                }
                assert_eq!(nested.total_entries, nested_names.len());

                for variant in [
                    "nested/",
                    "./nested",
                    "/nested",
                    "nested/../nested",
                    "//nested/.",
                ] {
                    let listing = fixture.read_dir(variant, None, 1, sort).await?;

                    assert_eq!(listing.total_entries, nested.total_entries, "{variant}");
                    assert_eq!(
                        serde_json::to_value(&listing.entries)?,
                        serde_json::to_value(&nested.entries)?,
                        "{variant}"
                    );
                }

                // The listing routes add the server deny list on top of the filesystem's own
                // deny filter; matching only symlinks by raw path must list exactly what the
                // full second pass listed.
                for directory in ["", "nested"] {
                    let full: IsIgnoredFn =
                        IsIgnoredFn::from(fixture.server.filesystem.get_ignored())
                            .merge(IgnoreList::from_lines(["request-denied.txt"])?.into());
                    let symlinks_only = fixture
                        .server
                        .filesystem
                        .symlink_name_filter()
                        .merge(fixture.ignored.clone());

                    let expected = fixture
                        .read_dir_with(directory, full, None, 1, sort)
                        .await?;
                    let listing = fixture
                        .read_dir_with(directory, symlinks_only, None, 1, sort)
                        .await?;

                    assert_eq!(listing.total_entries, expected.total_entries, "{directory}");
                    assert_eq!(
                        serde_json::to_value(&listing.entries)?,
                        serde_json::to_value(&expected.entries)?,
                        "{directory}"
                    );

                    #[cfg(unix)]
                    if directory == "nested" {
                        let names = names(&listing);
                        assert!(!names.iter().any(|name| name == "linked.log"));
                        assert!(!names.iter().any(|name| name == "via-link"));
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn listing_entries_match_single_entry_lookups() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    fixture.state.mime_cache.invalidate_all();
                    let listing = fixture.read_dir("", None, 1, sort).await?;

                    assert_eq!(listing.total_entries, listing.entries.len());

                    fixture.state.mime_cache.invalidate_all();
                    for entry in &listing.entries {
                        let expected = fixture
                            .fs
                            .async_directory_entry(&entry.name.as_str())
                            .await?;

                        assert_eq!(
                            serde_json::to_value(entry)?,
                            serde_json::to_value(expected)?
                        );

                        if entry.name == "cached" {
                            assert_eq!((entry.size, entry.size_physical), (123, 4096));
                        }
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn warm_listing_matches_the_cold_listing() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    fixture.state.mime_cache.invalidate_all();
                    let cold = fixture.read_dir("", None, 1, sort).await?;
                    let warm = fixture.read_dir("", None, 1, sort).await?;

                    assert_eq!(
                        serde_json::to_value(warm.entries)?,
                        serde_json::to_value(cold.entries)?
                    );
                }
            }

            Ok(())
        });
    }

    #[test]
    fn paged_listing_concatenates_to_the_unpaged_listing() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;
                let per_page = if extra_files == 0 { 2 } else { 80 };

                for sort in SORTS {
                    let listing = fixture.read_dir("", None, 1, sort).await?;
                    let expected = serde_json::to_value(&listing.entries)?;

                    let mut paged = Vec::new();
                    for page in 1..=listing.total_entries.div_ceil(per_page) {
                        let result = fixture.read_dir("", Some(per_page), page, sort).await?;

                        assert_eq!(result.total_entries, listing.total_entries);
                        paged.extend(result.entries);
                    }

                    assert_eq!(serde_json::to_value(paged)?, expected);
                }
            }

            Ok(())
        });
    }

    #[test]
    fn nested_listing_hides_denied_links_and_stays_editable() {
        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;

                for sort in SORTS {
                    fixture.state.mime_cache.invalidate_all();
                    let nested = fixture.read_dir("nested", None, 1, sort).await?;

                    assert!(
                        nested
                            .entries
                            .iter()
                            .all(|entry| entry.name != "denied-link")
                    );

                    for entry in &nested.entries {
                        let expected = fixture
                            .fs
                            .async_directory_entry(&Path::new("nested").join(&entry.name))
                            .await?;

                        assert_eq!(
                            serde_json::to_value(entry)?,
                            serde_json::to_value(expected)?
                        );
                        assert!(entry.editable);
                    }
                }
            }

            Ok(())
        });
    }

    #[test]
    fn listing_and_single_entry_share_one_blocking_worker() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            fixture.state.mime_cache.invalidate_all();

            let prepared = fixture
                .server
                .filesystem
                .prepare_api_entry_cap(
                    &fixture.cap,
                    PathBuf::from("nested/data.bin"),
                    fixture.cap.symlink_metadata("nested/data.bin")?,
                )
                .await;

            let (entry, listing) = tokio::try_join!(
                fixture.server.filesystem.finish_api_entry_cap(
                    &fixture.cap,
                    prepared,
                    DirectoryEntryOptions::server_fs(true),
                ),
                fixture.read_dir("nested", None, 1, NameAsc),
            )?;

            assert!(entry.editable);
            assert!(listing.entries.iter().any(|entry| entry.name == "data.bin"));

            Ok(())
        });
    }

    #[test]
    fn large_listing_keeps_filter_order_and_skips_vanished_entries() -> Result<(), anyhow::Error> {
        use std::sync::Mutex;

        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            for i in 0..100 {
                std::fs::write(temp.path().join(format!("file-{i:03}.txt")), b"same size")?;
            }

            let (_server_temp, server) = Server::mock_in_tempdir().await;

            let cap = CapFilesystem::new(temp.path()).await?;
            let mut enumeration = Vec::new();
            let mut directory = cap.read_dir("")?;

            while let Some(entry) = directory.next() {
                enumeration.push(PathBuf::from(entry?.file_name()));
            }

            let calls = Arc::new(Mutex::new(Vec::new()));
            let filter = IsIgnoredFn::from({
                let calls = Arc::clone(&calls);
                let root = temp.path().to_path_buf();

                move |_, path: PathBuf| {
                    let mut calls = calls.lock().unwrap();
                    calls.push(path.clone());

                    if calls.len() == 100 {
                        std::fs::remove_file(root.join("file-050.txt")).unwrap();
                    }

                    Some(path)
                }
            });

            let fs = cap.get_virtual(server).with_is_ignored(filter);
            let listing = fs
                .async_read_dir(&"", None, 1, Default::default(), NameDesc)
                .await?;
            let expected: Vec<_> = (0..100)
                .rev()
                .filter(|i| *i != 50)
                .map(|i| PathBuf::from(format!("file-{i:03}.txt")))
                .collect();

            assert_eq!(listing.total_entries, 100);
            assert_eq!(listing.entries.len(), 99);
            assert_eq!(
                listing
                    .entries
                    .iter()
                    .map(|entry| PathBuf::from(entry.name.as_str()))
                    .collect::<Vec<_>>(),
                expected
            );

            let calls = calls.lock().unwrap();
            assert_eq!(*calls, enumeration);

            Ok(())
        })
    }

    #[cfg(unix)]
    #[test]
    fn retained_directory_entry_and_rewritten_path_open_the_right_file() -> Result<(), anyhow::Error>
    {
        tokio_test::block_on(async {
            let temp = tempfile::tempdir()?;
            std::fs::create_dir(temp.path().join("nested"))?;
            std::fs::write(temp.path().join("nested/data.bin"), b"retained text")?;
            std::fs::write(temp.path().join("other.bin"), b"\x89PNG\r\n\x1a\n")?;

            let (_server_temp, server) = Server::mock_in_tempdir().await;

            let cap = CapFilesystem::new(temp.path()).await?;
            let fs = cap.get_virtual(server);
            let directory = Arc::new(cap.open_listing_dir("nested")?);

            std::fs::rename(temp.path().join("nested"), temp.path().join("moved"))?;

            let prepared =
                fs.prepare_directory_entry(&directory, Path::new("nested"), "data.bin")?;
            assert!(prepared.parent.is_some());

            let entry = fs
                .server
                .filesystem
                .finish_api_entry_cap(&cap, prepared, Default::default())
                .await?;

            assert_eq!(entry.mime, "application/octet-stream");
            assert!(entry.editable);

            fs.server.app_state.mime_cache.invalidate_all();
            let fs = fs.with_is_ignored(IsIgnoredFn::new(
                |_, _| Some(PathBuf::from("other.bin")),
                |_, _| async { Some(PathBuf::from("other.bin")) },
            ));
            let directory = Arc::new(cap.open_listing_dir("moved")?);
            let prepared =
                fs.prepare_directory_entry(&directory, Path::new("moved"), "data.bin")?;
            assert!(prepared.parent.is_none());

            let entry = fs
                .server
                .filesystem
                .finish_api_entry_cap(&cap, prepared, Default::default())
                .await?;

            assert_eq!(entry.name, "other.bin");
            assert_eq!(entry.mime, "image/png");

            Ok(())
        })
    }

    #[test]
    fn descended_directories_stay_reachable_and_creatable_but_not_writable() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;

            std::fs::create_dir_all(root.join("game/csgo/cfg"))?;
            std::fs::write(root.join("game/csgo/cfg/server.cfg"), b"hostname wings")?;
            std::fs::write(root.join("game/csgo/other.txt"), b"other")?;
            std::fs::write(root.join("top.txt"), b"top")?;

            let mut fs = fixture
                .cap
                .get_virtual(fixture.server.clone())
                .with_is_ignored(IsIgnoredFn::from(IgnoreList::from_lines([
                    "*",
                    "!game/csgo/cfg",
                ])?));
            fs.is_writable = true;

            fn names(listing: &DirectoryListing) -> Vec<String> {
                listing
                    .entries
                    .iter()
                    .map(|entry| entry.name.to_string())
                    .collect()
            }

            let root_listing = fs
                .async_read_dir(&"", None, 1, IsIgnoredFn::default(), NameAsc)
                .await?;
            let root_names = names(&root_listing);
            assert!(root_names.iter().any(|name| name == "game"));
            assert!(!root_names.iter().any(|name| name == "top.txt"));

            fs.async_metadata(&"game").await?;

            let csgo = fs
                .async_read_dir(&"game/csgo", None, 1, IsIgnoredFn::default(), NameAsc)
                .await?;
            let csgo_names = names(&csgo);
            assert!(csgo_names.iter().any(|name| name == "cfg"));
            assert!(!csgo_names.iter().any(|name| name == "other.txt"));

            assert!(fs.async_metadata(&"top.txt").await.is_err());
            fs.async_create_dir_all(&"game/csgo").await?;
            assert!(fs.async_create_dir_all(&"game/newdir").await.is_err());
            assert!(fs.async_create_file(&"game/csgo/new.txt").await.is_err());

            Ok(())
        });
    }

    // VirtualCapFilesystem::async_read_dir_checked
    #[test]
    fn checked_listing_matches_metadata_then_listing() {
        fn describe(checked: CheckedDirectoryListing) -> Result<String, anyhow::Error> {
            Ok(match checked {
                CheckedDirectoryListing::Listing(listing) => format!(
                    "listing {} {}",
                    listing.total_entries,
                    serde_json::to_string(&listing.entries)?
                ),
                CheckedDirectoryListing::NotFound => "not found".into(),
                CheckedDirectoryListing::NotDirectory => "not directory".into(),
            })
        }

        with_one_blocking_worker(|| async {
            for extra_files in EXTRA_FILES {
                let fixture = ListingFixture::new(extra_files).await?;
                let root = &fixture.server.filesystem.base_path;
                std::fs::create_dir(root.join("nested/nested"))?;
                std::fs::write(root.join("nested/nested/inner.txt"), b"inner")?;
                std::fs::create_dir(root.join("denied-dir"))?;
                std::fs::write(root.join("denied-dir/inside.txt"), b"hidden")?;
                std::fs::create_dir(root.join("nested/request-denied.txt"))?;
                std::fs::write(root.join("nested/request-denied.txt/inside.txt"), b"hidden")?;
                fixture
                    .server
                    .filesystem
                    .update_ignored(&["denied.txt", "denied-dir", "denied-dir/**"])
                    .await;

                for path in [
                    "",
                    "nested",
                    "nested/nested",
                    "a.txt",
                    "missing",
                    "nested/missing/deeper",
                    "dir-link",
                    "file-link",
                    "broken-link",
                    "denied-link",
                    "nested/parent-link",
                    "denied.txt",
                    "denied-dir",
                    "nested/request-denied.txt",
                ] {
                    for (per_page, page, sort) in [(None, 1, NameAsc), (Some(3), 2, SizeDesc)] {
                        let fast = fixture
                            .fs
                            .async_read_dir_checked(
                                &path,
                                per_page,
                                page,
                                fixture.ignored.clone(),
                                sort,
                            )
                            .await?;
                        let reference = crate::server::filesystem::virtualfs::read_dir_checked(
                            &fixture.fs,
                            &path,
                            per_page,
                            page,
                            fixture.ignored.clone(),
                            sort,
                        )
                        .await?;

                        assert_eq!(
                            describe(fast)?,
                            describe(reference)?,
                            "path {path:?}, per_page {per_page:?}, page {page}, extra_files {extra_files}"
                        );
                    }
                }
            }

            Ok(())
        });
    }

    #[cfg(unix)]
    #[test]
    fn checked_listing_of_symlink_to_denied_dir_is_not_found() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::create_dir(root.join("denied-dir"))?;
            std::fs::write(root.join("denied-dir/inside.txt"), b"hidden")?;
            std::os::unix::fs::symlink("denied-dir", root.join("denied-dir-link"))?;
            fixture
                .server
                .filesystem
                .update_ignored(&["/denied-dir", "/denied-dir/**"])
                .await;

            let checked = fixture
                .fs
                .async_read_dir_checked(
                    &"denied-dir-link",
                    None,
                    1,
                    fixture.ignored.clone(),
                    NameAsc,
                )
                .await?;
            assert!(matches!(checked, CheckedDirectoryListing::NotFound));

            Ok(())
        });
    }

    // VirtualCapFilesystem::read_file
    #[cfg(unix)]
    #[test]
    fn reads_through_symlinks_to_denied_files_are_refused() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::os::unix::fs::symlink(".", root.join("self-link"))?;
            std::os::unix::fs::symlink("request-denied.txt", root.join("request-link"))?;

            let egg_denied = ["denied-link", "nested/denied-link", "self-link/denied.txt"];
            let request_denied = ["request-link", "self-link/request-denied.txt"];
            fixture
                .server
                .filesystem
                .update_ignored(&["/denied.txt"])
                .await;
            let merged =
                fixture
                    .fs
                    .clone()
                    .with_is_ignored(IsIgnoredFn::from(IgnoreList::from_lines([
                        "/request-denied.txt",
                    ])?));

            for (fs, denied) in [
                (&fixture.fs, egg_denied.as_slice()),
                (&merged, egg_denied.as_slice()),
                (&merged, request_denied.as_slice()),
            ] {
                for path in denied {
                    let sync = read_sync(fs, path).expect_err(path);
                    assert!(is_not_found(&sync), "{path}: {sync:?}");
                    let asynchronous = read_async(fs, path).await.expect_err(path);
                    assert!(is_not_found(&asynchronous), "{path}: {asynchronous:?}");
                }

                for path in ["file-link", "nested/parent-link", "self-link/a.txt"] {
                    assert_eq!(read_sync(fs, path)?, b"hello", "{path}");
                    assert_eq!(read_async(fs, path).await?, b"hello", "{path}");
                }
            }

            Ok(())
        });
    }

    #[cfg(unix)]
    #[test]
    fn non_primary_fs_reads_through_symlinks_to_denied_files() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let mut fs = fixture.fs.clone();
            fs.is_primary_server_fs = false;

            for path in ["denied-link", "nested/denied-link"] {
                assert_eq!(read_sync(&fs, path)?, b"hidden", "{path}");
                assert_eq!(read_async(&fs, path).await?, b"hidden", "{path}");
            }

            Ok(())
        });
    }

    // VirtualCapFilesystem::metadata
    #[cfg(unix)]
    #[test]
    fn metadata_of_symlink_to_denied_file_still_resolves() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;

            let fs = fixture.fs.clone();
            std::thread::spawn(move || fs.metadata(&"denied-link"))
                .join()
                .expect("metadata worker panicked")?;
            fixture.fs.async_metadata(&"denied-link").await?;

            Ok(())
        });
    }

    // VirtualCapFilesystem::async_read_dir
    #[cfg(unix)]
    #[test]
    fn listing_through_dir_symlink_hides_egg_denied_target_entries() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::write(root.join("cached/secret.txt"), b"hidden")?;
            std::fs::write(root.join("cached/inside.txt"), b"inner")?;
            fixture
                .server
                .filesystem
                .update_ignored(&["/cached/secret.txt"])
                .await;

            let listing = fixture.read_dir("dir-link", None, 1, NameAsc).await?;
            let names: Vec<_> = listing
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect();
            assert_eq!(names, ["inside.txt"]);

            fixture
                .fs
                .async_directory_entry(&"dir-link/inside.txt")
                .await?;
            assert!(
                fixture
                    .fs
                    .async_directory_entry(&"dir-link/secret.txt")
                    .await
                    .is_err()
            );

            Ok(())
        });
    }

    #[cfg(unix)]
    #[test]
    fn listing_through_dir_symlink_hides_request_denied_target_entries() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::write(root.join("cached/secret.txt"), b"hidden")?;
            std::fs::write(root.join("cached/inside.txt"), b"inner")?;

            let merged =
                fixture
                    .fs
                    .clone()
                    .with_is_ignored(IsIgnoredFn::from(IgnoreList::from_lines([
                        "/cached/secret.txt",
                    ])?));
            let listing = merged
                .async_read_dir(&"dir-link", None, 1, fixture.ignored.clone(), NameAsc)
                .await?;
            let names: Vec<_> = listing
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect();
            assert_eq!(names, ["inside.txt"]);

            Ok(())
        });
    }

    // VirtualCapFilesystem::async_walk_dir
    #[cfg(unix)]
    #[test]
    fn walk_through_dir_symlink_hides_egg_denied_target_entries() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::write(root.join("cached/secret.txt"), b"hidden")?;
            std::fs::write(root.join("cached/inside.txt"), b"inner")?;
            fixture
                .server
                .filesystem
                .update_ignored(&["/cached/secret.txt"])
                .await;

            let mut walk = fixture
                .fs
                .async_walk_dir(&"dir-link", IsIgnoredFn::default())
                .await?;
            let mut paths = Vec::new();
            while let Some(entry) = walk.next_entry().await {
                paths.push(entry?.1);
            }

            let names: Vec<_> = paths.iter().filter_map(|path| path.file_name()).collect();
            assert!(names.iter().any(|name| *name == "inside.txt"));
            assert!(!names.iter().any(|name| *name == "secret.txt"));

            Ok(())
        });
    }

    // VirtualCapFilesystem::walk_dir
    #[cfg(unix)]
    #[test]
    fn walk_through_dir_symlink_hides_request_denied_target_entries() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::write(root.join("cached/secret.txt"), b"hidden")?;
            std::fs::write(root.join("cached/inside.txt"), b"inner")?;

            let merged =
                fixture
                    .fs
                    .clone()
                    .with_is_ignored(IsIgnoredFn::from(IgnoreList::from_lines([
                        "/cached/secret.txt",
                    ])?));
            let paths = std::thread::spawn(move || {
                let mut walk = merged.walk_dir(&"dir-link", IsIgnoredFn::default())?;
                let mut paths = Vec::new();
                while let Some(entry) = walk.next_entry() {
                    paths.push(entry?.1);
                }
                Ok::<_, anyhow::Error>(paths)
            })
            .join()
            .expect("walk worker panicked")?;

            let names: Vec<_> = paths.iter().filter_map(|path| path.file_name()).collect();
            assert!(names.iter().any(|name| *name == "inside.txt"));
            assert!(!names.iter().any(|name| *name == "secret.txt"));

            Ok(())
        });
    }

    // VirtualCapFilesystem::async_read_dir_archive
    #[cfg(unix)]
    #[test]
    fn archive_through_dir_symlink_parent_omits_egg_denied_target_entries() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::create_dir(root.join("cached/sub"))?;
            std::fs::write(root.join("cached/sub/secret.txt"), b"SECRET-SUB")?;
            std::fs::write(root.join("cached/sub/ok.txt"), b"ok-sub")?;
            fixture
                .server
                .filesystem
                .update_ignored(&["/cached/sub/secret.txt"])
                .await;

            let mut reader = fixture
                .fs
                .async_read_dir_archive(
                    &"dir-link/sub",
                    StreamableArchiveFormat::Tar,
                    CompressionLevel::default(),
                    crate::server::filesystem::archive::create::ArchiveProgress::default(),
                    IsIgnoredFn::default(),
                )
                .await?;
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut bytes).await?;

            let entries = tar_entries(&bytes)?;
            assert!(entries.iter().any(|(path, contents)| {
                path.file_name().is_some_and(|name| name == "ok.txt") && contents == b"ok-sub"
            }));
            assert!(
                !entries
                    .iter()
                    .any(|(path, _)| path.file_name().is_some_and(|name| name == "secret.txt"))
            );
            assert!(
                !entries
                    .iter()
                    .any(|(_, contents)| contents == b"SECRET-SUB")
            );
            assert!(!bytes.windows(10).any(|window| window == b"SECRET-SUB"));

            Ok(())
        });
    }

    // VirtualCapFilesystem::async_read_dir_files_archive
    #[cfg(unix)]
    #[test]
    fn files_archive_through_dir_symlink_parent_omits_request_denied_target_entries() {
        with_one_blocking_worker(|| async {
            let fixture = ListingFixture::new(0).await?;
            let root = &fixture.server.filesystem.base_path;
            std::fs::create_dir(root.join("cached/sub"))?;
            std::fs::write(root.join("cached/sub/secret.txt"), b"SECRET-SUB")?;
            std::fs::write(root.join("cached/sub/ok.txt"), b"ok-sub")?;

            let fs = fixture
                .fs
                .clone()
                .with_is_ignored(IsIgnoredFn::from(IgnoreList::from_lines([
                    "/cached/sub/secret.txt",
                ])?));
            let mut reader = fs
                .async_read_dir_files_archive(
                    &"dir-link/sub",
                    vec![PathBuf::from("secret.txt"), PathBuf::from("ok.txt")],
                    StreamableArchiveFormat::Tar,
                    CompressionLevel::default(),
                    crate::server::filesystem::archive::create::ArchiveProgress::default(),
                    IsIgnoredFn::default(),
                )
                .await?;
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut bytes).await?;

            let entries = tar_entries(&bytes)?;
            assert!(entries.iter().any(|(path, contents)| {
                path.file_name().is_some_and(|name| name == "ok.txt") && contents == b"ok-sub"
            }));
            assert!(
                !entries
                    .iter()
                    .any(|(path, _)| path.file_name().is_some_and(|name| name == "secret.txt"))
            );
            assert!(!bytes.windows(10).any(|window| window == b"SECRET-SUB"));

            Ok(())
        });
    }
}
