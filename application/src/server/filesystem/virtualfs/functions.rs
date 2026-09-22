use super::{AsyncReadableFileStream, FileType, VirtualWalkEntry};
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

/// What a deny-list filter decided about one entry.
///
/// [`Self::Descend`] exists because an excluded directory is normally not walked
/// at all. A re-include rule pointing at something beneath it can only ever match
/// if the walk still enters the directory, so the filter has to distinguish
/// "excluded, stop here" from "excluded, but keep going".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreVerdict {
    Keep(PathBuf),
    Skip,
    Descend(PathBuf),
}

impl IgnoreVerdict {
    /// The path if the entry survived the filter.
    #[inline]
    pub fn keep(self) -> Option<PathBuf> {
        match self {
            Self::Keep(path) => Some(path),
            Self::Skip | Self::Descend(_) => None,
        }
    }

    /// The path if a directory walk should enter this entry, kept or not.
    #[inline]
    pub fn descend(self) -> Option<PathBuf> {
        match self {
            Self::Keep(path) | Self::Descend(path) => Some(path),
            Self::Skip => None,
        }
    }

    /// The path if a reader may still reach this entry: kept, or a directory
    /// the walk enters for the re-included entries beneath it.
    #[inline]
    pub fn reachable(self, file_type: FileType) -> Option<PathBuf> {
        match self {
            Self::Keep(path) => Some(path),
            Self::Descend(path) if file_type.is_dir() => Some(path),
            Self::Skip | Self::Descend(_) => None,
        }
    }

    #[inline]
    pub fn is_kept(&self) -> bool {
        matches!(self, Self::Keep(_))
    }

    /// The most a later filter can grant an entry an earlier filter only
    /// descended into: kept drops to descend, skip and descend stay.
    #[inline]
    fn demote(self) -> Self {
        match self {
            Self::Keep(path) => Self::Descend(path),
            Self::Skip | Self::Descend(_) => self,
        }
    }
}

impl From<Option<PathBuf>> for IgnoreVerdict {
    fn from(path: Option<PathBuf>) -> Self {
        match path {
            Some(path) => Self::Keep(path),
            None => Self::Skip,
        }
    }
}

type IsIgnoredFnInner = dyn Fn(FileType, PathBuf) -> IgnoreVerdict + Send + Sync + 'static;
type AsyncIsIgnoredFnInner = dyn Fn(FileType, PathBuf) -> futures::future::BoxFuture<'static, IgnoreVerdict>
    + Send
    + Sync
    + 'static;

/// One deny-list filter carrying both ways to run it.
///
/// A single filter is reachable from both halves of the filesystem traits, so
/// splitting it into a sync and an async type would mean threading two values
/// everywhere and letting a caller configure one but not the other. Instead the
/// caller picks a strategy by context: sync bodies deref to the blocking
/// closure, async ones use [`IsIgnoredFn::call_async`].
///
/// Filters that do no I/O leave the async half unset and run inline, so only a
/// filter that genuinely awaits pays for a boxed future.
#[derive(Clone)]
pub struct IsIgnoredFn {
    sync: Arc<IsIgnoredFnInner>,
    r#async: Option<Arc<AsyncIsIgnoredFnInner>>,
}

impl IsIgnoredFn {
    /// Pairs a blocking body with the async one it mirrors.
    ///
    /// Both must accept and reject exactly the same paths; only how they get
    /// there may differ. For anything that does no I/O, prefer `from` - the
    /// single body is then reused for both.
    pub fn new<S, SR, A, Fut>(sync: S, r#async: A) -> Self
    where
        S: Fn(FileType, PathBuf) -> SR + Send + Sync + 'static,
        SR: Into<IgnoreVerdict>,
        A: Fn(FileType, PathBuf) -> Fut + Send + Sync + 'static,
        Fut: Future<Output: Into<IgnoreVerdict>> + Send + 'static,
    {
        Self {
            sync: Arc::new(move |file_type, path| sync(file_type, path).into()),
            r#async: Some(Arc::new(move |file_type, path| {
                let fut = r#async(file_type, path);

                Box::pin(async move { fut.await.into() })
            })),
        }
    }

    pub async fn call_async(&self, file_type: FileType, path: PathBuf) -> IgnoreVerdict {
        match &self.r#async {
            Some(r#async) => r#async(file_type, path).await,
            None => (self.sync)(file_type, path),
        }
    }

    pub fn merge(self, other: IsIgnoredFn) -> IsIgnoredFn {
        let (first, second) = (Arc::clone(&self.sync), Arc::clone(&other.sync));
        let sync: Arc<IsIgnoredFnInner> =
            Arc::new(move |file_type, path| match first(file_type, path) {
                IgnoreVerdict::Skip => IgnoreVerdict::Skip,
                IgnoreVerdict::Keep(path) => second(file_type, path),
                IgnoreVerdict::Descend(path) => second(file_type, path).demote(),
            });

        if self.r#async.is_none() && other.r#async.is_none() {
            return Self::from_sync(sync);
        }

        Self {
            sync,
            r#async: Some(Arc::new(move |file_type, path| {
                let (first, second) = (self.clone(), other.clone());

                Box::pin(async move {
                    match first.call_async(file_type, path).await {
                        IgnoreVerdict::Skip => IgnoreVerdict::Skip,
                        IgnoreVerdict::Keep(path) => second.call_async(file_type, path).await,
                        IgnoreVerdict::Descend(path) => {
                            second.call_async(file_type, path).await.demote()
                        }
                    }
                })
            })),
        }
    }

    pub fn excluding(self, path: PathBuf) -> Self {
        self.merge(IsIgnoredFn::from(move |_, candidate: PathBuf| {
            if candidate == path {
                None
            } else {
                Some(candidate)
            }
        }))
    }

    #[inline]
    fn from_sync(sync: Arc<IsIgnoredFnInner>) -> Self {
        Self {
            sync,
            r#async: None,
        }
    }
}

impl Default for IsIgnoredFn {
    fn default() -> Self {
        Self::from_sync(Arc::new(|_, path| IgnoreVerdict::Keep(path)))
    }
}

impl Deref for IsIgnoredFn {
    type Target = IsIgnoredFnInner;

    fn deref(&self) -> &Self::Target {
        &*self.sync
    }
}

impl<R: Into<IgnoreVerdict>, T: Fn(FileType, PathBuf) -> R + Send + Sync + 'static> From<T>
    for IsIgnoredFn
{
    fn from(f: T) -> Self {
        Self::from_sync(Arc::new(move |file_type, path| f(file_type, path).into()))
    }
}

type DirectoryWalkFilterFnInner = dyn Fn(FileType, &Path) -> bool + Send + Sync + 'static;

#[derive(Clone)]
pub struct DirectoryWalkFilterFn(Arc<DirectoryWalkFilterFnInner>);

impl<T: Fn(FileType, &Path) -> bool + Send + Sync + 'static> From<T> for DirectoryWalkFilterFn {
    fn from(f: T) -> Self {
        Self(Arc::new(f))
    }
}

impl Deref for DirectoryWalkFilterFn {
    type Target = DirectoryWalkFilterFnInner;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

type DirectoryWalkFnInner =
    dyn Fn(VirtualWalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static;

#[derive(Clone)]
pub struct DirectoryWalkFn(Arc<DirectoryWalkFnInner>);

impl<T: Fn(VirtualWalkEntry) -> Result<(), anyhow::Error> + Send + Sync + 'static> From<T>
    for DirectoryWalkFn
{
    fn from(f: T) -> Self {
        Self(Arc::new(f))
    }
}

impl Deref for DirectoryWalkFn {
    type Target = DirectoryWalkFnInner;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

type AsyncDirectoryWalkFnInner = dyn Fn(VirtualWalkEntry) -> futures::future::BoxFuture<'static, Result<(), anyhow::Error>>
    + Send
    + Sync
    + 'static;

#[derive(Clone)]
pub struct AsyncDirectoryWalkFn(Arc<AsyncDirectoryWalkFnInner>);

impl<
    T: Fn(VirtualWalkEntry) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), anyhow::Error>> + Send + 'static,
> From<T> for AsyncDirectoryWalkFn
{
    fn from(f: T) -> Self {
        Self(Arc::new(move |entry| {
            let fut = f(entry);
            Box::pin(fut)
        }))
    }
}

impl Deref for AsyncDirectoryWalkFn {
    type Target = AsyncDirectoryWalkFnInner;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

type DirectoryStreamWalkFnInner = dyn Fn(
        VirtualWalkEntry,
        AsyncReadableFileStream,
    ) -> futures::future::BoxFuture<'static, Result<(), anyhow::Error>>
    + Send
    + Sync
    + 'static;

#[derive(Clone)]
pub struct AsyncDirectoryStreamWalkFn(Arc<DirectoryStreamWalkFnInner>);

impl<
    T: Fn(VirtualWalkEntry, AsyncReadableFileStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), anyhow::Error>> + Send + 'static,
> From<T> for AsyncDirectoryStreamWalkFn
{
    fn from(f: T) -> Self {
        Self(Arc::new(move |entry, stream| {
            let fut = f(entry, stream);
            Box::pin(fut)
        }))
    }
}

impl Deref for AsyncDirectoryStreamWalkFn {
    type Target = DirectoryStreamWalkFnInner;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type VerdictFn = fn(PathBuf) -> IgnoreVerdict;

    fn path() -> PathBuf {
        PathBuf::from("game/csgo")
    }

    fn keep(path: PathBuf) -> IgnoreVerdict {
        IgnoreVerdict::Keep(path)
    }

    fn skip(_: PathBuf) -> IgnoreVerdict {
        IgnoreVerdict::Skip
    }

    fn descend(path: PathBuf) -> IgnoreVerdict {
        IgnoreVerdict::Descend(path)
    }

    fn filter(verdict: VerdictFn) -> IsIgnoredFn {
        IsIgnoredFn::new(
            move |_: FileType, path: PathBuf| verdict(path),
            move |_: FileType, path: PathBuf| async move { verdict(path) },
        )
    }

    fn renaming(verdict: VerdictFn) -> IsIgnoredFn {
        IsIgnoredFn::new(
            move |_: FileType, _: PathBuf| verdict(PathBuf::from("renamed")),
            move |_: FileType, _: PathBuf| async move { verdict(PathBuf::from("renamed")) },
        )
    }

    fn counting(calls: Arc<AtomicUsize>) -> IsIgnoredFn {
        let async_calls = Arc::clone(&calls);

        IsIgnoredFn::new(
            move |_: FileType, path: PathBuf| {
                calls.fetch_add(1, Ordering::SeqCst);
                IgnoreVerdict::Keep(path)
            },
            move |_: FileType, path: PathBuf| {
                let calls = Arc::clone(&async_calls);

                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    IgnoreVerdict::Keep(path)
                }
            },
        )
    }

    // IgnoreVerdict
    #[test]
    fn a_descended_entry_is_walked_but_never_emitted() {
        assert_eq!(IgnoreVerdict::Keep(path()).keep(), Some(path()));
        assert_eq!(IgnoreVerdict::Descend(path()).keep(), None);
        assert_eq!(IgnoreVerdict::Skip.keep(), None);

        assert_eq!(IgnoreVerdict::Keep(path()).descend(), Some(path()));
        assert_eq!(IgnoreVerdict::Descend(path()).descend(), Some(path()));
        assert_eq!(IgnoreVerdict::Skip.descend(), None);

        assert_eq!(
            IgnoreVerdict::Keep(path()).reachable(FileType::File),
            Some(path())
        );
        assert_eq!(
            IgnoreVerdict::Keep(path()).reachable(FileType::Dir),
            Some(path())
        );
        assert_eq!(
            IgnoreVerdict::Descend(path()).reachable(FileType::Dir),
            Some(path())
        );
        assert_eq!(
            IgnoreVerdict::Descend(path()).reachable(FileType::File),
            None
        );
        assert_eq!(IgnoreVerdict::Skip.reachable(FileType::Dir), None);

        assert!(IgnoreVerdict::Keep(path()).is_kept());
        assert!(!IgnoreVerdict::Descend(path()).is_kept());
        assert!(!IgnoreVerdict::Skip.is_kept());

        assert_eq!(
            IgnoreVerdict::from(Some(path())),
            IgnoreVerdict::Keep(path())
        );
        assert_eq!(IgnoreVerdict::from(None::<PathBuf>), IgnoreVerdict::Skip);
    }

    // IsIgnoredFn::merge
    #[test]
    fn merge_takes_the_stricter_verdict_on_both_paths() {
        let cases: [(VerdictFn, VerdictFn, IgnoreVerdict); 9] = [
            (keep, keep, IgnoreVerdict::Keep(path())),
            (keep, skip, IgnoreVerdict::Skip),
            (keep, descend, IgnoreVerdict::Descend(path())),
            (skip, keep, IgnoreVerdict::Skip),
            (skip, skip, IgnoreVerdict::Skip),
            (skip, descend, IgnoreVerdict::Skip),
            (descend, keep, IgnoreVerdict::Descend(path())),
            (descend, skip, IgnoreVerdict::Skip),
            (descend, descend, IgnoreVerdict::Descend(path())),
        ];

        for (first, second, expected) in cases {
            let merged = filter(first).merge(filter(second));

            assert_eq!(merged(FileType::File, path()), expected);
            assert_eq!(
                tokio_test::block_on(merged.call_async(FileType::File, path())),
                expected
            );
        }
    }

    #[test]
    fn merge_skips_without_running_the_second_filter() {
        let calls = Arc::new(AtomicUsize::new(0));
        let merged = filter(skip).merge(counting(Arc::clone(&calls)));

        assert_eq!(merged(FileType::File, path()), IgnoreVerdict::Skip);
        assert_eq!(
            tokio_test::block_on(merged.call_async(FileType::File, path())),
            IgnoreVerdict::Skip
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn merge_hands_the_second_filter_the_first_ones_path() {
        let cases: [(VerdictFn, VerdictFn); 2] = [(keep, keep), (descend, descend)];

        for (first, expected) in cases {
            let merged = renaming(first).merge(filter(keep));
            let expected = expected(PathBuf::from("renamed"));

            assert_eq!(merged(FileType::File, path()), expected);
            assert_eq!(
                tokio_test::block_on(merged.call_async(FileType::File, path())),
                expected
            );
        }
    }
}
