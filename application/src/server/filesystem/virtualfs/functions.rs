use super::{AsyncReadableFileStream, FileType, VirtualWalkEntry};
use std::{ops::Deref, path::PathBuf, sync::Arc};

type IsIgnoredFnInner = dyn Fn(FileType, PathBuf) -> Option<PathBuf> + Send + Sync + 'static;
type AsyncIsIgnoredFnInner = dyn Fn(FileType, PathBuf) -> futures::future::BoxFuture<'static, Option<PathBuf>>
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
    pub fn new<S, A, Fut>(sync: S, r#async: A) -> Self
    where
        S: Fn(FileType, PathBuf) -> Option<PathBuf> + Send + Sync + 'static,
        A: Fn(FileType, PathBuf) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<PathBuf>> + Send + 'static,
    {
        Self {
            sync: Arc::new(sync),
            r#async: Some(Arc::new(move |file_type, path| {
                Box::pin(r#async(file_type, path))
            })),
        }
    }

    pub async fn call_async(&self, file_type: FileType, path: PathBuf) -> Option<PathBuf> {
        match &self.r#async {
            Some(r#async) => r#async(file_type, path).await,
            None => (self.sync)(file_type, path),
        }
    }

    pub fn merge(self, other: IsIgnoredFn) -> IsIgnoredFn {
        let (first, second) = (Arc::clone(&self.sync), Arc::clone(&other.sync));
        let sync: Arc<IsIgnoredFnInner> =
            Arc::new(move |file_type, path| second(file_type, first(file_type, path)?));

        if self.r#async.is_none() && other.r#async.is_none() {
            return Self::from_sync(sync);
        }

        Self {
            sync,
            r#async: Some(Arc::new(move |file_type, path| {
                let (first, second) = (self.clone(), other.clone());

                Box::pin(async move {
                    let path = first.call_async(file_type, path).await?;

                    second.call_async(file_type, path).await
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
        Self::from_sync(Arc::new(|_, path| Some(path)))
    }
}

impl Deref for IsIgnoredFn {
    type Target = IsIgnoredFnInner;

    fn deref(&self) -> &Self::Target {
        &*self.sync
    }
}

impl From<ignore::gitignore::Gitignore> for IsIgnoredFn {
    fn from(gi: ignore::gitignore::Gitignore) -> Self {
        Self::from_sync(Arc::new(move |file_type, path| {
            if gi.matched(&path, file_type.is_dir()).is_ignore() {
                None
            } else {
                Some(path)
            }
        }))
    }
}

impl From<Vec<ignore::gitignore::Gitignore>> for IsIgnoredFn {
    fn from(gis: Vec<ignore::gitignore::Gitignore>) -> Self {
        Self::from_sync(Arc::new(move |file_type, path| {
            for gi in &gis {
                if gi.matched(&path, file_type.is_dir()).is_ignore() {
                    return None;
                }
            }
            Some(path)
        }))
    }
}

impl<T: Fn(FileType, PathBuf) -> Option<PathBuf> + Send + Sync + 'static> From<T> for IsIgnoredFn {
    fn from(f: T) -> Self {
        Self::from_sync(Arc::new(f))
    }
}

#[cfg(test)]
mod is_ignored_fn_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn excluding_rejects_only_the_exact_path() {
        let filter = IsIgnoredFn::default().excluding(PathBuf::from("logs/archive.zip"));

        assert!(filter(FileType::File, PathBuf::from("logs/archive.zip")).is_none());
        assert!(filter(FileType::File, PathBuf::from("logs/./archive.zip")).is_none());

        assert_eq!(
            filter(FileType::File, PathBuf::from("logs/archive.zip.bak")),
            Some(PathBuf::from("logs/archive.zip.bak"))
        );
        assert_eq!(
            filter(FileType::File, PathBuf::from("archive.zip")),
            Some(PathBuf::from("archive.zip"))
        );
        assert_eq!(
            filter(FileType::Dir, PathBuf::from("logs")),
            Some(PathBuf::from("logs"))
        );
    }

    #[test]
    fn excluding_keeps_the_underlying_filter() {
        let gitignore = crate::server::filesystem::build_gitignore_matcher(["*.log"].iter())
            .expect("building the matcher failed");
        let filter = IsIgnoredFn::from(gitignore).excluding(PathBuf::from("archive.zip"));

        assert!(filter(FileType::File, PathBuf::from("latest.log")).is_none());
        assert!(filter(FileType::File, PathBuf::from("archive.zip")).is_none());
        assert_eq!(
            filter(FileType::File, PathBuf::from("server.properties")),
            Some(PathBuf::from("server.properties"))
        );
    }

    #[test]
    fn excluding_applies_to_the_async_half_too() {
        tokio_test::block_on(async {
            let filter = IsIgnoredFn::default().excluding(PathBuf::from("logs/archive.zip"));

            assert!(
                filter
                    .call_async(FileType::File, PathBuf::from("logs/archive.zip"))
                    .await
                    .is_none()
            );
            assert!(
                filter
                    .call_async(FileType::File, PathBuf::from("logs/other.zip"))
                    .await
                    .is_some()
            );
        });
    }

    #[test]
    fn path_equality_normalizes_interior_current_dir_components() {
        assert_eq!(
            Path::new("logs/./archive.zip"),
            Path::new("logs/archive.zip")
        );
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
