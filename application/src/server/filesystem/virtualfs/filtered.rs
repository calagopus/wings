use super::{
    AsyncDirectoryStreamWalk, AsyncDirectoryWalk, AsyncFileRead, ByteRange, DirectoryListing,
    DirectoryWalk, FileMetadata, FileRead, IsIgnoredFn, VirtualReadableFilesystem,
};
use crate::{
    io::compression::CompressionLevel,
    models::{DirectoryEntry, DirectorySortingMode},
    server::filesystem::{archive::StreamableArchiveFormat, cap::FileType},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub struct VirtualFilteredFilesystem {
    pub inner: Arc<dyn VirtualReadableFilesystem>,
    pub is_ignored: IsIgnoredFn,
}

impl VirtualFilteredFilesystem {
    fn denied() -> anyhow::Error {
        anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        ))
    }

    fn check_reachable(&self, file_type: FileType, path: &Path) -> Result<(), anyhow::Error> {
        match (self.is_ignored)(file_type, path.to_path_buf()).reachable(file_type) {
            Some(_) => Ok(()),
            None => Err(Self::denied()),
        }
    }

    fn check_entry(
        &self,
        path: &Path,
        entry: DirectoryEntry,
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let file_type = if entry.directory {
            FileType::Dir
        } else if entry.symlink {
            FileType::Symlink
        } else {
            FileType::File
        };
        self.check_reachable(file_type, path)?;

        Ok(entry)
    }

    fn merged(&self, is_ignored: IsIgnoredFn) -> IsIgnoredFn {
        self.is_ignored.clone().merge(is_ignored)
    }
}

#[async_trait::async_trait]
impl VirtualReadableFilesystem for VirtualFilteredFilesystem {
    fn is_primary_server_fs(&self) -> bool {
        self.inner.is_primary_server_fs()
    }
    fn is_ignored(&self, path: &Path, file_type: FileType) -> bool {
        self.inner.is_ignored(path, file_type)
            || (self.is_ignored)(file_type, path.to_path_buf())
                .reachable(file_type)
                .is_none()
    }
    fn is_fast(&self) -> bool {
        self.inner.is_fast()
    }
    fn is_writable(&self) -> bool {
        self.inner.is_writable()
    }

    fn backing_server(&self) -> &crate::server::Server {
        self.inner.backing_server()
    }

    fn metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.metadata(path)?;
        self.check_reachable(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    async fn async_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.async_metadata(path).await?;
        self.check_reachable(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    fn symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.symlink_metadata(path)?;
        self.check_reachable(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }
    async fn async_symlink_metadata(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<FileMetadata, anyhow::Error> {
        let metadata = self.inner.async_symlink_metadata(path).await?;
        self.check_reachable(metadata.file_type, path.as_ref())?;

        Ok(metadata)
    }

    fn resolve_reachable(
        &self,
        file_type: FileType,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_reachable(file_type, path.as_ref())?;
        let resolved = self.inner.resolve_reachable(file_type, path)?;
        self.check_reachable(file_type, &resolved)?;

        Ok(resolved)
    }
    async fn async_resolve_reachable(
        &self,
        file_type: FileType,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_reachable(file_type, path.as_ref())?;
        let resolved = self.inner.async_resolve_reachable(file_type, path).await?;
        self.check_reachable(file_type, &resolved)?;

        Ok(resolved)
    }

    async fn async_directory_entry(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let entry = self.inner.async_directory_entry(path).await?;

        self.check_entry(path.as_ref(), entry)
    }
    fn directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let entry = self.inner.directory_entry_buffer(path, buffer)?;

        self.check_entry(path.as_ref(), entry)
    }
    async fn async_directory_entry_buffer(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        buffer: &[u8],
    ) -> Result<DirectoryEntry, anyhow::Error> {
        let entry = self
            .inner
            .async_directory_entry_buffer(path, buffer)
            .await?;

        self.check_entry(path.as_ref(), entry)
    }
    fn directory_entry_from_metadata(
        &self,
        path: &Path,
        metadata: &cap_std::fs::Metadata,
        buffer: Option<&[u8]>,
    ) -> Option<DirectoryEntry> {
        let entry = self
            .inner
            .directory_entry_from_metadata(path, metadata, buffer)?;

        self.check_entry(path, entry).ok()
    }

    async fn async_read_dir(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        per_page: Option<usize>,
        page: usize,
        is_ignored: IsIgnoredFn,
        sort: DirectorySortingMode,
    ) -> Result<DirectoryListing, anyhow::Error> {
        self.check_reachable(FileType::Dir, path.as_ref())?;

        self.inner
            .async_read_dir(path, per_page, page, self.merged(is_ignored), sort)
            .await
    }

    fn walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn DirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        self.check_reachable(FileType::Dir, path.as_ref())?;

        self.inner.walk_dir(path, self.merged(is_ignored))
    }
    async fn async_walk_dir<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryWalk + Send + Sync + 'a>, anyhow::Error> {
        self.check_reachable(FileType::Dir, path.as_ref())?;

        self.inner
            .async_walk_dir(path, self.merged(is_ignored))
            .await
    }
    async fn async_walk_dir_stream<'a>(
        &'a self,
        path: &(dyn AsRef<Path> + Send + Sync),
        is_ignored: IsIgnoredFn,
    ) -> Result<Box<dyn AsyncDirectoryStreamWalk + Send + Sync + 'a>, anyhow::Error> {
        self.check_reachable(FileType::Dir, path.as_ref())?;

        self.inner
            .async_walk_dir_stream(path, self.merged(is_ignored))
            .await
    }

    fn read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<FileRead, anyhow::Error> {
        self.check_reachable(FileType::File, path.as_ref())?;

        self.inner.read_file(path, range)
    }
    async fn async_read_file(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        range: Option<ByteRange>,
    ) -> Result<AsyncFileRead, anyhow::Error> {
        self.check_reachable(FileType::File, path.as_ref())?;

        self.inner.async_read_file(path, range).await
    }
    fn read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_reachable(FileType::Symlink, path.as_ref())?;

        self.inner.read_symlink(path)
    }
    async fn async_read_symlink(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
    ) -> Result<PathBuf, anyhow::Error> {
        self.check_reachable(FileType::Symlink, path.as_ref())?;

        self.inner.async_read_symlink(path).await
    }

    async fn async_read_dir_archive(
        &self,
        path: &(dyn AsRef<Path> + Send + Sync),
        archive_format: StreamableArchiveFormat,
        compression_level: CompressionLevel,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        is_ignored: IsIgnoredFn,
    ) -> Result<crate::io::fallible_reader::FalliblePipeReader, anyhow::Error> {
        self.check_reachable(FileType::Dir, path.as_ref())?;

        self.inner
            .async_read_dir_archive(
                path,
                archive_format,
                compression_level,
                progress,
                self.merged(is_ignored),
            )
            .await
    }

    async fn close(&self) -> Result<(), anyhow::Error> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{Server, filesystem::RequestIgnored};

    fn hidden_vault(server: &Server) -> VirtualFilteredFilesystem {
        let root = server.filesystem.base_path.to_path_buf();
        std::fs::create_dir_all(root.join("plugins/Vault")).unwrap();
        std::fs::write(root.join("plugins/Vault/config.yml"), b"secret").unwrap();
        std::fs::write(root.join("plugins/Vault/other.yml"), b"public").unwrap();

        VirtualFilteredFilesystem {
            inner: Arc::new(server.filesystem.cap_filesystem.get_virtual(server.clone())),
            is_ignored: RequestIgnored::compile(&["plugins/Vault/config.yml"])
                .unwrap()
                .lexical_filter(server, std::path::Path::new("")),
        }
    }

    fn is_not_found(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound)
        })
    }

    // VirtualFilteredFilesystem
    #[test]
    fn hidden_entries_read_as_missing() {
        Server::with_mock(|server| async move {
            let fs = hidden_vault(&server);

            for path in [
                "plugins/Vault/config.yml",
                "/plugins/Vault/config.yml",
                "./plugins/Vault/config.yml",
            ] {
                assert!(is_not_found(&fs.metadata(&path).err().unwrap()), "{path}");
                assert!(
                    is_not_found(&fs.async_symlink_metadata(&path).await.err().unwrap()),
                    "{path}"
                );
                assert!(
                    is_not_found(&fs.read_file(&path, None).err().unwrap()),
                    "{path}"
                );
                assert!(fs.async_read_file(&path, None).await.is_err(), "{path}");
                assert!(fs.async_directory_entry(&path).await.is_err(), "{path}");
            }

            for path in ["plugins/Vault/other.yml", "/plugins/Vault/other.yml"] {
                assert!(fs.metadata(&path).is_ok(), "{path}");
                assert!(fs.read_file(&path, None).is_ok(), "{path}");
            }
            assert!(fs.metadata(&"plugins/Vault").is_ok());
        });
    }

    #[test]
    fn listings_and_walks_omit_hidden_entries() {
        Server::with_mock(|server| async move {
            let fs = hidden_vault(&server);

            let listing = fs
                .async_read_dir(
                    &"plugins/Vault",
                    None,
                    1,
                    IsIgnoredFn::default(),
                    DirectorySortingMode::default(),
                )
                .await
                .unwrap();
            let names: Vec<_> = listing
                .entries
                .iter()
                .map(|entry| entry.name.to_string())
                .collect();
            assert_eq!(names, ["other.yml"]);

            let mut walk = fs.walk_dir(&"", IsIgnoredFn::default()).unwrap();
            let mut walked = Vec::new();
            while let Some(entry) = walk.next_entry() {
                walked.push(entry.unwrap().1);
            }
            assert!(walked.iter().any(|path| path.ends_with("other.yml")));
            assert!(!walked.iter().any(|path| path.ends_with("config.yml")));

            let mut walk = fs
                .async_walk_dir(&"plugins", IsIgnoredFn::default())
                .await
                .unwrap();
            let mut walked = Vec::new();
            while let Some(entry) = walk.next_entry().await {
                walked.push(entry.unwrap().1);
            }
            assert!(walked.iter().any(|path| path.ends_with("other.yml")));
            assert!(!walked.iter().any(|path| path.ends_with("config.yml")));
        });
    }
}
