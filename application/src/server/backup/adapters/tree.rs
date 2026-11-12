use crate::{
    models::DirectoryEntry,
    routes::MimeCacheValue,
    server::filesystem::{
        cap::FileType,
        encode_mode,
        virtualfs::{AsyncDirectoryWalk, DirectoryWalk, FileMetadata, IsIgnoredFn},
    },
    utils::{PortablePermissions, detect_mime_type},
};
use compact_str::{CompactString, ToCompactString};
use std::path::{Path, PathBuf};

const MAX_TREE_DEPTH: usize = 1024;

pub struct FileMeta<S = ()> {
    pub file_type: FileType,
    pub mode: u32,
    pub size: u64,
    pub mtime: chrono::DateTime<chrono::Utc>,
    pub symlink: S,
}

impl<S> FileMeta<S> {
    pub fn to_directory_entry(&self, path: &Path, buffer: Option<&[u8]>) -> DirectoryEntry {
        let detected_mime = if self.file_type.is_symlink() {
            MimeCacheValue::symlink()
        } else if self.file_type.is_file() && self.size == 0 {
            MimeCacheValue::text()
        } else {
            detect_mime_type(path, buffer)
        };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(self.mode),
            mode_bits: compact_str::format_compact!("{:o}", self.mode & 0o777),
            size: self.size,
            size_physical: self.size,
            editable: self.file_type.is_file() && detected_mime.valid_utf8,
            inner_editable: self.file_type.is_file() && detected_mime.valid_inner_utf8,
            directory: false,
            file: self.file_type.is_file(),
            symlink: self.file_type.is_symlink(),
            r#virtual: true,
            mime: detected_mime.mime,
            modified: self.mtime,
            created: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
        }
    }
}

pub enum TreeEntry<S> {
    Dir {
        mode: u32,
        mtime: chrono::DateTime<chrono::Utc>,
    },
    File(FileMeta<S>),
}

pub struct TreeNode<S = ()> {
    pub size: u64,
    pub mtime: chrono::DateTime<chrono::Utc>,
    pub mode: u32,
    pub has_explicit_entry: bool,
    pub dirs: thin_vec::ThinVec<(CompactString, TreeNode<S>)>,
    pub files: thin_vec::ThinVec<(CompactString, FileMeta<S>)>,
}

impl<S> Default for TreeNode<S> {
    fn default() -> Self {
        Self {
            size: 0,
            mtime: Default::default(),
            mode: 0,
            has_explicit_entry: false,
            dirs: thin_vec::ThinVec::new(),
            files: thin_vec::ThinVec::new(),
        }
    }
}

// drops the tree iteratively, recursive dropping would overflow the stack on deeply nested trees
impl<S> Drop for TreeNode<S> {
    fn drop(&mut self) {
        while let Some((_, mut node)) = self.dirs.pop() {
            self.dirs.append(&mut node.dirs);
        }
    }
}

impl<S> TreeNode<S> {
    pub fn insert(&mut self, components: &[&str], entry: TreeEntry<S>) {
        if components.is_empty() || components.len() > MAX_TREE_DEPTH {
            return;
        }

        match entry {
            TreeEntry::Dir { mode, mtime } => {
                let node = self.upsert_dir_path(components);
                node.has_explicit_entry = true;
                node.mtime = mtime;
                node.mode = mode;
            }
            TreeEntry::File(meta) => {
                let (leaf, parents) = match components.split_last() {
                    Some(value) => value,
                    None => return,
                };

                let parent = self.upsert_dir_path(parents);
                parent.files.push((leaf.to_compact_string(), meta));
            }
        }
    }

    pub fn finish(mut self) -> Self {
        self.sort_files();
        self.aggregate_sizes();
        self
    }

    fn sort_files(&mut self) {
        self.files.reverse();
        self.files.sort_by(|(a, _), (b, _)| a.cmp(b));
        self.files.dedup_by(|(a, _), (b, _)| a == b);
        for (_, child) in self.dirs.iter_mut() {
            child.sort_files();
        }
    }

    fn upsert_dir_path(&mut self, components: &[&str]) -> &mut Self {
        let mut current = self;
        for name in components {
            let idx = match current.dirs.binary_search_by(|(n, _)| n.as_str().cmp(name)) {
                Ok(idx) => idx,
                Err(idx) => {
                    current
                        .dirs
                        .insert(idx, (name.to_compact_string(), Self::default()));
                    idx
                }
            };
            // SAFETY: `idx` is a valid index into `current.dirs` by construction above.
            current = unsafe { &mut current.dirs.get_unchecked_mut(idx).1 };
        }
        current
    }

    fn aggregate_sizes(&mut self) -> u64 {
        let mut total: u64 = self.files.iter().map(|(_, m)| m.size).sum();
        for (_, child) in self.dirs.iter_mut() {
            total = total.saturating_add(child.aggregate_sizes());
        }
        self.size = total;
        total
    }

    pub fn lookup_dir(&self, path: &Path) -> Option<&Self> {
        if path == Path::new("") || path == Path::new("/") {
            return Some(self);
        }
        let mut current = self;
        for component in path.components() {
            let name = component.as_os_str().to_str()?;
            let idx = current
                .dirs
                .binary_search_by(|(n, _)| n.as_str().cmp(name))
                .ok()?;
            current = &current.dirs.get(idx)?.1;
        }
        Some(current)
    }

    pub fn lookup_file(&self, path: &Path) -> Option<&FileMeta<S>> {
        let parent_path = path.parent()?;
        let leaf = path.file_name()?.to_str()?;

        let parent = self.lookup_dir(parent_path)?;
        let idx = parent
            .files
            .binary_search_by(|(n, _)| n.as_str().cmp(leaf))
            .ok()?;
        Some(&parent.files.get(idx)?.1)
    }

    pub fn to_directory_entry(&self, path: &Path) -> DirectoryEntry {
        let mode = if self.mode != 0 { self.mode } else { 0o755 };

        DirectoryEntry {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            mode: encode_mode(mode),
            mode_bits: compact_str::format_compact!("{:o}", mode & 0o777),
            size: self.size,
            size_physical: self.size,
            editable: false,
            inner_editable: false,
            directory: true,
            file: false,
            symlink: false,
            r#virtual: true,
            mime: MimeCacheValue::directory().mime,
            modified: self.mtime,
            created: chrono::DateTime::from_timestamp(0, 0).unwrap_or_default(),
        }
    }

    pub fn metadata(&self, path: &Path) -> Result<FileMetadata, anyhow::Error> {
        if path == Path::new("") || path == Path::new("/") {
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(0o755),
                size: 0,
                modified: None,
                created: None,
            });
        }

        if let Some(node) = self.lookup_dir(path) {
            let mode = if node.mode != 0 { node.mode } else { 0o755 };
            return Ok(FileMetadata {
                file_type: FileType::Dir,
                permissions: PortablePermissions::from_mode_dir(mode),
                size: 0,
                modified: node.has_explicit_entry.then(|| node.mtime.into()),
                created: None,
            });
        }

        if let Some(meta) = self.lookup_file(path) {
            return Ok(FileMetadata {
                file_type: meta.file_type,
                permissions: PortablePermissions::from_mode_file(meta.mode),
                size: meta.size,
                modified: Some(meta.mtime.into()),
                created: None,
            });
        }

        Err(anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        )))
    }

    pub fn lookup_entry(
        &self,
        path: &Path,
        buffer: Option<&[u8]>,
    ) -> Result<DirectoryEntry, anyhow::Error> {
        if let Some(node) = self.lookup_dir(path) {
            return Ok(node.to_directory_entry(path));
        }
        if let Some(meta) = self.lookup_file(path) {
            return Ok(meta.to_directory_entry(path, buffer));
        }
        Err(anyhow::anyhow!(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        )))
    }

    pub fn walk(&self, path: &Path, is_ignored: &IsIgnoredFn) -> Vec<(FileType, PathBuf)> {
        fn walk<S>(
            node: &TreeNode<S>,
            current_path: &Path,
            is_ignored: &IsIgnoredFn,
            out: &mut Vec<(FileType, PathBuf)>,
        ) {
            for (name, meta) in node.files.iter() {
                let child_path = current_path.join(name.as_str());
                if let Some(filtered) = (is_ignored)(meta.file_type, child_path).keep() {
                    out.push((meta.file_type, filtered));
                }
            }
            for (name, child) in node.dirs.iter() {
                let child_path = current_path.join(name.as_str());
                if let Some(filtered) = (is_ignored)(FileType::Dir, child_path.clone()).keep() {
                    out.push((FileType::Dir, filtered));
                }
                walk(child, &child_path, is_ignored, out);
            }
        }

        let mut flat = Vec::new();
        if let Some(start) = self.lookup_dir(path) {
            walk(start, path, is_ignored, &mut flat);
        }

        flat
    }
}

pub struct TreeWalk {
    items: std::vec::IntoIter<(FileType, PathBuf)>,
}

impl TreeWalk {
    pub fn new(items: Vec<(FileType, PathBuf)>) -> Self {
        Self {
            items: items.into_iter(),
        }
    }
}

impl DirectoryWalk for TreeWalk {
    fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
        self.items.next().map(Ok)
    }
}

#[async_trait::async_trait]
impl AsyncDirectoryWalk for TreeWalk {
    async fn next_entry(&mut self) -> Option<Result<(FileType, PathBuf), anyhow::Error>> {
        self.items.next().map(Ok)
    }
}
