use super::{ArchiveSource, create::ArchiveProgress};
use crate::io::compression::{
    CompressionType,
    reader::{CompressionReader, CompressionReaderMt},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

mod ddup;
mod itaf;
mod none;
mod pxar;
mod rar;
mod seven_zip;
mod tar;
mod tar_budget;
mod writers;
mod zip;

pub use ddup::*;
pub use itaf::*;
pub use none::*;
pub use pxar::*;
pub use rar::*;
pub use seven_zip::*;
pub use tar::*;
pub use zip::*;

fn decompressed_reader(
    source: ArchiveSource,
    compression: CompressionType,
    threads: usize,
    progress: &ArchiveProgress,
) -> Result<Box<dyn Read>, anyhow::Error> {
    if source.is_seekable() {
        Ok(Box::new(CompressionReaderMt::new(
            progress.counting_reader(source.seekable()?),
            compression,
            threads,
        )?))
    } else {
        Ok(Box::new(CompressionReader::new(
            progress.counting_reader(source.stream()),
            compression,
        )?))
    }
}

pub fn resolve_entry_path(destination: &Path, path: &Path) -> Option<PathBuf> {
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return None;
    }

    Some(super::super::cap::CapFilesystem::resolve_path(
        &destination.join(path),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // resolve_entry_path

    #[test]
    fn resolve_entry_path_resolves_plain_entries_under_the_destination() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("a/b.txt")),
            Some(PathBuf::from("logs/a/b.txt"))
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("a/b.txt")),
            Some(PathBuf::from("a/b.txt"))
        );
    }

    #[test]
    fn resolve_entry_path_strips_current_dir_components_that_tar_writers_emit() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("./a/./b.txt")),
            Some(PathBuf::from("logs/a/b.txt"))
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("./server.properties")),
            Some(PathBuf::from("server.properties"))
        );
    }

    #[test]
    fn resolve_entry_path_rejects_parent_dir_escapes() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("../config/secrets.yml")),
            None
        );
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("a/../../config/secrets.yml")),
            None
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("x/../config/config.yml")),
            None
        );
    }

    #[test]
    fn resolve_entry_path_rejects_absolute_entries() {
        assert_eq!(
            resolve_entry_path(Path::new("logs"), Path::new("/config/secrets.yml")),
            None
        );
        assert_eq!(
            resolve_entry_path(Path::new(""), Path::new("/etc/passwd")),
            None
        );
    }
}
