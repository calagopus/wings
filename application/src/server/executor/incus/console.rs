//! Instance console output, read from the log file liblxc keeps on the host.
//!
//! The file holds everything the process prints, whether or not anyone is connected, so output is
//! never lost or replayed across reconnects and Wings restarts.

use std::{
    io::SeekFrom,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const CHUNK: u64 = 256 * 1024;
fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    name.into()
}

/// Removes output left behind by an earlier instance of the same name.
pub(super) async fn clear(path: &Path) -> std::io::Result<()> {
    for file in [path.to_path_buf(), rotated(path)] {
        match tokio::fs::remove_file(&file).await {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
    }
    Ok(())
}

/// The retained output, oldest first.
pub(super) async fn history(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut result = Vec::new();
    for file in [rotated(path), path.to_path_buf()] {
        match tokio::fs::read(&file).await {
            Ok(data) => result.extend(data),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(result)
}

/// The last `lines` lines of `data`, without copying the rest of it around.
pub(super) fn last_lines(data: &[u8], lines: usize) -> &[u8] {
    if lines == 0 {
        return &[];
    }
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    let start = body
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(lines - 1)
        .map_or(0, |(index, _)| index + 1);
    data.get(start..).unwrap_or(data)
}

/// Follows the log file through rotations.
pub(super) struct Tail {
    path: PathBuf,
    inode: Option<u64>,
    offset: u64,
}

impl Tail {
    pub(super) fn from_start(path: PathBuf) -> Self {
        Self {
            path,
            inode: None,
            offset: 0,
        }
    }

    /// Skips what is already in the file, for reattaching to a running instance.
    pub(super) async fn from_end(path: PathBuf) -> Self {
        let metadata = tokio::fs::metadata(&path).await.ok();
        Self {
            inode: metadata.as_ref().map(MetadataExt::ino),
            offset: metadata.map_or(0, |metadata| metadata.len()),
            path,
        }
    }

    /// The next piece of new output, or `None` when there is nothing new.
    pub(super) async fn next(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let current = match tokio::fs::metadata(&self.path).await {
            Ok(metadata) => Some(metadata),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };

        if let Some(inode) = self.inode
            && current.as_ref().map(MetadataExt::ino) != Some(inode)
        {
            // Rotated away: finish the old file before moving to the new one.
            let old = rotated(&self.path);
            if tokio::fs::metadata(&old)
                .await
                .is_ok_and(|metadata| metadata.ino() == inode)
                && let Some(data) = self.read(&old).await?
            {
                return Ok(Some(data));
            }
            self.inode = None;
            self.offset = 0;
        }

        let Some(current) = current else {
            return Ok(None);
        };
        if self.inode.is_none() {
            self.inode = Some(current.ino());
            self.offset = 0;
        }
        if current.len() < self.offset {
            self.offset = 0;
        }
        if current.len() == self.offset {
            return Ok(None);
        }
        let path = self.path.clone();
        self.read(&path).await
    }

    async fn read(&mut self, path: &Path) -> std::io::Result<Option<Vec<u8>>> {
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(SeekFrom::Start(self.offset)).await?;
        let mut data = Vec::new();
        file.take(CHUNK).read_to_end(&mut data).await?;
        self.offset += data.len() as u64;
        Ok((!data.is_empty()).then_some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn drain(tail: &mut Tail) -> String {
        let mut output = Vec::new();
        while let Some(data) = tail.next().await.expect("tail should read") {
            output.extend(data);
        }
        String::from_utf8(output).expect("utf8 output")
    }

    #[tokio::test]
    async fn tail_follows_rotation_without_loss_or_repeats() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("console.log");
        let mut tail = Tail::from_start(path.clone());
        assert_eq!(drain(&mut tail).await, "");

        std::fs::write(&path, "one\n").expect("write");
        assert_eq!(drain(&mut tail).await, "one\n");
        assert_eq!(drain(&mut tail).await, "");

        std::fs::write(&path, "one\ntwo\n").expect("write");
        std::fs::rename(&path, rotated(&path)).expect("rotate");
        std::fs::write(&path, "three\n").expect("write");
        assert_eq!(drain(&mut tail).await, "two\nthree\n");

        assert_eq!(history(&path).await.expect("history"), b"one\ntwo\nthree\n");

        let mut attached = Tail::from_end(path.clone()).await;
        assert_eq!(drain(&mut attached).await, "");

        clear(&path).await.expect("clear");
        assert_eq!(history(&path).await.expect("history"), b"");
    }

    #[test]
    fn last_lines_counts_complete_and_partial_lines() {
        assert_eq!(last_lines(b"a\nb\nc\n", 2), b"b\nc\n");
        assert_eq!(last_lines(b"a\nb\nc", 1), b"c");
        assert_eq!(last_lines(b"a\n", 5), b"a\n");
        assert_eq!(last_lines(b"a\n", 0), b"");
    }
}
