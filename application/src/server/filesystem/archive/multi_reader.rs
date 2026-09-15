use crate::io::{SafeSliceExt, SafeSliceMutExt};
use positioned_io::ReadAt;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

/// Window pulled in when a read continues where the previous one stopped.
const READAHEAD_SEQUENTIAL: usize = 256 * 1024;
/// Window pulled in after a seek, sized for an archive header and the start of a
/// small entry so that a directory scan does not drag whole windows for a few bytes.
const READAHEAD_RANDOM: usize = 16 * 1024;

/// A simple file wrapper that allows multiple independent read cursors to exist on a single file. (Mainly for archives)
///
/// Reads are served from a read-ahead window so that decoders which pull a few
/// kilobytes at a time do not issue a `pread` each; the window grows when reads are
/// sequential and shrinks after a seek.
///
/// # Cloning
///
/// Cloning a `MultiReader` will create a new reader with its own independent cursor (same position as the original), allowing
/// multiple parts of code to read from the same file without interfering with each other's read positions.
pub struct MultiReader {
    file: Arc<File>,
    file_size: u64,
    offset: u64,
    window: Vec<u8>,
    window_start: u64,
    window_len: usize,
}

impl MultiReader {
    pub fn new(file: Arc<File>) -> std::io::Result<Self> {
        let file_size = file.metadata()?.len();

        Ok(MultiReader {
            file,
            file_size,
            offset: 0,
            window: vec![0; READAHEAD_SEQUENTIAL],
            window_start: 0,
            window_len: 0,
        })
    }

    #[inline]
    fn window_end(&self) -> u64 {
        self.window_start + self.window_len as u64
    }

    fn fill_window(&mut self) -> std::io::Result<()> {
        let size = if self.offset == self.window_end() {
            READAHEAD_SEQUENTIAL
        } else {
            READAHEAD_RANDOM
        };

        let filled = self
            .file
            .read_at(self.offset, self.window.get_slice_mut(..size)?)?;

        self.window_start = self.offset;
        self.window_len = filled;

        Ok(())
    }
}

impl Clone for MultiReader {
    fn clone(&self) -> Self {
        Self {
            file: Arc::clone(&self.file),
            file_size: self.file_size,
            offset: self.offset,
            window: vec![0; READAHEAD_SEQUENTIAL],
            window_start: 0,
            window_len: 0,
        }
    }
}

impl Read for MultiReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() >= READAHEAD_SEQUENTIAL {
            let bytes_read = self.file.read_at(self.offset, buf)?;
            self.offset += bytes_read as u64;

            return Ok(bytes_read);
        }

        if self.offset < self.window_start || self.offset >= self.window_end() {
            self.fill_window()?;

            if self.window_len == 0 {
                return Ok(0);
            }
        }

        let start = (self.offset - self.window_start) as usize;
        let available = self.window.get_slice(start..self.window_len)?;
        let count = available.len().min(buf.len());

        buf.get_slice_mut(..count)?
            .copy_from_slice(available.get_slice(..count)?);
        self.offset += count as u64;

        Ok(count)
    }
}

impl Seek for MultiReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset >= 0 {
                    self.file_size.saturating_add(offset as u64)
                } else {
                    self.file_size
                        .saturating_sub(offset.saturating_abs() as u64)
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    self.offset.saturating_add(offset as u64)
                } else {
                    self.offset.saturating_sub(offset.saturating_abs() as u64)
                }
            }
        };

        Ok(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn reader_over(data: &[u8]) -> MultiReader {
        let mut file = tempfile::tempfile().expect("tempfile");
        file.write_all(data).expect("write");
        MultiReader::new(Arc::new(file)).expect("reader")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn small_reads_come_from_the_window() {
        let data = pattern(READAHEAD_SEQUENTIAL * 3 + 17);
        let mut reader = reader_over(&data);

        let mut out = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = reader.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }

        assert_eq!(out, data);
    }

    #[test]
    fn seeking_reads_the_right_bytes_and_uses_a_small_window() {
        let data = pattern(READAHEAD_SEQUENTIAL * 2);
        let mut reader = reader_over(&data);

        reader.seek(SeekFrom::Start(300_000)).expect("seek");
        let mut buf = [0; 30];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(&buf[..], &data[300_000..300_030]);
        assert_eq!(reader.window_start, 300_000);
        assert_eq!(reader.window_len, READAHEAD_RANDOM);

        reader.seek(SeekFrom::Current(-10)).expect("seek back");
        reader.read_exact(&mut buf).expect("read inside window");
        assert_eq!(&buf[..], &data[300_020..300_050]);
        assert_eq!(reader.window_start, 300_000);
    }

    #[test]
    fn sequential_reads_grow_the_window_after_a_seek() {
        let data = pattern(READAHEAD_SEQUENTIAL * 2);
        let mut reader = reader_over(&data);

        reader.seek(SeekFrom::Start(1000)).expect("seek");
        let mut sink = vec![0; READAHEAD_RANDOM + 100];
        reader
            .read_exact(&mut sink)
            .expect("read past the small window");

        assert_eq!(reader.window_start, 1000 + READAHEAD_RANDOM as u64);
        assert_eq!(reader.window_len, READAHEAD_SEQUENTIAL);
        assert_eq!(&sink[..], &data[1000..1000 + READAHEAD_RANDOM + 100]);
    }

    #[test]
    fn large_reads_bypass_the_window() {
        let data = pattern(READAHEAD_SEQUENTIAL * 2 + 5);
        let mut reader = reader_over(&data);

        let mut big = vec![0; READAHEAD_SEQUENTIAL + 1];
        reader.read_exact(&mut big).expect("read");
        assert_eq!(&big[..], &data[..READAHEAD_SEQUENTIAL + 1]);
        assert_eq!(reader.window_len, 0);

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).expect("rest");
        assert_eq!(&rest[..], &data[READAHEAD_SEQUENTIAL + 1..]);
    }

    #[test]
    fn clones_keep_their_own_cursor_and_window() {
        let data = pattern(READAHEAD_SEQUENTIAL);
        let mut reader = reader_over(&data);
        let mut buf = [0; 100];
        reader.read_exact(&mut buf).expect("read");

        let mut clone = reader.clone();
        assert_eq!(clone.offset, 100);
        assert_eq!(clone.window_len, 0);

        clone.read_exact(&mut buf).expect("clone read");
        assert_eq!(&buf[..], &data[100..200]);

        reader.read_exact(&mut buf).expect("original read");
        assert_eq!(&buf[..], &data[100..200]);
    }

    #[test]
    fn reading_past_the_end_returns_zero() {
        let data = pattern(10);
        let mut reader = reader_over(&data);
        reader.seek(SeekFrom::End(5)).expect("seek");

        let mut buf = [0; 8];
        assert_eq!(reader.read(&mut buf).expect("read"), 0);
    }
}
