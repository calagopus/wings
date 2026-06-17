use super::{Entry, EntryKind, Metadata, Stat, StatxTimestamp, Symlink, format::Header};
use std::{
    ffi::OsString,
    io::Read,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};

const SKIP_BUF_SIZE: usize = 4096;

enum State {
    Begin,
    InDirectory,
    InPayload(u64),
    Eof,
}

pub struct Decoder<R: Read> {
    input: R,
    path: PathBuf,
    path_lengths: Vec<usize>,
    pending: Option<Header>,
    state: State,
}

impl<R: Read> Iterator for Decoder<R> {
    type Item = std::io::Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_do().transpose()
    }
}

impl<R: Read> Decoder<R> {
    pub fn from_std(input: R) -> std::io::Result<Self> {
        Ok(Self {
            input,
            path: PathBuf::from("/"),
            path_lengths: Vec::new(),
            pending: None,
            state: State::Begin,
        })
    }

    pub fn contents(&mut self) -> std::io::Result<Option<Contents<'_, R>>> {
        match self.state {
            State::InPayload(_) => Ok(Some(Contents { decoder: self })),
            _ => Ok(None),
        }
    }

    fn next_do(&mut self) -> std::io::Result<Option<Entry>> {
        loop {
            match self.state {
                State::Eof => return Ok(None),
                State::Begin => return self.read_root().map(Some),
                State::InPayload(remaining) => {
                    self.skip(remaining)?;
                    self.state = State::InDirectory;
                }
                State::InDirectory => {}
            }

            let header = self.take_header()?;
            match header.htype {
                super::format::PXAR_FILENAME => return self.read_named_entry(header).map(Some),
                super::format::PXAR_GOODBYE => {
                    self.skip(header.content_size()?)?;
                    if self.path_lengths.pop().is_none() {
                        return Err(std::io::Error::other(
                            "pxar: goodbye table without open directory",
                        ));
                    }
                    if self.path_lengths.is_empty() {
                        self.state = State::Eof;
                        return Ok(None);
                    }
                }
                _ => {
                    return Err(std::io::Error::other(
                        "pxar: expected filename or goodbye in directory",
                    ));
                }
            }
        }
    }

    fn read_root(&mut self) -> std::io::Result<Entry> {
        let header = self.read_header()?;
        if header.htype != super::format::PXAR_ENTRY {
            return Err(std::io::Error::other(
                "pxar: archive does not start with an entry",
            ));
        }
        let metadata = self.read_metadata(header)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::other("pxar: root entry is not a directory"));
        }

        self.path = PathBuf::from("/");
        self.path_lengths
            .push(self.path.as_os_str().as_bytes().len());
        self.state = State::InDirectory;

        Ok(Entry {
            path: self.path.clone(),
            metadata,
            kind: EntryKind::Directory,
        })
    }

    fn read_named_entry(&mut self, filename_header: Header) -> std::io::Result<Entry> {
        let mut name = self.read_data(filename_header.content_size()?)?;
        if name.pop() != Some(0) {
            return Err(std::io::Error::other(
                "pxar: file name missing terminating zero",
            ));
        }
        super::format::validate_filename(&name)?;
        self.set_path(&name)?;

        let entry_header = self.read_header()?;
        if entry_header.htype != super::format::PXAR_ENTRY {
            return Err(std::io::Error::other(
                "pxar: filename not followed by an entry",
            ));
        }
        let metadata = self.read_metadata(entry_header)?;
        let path = self.path.clone();

        let next = self.read_header()?;
        let kind = match next.htype {
            super::format::PXAR_PAYLOAD => {
                let size = next.content_size()?;
                self.state = State::InPayload(size);
                EntryKind::File { size, offset: None }
            }
            super::format::PXAR_SYMLINK => {
                let data = self.read_data(next.content_size()?)?;
                self.state = State::InDirectory;
                EntryKind::Symlink(Symlink { data })
            }
            super::format::PXAR_FILENAME | super::format::PXAR_GOODBYE => {
                self.pending = Some(next);
                self.path_lengths
                    .push(self.path.as_os_str().as_bytes().len());
                self.state = State::InDirectory;
                EntryKind::Directory
            }
            _ => return Err(std::io::Error::other("pxar: unsupported entry type")),
        };

        Ok(Entry {
            path,
            metadata,
            kind,
        })
    }

    fn read_metadata(&mut self, header: Header) -> std::io::Result<Metadata> {
        if header.content_size()? != super::format::STAT_SIZE {
            return Err(std::io::Error::other(
                "pxar: entry has an unexpected stat size",
            ));
        }
        let buf = self.read_data(super::format::STAT_SIZE)?;
        let stat = Stat {
            mode: read_u64(&buf, 0)?,
            flags: read_u64(&buf, 8)?,
            uid: read_u32(&buf, 16)?,
            gid: read_u32(&buf, 20)?,
            mtime: StatxTimestamp {
                secs: read_u64(&buf, 24)? as i64,
                nanos: read_u32(&buf, 32)?,
            },
        };

        Ok(Metadata { stat })
    }

    fn set_path(&mut self, name: &[u8]) -> std::io::Result<()> {
        let keep = *self
            .path_lengths
            .last()
            .ok_or_else(|| std::io::Error::other("pxar: path stack underflow"))?;
        let mut bytes = std::mem::take(&mut self.path).into_os_string().into_vec();
        bytes.truncate(keep);
        let mut path = PathBuf::from(OsString::from_vec(bytes));
        path.push(OsString::from_vec(name.to_vec()));
        self.path = path;

        Ok(())
    }

    fn take_header(&mut self) -> std::io::Result<Header> {
        match self.pending.take() {
            Some(header) => Ok(header),
            None => self.read_header(),
        }
    }

    fn read_header(&mut self) -> std::io::Result<Header> {
        let mut buf = [0; 16];
        self.input.read_exact(&mut buf)?;
        let header = Header {
            htype: read_u64(&buf, 0)?,
            full_size: read_u64(&buf, 8)?,
        };
        header.content_size()?;

        Ok(header)
    }

    fn read_data(&mut self, size: u64) -> std::io::Result<Vec<u8>> {
        let size = usize::try_from(size).map_err(std::io::Error::other)?;
        let mut buf = vec![0; size];
        self.input.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn skip(&mut self, mut len: u64) -> std::io::Result<()> {
        let mut scratch = [0; SKIP_BUF_SIZE];
        while len > 0 {
            let want = len.min(scratch.len() as u64) as usize;
            let slice = scratch
                .get_mut(..want)
                .ok_or_else(|| std::io::Error::other("pxar: skip buffer too small"))?;
            self.input.read_exact(slice)?;
            len -= want as u64;
        }

        Ok(())
    }
}

pub struct Contents<'a, R: Read> {
    decoder: &'a mut Decoder<R>,
}

impl<R: Read> Read for Contents<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = match self.decoder.state {
            State::InPayload(remaining) => remaining,
            _ => return Ok(0),
        };
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = remaining.min(buf.len() as u64) as usize;
        let slice = buf
            .get_mut(..want)
            .ok_or_else(|| std::io::Error::other("pxar: read buffer too small"))?;
        let got = self.decoder.input.read(slice)?;
        self.decoder.state = State::InPayload(remaining - got as u64);

        Ok(got)
    }
}

fn read_u64(buf: &[u8], at: usize) -> std::io::Result<u64> {
    let array: [u8; 8] = buf
        .get(at..at + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| std::io::Error::other("pxar: truncated u64 field"))?;
    Ok(u64::from_le_bytes(array))
}

fn read_u32(buf: &[u8], at: usize) -> std::io::Result<u32> {
    let array: [u8; 4] = buf
        .get(at..at + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| std::io::Error::other("pxar: truncated u32 field"))?;
    Ok(u32::from_le_bytes(array))
}
