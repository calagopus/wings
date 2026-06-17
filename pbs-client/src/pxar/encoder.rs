use super::{Metadata, format::GoodbyeItem};
use std::{
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

const COPY_BUF_SIZE: usize = 128 * 1024;

struct DirState {
    items: Vec<GoodbyeItem>,
    entry_offset: u64,
    file_offset: Option<u64>,
    file_hash: u64,
}

pub struct Encoder<W: Write> {
    out: W,
    pos: u64,
    stack: Vec<DirState>,
    finished: bool,
}

impl<W: Write> Encoder<W> {
    pub fn from_std(out: W, root_metadata: &Metadata) -> std::io::Result<Self> {
        if !root_metadata.is_dir() {
            return Err(std::io::Error::other(
                "pxar: root metadata must describe a directory",
            ));
        }

        let mut this = Self {
            out,
            pos: 0,
            stack: Vec::new(),
            finished: false,
        };

        this.encode_metadata(root_metadata)?;
        this.stack.push(DirState {
            items: Vec::new(),
            entry_offset: 0,
            file_offset: None,
            file_hash: 0,
        });

        Ok(this)
    }

    pub fn create_directory(&mut self, name: &str, metadata: &Metadata) -> std::io::Result<()> {
        if !metadata.is_dir() {
            return Err(std::io::Error::other(
                "pxar: directory metadata must describe a directory",
            ));
        }

        let name = name.as_bytes();
        let file_offset = self.pos;
        self.encode_filename(name)?;

        let entry_offset = self.pos;
        self.encode_metadata(metadata)?;

        self.stack.push(DirState {
            items: Vec::new(),
            entry_offset,
            file_offset: Some(file_offset),
            file_hash: super::format::hash_filename(name),
        });

        Ok(())
    }

    pub fn add_file(
        &mut self,
        metadata: &Metadata,
        name: &str,
        size: u64,
        content: &mut dyn Read,
    ) -> std::io::Result<()> {
        let name = name.as_bytes();
        let file_offset = self.pos;
        self.encode_filename(name)?;
        self.encode_metadata(metadata)?;

        self.write_header(super::format::PXAR_PAYLOAD, size)?;
        self.copy_exact(content, size)?;

        self.push_item(name, file_offset)
    }

    pub fn add_symlink(
        &mut self,
        metadata: &Metadata,
        name: &str,
        target: &Path,
    ) -> std::io::Result<()> {
        let name = name.as_bytes();
        let file_offset = self.pos;
        self.encode_filename(name)?;
        self.encode_metadata(metadata)?;

        let target = target.as_os_str().as_bytes();
        let mut data = Vec::with_capacity(target.len() + 1);
        data.extend_from_slice(target);
        data.push(0);
        self.write_header(super::format::PXAR_SYMLINK, data.len() as u64)?;
        self.write_all(&data)?;

        self.push_item(name, file_offset)
    }

    pub fn finish(&mut self) -> std::io::Result<()> {
        let state = self
            .stack
            .pop()
            .ok_or_else(|| std::io::Error::other("pxar: finish called with no open directory"))?;

        let goodbye_offset = self.pos;
        let table = build_goodbye_table(&state.items, goodbye_offset, state.entry_offset)?;
        self.write_header(super::format::PXAR_GOODBYE, table.len() as u64)?;
        self.write_all(&table)?;

        if let Some(parent) = self.stack.last_mut() {
            let file_offset = state.file_offset.ok_or_else(|| {
                std::io::Error::other("pxar: nested directory without a file offset")
            })?;
            parent.items.push(GoodbyeItem {
                hash: state.file_hash,
                offset: file_offset,
                size: self.pos - file_offset,
            });
        }

        Ok(())
    }

    pub fn close(mut self) -> std::io::Result<()> {
        if !self.stack.is_empty() {
            return Err(std::io::Error::other(
                "pxar: close with directories still open",
            ));
        }
        self.out.flush()?;
        self.finished = true;
        Ok(())
    }

    fn push_item(&mut self, name: &[u8], file_offset: u64) -> std::io::Result<()> {
        let state = self
            .stack
            .last_mut()
            .ok_or_else(|| std::io::Error::other("pxar: entry written outside of a directory"))?;
        state.items.push(GoodbyeItem {
            hash: super::format::hash_filename(name),
            offset: file_offset,
            size: self.pos - file_offset,
        });

        Ok(())
    }

    fn encode_filename(&mut self, name: &[u8]) -> std::io::Result<()> {
        super::format::validate_filename(name)?;
        self.write_header(super::format::PXAR_FILENAME, name.len() as u64 + 1)?;
        self.write_all(name)?;
        self.write_all(&[0u8])
    }

    fn encode_metadata(&mut self, metadata: &Metadata) -> std::io::Result<()> {
        let stat = &metadata.stat;
        self.write_header(super::format::PXAR_ENTRY, super::format::STAT_SIZE)?;
        self.write_all(&stat.mode.to_le_bytes())?;
        self.write_all(&stat.flags.to_le_bytes())?;
        self.write_all(&stat.uid.to_le_bytes())?;
        self.write_all(&stat.gid.to_le_bytes())?;
        self.write_all(&stat.mtime.secs.to_le_bytes())?;
        self.write_all(&stat.mtime.nanos.to_le_bytes())?;
        self.write_all(&0u32.to_le_bytes())
    }

    fn write_header(&mut self, htype: u64, content_size: u64) -> std::io::Result<()> {
        self.write_all(&htype.to_le_bytes())?;
        self.write_all(&(content_size + super::format::HEADER_SIZE).to_le_bytes())
    }

    fn copy_exact(&mut self, content: &mut dyn Read, mut size: u64) -> std::io::Result<()> {
        let mut buf = vec![0; COPY_BUF_SIZE];
        while size > 0 {
            let want = size.min(buf.len() as u64) as usize;
            let slice = buf
                .get_mut(..want)
                .ok_or_else(|| std::io::Error::other("pxar: copy buffer too small"))?;
            let got = content.read(slice)?;
            if got == 0 {
                return Err(std::io::Error::other(
                    "pxar: file content ended before the declared size",
                ));
            }
            let written = slice
                .get(..got)
                .ok_or_else(|| std::io::Error::other("pxar: short read past buffer"))?;
            self.write_all(written)?;
            size -= got as u64;
        }
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.out.write_all(buf)?;
        self.pos += buf.len() as u64;
        Ok(())
    }
}

impl<W: Write> Drop for Encoder<W> {
    fn drop(&mut self) {
        debug_assert!(
            self.finished || std::thread::panicking(),
            "pxar Encoder dropped without close()",
        );
    }
}

fn build_goodbye_table(
    items: &[GoodbyeItem],
    goodbye_offset: u64,
    entry_offset: u64,
) -> std::io::Result<Vec<u8>> {
    let mut sorted = items.to_vec();
    sorted.sort_unstable_by_key(|item| item.hash);

    let n = sorted.len();
    let mut tree = vec![GoodbyeItem::default(); n];
    let mut error = None;

    super::format::bst_copy(n, |src, dest| match (sorted.get(src), tree.get_mut(dest)) {
        (Some(item), Some(slot)) => {
            let offset = goodbye_offset.saturating_sub(item.offset);
            *slot = GoodbyeItem {
                hash: item.hash,
                offset,
                size: item.size,
            };
        }
        _ => {
            error = Some(std::io::Error::other(
                "pxar: goodbye table permutation out of range",
            ))
        }
    });

    if let Some(err) = error {
        return Err(err);
    }

    let goodbye_size =
        (n as u64 + 1) * super::format::GOODBYE_ITEM_SIZE + super::format::HEADER_SIZE;
    let mut out = Vec::with_capacity((n + 1) * super::format::GOODBYE_ITEM_SIZE as usize);
    for item in &tree {
        out.extend_from_slice(&item.to_le_bytes());
    }
    let tail = GoodbyeItem {
        hash: super::format::PXAR_GOODBYE_TAIL_MARKER,
        offset: goodbye_offset.saturating_sub(entry_offset),
        size: goodbye_size,
    };
    out.extend_from_slice(&tail.to_le_bytes());

    Ok(out)
}
