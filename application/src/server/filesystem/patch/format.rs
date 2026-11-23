use crate::io::SafeSliceExt;
use diffy::{
    binary::{BinaryBlockKind, BinaryPatch},
    patch_set::{FileMode, FileOperation, ParseOptions, PatchKind, PatchSet},
};
use std::{
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitOperation {
    Create,
    Delete,
    Modify,
    Rename,
    Copy,
}

enum PatchData<'a> {
    Git(PatchKind<'a, [u8]>),
    Bsdiff(&'a [u8]),
}

pub struct FilePatch<'a> {
    pub operation: GitOperation,
    pub source: Option<PathBuf>,
    pub target: Option<PathBuf>,
    /// `Some` when the patch changes the executable bit (or sets it on a new file).
    pub executable: Option<bool>,
    data: PatchData<'a>,
}

impl<'a> FilePatch<'a> {
    fn sanitize_path(path: &[u8]) -> Result<PathBuf, anyhow::Error> {
        let path = std::str::from_utf8(path)
            .map_err(|_| anyhow::anyhow!("patch path is not valid utf-8"))?;
        if path.contains('\0') {
            return Err(anyhow::anyhow!("patch path contains a nul byte"));
        }

        let mut sanitized = PathBuf::new();
        for component in Path::new(path).components() {
            match component {
                Component::Normal(part) => sanitized.push(part),
                Component::CurDir => {}
                _ => return Err(anyhow::anyhow!("patch path {path:?} leaves the root")),
            }
        }

        if sanitized.as_os_str().is_empty() {
            return Err(anyhow::anyhow!("patch path is empty"));
        }

        Ok(sanitized)
    }

    fn mode_change(
        old: Option<&FileMode>,
        new: Option<&FileMode>,
    ) -> Result<Option<bool>, anyhow::Error> {
        for mode in [old, new].into_iter().flatten() {
            if matches!(mode, FileMode::Symlink | FileMode::Gitlink) {
                return Err(anyhow::anyhow!(
                    "symlink and submodule patches are not supported"
                ));
            }
        }

        Ok(match (old, new) {
            (_, None) => None,
            (Some(old), Some(new)) if old == new => None,
            (_, Some(new)) => Some(*new == FileMode::Executable),
        })
    }

    /// Parses a git patch (`git diff`, `git diff --binary` or `git format-patch` output),
    pub fn parse_git(input: &'a [u8], strip: usize) -> Result<Vec<Self>, anyhow::Error> {
        let mut patches = Vec::new();

        for file_patch in PatchSet::parse_bytes(input, ParseOptions::gitdiff()) {
            let file_patch = file_patch?;
            let executable = Self::mode_change(file_patch.old_mode(), file_patch.new_mode())?;

            let (operation, source, target) = match file_patch.operation().strip_prefix(strip) {
                FileOperation::Create(path) => (
                    GitOperation::Create,
                    None,
                    Some(Self::sanitize_path(&path)?),
                ),
                FileOperation::Delete(path) => (
                    GitOperation::Delete,
                    Some(Self::sanitize_path(&path)?),
                    None,
                ),
                FileOperation::Modify { original, modified } => {
                    let original = Self::sanitize_path(&original)?;
                    let modified = Self::sanitize_path(&modified)?;
                    if original != modified {
                        return Err(anyhow::anyhow!(
                            "patch modifies {} under a different name {}",
                            original.display(),
                            modified.display()
                        ));
                    }

                    (GitOperation::Modify, Some(original), Some(modified))
                }
                FileOperation::Rename { from, to } => (
                    GitOperation::Rename,
                    Some(Self::sanitize_path(&from)?),
                    Some(Self::sanitize_path(&to)?),
                ),
                FileOperation::Copy { from, to } => (
                    GitOperation::Copy,
                    Some(Self::sanitize_path(&from)?),
                    Some(Self::sanitize_path(&to)?),
                ),
            };

            patches.push(Self {
                operation,
                source,
                target,
                executable,
                data: PatchData::Git(file_patch.into_patch()),
            });
        }

        if patches.is_empty() {
            return Err(anyhow::anyhow!("patch contains no file changes"));
        }

        let mut touched = std::collections::HashSet::new();
        for patch in &patches {
            let mut paths = vec![&patch.source, &patch.target];
            paths.dedup();

            for path in paths.into_iter().flatten() {
                if !touched.insert(path) {
                    return Err(anyhow::anyhow!(
                        "patch touches {} more than once",
                        path.display()
                    ));
                }
            }
        }

        Ok(patches)
    }

    /// Parses a bsdiff 4.x patch (as produced by `bsdiff`) for the file at `path`.
    pub fn parse_bsdiff(input: &'a [u8], path: &str) -> Result<Self, anyhow::Error> {
        let path = Self::sanitize_path(path.as_bytes())?;

        Ok(Self {
            operation: GitOperation::Modify,
            source: Some(path.clone()),
            target: Some(path),
            executable: None,
            data: PatchData::Bsdiff(input),
        })
    }

    /// Applies this file's changes to `base`, refusing to produce more than `cap` bytes.
    pub fn apply(&self, base: &[u8], cap: u64) -> Result<Vec<u8>, anyhow::Error> {
        let output = match &self.data {
            PatchData::Git(PatchKind::Text(patch)) => diffy::apply_bytes(base, patch)?,
            PatchData::Git(PatchKind::Binary(BinaryPatch::Full { forward, .. })) => {
                let data = Base85Lines(forward.data.data).inflate(forward.data.size, cap)?;
                match forward.kind {
                    BinaryBlockKind::Literal => data,
                    BinaryBlockKind::Delta => DeltaCursor::apply(base, &data, cap)?,
                }
            }
            PatchData::Bsdiff(patch) => CappedWriter::bspatch(patch, base, cap)?,
            PatchData::Git(PatchKind::Binary(BinaryPatch::Marker)) => {
                return Err(anyhow::anyhow!(
                    "binary patch has no data, generate it with `git diff --binary`"
                ));
            }
        };

        if output.len() as u64 > cap {
            return Err(anyhow::anyhow!("patched file exceeds the size limit"));
        }

        if self.operation == GitOperation::Delete && !output.is_empty() {
            return Err(anyhow::anyhow!("file contents do not match the deletion"));
        }

        Ok(output)
    }
}

struct Base85Lines<'a>(&'a [u8]);

impl Base85Lines<'_> {
    fn digit(byte: u8) -> Option<u32> {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'Z' => byte - b'A' + 10,
            b'a'..=b'z' => byte - b'a' + 36,
            _ => b"!#$%&()*+-;<=>?@^_`{|}~".iter().position(|&c| c == byte)? as u8 + 62,
        };

        Some(u32::from(digit))
    }

    fn decode(&self) -> Result<Vec<u8>, anyhow::Error> {
        let data = self.0;
        let mut output = Vec::with_capacity(data.len() / 5 * 4);

        for line in data.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some((&length, encoded)) = line.split_first() else {
                continue;
            };

            let length = match length {
                b'A'..=b'Z' => (length - b'A' + 1) as usize,
                b'a'..=b'z' => (length - b'a' + 27) as usize,
                _ => return Err(anyhow::anyhow!("invalid binary patch line length")),
            };
            let (chunks, rest) = encoded.as_chunks::<5>();
            if !rest.is_empty() || chunks.len() * 4 < length {
                return Err(anyhow::anyhow!("invalid binary patch line"));
            }

            let start = output.len();
            for chunk in chunks {
                let mut value: u32 = 0;
                for &byte in chunk {
                    value = Self::digit(byte)
                        .and_then(|digit| value.checked_mul(85)?.checked_add(digit))
                        .ok_or_else(|| anyhow::anyhow!("invalid base85 data"))?;
                }

                output.extend_from_slice(&value.to_be_bytes());
            }
            output.truncate(start + length);
        }

        Ok(output)
    }

    fn inflate(&self, size: u64, cap: u64) -> Result<Vec<u8>, anyhow::Error> {
        if size > cap {
            return Err(anyhow::anyhow!("patched file exceeds the size limit"));
        }

        let compressed = self.decode()?;
        let mut output = Vec::with_capacity(size as usize);
        flate2::read::ZlibDecoder::new(compressed.as_slice())
            .take(size.saturating_add(1))
            .read_to_end(&mut output)?;

        if output.len() as u64 != size {
            return Err(anyhow::anyhow!(
                "binary patch data does not match its declared size"
            ));
        }

        Ok(output)
    }
}

struct DeltaCursor<'a> {
    data: &'a [u8],
}

impl<'a> DeltaCursor<'a> {
    fn byte(&mut self) -> Result<u8, anyhow::Error> {
        let (&byte, rest) = self
            .data
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("truncated binary delta"))?;
        self.data = rest;

        Ok(byte)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], anyhow::Error> {
        let bytes = self
            .data
            .get_slice(..len)
            .map_err(|_| anyhow::anyhow!("truncated binary delta"))?;
        self.data = self.data.get_slice(len..)?;

        Ok(bytes)
    }

    fn size(&mut self) -> Result<u64, anyhow::Error> {
        let mut size: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            if shift > 63 {
                return Err(anyhow::anyhow!("binary delta size overflows"));
            }
            size |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(size);
            }
            shift += 7;
        }
    }

    fn masked_le(&mut self, control: u8, masks: &[u8]) -> Result<usize, anyhow::Error> {
        let mut value = 0usize;
        for (index, &mask) in masks.iter().enumerate() {
            if control & mask != 0 {
                value |= (self.byte()? as usize) << (index * 8);
            }
        }

        Ok(value)
    }

    fn apply(base: &[u8], delta: &'a [u8], cap: u64) -> Result<Vec<u8>, anyhow::Error> {
        let mut cursor = Self { data: delta };

        if cursor.size()? != base.len() as u64 {
            return Err(anyhow::anyhow!(
                "binary delta does not match the current file"
            ));
        }
        let size = cursor.size()?;
        if size > cap {
            return Err(anyhow::anyhow!("patched file exceeds the size limit"));
        }

        let mut output = Vec::with_capacity(size as usize);
        while !cursor.data.is_empty() {
            let control = cursor.byte()?;
            let chunk = if control & 0x80 != 0 {
                let offset = cursor.masked_le(control, &[0x01, 0x02, 0x04, 0x08])?;
                let len = match cursor.masked_le(control >> 4, &[0x01, 0x02, 0x04])? {
                    0 => 0x10000,
                    len => len,
                };

                base.get_slice(offset..offset.saturating_add(len))
                    .map_err(|_| anyhow::anyhow!("binary delta copies outside the current file"))?
            } else if control == 0 {
                return Err(anyhow::anyhow!("unexpected binary delta opcode 0"));
            } else {
                cursor.bytes(control as usize)?
            };

            if (output.len() + chunk.len()) as u64 > size {
                return Err(anyhow::anyhow!("binary delta exceeds its declared size"));
            }
            output.extend_from_slice(chunk);
        }

        if output.len() as u64 != size {
            return Err(anyhow::anyhow!(
                "binary delta does not match its declared size"
            ));
        }

        Ok(output)
    }
}

struct CappedWriter {
    buffer: Vec<u8>,
    cap: u64,
}

impl CappedWriter {
    fn bspatch(patch: &[u8], base: &[u8], cap: u64) -> Result<Vec<u8>, anyhow::Error> {
        let patcher = qbsdiff::Bspatch::new(patch)?;
        let size = patcher.hint_target_size();
        if size > cap {
            return Err(anyhow::anyhow!("patched file exceeds the size limit"));
        }

        let mut writer = Self {
            buffer: Vec::with_capacity(size as usize),
            cap,
        };
        patcher.apply(base, &mut writer)?;

        Ok(writer.buffer)
    }
}

impl Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if (self.buffer.len() + buf.len()) as u64 > self.cap {
            return Err(std::io::Error::other("patched file exceeds the size limit"));
        }
        self.buffer.extend_from_slice(buf);

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
