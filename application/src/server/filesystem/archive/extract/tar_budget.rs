use crate::io::{SafeSliceExt, SafeSliceMutExt};
use std::{io::Read, sync::Arc};

/// Bytes `tar::Archive::entries` may read between the end of one member's data
/// and the start of the next member's data.
const TAR_MEMBER_METADATA_BUDGET: u64 = 4 * 1024 * 1024;

const BLOCK_SIZE: u64 = 512;

/// Caps the extension headers (GNU long names/links, pax records) and sparse maps
/// `tar` buffers in memory before a member, while member data passes through
/// uncounted. Wrap the archive source with [`Self::reader`] and call
/// [`Self::member`] on every entry.
#[derive(Default)]
pub struct TarMetadataBudget(Arc<parking_lot::Mutex<BudgetState>>);

impl TarMetadataBudget {
    pub fn reader<R: Read>(&self, inner: R) -> TarMetadataBudgetReader<R> {
        TarMetadataBudgetReader {
            inner,
            state: Arc::clone(&self.0),
        }
    }

    pub fn member<R: Read>(&self, entry: &mut tar::Entry<'_, R>) -> std::io::Result<()> {
        let stored = if entry.header().entry_type().is_gnu_sparse() {
            sparse_stored_size(entry)?
        } else {
            entry.size()
        };

        let mut state = self.0.lock();
        match state.frame {
            Frame::Member { header } if header == entry.raw_header_position() => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "tar member header does not match the read position",
                ));
            }
        }

        let data = state.position;
        state.free_until = stored
            .checked_next_multiple_of(BLOCK_SIZE)
            .and_then(|stored| data.checked_add(stored))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "tar member size overflow")
            })?;
        state.frame = Frame::Header;
        state.counted = 0;

        Ok(())
    }
}

fn sparse_stored_size<R: Read>(entry: &mut tar::Entry<'_, R>) -> std::io::Result<u64> {
    let entry_size = entry.header().entry_size()?;

    let Some(extensions) = entry.pax_extensions()? else {
        return Ok(entry_size);
    };

    Ok(extensions
        .map_while(Result::ok)
        .find(|extension| extension.key() == Ok("size"))
        .and_then(|extension| extension.value().ok()?.parse().ok())
        .unwrap_or(entry_size))
}

pub struct TarMetadataBudgetReader<R: Read> {
    inner: R,
    state: Arc<parking_lot::Mutex<BudgetState>>,
}

impl<R: Read> Read for TarMetadataBudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;

        let mut state = self.state.lock();
        let start = state.position;
        state.position += bytes_read as u64;

        let free = state
            .free_until
            .saturating_sub(start)
            .min(bytes_read as u64) as usize;
        state.track(start + free as u64, buf.get_slice(free..bytes_read)?)?;

        Ok(bytes_read)
    }
}

#[derive(Clone, Copy)]
enum Frame {
    Header,
    ExtensionBody(u64),
    Member { header: u64 },
}

struct BudgetState {
    position: u64,
    free_until: u64,
    frame: Frame,
    block: tar::Header,
    filled: usize,
    counted: u64,
}

impl Default for BudgetState {
    fn default() -> Self {
        Self {
            position: 0,
            free_until: 0,
            frame: Frame::Header,
            block: tar::Header::new_old(),
            filled: 0,
            counted: 0,
        }
    }
}

impl BudgetState {
    fn track(&mut self, mut position: u64, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let consumed = match self.frame {
                Frame::ExtensionBody(remaining) => {
                    let consumed = remaining.min(bytes.len() as u64);
                    self.frame = match remaining - consumed {
                        0 => Frame::Header,
                        remaining => Frame::ExtensionBody(remaining),
                    };
                    self.count(consumed)?;

                    consumed as usize
                }
                Frame::Member { .. } => {
                    self.count(bytes.len() as u64)?;

                    bytes.len()
                }
                Frame::Header => {
                    let consumed = (BLOCK_SIZE as usize - self.filled).min(bytes.len());
                    self.block
                        .as_mut_bytes()
                        .get_slice_mut(self.filled..self.filled + consumed)?
                        .copy_from_slice(bytes.get_slice(..consumed)?);
                    self.filled += consumed;

                    if self.filled == BLOCK_SIZE as usize {
                        self.filled = 0;
                        self.end_block(position + consumed as u64)?;
                    }

                    consumed
                }
            };

            position += consumed as u64;
            bytes = bytes.get_slice(consumed..)?;
        }

        Ok(())
    }

    fn end_block(&mut self, end: u64) -> std::io::Result<()> {
        if self.block.as_bytes().iter().all(|byte| *byte == 0) {
            if self.counted > 0 {
                self.count(BLOCK_SIZE)?;
            }

            return Ok(());
        }

        let header = end - BLOCK_SIZE;
        let kind = self.block.entry_type();
        let recognized = self.block.as_gnu().is_some() || self.block.as_ustar().is_some();

        self.frame = if recognized
            && (kind.is_gnu_longname() || kind.is_gnu_longlink() || kind.is_pax_local_extensions())
        {
            match self
                .block
                .entry_size()
                .ok()
                .and_then(|size| size.checked_next_multiple_of(BLOCK_SIZE))
            {
                Some(0) => Frame::Header,
                Some(size) => Frame::ExtensionBody(size),
                None => Frame::Member { header },
            }
        } else {
            Frame::Member { header }
        };

        self.count(BLOCK_SIZE)
    }

    fn count(&mut self, bytes: u64) -> std::io::Result<()> {
        self.counted += bytes;

        if self.counted > TAR_MEMBER_METADATA_BUDGET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tar member metadata exceeds the size limit",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use tar::EntryType;

    // TarMetadataBudget

    const BUDGET: u64 = TAR_MEMBER_METADATA_BUDGET;
    const MIB: u64 = 1024 * 1024;
    const LONG_LINK: &str = "././@LongLink";

    enum Part<'a> {
        Bytes(Cow<'a, [u8]>),
        Zeros(u64),
    }

    fn source<'a>(parts: &'a [Part<'a>]) -> Box<dyn Read + 'a> {
        parts.iter().fold(
            Box::new(std::io::empty()),
            |source, part| -> Box<dyn Read + 'a> {
                match part {
                    Part::Bytes(bytes) => Box::new(source.chain(bytes.as_ref())),
                    Part::Zeros(len) => Box::new(source.chain(std::io::repeat(0).take(*len))),
                }
            },
        )
    }

    /// Ends reads at every multiple of 1000 bytes, so blocks arrive in pieces.
    struct Counted<R> {
        inner: R,
        pulled: u64,
    }

    impl<R: Read> Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let until_split = (1000 - self.pulled % 1000) as usize;
            let len = buf.len().min(until_split);
            let read = self.inner.read(buf.get_slice_mut(..len)?)?;
            self.pulled += read as u64;

            Ok(read)
        }
    }

    #[derive(Debug, PartialEq)]
    struct Digest {
        len: u64,
        fnv: u64,
        head: String,
    }

    fn digest(mut reader: impl Read) -> std::io::Result<Digest> {
        let mut buf = vec![0; 64 * 1024];
        let mut head = Vec::new();
        let mut len = 0;
        let mut fnv: u64 = 0xcbf2_9ce4_8422_2325;
        loop {
            let read = reader.read(&mut buf)?;
            if read == 0 {
                break;
            }
            let chunk = buf.get_slice(..read)?;
            for byte in chunk {
                fnv = (fnv ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
            }
            head.extend(chunk.iter().take(48usize.saturating_sub(head.len())));
            len += read as u64;
        }

        Ok(Digest {
            len,
            fnv,
            head: String::from_utf8_lossy(&head).into_owned(),
        })
    }

    #[derive(Debug, PartialEq)]
    struct Seen {
        path: Digest,
        link: Option<Digest>,
        kind: EntryType,
        size: u64,
        data: Digest,
    }

    fn walk<R: Read>(
        mut archive: tar::Archive<R>,
        budget: Option<&TarMetadataBudget>,
    ) -> std::io::Result<Vec<Seen>> {
        archive.set_ignore_zeros(true);
        let mut seen = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            if let Some(budget) = budget {
                budget.member(&mut entry)?;
            }
            let path = entry.path_bytes().into_owned();
            let kind = entry.header().entry_type();
            let wanted = if path.starts_with(b"skip/") || !(kind.is_file() || kind.is_gnu_sparse())
            {
                0
            } else if path.starts_with(b"partial/") {
                1000
            } else {
                u64::MAX
            };
            seen.push(Seen {
                path: digest(path.as_slice())?,
                link: entry
                    .link_name_bytes()
                    .map(|link| digest(link.as_ref()))
                    .transpose()?,
                kind,
                size: entry.size(),
                data: digest((&mut entry).take(wanted))?,
            });
        }

        Ok(seen)
    }

    fn budgeted(parts: &[Part<'_>]) -> (std::io::Result<Vec<Seen>>, u64) {
        let budget = TarMetadataBudget::default();
        let mut counted = Counted {
            inner: source(parts),
            pulled: 0,
        };
        let walked = walk(
            tar::Archive::new(budget.reader(&mut counted)),
            Some(&budget),
        );
        (walked, counted.pulled)
    }

    fn assert_rejected(
        case: &str,
        parts: &[Part<'_>],
        max_pulled: u64,
    ) -> Result<(), anyhow::Error> {
        let (walked, pulled) = budgeted(parts);
        let error = walked
            .err()
            .ok_or_else(|| anyhow::anyhow!("{case}: accepted"))?;
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidData,
            "{case}: {error}"
        );
        assert!(pulled < max_pulled, "{case}: pulled {pulled} bytes");

        Ok(())
    }

    fn header(kind: EntryType, path: &str, size: u64) -> std::io::Result<tar::Header> {
        let mut header = tar::Header::new_gnu();
        header.set_path(path)?;
        header.set_entry_type(kind);
        header.set_size(size);
        header.set_mode(0o644);

        Ok(header)
    }

    fn sparse(
        path: &str,
        stored: u64,
        real: u64,
        blocks: &[(u64, u64)],
        extended: bool,
    ) -> std::io::Result<tar::Header> {
        let mut header = header(EntryType::GNUSparse, path, stored)?;
        let gnu = header
            .as_gnu_mut()
            .ok_or_else(|| std::io::Error::other("sparse member without a gnu header"))?;
        gnu.set_real_size(real);
        gnu.set_is_extended(extended);
        for (slot, &(offset, length)) in gnu.sparse.iter_mut().zip(blocks) {
            slot.set_offset(offset);
            slot.set_length(length);
        }

        Ok(header)
    }

    fn sparse_extension(blocks: &[(u64, u64)], extended: bool) -> Vec<u8> {
        let mut extension = tar::GnuExtSparseHeader::new();
        for (slot, &(offset, length)) in extension.sparse_mut().iter_mut().zip(blocks) {
            slot.set_offset(offset);
            slot.set_length(length);
        }
        extension.set_is_extended(extended);
        extension.as_bytes().to_vec()
    }

    fn sealed(mut header: tar::Header) -> Vec<u8> {
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    fn pax(records: &[(&str, &str)]) -> std::io::Result<Vec<u8>> {
        let mut body = Vec::new();
        for (key, value) in records {
            let fixed = key.len() + value.len() + 3;
            let mut len = fixed + 1;
            while len != fixed + len.to_string().len() {
                len = fixed + len.to_string().len();
            }
            body.extend(format!("{len} {key}={value}\n").into_bytes());
        }
        let mut bytes = sealed(header(
            EntryType::XHeader,
            "PaxHeaders/entry",
            body.len() as u64,
        )?);
        let padded = bytes.len() + body.len().next_multiple_of(512);
        bytes.extend(body);
        bytes.resize(padded, 0);

        Ok(bytes)
    }

    fn padded(data: &[u8]) -> [Part<'_>; 2] {
        let len = data.len() as u64;
        [
            Part::Bytes(data.into()),
            Part::Zeros(len.next_multiple_of(512) - len),
        ]
    }

    fn stored(header: tar::Header, data: &[u8]) -> [Part<'_>; 3] {
        let [data, padding] = padded(data);
        [Part::Bytes(sealed(header).into()), data, padding]
    }

    /// An old GNU sparse member as `tar -S --format=gnu` writes it, with 512 byte
    /// extents separated by 512 byte holes, and its real size.
    fn sparse_map(path: &str, extents: u64) -> std::io::Result<(Vec<Part<'static>>, u64)> {
        let blocks = (0..extents).map(|i| (i * 1024, 512)).collect::<Vec<_>>();
        let (main, rest) = blocks.split_at(blocks.len().min(4));
        let stored = extents * 512;
        let real = extents * 1024 - 512;

        let mut chain = Vec::new();
        let mut extensions = rest.chunks(21).peekable();
        while let Some(extension) = extensions.next() {
            chain.extend(sparse_extension(extension, extensions.peek().is_some()));
        }

        let parts = vec![
            Part::Bytes(sealed(sparse(path, stored, real, main, !rest.is_empty())?).into()),
            Part::Bytes(chain.into()),
            Part::Zeros(stored),
        ];

        Ok((parts, real))
    }

    #[test]
    fn oversized_member_metadata_fails_before_it_is_buffered() -> Result<(), anyhow::Error> {
        let declared = 1 << 40;
        let cases = [
            (
                "gnu long name",
                vec![
                    Part::Bytes(
                        sealed(header(EntryType::GNULongName, LONG_LINK, declared)?).into(),
                    ),
                    Part::Zeros(4 * BUDGET),
                ],
            ),
            (
                "gnu long link",
                vec![
                    Part::Bytes(
                        sealed(header(EntryType::GNULongLink, LONG_LINK, declared)?).into(),
                    ),
                    Part::Zeros(4 * BUDGET),
                ],
            ),
            (
                "pax extensions",
                vec![
                    Part::Bytes(
                        sealed(header(EntryType::XHeader, "PaxHeaders/x", declared)?).into(),
                    ),
                    Part::Zeros(4 * BUDGET),
                ],
            ),
            (
                "long name and long link of one member together",
                vec![
                    Part::Bytes(sealed(header(EntryType::GNULongName, LONG_LINK, 3 * MIB)?).into()),
                    Part::Zeros(3 * MIB),
                    Part::Bytes(sealed(header(EntryType::GNULongLink, LONG_LINK, 3 * MIB)?).into()),
                    Part::Zeros(3 * MIB),
                    Part::Bytes(sealed(header(EntryType::Regular, "member", 0)?).into()),
                ],
            ),
        ];

        for (case, parts) in &cases {
            assert_rejected(case, parts, 2 * BUDGET)?;
        }

        Ok(())
    }

    #[test]
    fn sparse_maps_count_against_the_budget() -> Result<(), anyhow::Error> {
        let extension_blocks = BUDGET / 512 - 400;
        let (mut parts, real) = sparse_map("partial/sparse", 4 + 21 * extension_blocks)?;
        parts.extend(stored(header(EntryType::Regular, "after", 5)?, b"after"));

        let plain = walk(tar::Archive::new(source(&parts)), None)?;
        let expected = [("partial/sparse", real, 1000), ("after", 5, 5)]
            .into_iter()
            .map(|(path, size, read)| Ok((digest(path.as_bytes())?, size, read)))
            .collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(
            plain
                .iter()
                .map(|seen| (&seen.path, seen.size, seen.data.len))
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|(path, size, read)| (path, *size, *read))
                .collect::<Vec<_>>()
        );

        let (walked, _) = budgeted(&parts);
        assert_eq!(walked?, plain);

        let extension_blocks = BUDGET / 512 + 400;
        let (parts, _) = sparse_map("skip/sparse", 4 + 21 * extension_blocks)?;
        assert_rejected("sparse map over the budget", &parts, 2 * BUDGET)?;

        Ok(())
    }

    #[test]
    fn metadata_around_a_sparse_map_is_still_counted() -> Result<(), anyhow::Error> {
        let terabyte = 1 << 40;
        let extension_blocks = BUDGET / 512 - 400;
        let extents = 4 + 21 * extension_blocks;
        let (mut after_map, _) = sparse_map("skip/sparse", extents)?;
        let map_len = 512 * (1 + extension_blocks) + 512 * extents;
        after_map.push(Part::Bytes(
            sealed(header(EntryType::GNULongName, LONG_LINK, terabyte)?).into(),
        ));
        after_map.push(Part::Zeros(4 * BUDGET));

        let lookalike = [
            sealed(sparse("lookalike", 0, 0, &[], true)?),
            sparse_extension(&[], true).repeat((3 * BUDGET / 512) as usize),
        ]
        .concat();

        // a parser that left the padding of a 1 byte long name unread would see
        // the lookalike there, and every following block's byte 505 as its byte 504
        let mut shifted_lookalike = vec![b'n'];
        shifted_lookalike.extend(lookalike.get_slice(..511)?);
        let mut shifted_long_link = header(EntryType::GNULongLink, LONG_LINK, terabyte)?;
        shifted_long_link
            .as_mut_bytes()
            .get_slice_mut(505..506)?
            .fill(1);
        let mut shifted_extension = vec![0; 512];
        shifted_extension.get_slice_mut(505..506)?.fill(1);

        let cases = [
            (
                "long name after a sparse map within the budget",
                map_len,
                after_map,
            ),
            (
                "long name whose body is shaped like a sparse map",
                0,
                vec![
                    Part::Bytes(
                        sealed(header(EntryType::GNULongName, LONG_LINK, terabyte)?).into(),
                    ),
                    Part::Bytes(lookalike.as_slice().into()),
                ],
            ),
            (
                "empty pax header before such a long name",
                0,
                vec![
                    Part::Bytes(sealed(header(EntryType::XHeader, "PaxHeaders/x", 0)?).into()),
                    Part::Bytes(
                        sealed(header(EntryType::GNULongName, LONG_LINK, terabyte)?).into(),
                    ),
                    Part::Bytes(lookalike.as_slice().into()),
                ],
            ),
            (
                "long name padding shaped like a sparse map one byte off",
                0,
                vec![
                    Part::Bytes(sealed(header(EntryType::GNULongName, LONG_LINK, 1)?).into()),
                    Part::Bytes(shifted_lookalike.into()),
                    Part::Bytes(sealed(shifted_long_link).into()),
                    Part::Bytes(shifted_extension.repeat((3 * BUDGET / 512) as usize).into()),
                ],
            ),
        ];

        for (case, before, parts) in &cases {
            assert_rejected(case, parts, before + 2 * BUDGET)?;
        }

        Ok(())
    }

    #[test]
    fn member_sizes_cannot_hide_the_metadata_that_follows() -> Result<(), anyhow::Error> {
        let data = [7u8; 512];
        let terabyte = 1 << 40;
        let header_size = 0o77_777_777_777;
        let cases = [
            (
                "sparse member with a 1 TiB hole",
                vec![Part::Bytes(
                    sealed(sparse(
                        "skip/sparse",
                        512,
                        terabyte,
                        &[(terabyte - 512, 512)],
                        false,
                    )?)
                    .into(),
                )],
            ),
            (
                "pax size below the header size",
                vec![
                    Part::Bytes(pax(&[("size", "512")])?.into()),
                    Part::Bytes(
                        sealed(header(EntryType::Regular, "skip/pax", header_size)?).into(),
                    ),
                ],
            ),
            (
                "pax size below a sparse header size",
                vec![
                    Part::Bytes(pax(&[("size", "512")])?.into()),
                    Part::Bytes(
                        sealed(sparse(
                            "skip/pax-sparse",
                            header_size,
                            terabyte,
                            &[(terabyte - 512, 512)],
                            false,
                        )?)
                        .into(),
                    ),
                ],
            ),
        ];

        for (case, mut parts) in cases {
            parts.push(Part::Bytes(data.as_slice().into()));
            assert_eq!(
                walk(tar::Archive::new(source(&parts)), None)?.len(),
                1,
                "{case}"
            );

            parts.push(Part::Bytes(
                sealed(header(EntryType::GNULongName, LONG_LINK, terabyte)?).into(),
            ));
            parts.push(Part::Zeros(4 * BUDGET));
            assert_rejected(case, &parts, 2 * BUDGET)?;
        }

        Ok(())
    }

    #[test]
    fn extension_headers_and_zero_runs_read_the_same_with_the_budget() -> Result<(), anyhow::Error>
    {
        let long_name = "n".repeat(300);
        let link_path = format!("{}/link", "l".repeat(150));
        let link_target = format!("{}/target", "t".repeat(150));
        let huge_names = [
            format!("a/{}", "a".repeat(3 * MIB as usize)),
            format!("b/{}", "b".repeat(3 * MIB as usize)),
        ];

        let mut first = tar::Builder::new(Vec::new());
        first.append_data(
            &mut header(EntryType::Regular, "placeholder", 5)?,
            &long_name,
            b"hello".as_slice(),
        )?;
        first.append_link(
            &mut header(EntryType::Symlink, "placeholder", 0)?,
            &link_path,
            &link_target,
        )?;

        let mut second = tar::Builder::new(Vec::new());
        for name in &huge_names {
            second.append_data(
                &mut header(EntryType::Regular, "placeholder", 3)?,
                name,
                b"big".as_slice(),
            )?;
        }
        second.append_data(
            &mut header(EntryType::Regular, "placeholder", 5)?,
            "after",
            b"after".as_slice(),
        )?;

        let parts = [
            Part::Zeros(2 * BUDGET),
            Part::Bytes(first.into_inner()?.into()),
            Part::Zeros(2 * BUDGET),
            Part::Bytes(second.into_inner()?.into()),
            Part::Zeros(2 * BUDGET),
        ];

        let plain = walk(tar::Archive::new(source(&parts)), None)?;
        let expected = [long_name.as_str(), link_path.as_str()]
            .into_iter()
            .chain(huge_names.iter().map(String::as_str))
            .chain(["after"])
            .map(|path| digest(path.as_bytes()))
            .collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(
            plain.iter().map(|seen| &seen.path).collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );

        let budget = TarMetadataBudget::default();
        let budgeted = walk(
            tar::Archive::new(budget.reader(source(&parts))),
            Some(&budget),
        )?;
        assert_eq!(budgeted, plain);

        Ok(())
    }

    #[test]
    fn member_data_is_never_counted_as_metadata() -> Result<(), anyhow::Error> {
        let data: Vec<u8> = (0..2 * BUDGET as usize + 1000)
            .map(|i| (i % 251) as u8)
            .collect();
        let data_len = data.len() as u64;

        let mut nested = sealed(header(EntryType::GNULongName, LONG_LINK, BUDGET + 1)?);
        nested.resize(
            nested.len() + (BUDGET as usize + 1).next_multiple_of(512),
            b'n',
        );
        nested.extend(sealed(header(EntryType::Regular, "inner", 0)?));

        let pax_path = format!("{}/pax", "p".repeat(200));
        let pax_member = pax(&[("path", &pax_path), ("size", &data_len.to_string())])?;

        let blocks = (0..26).map(|i| (i * 1024, 512)).collect::<Vec<_>>();
        let (main_blocks, rest) = blocks.split_at(4);
        let (first_extension, second_extension) = rest.split_at(21);

        let pax_sparse_stored = BUDGET + 512;
        let pax_sparse_real = BUDGET + MIB + 512;
        let pax_sparse = pax(&[("size", &pax_sparse_stored.to_string())])?;

        let mut parts = Vec::new();
        for path in ["skip/big", "partial/big", "read/big"] {
            parts.extend(stored(header(EntryType::Regular, path, data_len)?, &data));
        }
        parts.extend(stored(
            header(EntryType::Regular, "nested.tar", nested.len() as u64)?,
            &nested,
        ));
        parts.push(Part::Bytes(pax_member.into()));
        parts.extend(stored(
            header(EntryType::Regular, "pax-placeholder", 0)?,
            &data,
        ));
        parts.push(Part::Bytes(
            sealed(sparse(
                "sparse",
                26 * 512,
                25 * 1024 + 512,
                main_blocks,
                true,
            )?)
            .into(),
        ));
        parts.push(Part::Bytes(sparse_extension(first_extension, true).into()));
        parts.push(Part::Bytes(
            sparse_extension(second_extension, false).into(),
        ));
        parts.extend(padded(data.get_slice(..26 * 512)?));
        parts.extend(stored(
            header(EntryType::Regular, "after-sparse", 5)?,
            b"after",
        ));
        parts.push(Part::Bytes(pax_sparse.into()));
        parts.push(Part::Bytes(
            sealed(sparse(
                "pax-sparse",
                0,
                pax_sparse_real,
                &[(0, BUDGET), (BUDGET + MIB, 512)],
                false,
            )?)
            .into(),
        ));
        parts.extend(padded(data.get_slice(..pax_sparse_stored as usize)?));
        parts.extend(stored(
            header(EntryType::Regular, "after-pax-sparse", 5)?,
            b"after",
        ));

        let plain = walk(tar::Archive::new(source(&parts)), None)?;
        let expected = [
            ("skip/big", 0),
            ("partial/big", 1000),
            ("read/big", data_len),
            ("nested.tar", nested.len() as u64),
            (pax_path.as_str(), data_len),
            ("sparse", 25 * 1024 + 512),
            ("after-sparse", 5),
            ("pax-sparse", pax_sparse_real),
            ("after-pax-sparse", 5),
        ]
        .into_iter()
        .map(|(path, read)| Ok((digest(path.as_bytes())?, read)))
        .collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(
            plain
                .iter()
                .map(|seen| (&seen.path, seen.data.len))
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|(path, read)| (path, *read))
                .collect::<Vec<_>>()
        );

        let budget = TarMetadataBudget::default();
        let budgeted = walk(
            tar::Archive::new(budget.reader(source(&parts))),
            Some(&budget),
        )?;
        assert_eq!(budgeted, plain);

        Ok(())
    }
}
