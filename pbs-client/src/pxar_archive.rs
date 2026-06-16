use pxar::encoder::sync::Encoder;
use pxar::{EntryKind, Metadata, PxarVariant};
use std::io::{self, Read, Write};
use std::path::Component;
use std::time::Duration;

fn perm_bits(mode: u32) -> u64 {
    u64::from(mode & 0o7777)
}

fn dir_metadata(mode: u32, mtime: u64) -> Metadata {
    Metadata::dir_builder(perm_bits(mode))
        .mtime_unix(Duration::from_secs(mtime))
        .build()
}

fn file_metadata(mode: u32, mtime: u64) -> Metadata {
    Metadata::file_builder(perm_bits(mode))
        .mtime_unix(Duration::from_secs(mtime))
        .build()
}

fn symlink_metadata(mode: u32, mtime: u64) -> Metadata {
    Metadata::builder(pxar::format::mode::IFLNK | perm_bits(mode))
        .mtime_unix(Duration::from_secs(mtime))
        .build()
}

fn normal_components(path: &std::path::Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Convert a tar byte stream into a pxar archive byte stream.
///
/// The tar entries are replayed into pxar's hierarchical encoder using a
/// directory stack, so the resulting archive is the `root.pxar` PBS stores.
pub fn tar_to_pxar<R: Read, W: Write>(tar: R, pxar_out: W) -> io::Result<()> {
    let mut encoder = Encoder::from_std(pxar_out, &Metadata::dir_builder(0o755).build())?;

    let mut archive = tar::Archive::new(tar);
    let mut stack: Vec<String> = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header().clone();
        let components = normal_components(&entry.path()?);

        let Some((name, parents)) = components.split_last() else {
            continue;
        };

        let mode = header.mode().unwrap_or(0o644);
        let mtime = header.mtime().unwrap_or(0);

        let shared = stack
            .iter()
            .zip(parents.iter())
            .take_while(|(a, b)| a == b)
            .count();
        while stack.len() > shared {
            encoder.finish()?;
            stack.pop();
        }
        for parent in parents.get(shared..).unwrap_or(&[]) {
            encoder.create_directory(parent, &Metadata::dir_builder(0o755).build())?;
            stack.push(parent.clone());
        }

        match header.entry_type() {
            tar::EntryType::Directory => {
                encoder.create_directory(name, &dir_metadata(mode, mtime))?;
                stack.push(name.clone());
            }
            tar::EntryType::Regular => {
                let size = header.size().unwrap_or(0);
                encoder.add_file(&file_metadata(mode, mtime), name, size, &mut entry)?;
            }
            tar::EntryType::Symlink => {
                if let Some(target) = entry.link_name()? {
                    encoder.add_symlink(&symlink_metadata(mode, mtime), name, target)?;
                }
            }
            _ => {}
        }
    }

    while stack.pop().is_some() {
        encoder.finish()?;
    }
    encoder.finish()?;
    encoder.close()?;

    Ok(())
}

/// Convert a pxar archive byte stream into a tar byte stream.
///
/// Used to restore, download and browse a PBS `root.pxar` snapshot through the
/// existing tar-based machinery.
pub fn pxar_to_tar<R: Read, W: Write>(pxar: R, tar_out: W) -> io::Result<()> {
    let mut decoder = pxar::decoder::sync::Decoder::from_std(PxarVariant::Unified(pxar))?;
    let mut builder = tar::Builder::new(tar_out);

    while let Some(entry) = decoder.next() {
        let entry = entry?;
        let components = normal_components(entry.path());
        if components.is_empty() {
            continue;
        }
        let path = components.join("/");

        let metadata = entry.metadata();
        let mode = (metadata.stat.mode & 0o7777) as u32;
        let mtime = metadata.stat.mtime.secs.max(0) as u64;

        let mut header = tar::Header::new_gnu();
        header.set_mode(mode);
        header.set_mtime(mtime);
        header.set_uid(0);
        header.set_gid(0);

        match entry.kind() {
            EntryKind::Directory => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                builder.append_data(&mut header, format!("{path}/"), io::empty())?;
            }
            EntryKind::File { size, .. } => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(*size);
                match decoder.contents()? {
                    Some(mut contents) => builder.append_data(&mut header, path, &mut contents)?,
                    None => builder.append_data(&mut header, path, io::empty())?,
                }
            }
            EntryKind::Symlink(target) => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                builder.append_link(&mut header, path, target.as_os_str())?;
            }
            _ => {}
        }
    }

    builder.into_inner()?.flush()?;

    Ok(())
}
