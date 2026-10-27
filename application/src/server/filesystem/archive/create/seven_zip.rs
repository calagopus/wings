use super::ArchiveProgress;
use crate::{
    io::{
        abort::{AbortGuard, AbortWriter},
        compression::CompressionLevel,
        fixed_reader::FixedReader,
    },
    server::filesystem::{archive::Archive, virtualfs::IsIgnoredFn},
};
use sevenz_rust2::{
    EncoderConfiguration, EncoderMethod, NtTime,
    encoder_options::{EncoderOptions, Lzma2Options},
};
use std::{
    io::{Seek, Write},
    path::Path,
};

pub struct Create7zOptions {
    pub compression_level: CompressionLevel,
    pub threads: usize,
}

pub async fn create_7z<W: Write + Seek + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    progress: ArchiveProgress,
    is_ignored: IsIgnoredFn,
    options: Create7zOptions,
) -> Result<W, anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = AbortWriter::new(destination, listener);
        let mut archive = sevenz_rust2::ArchiveWriter::new(writer)?;

        archive.set_content_methods(vec![
            EncoderConfiguration::new(EncoderMethod::LZMA2).with_options(EncoderOptions::Lzma2(
                Lzma2Options::from_level_mt(
                    options.compression_level.to_lzma2_level(),
                    crate::threading::resolve_threads(options.threads) as u32,
                    16 * 1024,
                ),
            )),
        ]);

        let mut directory_entries = chunked_vec::ChunkedVec::new();

        super::walk_sources(
            &filesystem,
            &base,
            sources,
            &is_ignored,
            |relative, path, metadata| {
                let mtime = metadata
                    .modified()
                    .map_or(None, |mtime| NtTime::try_from(mtime.into_std()).ok());
                let ctime = metadata
                    .created()
                    .map_or(None, |ctime| NtTime::try_from(ctime.into_std()).ok());

                if metadata.is_dir() {
                    if directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES {
                        directory_entries.push((relative.to_path_buf(), mtime, ctime));
                    }
                    progress.increment_bytes(metadata.len());
                } else if metadata.is_file() {
                    let file = filesystem.open(path)?;
                    let reader = progress.counting_reader(file);
                    let reader = FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                    let mut entry =
                        sevenz_rust2::ArchiveEntry::new_file(&relative.to_string_lossy());
                    if let Some(mtime) = mtime {
                        entry.has_last_modified_date = true;
                        entry.last_modified_date = mtime;
                    }
                    if let Some(ctime) = ctime {
                        entry.has_creation_date = true;
                        entry.creation_date = ctime;
                    }
                    entry.size = metadata.len();

                    archive.push_archive_entry(entry, Some(reader))?;
                    progress.increment_files();
                }

                Ok(())
            },
        )?;

        for (source_path, mtime, ctime) in directory_entries {
            let mut entry =
                sevenz_rust2::ArchiveEntry::new_directory(&source_path.to_string_lossy());
            if let Some(mtime) = mtime {
                entry.has_last_modified_date = true;
                entry.last_modified_date = mtime;
            }
            if let Some(ctime) = ctime {
                entry.has_creation_date = true;
                entry.creation_date = ctime;
            }

            archive.push_archive_entry(entry, None::<&[u8]>)?;
        }

        let mut inner = archive.finish()?.into_inner();
        inner.flush()?;

        Ok(inner)
    })
    .await?
}
