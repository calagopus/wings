use super::super::{Archive, ExtractOptions, create::ArchiveProgress};
use crate::{
    io::{
        abort::{AbortGuard, AbortReader},
        compression::reader::CompressionReaderMt,
    },
    server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub async fn extract_none(
    archive: Archive,
    destination: PathBuf,
    destination_filesystem: Arc<dyn VirtualWritableFilesystem>,
    progress: ArchiveProgress,
    total: Option<Arc<AtomicU64>>,
    options: ExtractOptions,
) -> Result<(), anyhow::Error> {
    let Archive {
        compression,
        server,
        source,
        ..
    } = archive;

    let (file, path) = source.file()?;

    let Some(file_name) = path
        .file_stem()
        .and_then(|stem| options.resolve(&destination, Path::new(stem)))
    else {
        return Err(anyhow::anyhow!("Invalid file name"));
    };

    if destination_filesystem.is_ignored(&file_name, FileType::File) {
        return Err(anyhow::anyhow!("Destination file is ignored"));
    }

    let metadata = server.filesystem.async_metadata(&path).await?;

    if let Some(total) = &total {
        total.store(metadata.len(), Ordering::Relaxed);
    }

    let (guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        let (read_progress, write_progress) = options.progress(&progress);
        let reader = read_progress.counting_reader(file);
        let reader = CompressionReaderMt::new(reader, compression, options.threads(&server))?;
        let mut reader = AbortReader::new(reader, listener);

        options.on_file(&file_name);

        let mut writer =
            write_progress.counting_writer(destination_filesystem.create_file_with_metadata(
                &file_name,
                Some(metadata.permissions().into()),
                metadata.modified().ok().map(|modified| modified.into_std()),
            )?);

        crate::io::copy(&mut reader, &mut writer)?;
        writer.flush()?;
        drop(writer);

        write_progress.increment_files();

        Ok(())
    })
    .await??;

    drop(guard);

    Ok(())
}
