use crate::{
    io::{
        SafeSliceExt,
        abort::{AbortGuard, AbortWriter},
        counting_reader::CountingReader,
        fixed_reader::FixedReader,
    },
    server::filesystem::virtualfs::IsIgnoredFn,
    utils::PortablePermissions,
};
use compact_str::ToCompactString;
use pbs_client::{
    catalog::CatalogWriter,
    pxar::{Metadata, encoder::Encoder, format::mode::IFLNK},
};
use std::{
    borrow::Cow,
    io::{Read, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

pub struct CreatePxarOptions {
    pub catalog_archive_name: String,
}

struct PxarMeta {
    mode: u32,
    mtime: u64,
}

fn pxar_meta(metadata: &cap_std::fs::Metadata) -> PxarMeta {
    PxarMeta {
        mode: PortablePermissions::from(metadata.permissions()).mode,
        mtime: metadata
            .modified()
            .map(|t| {
                t.into_std()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
            })
            .unwrap_or_default()
            .as_secs(),
    }
}

fn perm_bits(mode: u32) -> u64 {
    u64::from(mode & 0o7777)
}

struct PxarBuilder<W: Write> {
    encoder: Encoder<W>,
    catalog: CatalogWriter<Vec<u8>>,
}

impl<W: Write> PxarBuilder<W> {
    fn new(destination: W, archive_name: &str) -> std::io::Result<Self> {
        let encoder = Encoder::from_std(destination, &Metadata::dir_builder(0o755).build())?;
        let mut catalog = CatalogWriter::new(Vec::new())?;
        catalog.start_directory(archive_name.as_bytes());

        Ok(Self { encoder, catalog })
    }

    fn enter_dir(&mut self, name: &str, meta: &PxarMeta) -> std::io::Result<()> {
        let metadata = Metadata::dir_builder(perm_bits(meta.mode))
            .mtime_unix(Duration::from_secs(meta.mtime))
            .build();
        self.encoder.create_directory(name, &metadata)?;
        self.catalog.start_directory(name.as_bytes());
        Ok(())
    }

    fn exit_dir(&mut self) -> std::io::Result<()> {
        self.encoder.finish()?;
        self.catalog.end_directory()?;
        Ok(())
    }

    fn add_file(
        &mut self,
        name: &str,
        meta: &PxarMeta,
        size: u64,
        content: &mut dyn Read,
    ) -> std::io::Result<()> {
        let metadata = Metadata::file_builder(perm_bits(meta.mode))
            .mtime_unix(Duration::from_secs(meta.mtime))
            .build();
        self.encoder.add_file(&metadata, name, size, content)?;
        self.catalog
            .add_file(name.as_bytes(), size, meta.mtime as i64)?;
        Ok(())
    }

    fn add_symlink(&mut self, name: &str, target: &Path, meta: &PxarMeta) -> std::io::Result<()> {
        let metadata = Metadata::builder(IFLNK | perm_bits(meta.mode))
            .mtime_unix(Duration::from_secs(meta.mtime))
            .build();
        self.encoder.add_symlink(&metadata, name, target)?;
        self.catalog.add_symlink(name.as_bytes())?;
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<Vec<u8>> {
        self.encoder.finish()?;
        self.encoder.close()?;
        self.catalog.end_directory()?;
        self.catalog.finish()
    }
}

pub async fn create_pxar<W: Write + Send + 'static>(
    filesystem: crate::server::filesystem::cap::CapFilesystem,
    mut destination: W,
    base: &Path,
    sources: Vec<impl AsRef<Path> + Send + 'static>,
    bytes_archived: Option<Arc<AtomicU64>>,
    is_ignored: IsIgnoredFn,
    options: CreatePxarOptions,
) -> Result<(W, Vec<u8>), anyhow::Error> {
    let base = filesystem.relative_path(base);
    let (_guard, listener) = AbortGuard::new();

    tokio::task::spawn_blocking(move || {
        let writer = AbortWriter::new(&mut destination, listener);
        let mut archive = PxarBuilder::new(writer, &options.catalog_archive_name)?;

        for source in sources {
            let relative = source.as_ref();
            let source = base.join(relative);

            let source_metadata = match filesystem.symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            let Some(source) = (is_ignored)(source_metadata.file_type().into(), source) else {
                continue;
            };

            let meta = pxar_meta(&source_metadata);

            if source_metadata.is_dir() {
                let components = path_components(relative);
                enter_path_components(&mut archive, &components, &meta)?;

                let mut walker = filesystem
                    .walk_dir(source)?
                    .with_is_ignored(is_ignored.clone());

                let mut dir_stack = components
                    .into_iter()
                    .map(|c| c.to_compact_string())
                    .collect::<Vec<_>>();

                while let Some(Ok((_, path))) = walker.next_entry() {
                    let rel = match path.strip_prefix(&base) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    let metadata = match filesystem.symlink_metadata(&path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    let entry_components = path_components(rel);
                    let entry_dirs =
                        entry_components.get_slice(..entry_components.len().saturating_sub(1))?;
                    let entry_name = match entry_components.last() {
                        Some(n) => n.clone(),
                        None => continue,
                    };

                    sync_dir_stack(&mut archive, &mut dir_stack, entry_dirs)?;

                    let entry_meta = pxar_meta(&metadata);

                    if metadata.is_dir() {
                        archive.enter_dir(&entry_name, &entry_meta)?;
                        dir_stack.push(entry_name.to_compact_string());

                        if let Some(bytes_archived) = &bytes_archived {
                            bytes_archived.fetch_add(metadata.len(), Ordering::SeqCst);
                        }
                    } else if metadata.is_file() {
                        let file = filesystem.open(&path)?;
                        let reader: Box<dyn Read> = match &bytes_archived {
                            Some(bytes_archived) => Box::new(CountingReader::new_with_bytes_read(
                                file,
                                Arc::clone(bytes_archived),
                            )),
                            None => Box::new(file),
                        };
                        let mut reader =
                            FixedReader::new_with_fixed_bytes(reader, metadata.len() as usize);

                        archive.add_file(&entry_name, &entry_meta, metadata.len(), &mut reader)?;
                    } else if let Ok(target) = filesystem.read_link_contents(&path) {
                        archive.add_symlink(&entry_name, &target, &entry_meta)?;

                        if let Some(bytes_archived) = &bytes_archived {
                            bytes_archived.fetch_add(metadata.len(), Ordering::SeqCst);
                        }
                    }
                }

                while dir_stack.pop().is_some() {
                    archive.exit_dir()?;
                }

                if let Some(bytes_archived) = &bytes_archived {
                    bytes_archived.fetch_add(source_metadata.len(), Ordering::SeqCst);
                }
            } else if source_metadata.is_file() {
                let components = path_components(relative);
                let name = match components.last() {
                    Some(n) => n.clone(),
                    None => continue,
                };
                let enclosing = components.get_slice(..components.len() - 1)?;

                enter_path_components(&mut archive, enclosing, &meta)?;

                let file = filesystem.open(&source)?;
                let reader: Box<dyn Read> = match &bytes_archived {
                    Some(bytes_archived) => Box::new(CountingReader::new_with_bytes_read(
                        file,
                        Arc::clone(bytes_archived),
                    )),
                    None => Box::new(file),
                };
                let mut reader =
                    FixedReader::new_with_fixed_bytes(reader, source_metadata.len() as usize);

                archive.add_file(&name, &meta, source_metadata.len(), &mut reader)?;

                exit_path_components(&mut archive, enclosing.len())?;
            } else if let Ok(target) = filesystem.read_link_contents(&source) {
                let components = path_components(relative);
                let name = match components.last() {
                    Some(n) => n.clone(),
                    None => continue,
                };
                let enclosing = components.get_slice(..components.len() - 1)?;

                enter_path_components(&mut archive, enclosing, &meta)?;
                archive.add_symlink(&name, &target, &meta)?;
                exit_path_components(&mut archive, enclosing.len())?;

                if let Some(bytes_archived) = &bytes_archived {
                    bytes_archived.fetch_add(source_metadata.len(), Ordering::SeqCst);
                }
            }
        }

        let catalog = archive.finish()?;
        Ok((destination, catalog))
    })
    .await?
}

fn path_components(path: &Path) -> Vec<Cow<'_, str>> {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy()),
            _ => None,
        })
        .collect()
}

fn enter_path_components<W: Write>(
    archive: &mut PxarBuilder<W>,
    components: &[Cow<'_, str>],
    meta: &PxarMeta,
) -> Result<(), std::io::Error> {
    for component in components {
        archive.enter_dir(component, meta)?;
    }
    Ok(())
}

fn exit_path_components<W: Write>(
    archive: &mut PxarBuilder<W>,
    count: usize,
) -> Result<(), std::io::Error> {
    for _ in 0..count {
        archive.exit_dir()?;
    }
    Ok(())
}

fn sync_dir_stack<W: Write>(
    archive: &mut PxarBuilder<W>,
    dir_stack: &mut Vec<compact_str::CompactString>,
    target: &[Cow<'_, str>],
) -> Result<(), std::io::Error> {
    let shared = dir_stack
        .iter()
        .zip(target.iter())
        .take_while(|(a, b)| a == b)
        .count();
    while dir_stack.len() > shared {
        archive.exit_dir()?;
        dir_stack.pop();
    }

    for component in target.get_slice(shared..)? {
        archive.enter_dir(
            component,
            &PxarMeta {
                mode: 0o755,
                mtime: 0,
            },
        )?;
        dir_stack.push(component.to_compact_string());
    }

    Ok(())
}
