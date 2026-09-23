pub mod ddup_bak;
pub mod seven_zip;
pub mod zip;

#[cfg(test)]
mod tests {
    use super::{
        ddup_bak::VirtualDdupBakArchive, seven_zip::VirtualSevenZipArchive, zip::VirtualZipArchive,
    };
    use crate::{
        routes::AppState,
        server::{
            Server,
            filesystem::{
                archive::multi_reader::MultiReader,
                virtualfs::{
                    DirectoryWalkFilterFn, DirectoryWalkFn, IsIgnoredFn, VirtualReadableFilesystem,
                    VirtualWalkEntry,
                },
            },
        },
    };
    use std::{io::Write, path::Path, sync::Arc, time::Duration};

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nexample image contents";

    #[test]
    fn buffered_archive_entries_work_on_native_search_workers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("creating archive entry test runtime failed");

        let result = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(15), async {
                let temp = tempfile::tempdir()?;
                let state = AppState::mock();
                state
                    .config
                    .mutate_in_place_for_testing()
                    .system
                    .data_directory =
                    crate::config::SystemPath::new(temp.path().to_string_lossy().into_owned());
                let server = Server::mock(uuid::Uuid::new_v4(), state);
                server.filesystem.disk_checker.abort();

                let mut zip = zip::ZipWriter::new(tempfile::tempfile()?);
                zip.start_file("nested/data.bin", zip::write::SimpleFileOptions::default())?;
                zip.write_all(PNG)?;
                zip.start_file("empty.txt", zip::write::SimpleFileOptions::default())?;
                let zip = zip::ZipArchive::new(MultiReader::new(Arc::new(zip.finish()?))?)?;

                let mut seven_zip = sevenz_rust2::Archive::default();
                seven_zip.files = vec![
                    sevenz_rust2::ArchiveEntry {
                        name: "nested/data.bin".into(),
                        size: PNG.len() as u64,
                        ..Default::default()
                    },
                    sevenz_rust2::ArchiveEntry {
                        name: "empty.txt".into(),
                        ..Default::default()
                    },
                ];

                let content = temp.path().join("content");
                std::fs::create_dir_all(content.join("nested"))?;
                std::fs::write(content.join("nested/data.bin"), PNG)?;
                std::fs::write(content.join("empty.txt"), [])?;
                let mut ddup = ddup_bak::archive::Archive::new(tempfile::tempfile()?)?;
                ddup.add_directory(content.to_str().expect("temporary path is UTF-8"), None)?;

                let archives: Vec<Arc<dyn VirtualReadableFilesystem>> = vec![
                    Arc::new(VirtualZipArchive::new(
                        server.clone(),
                        zip,
                        Default::default(),
                    )),
                    Arc::new(VirtualSevenZipArchive::new(
                        server.clone(),
                        Arc::new(seven_zip),
                        Default::default(),
                        MultiReader::new(Arc::new(tempfile::tempfile()?))?,
                    )),
                    Arc::new(VirtualDdupBakArchive::new(
                        server,
                        Arc::new(ddup),
                        Default::default(),
                        None,
                    )),
                ];

                for filesystem in archives {
                    for (path, buffer) in [
                        ("nested/data.bin", PNG),
                        ("empty.txt", &[][..]),
                        ("nested", &[][..]),
                        ("missing", &[][..]),
                    ] {
                        let native = Arc::clone(&filesystem);
                        let sync = std::thread::spawn(move || {
                            assert!(tokio::runtime::Handle::try_current().is_err());
                            native.directory_entry_buffer(&path, buffer)
                        })
                        .join()
                        .expect("native archive entry worker panicked");
                        let asynchronous =
                            filesystem.async_directory_entry_buffer(&path, buffer).await;
                        match (sync, asynchronous) {
                            (Ok(sync), Ok(asynchronous)) => {
                                assert_eq!(
                                    serde_json::to_value(&sync)?,
                                    serde_json::to_value(asynchronous)?
                                );
                                match path {
                                    "nested/data.bin" => {
                                        assert_eq!(sync.mime, "image/png");
                                        assert_eq!(sync.size, PNG.len() as u64);
                                    }
                                    "empty.txt" => {
                                        assert!(sync.file);
                                        assert_eq!(sync.size, 0);
                                    }
                                    "nested" => assert!(sync.directory),
                                    _ => panic!("missing archive entry unexpectedly succeeded"),
                                }
                            }
                            (Err(sync), Err(asynchronous)) if path == "missing" => {
                                assert_eq!(sync.to_string(), asynchronous.to_string());
                            }
                            _ => panic!("sync and async archive entries differ for {path}"),
                        }
                    }

                    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
                        let mut walker = filesystem.walk_dir(&"", IsIgnoredFn::default())?;
                        walker.run_parallel(
                            2,
                            Some(DirectoryWalkFilterFn::from(
                                |file_type: crate::server::filesystem::cap::FileType, _: &Path| {
                                    file_type.is_file()
                                },
                            )),
                            DirectoryWalkFn::from({
                                let filesystem = Arc::clone(&filesystem);
                                move |entry: VirtualWalkEntry| {
                                    filesystem.directory_entry_buffer(&entry.path, PNG)?;
                                    Ok(())
                                }
                            }),
                        )
                    })
                    .await??;
                }

                Ok::<_, anyhow::Error>(())
            })
            .await
        });

        runtime.shutdown_timeout(Duration::from_secs(1));
        result
            .expect("archive search stalled with one blocking worker")
            .expect("archive entry test failed");
    }

    // VirtualReadableFilesystem::async_read_dir
    #[test]
    fn archive_listing_page_zero_matches_first_page() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("creating archive listing test runtime failed");

        let result = runtime.block_on(async {
            let temp = tempfile::tempdir()?;
            let state = AppState::mock();
            state
                .config
                .mutate_in_place_for_testing()
                .system
                .data_directory =
                crate::config::SystemPath::new(temp.path().to_string_lossy().into_owned());
            let server = Server::mock(uuid::Uuid::new_v4(), state);
            server.filesystem.disk_checker.abort();

            let mut zip = zip::ZipWriter::new(tempfile::tempfile()?);
            for name in ["a.txt", "b.txt", "c.txt"] {
                zip.start_file(name, zip::write::SimpleFileOptions::default())?;
            }
            let zip = zip::ZipArchive::new(MultiReader::new(Arc::new(zip.finish()?))?)?;

            let mut seven_zip = sevenz_rust2::Archive::default();
            seven_zip.files = ["a.txt", "b.txt", "c.txt"]
                .into_iter()
                .map(|name| sevenz_rust2::ArchiveEntry {
                    name: name.into(),
                    ..Default::default()
                })
                .collect();

            let content = temp.path().join("content");
            std::fs::create_dir_all(&content)?;
            for name in ["a.txt", "b.txt", "c.txt"] {
                std::fs::write(content.join(name), [])?;
            }
            let mut ddup = ddup_bak::archive::Archive::new(tempfile::tempfile()?)?;
            ddup.add_directory(content.to_str().expect("temporary path is UTF-8"), None)?;

            let archives: Vec<Arc<dyn VirtualReadableFilesystem>> = vec![
                Arc::new(VirtualZipArchive::new(
                    server.clone(),
                    zip,
                    Default::default(),
                )),
                Arc::new(VirtualSevenZipArchive::new(
                    server.clone(),
                    Arc::new(seven_zip),
                    Default::default(),
                    MultiReader::new(Arc::new(tempfile::tempfile()?))?,
                )),
                Arc::new(VirtualDdupBakArchive::new(
                    server,
                    Arc::new(ddup),
                    Default::default(),
                    None,
                )),
            ];

            for filesystem in archives {
                let list = async |per_page, page| {
                    filesystem
                        .async_read_dir(
                            &"",
                            Some(per_page),
                            page,
                            IsIgnoredFn::default(),
                            Default::default(),
                        )
                        .await
                };

                let first = list(2, 1).await?;
                let zero = list(2, 0).await?;
                assert_eq!(first.total_entries, 3);
                assert_eq!(first.entries.len(), 2);
                assert_eq!(zero.total_entries, first.total_entries);
                assert_eq!(
                    serde_json::to_value(&zero.entries)?,
                    serde_json::to_value(&first.entries)?
                );

                let unbounded = list(usize::MAX, 1).await?;
                assert_eq!(unbounded.entries.len(), 3);
            }

            Ok::<_, anyhow::Error>(())
        });

        runtime.shutdown_timeout(Duration::from_secs(1));
        result.expect("archive listing test failed");
    }
}
