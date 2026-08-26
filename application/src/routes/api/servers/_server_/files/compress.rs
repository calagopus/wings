use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::{
            archive::{ArchiveFormat, generated_archive_name},
            cap::FileType,
            virtualfs::IsIgnoredFn,
        },
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, atomic::AtomicU64},
    };
    use utoipa::ToSchema;

    fn foreground() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        format: ArchiveFormat,
        name: Option<compact_str::CompactString>,

        #[serde(default)]
        root: compact_str::CompactString,
        files: Vec<compact_str::CompactString>,

        #[serde(default = "foreground")]
        foreground: bool,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    pub struct Response {
        identifier: uuid::Uuid,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = crate::models::DirectoryEntry),
        (status = ACCEPTED, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = match crate::server::filesystem::RequestIgnored::compile(&data.ignored) {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "rejecting request, subuser ignored files cannot be compiled: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, Path::new(&data.root), &ignored)
            .await;

        let metadata = filesystem.async_symlink_metadata(&root).await;
        if !metadata.map_or(true, |m| m.file_type.is_dir()) {
            return ApiResponse::error("root is not a directory")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let archive_name = data
            .name
            .unwrap_or_else(|| generated_archive_name(data.format.extension()));
        let file_name = root.join(&archive_name);

        let parent = match file_name.parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let file_name = match file_name.file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let (destination_root, destination_filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, parent, &ignored)
            .await;
        let destination_path = destination_root.join(file_name);

        if destination_filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&destination_path, FileType::File)
                .await
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let excluded_destination = destination_filesystem
            .is_primary_server_fs()
            .then(|| destination_path.clone());

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));
        let files_processed = Arc::new(AtomicU64::new(0));

        let (identifier, task) =
            server
                .filesystem
                .operations
                .add_operation(
                    crate::server::filesystem::operations::FilesystemOperation::Compress {
                        path: PathBuf::from(&data.root),
                        files: data.files.iter().map(PathBuf::from).collect(),
                        destination_path: PathBuf::from(&data.root).join(archive_name),
                        start_time: chrono::Utc::now(),
                        bytes_processed: progress.clone(),
                        bytes_total: total.clone(),
                        files_processed: files_processed.clone(),
                    },
                    {
                        let root = root.clone();
                        let server = server.0.clone();
                        let filesystem = filesystem.clone();
                        let destination_path = destination_path.clone();
                        let destination_filesystem = destination_filesystem.clone();

                        async move {
                            let mut ignored: IsIgnoredFn =
                                server.filesystem.get_ignored().into();
                            if let Some(excluded_destination) = excluded_destination {
                                ignored = ignored.excluding(excluded_destination);
                            }

                            let writer = tokio::task::spawn_blocking(move || {
                                destination_filesystem.create_seekable_file(&destination_path)
                            })
                            .await??;

                            let mut total_size = 0;
                            for file in &data.files {
                                let directory_entry = match filesystem
                                    .async_directory_entry_buffer(&root.join(file), &[])
                                    .await
                                {
                                    Ok(entry) => entry,
                                    Err(_) => continue,
                                };

                                total_size += directory_entry.size;
                            }

                            total.store(total_size, std::sync::atomic::Ordering::Relaxed);

                            match data.format {
                            ArchiveFormat::Tar
                            | ArchiveFormat::TarGz
                            | ArchiveFormat::TarXz
                            | ArchiveFormat::TarLzip
                            | ArchiveFormat::TarBz2
                            | ArchiveFormat::TarLz4
                            | ArchiveFormat::TarZstd => {
                                crate::server::filesystem::archive::create::create_tar(
                                    server.filesystem.clone(),
                                    writer,
                                    &root,
                                    data.files,
                                    crate::server::filesystem::archive::create::ArchiveProgress::new(progress, files_processed),
                                    ignored,
                                    crate::server::filesystem::archive::create::CreateTarOptions {
                                        compression_type: data.format.compression_format(),
                                        compression_level: state.config.load()
                                            .system
                                            .backups
                                            .compression_level,
                                        threads: state.config.load().api.file_compression_threads,
                                    },
                                )
                                .await
                            }
                            ArchiveFormat::Zip => {
                                crate::server::filesystem::archive::create::create_zip(
                                    server.filesystem.clone(),
                                    writer,
                                    &root,
                                    data.files,
                                    crate::server::filesystem::archive::create::ArchiveProgress::new(progress, files_processed),
                                    ignored,
                                    crate::server::filesystem::archive::create::CreateZipOptions {
                                        compression_level: state.config.load()
                                            .system
                                            .backups
                                            .compression_level,
                                    },
                                )
                                .await
                            }
                            ArchiveFormat::SevenZip => {
                                crate::server::filesystem::archive::create::create_7z(
                                    server.filesystem.clone(),
                                    writer,
                                    &root,
                                    data.files,
                                    crate::server::filesystem::archive::create::ArchiveProgress::new(progress, files_processed),
                                    ignored,
                                    crate::server::filesystem::archive::create::Create7zOptions {
                                        compression_level: state.config.load()
                                            .system
                                            .backups
                                            .compression_level,
                                        threads: state.config.load().api.file_compression_threads,
                                    },
                                )
                                .await
                            }
                        }?;

                            Ok(())
                        }
                    },
                )
                .await;

        if data.foreground {
            match task.await {
                Ok(Some(Ok(()))) => {}
                Ok(None) => {
                    return ApiResponse::error("archive compression aborted by another source")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Ok(Some(Err(err))) => {
                    tracing::error!(
                        server = %server.uuid,
                        root = %root.display(),
                        "failed to compress files: {:#?}",
                        err,
                    );

                    return ApiResponse::error(&format!("failed to compress files: {err}"))
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        root = %root.display(),
                        "failed to compress files: {:#?}",
                        err,
                    );

                    return ApiResponse::error("failed to compress files")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            }

            ApiResponse::new_serialized(
                destination_filesystem
                    .async_directory_entry(&destination_path)
                    .await?,
            )
            .ok()
        } else {
            ApiResponse::new_serialized(Response { identifier })
                .with_status(StatusCode::ACCEPTED)
                .ok()
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
