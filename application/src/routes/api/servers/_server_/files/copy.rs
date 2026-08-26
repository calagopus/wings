use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::{cap::FileType, virtualfs::VirtualReadableFilesystem},
    };
    use axum::http::StatusCode;
    use compact_str::ToCompactString;
    use serde::{Deserialize, Serialize};
    use std::{
        path::Path,
        sync::{Arc, atomic::AtomicU64},
    };
    use utoipa::ToSchema;

    fn foreground() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(alias = "location")]
        path: compact_str::CompactString,
        name: Option<compact_str::CompactString>,

        #[serde(default)]
        overwrite: bool,
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
        (status = CONFLICT, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
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

        let parent = match Path::new(&data.path).parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let file_name = match Path::new(&data.path).file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, parent, &ignored)
            .await;
        let path = root.join(file_name);

        let metadata = match filesystem.async_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() && !metadata.file_type.is_dir() {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                } else {
                    metadata
                }
            }
            Err(_) => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        #[inline]
        async fn generate_new_name(
            filesystem: &dyn VirtualReadableFilesystem,
            location: &Path,
        ) -> compact_str::CompactString {
            let mut extension = location
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| compact_str::format_compact!(".{ext}"))
                .unwrap_or("".into());
            let mut base_name = location
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("")
                .to_compact_string();

            if base_name.ends_with(".tar") {
                extension = compact_str::format_compact!(".tar{extension}");
                base_name.truncate(base_name.len() - 4);
            }

            let parent = location.parent().unwrap_or(Path::new(""));
            let mut suffix = " copy".to_compact_string();

            for i in 0..51 {
                if i > 0 {
                    suffix = compact_str::format_compact!(" copy {i}");
                }

                let new_name = compact_str::format_compact!("{base_name}{suffix}{extension}");
                let new_path = parent.join(&new_name);

                if filesystem.async_symlink_metadata(&new_path).await.is_err() {
                    return new_name;
                }

                if i == 50 {
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    suffix = compact_str::format_compact!("copy.{timestamp}");

                    let final_name = compact_str::format_compact!("{base_name}{suffix}{extension}");
                    return final_name;
                }
            }

            compact_str::format_compact!("{base_name}{suffix}{extension}")
        }

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(parent, FileType::Dir)
                .await
        {
            return ApiResponse::error("parent directory not found")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let explicit_name = data.name.is_some();
        let new_name = if let Some(name) = data.name {
            name
        } else {
            generate_new_name(&*filesystem, &path).await
        };
        let file_name = parent.join(&new_name);

        let destination_parent = match file_name.parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("destination has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };
        let destination_file_name = match file_name.file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid destination file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let (destination_path, destination_filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, destination_parent, &ignored)
            .await;
        let destination_path = server
            .filesystem
            .relative_path(&destination_path.join(destination_file_name));

        if destination_filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&destination_path, metadata.file_type)
                .await
        {
            return ApiResponse::error("destination file not found")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        if explicit_name
            && !data.overwrite
            && destination_filesystem
                .async_metadata(&destination_path)
                .await
                .is_ok()
        {
            return ApiResponse::error("a file with that name already exists")
                .with_status(StatusCode::CONFLICT)
                .ok();
        }

        let total_size = match filesystem.async_directory_entry_buffer(&path, &[]).await {
            Ok(entry) => entry.size,
            Err(_) => metadata.size,
        };

        let bytes_processed = Arc::new(AtomicU64::new(0));
        let bytes_total = Arc::new(AtomicU64::new(total_size));
        let files_processed = Arc::new(AtomicU64::new(0));

        let (identifier, task) = server
            .filesystem
            .operations
            .add_operation(
                crate::server::filesystem::operations::FilesystemOperation::Copy {
                    path: path.clone(),
                    destination_path: file_name,
                    start_time: chrono::Utc::now(),
                    bytes_processed: bytes_processed.clone(),
                    bytes_total: bytes_total.clone(),
                    files_processed: files_processed.clone(),
                },
                {
                    let server = server.clone();
                    let destination_path = destination_path.clone();
                    let destination_filesystem = destination_filesystem.clone();

                    async move {
                        server
                            .filesystem
                            .copy_path(
                                crate::server::filesystem::archive::create::ArchiveProgress::new(
                                    bytes_processed,
                                    files_processed,
                                ),
                                &server,
                                metadata,
                                path,
                                filesystem.clone(),
                                destination_path,
                                destination_filesystem,
                            )
                            .await?;

                        Ok(())
                    }
                },
            )
            .await;

        if data.foreground {
            match task.await {
                Ok(Some(Ok(()))) => {}
                Ok(None) => {
                    return ApiResponse::error("file copy aborted by another source")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Ok(Some(Err(err))) => {
                    tracing::error!(
                        server = %server.uuid,
                        root = %root.display(),
                        "failed to copy file: {:#?}",
                        err,
                    );

                    return ApiResponse::error(&format!("failed to copy file: {err}"))
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        root = %root.display(),
                        "failed to copy file: {:#?}",
                        err,
                    );

                    return ApiResponse::error("failed to copy file")
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
