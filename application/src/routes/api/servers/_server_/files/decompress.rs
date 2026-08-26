use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::cap::FileType,
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::sync::{Arc, atomic::AtomicU64};
    use utoipa::ToSchema;

    fn foreground() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        root: compact_str::CompactString,
        file: compact_str::CompactString,

        #[serde(default = "foreground")]
        foreground: bool,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[derive(ToSchema, Serialize)]
    struct ResponseAccepted {
        identifier: uuid::Uuid,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = ACCEPTED, body = inline(ResponseAccepted)),
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

        let root = match server.filesystem.async_canonicalize(data.root).await {
            Ok(path) => path,
            Err(_) => {
                return ApiResponse::error("root not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let metadata = server.filesystem.async_metadata(&root).await;
        if !metadata.map(|m| m.is_dir()).unwrap_or(true) {
            return ApiResponse::error("root is not a directory")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let (destination_root, destination_filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, &root, &ignored)
            .await;

        if destination_filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&root, FileType::Dir)
                .await
        {
            return ApiResponse::error("root not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let source = root.join(data.file);

        if server
            .filesystem
            .async_is_ignored(&source, server.filesystem.probe_file_type(&source).await)
            .await
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let archive = match crate::server::filesystem::archive::Archive::open(
            server.0.clone(),
            source.clone(),
        )
        .await
        {
            Ok(archive) => archive,
            Err(err) => {
                return ApiResponse::error(&format!("failed to open archive: {err}"))
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));
        let files_processed = Arc::new(AtomicU64::new(0));

        let (identifier, task) = server
            .filesystem
            .operations
            .add_operation(
                crate::server::filesystem::operations::FilesystemOperation::Decompress {
                    path: source,
                    destination_path: root.clone(),
                    start_time: chrono::Utc::now(),
                    bytes_processed: progress.clone(),
                    bytes_total: total.clone(),
                    files_processed: files_processed.clone(),
                },
                async move {
                    archive
                        .extract(
                            destination_root,
                            destination_filesystem,
                            crate::server::filesystem::archive::create::ArchiveProgress::new(
                                progress,
                                files_processed,
                            ),
                            Some(total),
                        )
                        .await
                },
            )
            .await;

        if data.foreground {
            match task.await {
                Ok(Some(Ok(()))) => {}
                Ok(None) => {
                    return ApiResponse::error("archive decompression aborted by another source")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Ok(Some(Err(err))) => {
                    tracing::error!(
                        server = %server.uuid,
                        root = %root.display(),
                        "failed to decompress archive: {:#?}",
                        err,
                    );

                    return ApiResponse::error(&format!("failed to decompress archive: {err}"))
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        root = %root.display(),
                        "failed to decompress archive: {:#?}",
                        err,
                    );

                    return ApiResponse::error("failed to decompress archive")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            }

            ApiResponse::new_serialized(Response {}).ok()
        } else {
            ApiResponse::new_serialized(ResponseAccepted { identifier })
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
