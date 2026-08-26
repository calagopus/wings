use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::{
            backup::adapters::BackupAdapter,
            filesystem::{archive::StreamableArchiveFormat, cap::FileType},
        },
    };
    use axum::{extract::Path, http::StatusCode};
    use futures::StreamExt;
    use serde::{Deserialize, Serialize};
    use std::{
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    };
    use tokio::io::AsyncWriteExt;
    use utoipa::ToSchema;

    fn foreground() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        adapter: BackupAdapter,

        server: uuid::Uuid,
        #[schema(value_type = String)]
        path: PathBuf,
        #[serde(default)]
        archive_format: StreamableArchiveFormat,

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
            "backup" = uuid::Uuid,
            description = "The backup uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        Path(backup_id): Path<uuid::Uuid>,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = match crate::server::filesystem::RequestIgnored::compile(&data.ignored) {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    backup = %backup_id,
                    "rejecting request, subuser ignored files cannot be compiled: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let backup = match state
            .backup_manager
            .find_adapter(&state, data.adapter, backup_id)
            .await?
        {
            Some(backup) => backup,
            None => {
                return ApiResponse::error("backup not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let server = match state.server_manager.get_server(data.server).await {
            Some(server) => server,
            None => {
                return ApiResponse::error("server not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let parent = match data.path.parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let file_name = match data.path.file_name() {
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

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));

        let (identifier, task) = server
            .filesystem
            .operations
            .add_operation(
                crate::server::filesystem::operations::FilesystemOperation::ExportBackup {
                    backup: backup_id,
                    destination_path: data.path.clone(),
                    start_time: chrono::Utc::now(),
                    bytes_processed: progress.clone(),
                    bytes_total: total.clone(),
                },
                {
                    let state = state.clone();
                    let server = server.clone();
                    let backup = Arc::clone(&backup);
                    let progress = progress.clone();
                    let total = total.clone();
                    let destination_path = destination_path.clone();
                    let destination_filesystem = destination_filesystem.clone();

                    async move {
                        let mut writer = destination_filesystem
                            .async_create_file(&destination_path)
                            .await?;

                        match state.backup_manager.browse(&server, backup_id).await {
                            Ok(Some(browse_filesystem)) => {
                                if let Ok(entry) =
                                    browse_filesystem.async_directory_entry(&std::path::Path::new("")).await
                                {
                                    total.store(entry.size, std::sync::atomic::Ordering::Relaxed);
                                }

                                let files_processed = Arc::new(AtomicU64::new(0));
                                let mut reader = browse_filesystem
                                    .async_read_dir_archive(
                                        &std::path::Path::new(""),
                                        data.archive_format,
                                        state.config.load().system.backups.compression_level,
                                        crate::server::filesystem::archive::create::ArchiveProgress::new(
                                            progress.clone(),
                                            files_processed,
                                        ),
                                        Default::default(),
                                    )
                                    .await?;

                                tokio::io::copy(&mut reader, &mut writer).await?;
                            }
                            _ => {
                                let response =
                                    backup.download(&state, data.archive_format, None).await?;

                                if let Some(length) = response
                                    .headers
                                    .get(axum::http::header::CONTENT_LENGTH)
                                    .and_then(|h| h.to_str().ok())
                                    .and_then(|s| s.parse::<u64>().ok())
                                {
                                    total.store(length, std::sync::atomic::Ordering::Relaxed);
                                }

                                let mut stream = response.body.into_data_stream();
                                while let Some(chunk) = stream.next().await {
                                    let chunk = chunk?;
                                    writer.write_all(&chunk).await?;
                                    progress.fetch_add(
                                        chunk.len() as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                }
                            }
                        }

                        writer.shutdown().await?;

                        Ok(())
                    }
                },
            )
            .await;

        if data.foreground {
            match task.await {
                Ok(Some(Ok(()))) => {}
                Ok(None) => {
                    return ApiResponse::error("backup export aborted by another source")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Ok(Some(Err(err))) => {
                    tracing::error!(
                        server = %server.uuid,
                        backup = %backup_id,
                        destination = %destination_path.display(),
                        "failed to export backup: {:#?}",
                        err,
                    );

                    return ApiResponse::error(&format!("failed to export backup: {err}"))
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        backup = %backup_id,
                        destination = %destination_path.display(),
                        "failed to export backup: {:#?}",
                        err,
                    );

                    return ApiResponse::error("failed to export backup")
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
