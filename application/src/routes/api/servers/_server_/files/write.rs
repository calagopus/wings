use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::cap::FileType,
    };
    use axum::{
        body::Body,
        http::{HeaderMap, StatusCode},
    };
    use axum_extra::extract::Query;
    use futures::StreamExt;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        file: compact_str::CompactString,
        user: Option<uuid::Uuid>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        revision_id: Option<i64>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "file" = String, Query,
            description = "The file to view contents of",
        ),
        (
            "user" = uuid::Uuid, Query,
            description = "The user uuid of the editor. This is used for diff tracking.",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ), request_body = String)]
    pub async fn route(
        state: GetState,
        server: GetServer,
        headers: HeaderMap,
        Query(data): Query<Params>,
        body: Body,
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

        let parent = match Path::new(&data.file).parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let file_name = match Path::new(&data.file).file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, &parent, &ignored)
            .await;
        let path = root.join(file_name);

        let content_size: i64 = headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let metadata = filesystem.async_metadata(&path).await;

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(
                    &path,
                    metadata
                        .as_ref()
                        .map(|m| m.file_type)
                        .unwrap_or(FileType::File),
                )
                .await
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let old_content_size = if let Ok(metadata) = metadata.as_ref() {
            if !metadata.file_type.is_file() {
                return ApiResponse::error("file is not a file")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }

            metadata.size as i64
        } else {
            0
        };

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

        filesystem.async_create_dir_all(&root).await?;

        if filesystem.is_primary_server_fs()
            && !server
                .filesystem
                .has_headroom(content_size - old_content_size)
        {
            return ApiResponse::error("failed to allocate space")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let diff_key = server.filesystem.diff_key(&path).await;
        let diff_key = diff_key.to_string_lossy();
        let config_guard = state.config.load();
        let history = &config_guard.system.file_history;

        let pre_size = metadata.as_ref().ok().map(|m| m.size);
        let track = history.enabled
            && filesystem.is_primary_server_fs()
            && matches!(pre_size, Some(s) if s > 0 && s <= history.file_size_cap);

        let captured_before: Option<Vec<u8>> = if track {
            match filesystem.async_read_file(&path, None).await {
                Ok(mut handle) => {
                    if handle.size > history.file_size_cap {
                        None
                    } else {
                        let mut buf = Vec::with_capacity(handle.size as usize);
                        match handle.reader.read_to_end(&mut buf).await {
                            Ok(_) if buf.len() <= history.file_size_cap as usize => Some(buf),
                            Ok(_) => None,
                            Err(err) => {
                                tracing::debug!(
                                    server = %server.uuid,
                                    path = %path.display(),
                                    "diff: failed to read pre-edit content: {err}"
                                );
                                None
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        server = %server.uuid,
                        path = %path.display(),
                        "diff: failed to open pre-edit file: {err}"
                    );
                    None
                }
            }
        } else {
            None
        };

        let file_size_cap = history.file_size_cap;
        drop(config_guard);

        let mut file = filesystem.async_create_file(&path).await?;
        let mut stream = body.into_data_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                std::io::Error::other(format!("failed to read request body: {err}"))
            })?;
            file.write_all(&chunk).await?;
        }

        file.shutdown().await?;

        let mut revision_id = None;

        if track {
            match filesystem.async_read_file(&path, None).await {
                Ok(mut handle) => {
                    if handle.size <= file_size_cap {
                        let mut buf = Vec::with_capacity(handle.size as usize);
                        match handle.reader.read_to_end(&mut buf).await {
                            Ok(_) if buf.len() <= file_size_cap as usize => {
                                match server
                                    .diff
                                    .record_edit(&diff_key, captured_before, buf, data.user)
                                    .await
                                {
                                    Ok(id) => {
                                        if id != 0 {
                                            revision_id = Some(id);
                                        }
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            server = %server.uuid,
                                            path = %diff_key,
                                            "diff: record_edit failed: {err:#}"
                                        );
                                    }
                                }
                            }
                            Ok(_) => {
                                tracing::debug!(
                                    server = %server.uuid,
                                    path = %diff_key,
                                    "diff: post-write content exceeds file_size_cap; not recorded"
                                );
                            }
                            Err(err) => {
                                tracing::debug!(
                                    server = %server.uuid,
                                    path = %diff_key,
                                    "diff: failed to read post-edit content: {err}"
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            server = %server.uuid,
                            path = %diff_key,
                            "diff: post-write file exceeds file_size_cap (size {}); not recorded",
                            handle.size
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        server = %server.uuid,
                        path = %diff_key,
                        "diff: failed to open post-edit file: {err}"
                    );
                }
            }
        }

        ApiResponse::new_serialized(Response { revision_id }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
