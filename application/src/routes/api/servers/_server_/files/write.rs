use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
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
    use tokio::io::AsyncWriteExt;
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
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "file not found")?;

        let parent = Path::new(&data.file)
            .parent()
            .or_api_error(StatusCode::EXPECTATION_FAILED, "file has no parent")?;

        let file_name = Path::new(&data.file)
            .file_name()
            .or_api_error(StatusCode::EXPECTATION_FAILED, "invalid file name")?;

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, &parent, &ignored)
            .await;
        let path = root.join(file_name);

        if filesystem.is_primary_server_fs()
            && ignored.is_ignored_subtree_resolved(&server, parent).await
        {
            return ApiResponse::error("parent directory not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let content_size: i64 = headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let metadata = filesystem.async_metadata(&path).await;

        if filesystem.is_primary_server_fs()
            && ignored
                .is_ignored_resolved(
                    &server,
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
                Ok(mut handle) => match handle.read_to_end_capped(history.file_size_cap).await {
                    Ok(before) => before,
                    Err(err) => {
                        tracing::debug!(
                            server = %server.uuid,
                            path = %path.display(),
                            "diff: failed to read pre-edit content: {err}"
                        );
                        None
                    }
                },
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
                Ok(mut handle) => match handle.read_to_end_capped(file_size_cap).await {
                    Ok(Some(buf)) => match server
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
                    },
                    Ok(None) => {
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
                },
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
