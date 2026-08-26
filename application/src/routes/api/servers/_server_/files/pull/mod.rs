use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod _pull_;
mod query;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::api::servers::_server_::GetServer,
    };
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        downloads: Vec<crate::models::Download>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    #[deprecated(
        note = "This endpoint is purely for pterodactyl compatibility. Use the operations system instead."
    )]
    pub async fn route(server: GetServer) -> ApiResponseResult {
        let values = server.filesystem.pulls().await;
        let mut downloads = Vec::new();
        downloads.reserve_exact(values.len());

        for download in values.values() {
            downloads.push(download.read().await.to_api_response());
        }

        ApiResponse::new_serialized(Response { downloads }).ok()
    }
}

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::cap::FileType,
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default, alias = "directory")]
        root: compact_str::CompactString,

        url: compact_str::CompactString,
        file_name: Option<compact_str::CompactString>,

        #[serde(default)]
        use_header: bool,
        #[serde(default)]
        foreground: bool,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[derive(ToSchema, Serialize)]
    struct ResponsePending {
        identifier: uuid::Uuid,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = ACCEPTED, body = inline(ResponsePending)),
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
            .resolve_writable_fs_ignoring(&server, &data.root, &ignored)
            .await;

        let metadata = filesystem.async_symlink_metadata(&root).await;
        if !metadata.map_or(true, |m| m.file_type.is_dir()) {
            return ApiResponse::error("root is not a directory")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&root, FileType::Dir)
                .await
        {
            return ApiResponse::error("path not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        if let Some(file_name) = &data.file_name {
            let metadata = filesystem.async_metadata(&root.join(file_name)).await;
            if !metadata.map_or(true, |m| m.file_type.is_file()) {
                return ApiResponse::error("file is not a file")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        }

        if state.config.load().api.disable_remote_download {
            return ApiResponse::error("remote pulling is disabled")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        if server.filesystem.pulls().await.len()
            >= state.config.load().api.server_remote_download_limit
        {
            return ApiResponse::error("too many concurrent pulls")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        filesystem.async_create_dir_all(&root).await?;
        let download = Arc::new(RwLock::new(
            match crate::server::filesystem::pull::Download::new(
                server.0.clone(),
                filesystem,
                &root,
                data.file_name,
                data.url,
                data.use_header,
            )
            .await
            {
                Ok(download) => download,
                Err(err) => {
                    tracing::error!("failed to create pull: {:?}", err);

                    return ApiResponse::error(&format!("failed to create pull: {err}"))
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            },
        ));

        let mut pulls = server.filesystem.pulls.write().await;
        {
            let operations = server.filesystem.operations.operations().await;
            pulls.retain(|key, _| operations.contains_key(key));
        }

        if pulls.len() >= state.config.load().api.server_remote_download_limit {
            return ApiResponse::error("too many concurrent pulls")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let (identifier, task) = download.write().await.start().await?;
        pulls.insert(identifier, Arc::clone(&download));
        drop(pulls);

        if data.foreground {
            match task.await {
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(err))) => {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to pull file: {:#?}",
                        err,
                    );

                    return ApiResponse::error(&err.to_string())
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Ok(None) => {
                    return ApiResponse::error("pull aborted by another source")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to pull file: {:#?}",
                        err,
                    );

                    return ApiResponse::error("failed to pull file")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            }

            ApiResponse::new_serialized(Response {}).ok()
        } else {
            ApiResponse::new_serialized(ResponsePending { identifier })
                .with_status(StatusCode::ACCEPTED)
                .ok()
        }
    }
}

#[allow(deprecated)]
pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/query", query::router(state))
        .nest("/{pull}", _pull_::router(state))
        .routes(routes!(get::route))
        .routes(routes!(post::route))
        .with_state(state.clone())
}
