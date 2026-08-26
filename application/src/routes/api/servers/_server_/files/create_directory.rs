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
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(alias = "path")]
        root: compact_str::CompactString,
        name: compact_str::CompactString,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

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

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, &data.root, &ignored)
            .await;

        let metadata = filesystem.async_metadata(&root).await;
        if !metadata.map_or(true, |m| m.file_type.is_dir()) {
            return ApiResponse::error("path is not a directory")
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

        let destination = root.join(&data.name);

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&destination, FileType::Dir)
                .await
        {
            return ApiResponse::error("destination not found")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        filesystem.async_create_dir_all(&destination).await?;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
