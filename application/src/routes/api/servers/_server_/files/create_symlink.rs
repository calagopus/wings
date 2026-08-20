use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::cap::{CapFilesystem, FileType},
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(alias = "path")]
        root: compact_str::CompactString,

        link: compact_str::CompactString,
        target: compact_str::CompactString,
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
        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs(&server, &data.root)
            .await;

        match filesystem.async_metadata(&root).await {
            Ok(metadata) if metadata.file_type.is_dir() => {}
            _ => {
                return ApiResponse::error("path is not a directory")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
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

        let link = root.join(data.link.as_str());
        let (contents, target) =
            CapFilesystem::resolve_symlink_contents(&link, Path::new(data.target.as_str()));

        let target_metadata = match filesystem.async_symlink_metadata(&target).await {
            Ok(metadata) => metadata,
            Err(_) => {
                return ApiResponse::error("target not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&target, target_metadata.file_type)
                .await
        {
            return ApiResponse::error("target not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&link, FileType::File)
                .await
        {
            return ApiResponse::error("destination not found")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        if filesystem.async_symlink_metadata(&link).await.is_ok() {
            return ApiResponse::error("destination already exists")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        filesystem
            .async_create_symlink_contents(&contents, &link)
            .await?;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
