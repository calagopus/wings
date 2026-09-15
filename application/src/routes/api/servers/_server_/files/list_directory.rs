use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
    };
    use axum::{extract::Query, http::StatusCode};
    use serde::Deserialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default, alias = "directory")]
        pub root: compact_str::CompactString,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = Vec<crate::models::DirectoryEntry>),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "directory" = String, Query,
            description = "The directory to list files from",
        ),
    ))]
    #[deprecated(
        note = "This endpoint is purely for pterodactyl compatibility. Use `/files/list` instead."
    )]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs(&server, Path::new(&data.root))
            .await;

        let metadata = filesystem.async_metadata(&root).await;
        if let Ok(metadata) = metadata {
            if !metadata.file_type.is_dir() {
                return ApiResponse::error("path not a directory")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        } else {
            return ApiResponse::error("path not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let is_ignored = if filesystem.is_primary_server_fs() {
            server.filesystem.symlink_name_filter()
        } else {
            Default::default()
        };

        let entries = filesystem
            .async_read_dir(
                &root,
                Some(state.config.load().api.directory_entry_limit),
                1,
                is_ignored,
                crate::models::DirectorySortingMode::NameAsc,
            )
            .await?;

        let capacity = entries.entries.len().saturating_mul(320).saturating_add(64);

        ApiResponse::new_serialized_with_capacity(entries.entries, capacity).ok()
    }
}

#[allow(deprecated)]
pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
