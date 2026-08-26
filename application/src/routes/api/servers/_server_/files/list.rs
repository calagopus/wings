use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use axum_extra::extract::Query;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default, alias = "directory")]
        root: compact_str::CompactString,
        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,

        per_page: Option<usize>,
        page: Option<usize>,

        #[serde(default)]
        sort: crate::models::DirectorySortingMode,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        total: usize,

        filesystem_primary: bool,
        filesystem_writable: bool,
        filesystem_fast: bool,

        entries: Vec<crate::models::DirectoryEntry>,
    }

    #[utoipa::path(get, path = "/", responses(
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
            "directory" = String, Query,
            description = "The directory to list files from",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
        (
            "per_page" = usize, Query,
            description = "The number of entries to return per page",
        ),
        (
            "page" = usize, Query,
            description = "The page number to return",
        ),
        (
            "sort" = crate::models::DirectorySortingMode, Query,
            description = "The sorting mode to use",
        ),
    ))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        let per_page = match data.per_page {
            Some(per_page) => Some(per_page),
            None => match state.config.load().api.directory_entry_limit {
                0 => None,
                limit => Some(limit),
            },
        };
        let page = data.page.unwrap_or(1);

        let ignore = if data.ignored.is_empty() {
            None
        } else {
            match crate::server::filesystem::build_gitignore_matcher(data.ignored.iter()) {
                Ok(ignore) => Some(ignore),
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        "rejecting request, subuser ignored files cannot be compiled: {:#?}",
                        err
                    );

                    return ApiResponse::error("directory not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            }
        };

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

        let is_ignored = if filesystem.is_primary_server_fs()
            && let Some(ignore) = ignore
        {
            vec![server.filesystem.get_ignored(), ignore].into()
        } else if filesystem.is_primary_server_fs() {
            server.filesystem.get_ignored().into()
        } else {
            Default::default()
        };

        let entries = filesystem
            .async_read_dir(&root, per_page, page, is_ignored, data.sort)
            .await?;

        ApiResponse::new_serialized(Response {
            total: entries.total_entries,
            filesystem_primary: filesystem.is_primary_server_fs(),
            filesystem_writable: filesystem.is_writable(),
            filesystem_fast: filesystem.is_fast(),
            entries: entries.entries,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
