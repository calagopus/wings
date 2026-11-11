use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod _entry_;
mod purge;
mod restore;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::trash::TrashEntry,
    };
    use axum_extra::extract::Query;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,

        per_page: Option<usize>,
        page: Option<usize>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        total: usize,
        entries: Vec<TrashEntry>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
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

        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let entries = server
            .filesystem
            .trash
            .visible_entries(&server, &ignored)
            .await;
        let total = entries.len();

        let entries = match per_page {
            Some(per_page) => entries
                .into_iter()
                .skip(page.saturating_sub(1).saturating_mul(per_page))
                .take(per_page)
                .collect(),
            None => entries,
        };

        ApiResponse::new_serialized(Response { total, entries }).ok()
    }
}

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::trash::{TrashEntry, TrashSource},
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        root: compact_str::CompactString,

        files: Vec<compact_str::CompactString>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        entries: Vec<TrashEntry>,
        skipped: Vec<compact_str::CompactString>,
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
    ), request_body = inline(Payload))]
    pub async fn route(
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        if !server.filesystem.trash.is_enabled() {
            return ApiResponse::error("trash is disabled for this server")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let ignored = crate::routes::token::ignored(&server, &data.ignored, "file not found")?;

        super::super::reject_any_protected(
            &server,
            &data
                .files
                .iter()
                .map(|file| Path::new(&data.root).join(file))
                .collect::<Vec<_>>(),
        )
        .await?;

        let mut entries = Vec::new();
        let mut skipped = Vec::new();
        let mut failed_count = 0;
        for file in data.files {
            let path = Path::new(&data.root).join(&file);

            let (source, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, &path, &ignored)
                .await;
            if source.as_os_str().is_empty() || source == Path::new(&data.root) {
                continue;
            }

            if !filesystem.is_primary_server_fs() {
                skipped.push(file);
                continue;
            }

            let metadata = match filesystem.async_symlink_metadata(&source).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if ignored
                .is_ignored_resolved_parent(&server, &source, metadata.file_type)
                .await
            {
                continue;
            }

            match server
                .filesystem
                .trash
                .trash(&server, &source, TrashSource::Api)
                .await
            {
                Ok(entry) => entries.push(entry),
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        path = %source.display(),
                        "failed to trash file: {:#?}",
                        err,
                    );

                    failed_count += 1;
                }
            }
        }

        if failed_count > 0 {
            return ApiResponse::error(&format!(
                "failed to trash {failed_count} file{}",
                if failed_count == 1 { "" } else { "s" }
            ))
            .with_status(StatusCode::EXPECTATION_FAILED)
            .ok();
        }

        ApiResponse::new_serialized(Response { entries, skipped }).ok()
    }
}

mod delete {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum_extra::extract::Query;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        deleted: usize,
    }

    #[utoipa::path(delete, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let entries = server
            .filesystem
            .trash
            .visible_entries(&server, &ignored)
            .await;
        let deleted = server
            .filesystem
            .trash
            .purge_many(&server, entries.into_iter().map(|entry| entry.uuid))
            .await;

        ApiResponse::new_serialized(Response { deleted }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/{entry}", _entry_::router(state))
        .nest("/restore", restore::router(state))
        .nest("/purge", purge::router(state))
        .routes(routes!(get::route))
        .routes(routes!(post::route))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
