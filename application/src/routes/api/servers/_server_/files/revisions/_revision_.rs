use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::cap::FileType,
    };
    use axum::{extract::Path, http::StatusCode};
    use axum_extra::extract::Query;
    use serde::Deserialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        file: Option<compact_str::CompactString>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = String),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "revision" = i64,
            description = "The revision id",
            example = "1",
        ),
        (
            "file" = Option<String>, Query,
            description = "The file path the revision must belong to, rejected if it does not match",
            example = "/path/to/file.txt",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(
        server: GetServer,
        Path((_server, revision_id)): Path<(uuid::Uuid, i64)>,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        let ignored = match crate::server::filesystem::RequestIgnored::compile(&data.ignored) {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "rejecting request, subuser ignored files cannot be compiled: {:#?}",
                    err
                );

                return ApiResponse::error("revision not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let Some(revision_path) = server.diff.revision_path(revision_id).await? else {
            return ApiResponse::error("revision not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        };
        let revision_path = std::path::Path::new(&revision_path);

        if server
            .filesystem
            .async_is_ignored(revision_path, FileType::File)
            .await
            || ignored
                .is_ignored(&server, revision_path, FileType::File)
                .await
        {
            return ApiResponse::error("revision not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        if let Some(file) = data.file
            && server
                .filesystem
                .diff_key(std::path::Path::new(&file))
                .await
                != revision_path
        {
            return ApiResponse::error("revision not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let Some(contents) = server.diff.get_content(revision_id).await? else {
            return ApiResponse::error("revision not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        };

        ApiResponse::new(axum::body::Body::from(contents)).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
