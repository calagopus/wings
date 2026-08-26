use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod _revision_;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::api::servers::_server_::GetServer,
        server::filesystem::cap::FileType,
    };
    use axum::http::StatusCode;
    use axum_extra::extract::Query;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        file: compact_str::CompactString,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        revisions: Vec<crate::server::diff::RevisionInfo>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "file" = String, Query,
            description = "The file path to list revisions for",
            example = "/path/to/file.txt",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
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

        let path = server
            .filesystem
            .diff_key(std::path::Path::new(&data.file))
            .await;

        if server
            .filesystem
            .async_is_ignored(&path, FileType::File)
            .await
            || ignored.is_ignored(&server, &path, FileType::File).await
        {
            return ApiResponse::new_serialized(Response {
                revisions: Vec::new(),
            })
            .ok();
        }

        let revisions = server.diff.list(&path.to_string_lossy()).await?;

        ApiResponse::new_serialized(Response { revisions }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/{revision}", _revision_::router(state))
        .routes(routes!(get::route))
        .with_state(state.clone())
}
