use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
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
        entries: Vec<crate::models::DirectoryEntry>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
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

        let mut entries = Vec::new();
        entries.reserve_exact(data.files.len());

        for path_raw in data.files {
            let path = Path::new(&data.root).join(&path_raw);

            let parent = match path.parent() {
                Some(parent) => parent,
                None => continue,
            };

            let file_name = match path.file_name() {
                Some(name) => name,
                None => continue,
            };

            let (path, filesystem) = server
                .filesystem
                .resolve_readable_fs_ignoring(&server, parent, &ignored)
                .await;

            let mut entry = match filesystem
                .async_directory_entry(&path.join(file_name))
                .await
            {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            entry.name = path_raw;

            entries.push(entry);
        }

        let capacity = entries.len().saturating_mul(320).saturating_add(64);

        ApiResponse::new_serialized_with_capacity(Response { entries }, capacity).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
