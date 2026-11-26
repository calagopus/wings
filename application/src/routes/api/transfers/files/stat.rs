use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::http::{HeaderMap, StatusCode};
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        files: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        entries: Vec<crate::models::DirectoryEntry>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        headers: HeaderMap,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let key = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let (r#type, token) = match key.split_once(' ') {
            Some((t, tok)) => (t, tok),
            None => {
                return ApiResponse::error("invalid authorization header")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .with_header("WWW-Authenticate", "Bearer")
                    .ok();
            }
        };

        if r#type != "Bearer" {
            return ApiResponse::error("invalid authorization header")
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let payload: super::super::post::FileTransferJwtPayload =
            crate::routes::token::verify(&state, token, "transfer")?;

        let subject = crate::routes::token::subject_uuid(&payload.base)?;

        let server = crate::routes::token::server(&state, subject).await?;

        let ignored = payload
            .ignored_files
            .request_ignored(&server, "file not found")?;

        let mut entries = Vec::with_capacity(data.files.len());
        for path_raw in data.files {
            let path = Path::new(&payload.destination_path).join(&path_raw);

            let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
                continue;
            };

            let (parent, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, parent, &ignored)
                .await;

            let Ok(mut entry) = filesystem
                .async_directory_entry(&parent.join(file_name))
                .await
            else {
                continue;
            };
            entry.name = path_raw;

            entries.push(entry);
        }

        ApiResponse::new_serialized(Response { entries }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
