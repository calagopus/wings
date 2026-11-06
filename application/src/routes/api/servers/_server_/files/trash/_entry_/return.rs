use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::trash::{ReturnOutcome, TrashEntry},
    };
    use axum::{extract::Path, http::StatusCode};
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        restorations: Vec<uuid::Uuid>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        returned: Vec<uuid::Uuid>,
        unavailable: Vec<uuid::Uuid>,
        entry: Option<TrashEntry>,
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
        (
            "entry" = uuid::Uuid,
            description = "The trash entry uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        server: GetServer,
        Path((_server, entry_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let meta = server
            .filesystem
            .trash
            .get_visible(&server, entry_id, &ignored)
            .await
            .or_api_error(StatusCode::NOT_FOUND, "entry not found")?;

        let mut returned = Vec::new();
        let mut unavailable = Vec::new();
        for id in data.restorations {
            let Some(restoration) = meta
                .restorations
                .iter()
                .find(|restoration| restoration.id == id)
            else {
                unavailable.push(id);
                continue;
            };

            let file_type = restoration.file_type();
            let destination = std::path::Path::new(restoration.destination.as_str());

            if server
                .filesystem
                .trash
                .is_inner_ignored(
                    &server,
                    &meta,
                    std::path::Path::new(restoration.inner.as_str()),
                    file_type,
                    &ignored,
                )
                .await
                || ignored
                    .is_ignored_resolved_parent(&server, destination, file_type)
                    .await
                || server.filesystem.async_is_protected_path(destination).await
            {
                unavailable.push(id);
                continue;
            }

            let (_, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, destination, &ignored)
                .await;
            if !filesystem.is_primary_server_fs() {
                unavailable.push(id);
                continue;
            }

            match server
                .filesystem
                .trash
                .return_restoration(&server, entry_id, id)
                .await
            {
                Ok(ReturnOutcome::Returned) => returned.push(id),
                Ok(ReturnOutcome::Unavailable) => unavailable.push(id),
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        entry = %entry_id,
                        restoration = %id,
                        "failed to return restored path to trash: {:#?}",
                        err
                    );

                    unavailable.push(id);
                }
            }
        }

        let entry = server
            .filesystem
            .trash
            .visible_entry(&server, entry_id, &ignored)
            .await;

        ApiResponse::new_serialized(Response {
            returned,
            unavailable,
            entry,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
