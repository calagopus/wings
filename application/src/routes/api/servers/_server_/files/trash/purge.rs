use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        entries: Vec<uuid::Uuid>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        deleted: usize,
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
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let mut entries = Vec::with_capacity(data.entries.len());
        let mut kept_ignored = false;
        for uuid in data.entries {
            let Some(meta) = server
                .filesystem
                .trash
                .get_visible(&server, uuid, &ignored)
                .await
            else {
                continue;
            };

            if server
                .filesystem
                .trash
                .payload_holds_ignored(&server, uuid, &meta, &ignored)
                .await
            {
                kept_ignored = true;
                continue;
            }

            entries.push(uuid);
        }

        let deleted = server.filesystem.trash.purge_many(&server, entries).await;

        if kept_ignored {
            return super::super::super::ignored_contents_error();
        }

        ApiResponse::new_serialized(Response { deleted }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
