use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod restore;
mod r#return;

mod get {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::trash::TrashEntry,
    };
    use axum::{extract::Path, http::StatusCode};
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
        entry: TrashEntry,
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
            "entry" = uuid::Uuid,
            description = "The trash entry uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(
        server: GetServer,
        Path((_server, entry_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let entry = server
            .filesystem
            .trash
            .visible_entry(&server, entry_id, &ignored)
            .await
            .or_api_error(StatusCode::NOT_FOUND, "entry not found")?;

        ApiResponse::new_serialized(Response { entry }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/restore", restore::router(state))
        .nest("/return", r#return::router(state))
        .routes(routes!(get::route))
        .with_state(state.clone())
}
