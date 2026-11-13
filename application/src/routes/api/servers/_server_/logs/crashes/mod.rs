use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod _crash_;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::crash_history::Crash,
    };
    use axum::http::StatusCode;
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        crashes: Vec<Crash>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(state: GetState, server: GetServer) -> ApiResponseResult {
        if !state.config.load().system.crash_history.enabled {
            return ApiResponse::error("crash history is disabled")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let crashes = state.crash_history.list(server.uuid).await?;

        ApiResponse::new_serialized(Response { crashes }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .nest("/{crash}", _crash_::router(state))
        .with_state(state.clone())
}
