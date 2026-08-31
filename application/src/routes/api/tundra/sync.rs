use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::http::StatusCode;
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_IMPLEMENTED, body = ApiError),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        let Some(tundra) = state.tundra.as_ref() else {
            return ApiResponse::error("tundra is not enabled on this node")
                .with_status(StatusCode::NOT_IMPLEMENTED)
                .ok();
        };

        tundra.poke();

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
