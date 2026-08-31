use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod ws;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::http::StatusCode;

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = serde_json::Value),
        (status = NOT_IMPLEMENTED, body = ApiError),
        (status = SERVICE_UNAVAILABLE, body = ApiError),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        let Some(tundra) = state.tundra.as_ref() else {
            return ApiResponse::error("tundra is not enabled on this node")
                .with_status(StatusCode::NOT_IMPLEMENTED)
                .ok();
        };

        match tundra.hub.request_metrics().await {
            Ok(metrics) => ApiResponse::new_serialized(metrics).ok(),
            Err(err) => {
                tracing::debug!("failed to request tundra metrics: {:#}", err);

                ApiResponse::error("the tundra daemon is not reachable")
                    .with_status(StatusCode::SERVICE_UNAVAILABLE)
                    .ok()
            }
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .nest("/ws", ws::router(state))
        .with_state(state.clone())
}
