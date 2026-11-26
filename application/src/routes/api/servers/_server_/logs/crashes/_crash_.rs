use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
    };
    use axum::{extract::Path, http::StatusCode};

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = String),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "crash" = i64,
            description = "The crash id",
            example = "1767225600000",
        ),
    ))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Path((_server, crash_id)): Path<(uuid::Uuid, i64)>,
    ) -> ApiResponseResult {
        if !state.config.load().system.crash_history.enabled {
            return ApiResponse::error("crash history is disabled")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let log = state
            .crash_history
            .log(server.uuid, crash_id)
            .await?
            .or_api_error(StatusCode::NOT_FOUND, "crash not found")?;

        ApiResponse::new(axum::body::Body::from(log))
            .with_header("Content-Type", "text/plain")
            .ok()
    }
}

mod delete {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
    };
    use axum::{extract::Path, http::StatusCode};
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "crash" = i64,
            description = "The crash id",
            example = "1767225600000",
        ),
    ))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Path((_server, crash_id)): Path<(uuid::Uuid, i64)>,
    ) -> ApiResponseResult {
        if !state.crash_history.delete(server.uuid, crash_id).await? {
            return ApiResponse::error("crash not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
