use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::resource_history::{History, MAX_POINTS},
    };
    use axum::{extract::Query, http::StatusCode};
    use serde::Deserialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        points: usize,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = History),
        (status = BAD_REQUEST, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "start" = chrono::DateTime<chrono::Utc>, Query,
            description = "Start of the range, inclusive",
            example = "2024-01-01T00:00:00Z",
        ),
        (
            "end" = chrono::DateTime<chrono::Utc>, Query,
            description = "End of the range, exclusive",
            example = "2026-01-01T00:00:00Z",
        ),
        (
            "points" = usize, Query,
            description = "Number of equally wide points to split the range into",
            example = "12",
        ),
    ))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        if !state.config.load().system.resource_history.enabled {
            return ApiResponse::error("resource history is disabled")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let (start, end) = (data.start.timestamp(), data.end.timestamp());
        if end <= start {
            return ApiResponse::error("end must be after start")
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }
        if data.points == 0 || data.points > MAX_POINTS {
            return ApiResponse::error(&format!("points must be between 1 and {MAX_POINTS}"))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let history = state
            .resource_history
            .query(server.uuid, start, end, data.points)
            .await?
            .unwrap_or_else(|| History::empty(start, end, data.points));

        ApiResponse::new_serialized(history).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
