use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod abort;
mod trigger;

mod get {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::{extract::Path, http::StatusCode};
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        status: &'a crate::server::schedule::ScheduleStatus,
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
            "schedule" = uuid::Uuid,
            description = "The schedule uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(
        server: GetServer,
        Path((_server, schedule_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> ApiResponseResult {
        let schedules = server.schedules.get_schedules().await;

        let schedule = schedules
            .iter()
            .find(|s| s.uuid == schedule_id)
            .or_api_error(StatusCode::NOT_FOUND, "schedule not found")?;

        ApiResponse::new_serialized(Response {
            status: &*schedule.status.read().await,
        })
        .with_status(StatusCode::ACCEPTED)
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/abort", abort::router(state))
        .nest("/trigger", trigger::router(state))
        .routes(routes!(get::route))
        .with_state(state.clone())
}
