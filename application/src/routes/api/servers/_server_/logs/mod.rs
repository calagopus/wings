use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod crashes;
mod install;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::api::servers::_server_::GetServer,
    };
    use axum::extract::Query;
    use serde::Deserialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        lines: Option<usize>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = String),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "lines" = Option<usize>, Query,
            description = "The number of lines to tail from the log",
            example = "100",
        ),
    ))]
    pub async fn route(server: GetServer, Query(params): Query<Params>) -> ApiResponseResult {
        let log_stream = server.logs(params.lines).await;

        ApiResponse::new_stream(log_stream)
            .with_header("Content-Type", "text/plain")
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .nest("/crashes", crashes::router(state))
        .nest("/install", install::router(state))
        .with_state(state.clone())
}
