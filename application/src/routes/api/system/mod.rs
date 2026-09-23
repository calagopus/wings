use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod config;
mod ips;
mod logs;
mod overview;
mod restic;
mod stats;
mod upgrade;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        architecture: &'static str,
        cpu_count: usize,
        kernel_version: String,
        os: &'static str,
        version: &'a str,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        ApiResponse::new_serialized(Response {
            architecture: std::env::consts::ARCH,
            cpu_count: rayon::current_num_threads(),
            kernel_version: sysinfo::System::kernel_long_version(),
            os: std::env::consts::OS,
            version: &state.version,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .nest("/overview", overview::router(state))
        .nest("/ips", ips::router(state))
        .nest("/logs", logs::router(state))
        .nest("/upgrade", upgrade::router(state))
        .nest("/config", config::router(state))
        .nest("/stats", stats::router(state))
        .nest("/restic", restic::router(state))
        .with_state(state.clone())
}
