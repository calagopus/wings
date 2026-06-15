use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::transfer::TransferCapabilities,
    };

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = TransferCapabilities),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        ApiResponse::new_serialized(TransferCapabilities::from_config(&state.config.load())).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
