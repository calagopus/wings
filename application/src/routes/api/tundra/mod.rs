use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

#[cfg(unix)]
mod metrics;
#[cfg(unix)]
mod rotate;
#[cfg(unix)]
mod sync;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        supported: bool,
        connected: bool,
        epoch: Option<u64>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        #[cfg(unix)]
        let response = {
            let tundra = state.tundra.as_ref();

            Response {
                supported: tundra.is_some(),
                connected: tundra.is_some_and(|tundra| tundra.hub.connected()),
                epoch: tundra
                    .and_then(|tundra| tundra.cached())
                    .map(|snapshot| snapshot.epoch),
            }
        };
        #[cfg(not(unix))]
        let response = {
            let _ = state;

            Response {
                supported: false,
                connected: false,
                epoch: None,
            }
        };

        ApiResponse::new_serialized(response).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    let router = OpenApiRouter::new().routes(routes!(get::route));

    #[cfg(unix)]
    let router = router
        .nest("/sync", sync::router(state))
        .nest("/rotate", rotate::router(state))
        .nest("/metrics", metrics::router(state));

    router.with_state(state.clone())
}
