use super::State;
use axum::routing::any;
use utoipa_axum::router::OpenApiRouter;

mod broadcast;
mod deny;
mod permissions;

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/deny", deny::router(state))
        .nest("/broadcast", broadcast::router(state))
        .nest("/permissions", permissions::router(state))
        .route("/query", any(crate::server::tunnel::handle_ws))
        .route("/socket", any(crate::server::tunnel::unix::handle_ws))
        .with_state(state.clone())
}
