use super::State;
use utoipa_axum::router::OpenApiRouter;

mod restore;

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/restore", restore::router(state))
        .with_state(state.clone())
}
