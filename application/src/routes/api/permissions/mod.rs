use super::State;
use utoipa_axum::router::OpenApiRouter;

mod invalidate;

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/invalidate", invalidate::router(state))
        .with_state(state.clone())
}
