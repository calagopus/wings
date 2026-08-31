use super::{GetState, State};
use crate::response::ApiResponse;
use axum::{
    body::Body,
    extract::Request,
    http::{Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::any,
};
use utoipa_axum::router::OpenApiRouter;

mod backups;
mod deauthorize_user;
mod ports;
pub mod servers;
mod system;
mod transfers;
mod tundra;
mod update;

pub async fn auth(state: GetState, req: Request, next: Next) -> Result<Response<Body>, StatusCode> {
    let key = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let (r#type, token) = match key.split_once(' ') {
        Some((t, tok)) => (t, tok),
        None => {
            return Ok(ApiResponse::error("invalid authorization header")
                .with_status(StatusCode::UNAUTHORIZED)
                .with_header("WWW-Authenticate", "Bearer")
                .into_response());
        }
    };

    if r#type != "Bearer" {
        return Ok(ApiResponse::error("invalid authorization header")
            .with_status(StatusCode::UNAUTHORIZED)
            .with_header("WWW-Authenticate", "Bearer")
            .into_response());
    }

    if !constant_time_eq::constant_time_eq(token.as_bytes(), state.config.load().token.as_bytes()) {
        return Ok(ApiResponse::error("invalid authorization token")
            .with_status(StatusCode::UNAUTHORIZED)
            .with_header("WWW-Authenticate", "Bearer")
            .into_response());
    }

    Ok(next.run(req).await)
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest(
            "/system",
            system::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest(
            "/update",
            update::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest("/transfers", transfers::router(state))
        .nest(
            "/servers",
            servers::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest(
            "/backups",
            backups::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest(
            "/deauthorize-user",
            deauthorize_user::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest(
            "/ports",
            ports::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest(
            "/tundra",
            tundra::router(state)
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth)),
        )
        .route(
            "/servers/{server}/ws",
            any(crate::server::websocket::handler::handle_ws),
        )
        .with_state(state.clone())
}
