use super::State;
use crate::{response::ApiResponse, routes::GetState};
use axum::{
    body::Body,
    extract::{Path, Request},
    http::{Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use utoipa_axum::{router::OpenApiRouter, routes};

mod backup;
mod commands;
mod database_backup;
mod files;
mod install;
mod logs;
mod power;
mod reinstall;
mod schedules;
mod script;
mod sync;
mod transfer;
mod utilization;
mod version;
mod ws;

pub type GetServer = axum::extract::Extension<crate::server::Server>;

pub async fn auth(
    state: GetState,
    Path(parts): Path<Vec<String>>,
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let uuid = match parts.first() {
        Some(uuid) => match uuid.parse::<uuid::Uuid>() {
            Ok(uuid) => uuid,
            Err(_) => {
                return Ok(ApiResponse::error("invalid server uuid")
                    .with_status(StatusCode::BAD_REQUEST)
                    .into_response());
            }
        },
        None => {
            return Ok(ApiResponse::error("missing server uuid")
                .with_status(StatusCode::BAD_REQUEST)
                .into_response());
        }
    };

    let server = match state.server_manager.get_server(uuid).await {
        Some(server) => server,
        None => {
            return Ok(ApiResponse::error("server not found")
                .with_status(StatusCode::NOT_FOUND)
                .into_response());
        }
    };

    req.extensions_mut().insert(server);

    Ok(next.run(req).await)
}

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::api::servers::_server_::GetServer,
    };

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = crate::models::Server),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(server: GetServer) -> ApiResponseResult {
        ApiResponse::new_serialized(server.to_api_response().await).ok()
    }
}

mod delete {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{GetState, api::servers::_server_::GetServer},
    };
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(state: GetState, server: GetServer) -> ApiResponseResult {
        state.server_manager.delete_server(&server).await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/utilization", utilization::router(state))
        .nest("/logs", logs::router(state))
        .nest("/install", install::router(state))
        .nest("/transfer", transfer::router(state))
        .nest("/script", script::router(state))
        .nest("/power", power::router(state))
        .nest("/version", version::router(state))
        .nest("/commands", commands::router(state))
        .nest("/sync", sync::router(state))
        .nest("/reinstall", reinstall::router(state))
        .nest("/ws", ws::router(state))
        .nest("/files", files::router(state))
        .nest("/backup", backup::router(state))
        .nest("/database-backup", database_backup::router(state))
        .nest("/schedules", schedules::router(state))
        .routes(routes!(get::route))
        .routes(routes!(delete::route))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state.clone())
}
