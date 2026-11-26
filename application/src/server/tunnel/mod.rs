use crate::{
    response::ApiResponse,
    routes::{GetState, api::servers::_server_::GetServer},
};
use axum::{
    extract::{Query, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

mod stream;
mod tcp;
mod udp;
#[cfg(target_os = "linux")]
pub mod unix;

#[cfg(not(target_os = "linux"))]
pub mod unix {
    use crate::response::ApiResponse;
    use axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
    };

    pub async fn handle_ws() -> Response {
        ApiResponse::error("unix socket tunnels are not supported on this platform")
            .with_status(StatusCode::NOT_IMPLEMENTED)
            .into_response()
    }
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Deserialize)]
pub struct Params {
    protocol: Protocol,
    port: u16,
}

pub async fn handle_ws(
    ws: WebSocketUpgrade,
    state: GetState,
    server: GetServer,
    Query(params): Query<Params>,
) -> Response {
    let target = match state
        .executor
        .resolve_internal_target(&server, params.port)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => {
            return ApiResponse::error("server is offline")
                .with_status(StatusCode::CONFLICT)
                .into_response();
        }
        Err(err) => {
            tracing::error!(server = %server.uuid, "failed to resolve internal target: {:?}", err);
            return ApiResponse::error("failed to resolve server")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .into_response();
        }
    };

    match params.protocol {
        Protocol::Tcp => ws
            .max_message_size(stream::MAX_MESSAGE_SIZE)
            .max_frame_size(stream::MAX_MESSAGE_SIZE)
            .on_upgrade(move |socket| tcp::tunnel(socket, target)),
        Protocol::Udp => ws
            .max_message_size(udp::RECV_BUFFER_SIZE)
            .max_frame_size(udp::RECV_BUFFER_SIZE)
            .on_upgrade(move |socket| udp::tunnel(socket, target)),
    }
}
