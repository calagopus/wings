use crate::routes::{GetState, State};
use anyhow::Context;
use axum::{
    Json, Router,
    extract::{
        Query, Request,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tundra_common::sync::{NodeMsg, RemoteMsg};

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(crate::routes::ApiError::new(message))).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn auth(state: GetState, req: Request, next: Next) -> Response {
    let authorized = state.tundra.as_ref().is_some_and(|tundra| {
        bearer(req.headers()).is_some_and(|token| tundra.authenticate(token))
    });

    if !authorized {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    next.run(req).await
}

fn ready(state: &State) -> Option<Arc<super::TundraManager>> {
    state
        .tundra
        .as_ref()
        .filter(|tundra| tundra.serving())
        .map(Arc::clone)
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "the control plane has no current mesh state",
    )
}

#[derive(Serialize)]
struct IdentityResponse {
    uuid: uuid::Uuid,
    cert_sha256: Option<tundra_common::hash::Hash32>,
}

async fn identity(state: GetState) -> Response {
    let Some(tundra) = ready(&state) else {
        return unavailable();
    };

    let uuid = state.config.load().uuid;
    let cert_sha256 = tundra.cached().and_then(|snapshot| {
        snapshot
            .nodes
            .iter()
            .find(|node| node.uuid == uuid)
            .and_then(|node| node.cert_sha256)
    });

    Json(IdentityResponse { uuid, cert_sha256 }).into_response()
}

#[derive(Deserialize)]
struct CsrPayload {
    csr_pem: String,
}

#[derive(Serialize)]
struct CsrResponse<'a> {
    cert_pem: String,
    cert_sha256: tundra_common::hash::Hash32,
    ca_pem: &'a str,
}

async fn csr(state: GetState, Json(payload): Json<CsrPayload>) -> Response {
    let Some(tundra) = ready(&state) else {
        return unavailable();
    };

    let uuid = state.config.load().uuid;
    let signed = match tundra.ca().sign_csr(&payload.csr_pem, &uuid) {
        Ok(signed) => signed,
        Err(err) => return error(StatusCode::BAD_REQUEST, &err.to_string()),
    };

    if let Err(err) = state.config.client.tundra_store_cert(signed.sha256).await {
        tracing::error!("failed to publish the tundra certificate digest: {:#}", err);

        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to publish the certificate digest",
        );
    }

    tundra.poke();
    tracing::info!(fingerprint = %signed.sha256, "issued the tundra node certificate");

    Json(CsrResponse {
        cert_pem: signed.pem,
        cert_sha256: signed.sha256,
        ca_pem: tundra.ca().cert_pem(),
    })
    .into_response()
}

#[derive(Deserialize)]
struct ConnectTokenParams {
    target: uuid::Uuid,
}

#[derive(Serialize)]
struct ConnectTokenResponse {
    jwt: String,
}

async fn connect_token(state: GetState, Query(params): Query<ConnectTokenParams>) -> Response {
    if ready(&state).is_none() {
        return unavailable();
    }

    match state
        .config
        .client
        .tundra_connect_token(params.target)
        .await
    {
        Ok(jwt) => Json(ConnectTokenResponse { jwt }).into_response(),
        Err(err) => {
            tracing::warn!(target = %params.target, "failed to relay a connect token: {:#}", err);

            error(
                StatusCode::BAD_GATEWAY,
                "failed to obtain a connect token from the panel",
            )
        }
    }
}

async fn snapshot(state: GetState) -> Response {
    let Some(tundra) = ready(&state) else {
        return unavailable();
    };

    match tundra.snapshot(&state).await {
        Some(snapshot) => Json(snapshot).into_response(),
        None => unavailable(),
    }
}

async fn ws(state: GetState, upgrade: WebSocketUpgrade) -> Response {
    if ready(&state).is_none() {
        return unavailable();
    }

    upgrade
        .max_message_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| task(socket, state.0))
}

async fn send(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    message: &RemoteMsg,
) -> Result<(), ()> {
    let text = serde_json::to_string(message).map_err(|_| ())?;

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        sink.send(Message::Text(text.into())),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn task(socket: WebSocket, state: State) {
    let Some(tundra) = state.tundra.clone() else {
        return;
    };

    let mut registration = tundra.hub.register();
    let conn_id = registration.id;
    if !tundra.serving() {
        tundra.hub.unregister(conn_id);
        return;
    }

    tracing::info!(conn_id, "tundra daemon websocket connected");

    let (mut sink, mut stream) = socket.split();

    if let Some(snapshot) = tundra.snapshot(&state).await
        && send(&mut sink, &RemoteMsg::Snapshot { snapshot })
            .await
            .is_err()
    {
        tundra.hub.unregister(conn_id);

        return;
    }

    loop {
        tokio::select! {
            outgoing = registration.commands.recv() => match outgoing {
                Some(message) => {
                    if send(&mut sink, &message).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            changed = registration.snapshots.changed() => {
                if changed.is_err() {
                    break;
                }

                let latest = registration.snapshots.borrow_and_update().clone();
                if let Some(snapshot) = latest {
                    let message = RemoteMsg::Snapshot {
                        snapshot: tundra_common::state::Snapshot::clone(&snapshot),
                    };

                    if send(&mut sink, &message).await.is_err() {
                        break;
                    }
                }
            },
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<NodeMsg>(&text) {
                    Ok(message) => tundra.hub.deliver(message),
                    Err(err) => tracing::warn!(
                        "failed to parse a message from the tundra daemon: {:?}",
                        err
                    ),
                },
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(err)) => {
                    tracing::warn!("the tundra daemon websocket failed: {:?}", err);
                    break;
                }
            },
        }
    }

    tundra.hub.unregister(conn_id);
    tracing::info!(conn_id, "tundra daemon websocket closed");
}

pub fn router(state: &State) -> Router {
    Router::new()
        .route("/api/node/identity", get(identity))
        .route("/api/node/csr", post(csr))
        .route("/api/node/connect-token", get(connect_token))
        .route("/api/node/state", get(snapshot))
        .route("/api/node/ws", any(ws))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state.clone())
}

pub async fn serve(state: State) -> Result<(), anyhow::Error> {
    let Some(tundra) = state.tundra.clone() else {
        return Ok(());
    };

    let path = tundra.socket_path();
    let _ = tokio::fs::remove_file(&path).await;

    let listener = tokio::net::UnixListener::bind(&path)
        .context(format!("failed to bind {}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;

        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&path, perms).await?;
    }

    tracing::info!("tundra control plane listening on {}", path.display());

    axum::serve(listener, router(&state).into_make_service())
        .await
        .map_err(Into::into)
}
