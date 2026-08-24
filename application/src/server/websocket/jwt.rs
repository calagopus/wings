use super::{WebsocketEvent, WebsocketJwtPayload, WebsocketMessage};
use crate::server::{permissions::Permission, websocket::ServerWebsocketHandler};
use axum::extract::ws::Message;
use compact_str::ToCompactString;
use std::sync::Arc;

pub enum JwtError {
    CloseSocket,
    Expired,
    Misc(anyhow::Error),
    MiscStr(String),
}

impl From<anyhow::Error> for JwtError {
    fn from(err: anyhow::Error) -> Self {
        JwtError::Misc(err)
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(err: serde_json::Error) -> Self {
        JwtError::Misc(err.into())
    }
}

pub async fn handle_jwt(
    state: &crate::routes::AppState,
    server: &crate::server::Server,
    websocket_handler: &ServerWebsocketHandler,
    message: Message,
) -> Result<Option<WebsocketMessage>, JwtError> {
    let message: WebsocketMessage = match message {
        Message::Text(text) => match serde_json::from_str(&text) {
            Ok(msg) => msg,
            Err(err) => {
                tracing::debug!(
                    server = %server.uuid,
                    "failed to deserialize websocket message: {:?}",
                    err
                );

                return Ok(None);
            }
        },
        Message::Binary(bin) => match rmp_serde::from_slice(&bin) {
            Ok(msg) => msg,
            Err(err) => {
                tracing::debug!(
                    server = %server.uuid,
                    "failed to deserialize websocket binary message: {:?}",
                    err
                );

                return Ok(None);
            }
        },
        _ => return Err(JwtError::Misc(anyhow::anyhow!("invalid message type"))),
    };

    match message.event {
        WebsocketEvent::Authentication => {
            match state
                .config
                .jwt
                .verify::<WebsocketJwtPayload>(message.args.first().map_or("", |v| v.as_str()))
            {
                Ok(jwt) => {
                    if let Err(err) = jwt.base.validate(&state.config.jwt, Some("websocket")) {
                        return Err(JwtError::MiscStr(format!("invalid token: {err}")));
                    }

                    if !jwt.permissions.has_permission(Permission::WebsocketConnect)
                        || jwt.server_uuid != server.uuid
                    {
                        tracing::debug!(
                            server = %server.uuid,
                            "jwt does not have permission to connect to websocket: {:?}",
                            jwt.permissions
                        );

                        if jwt.permissions.has_permission(Permission::WebsocketConnect) {
                            websocket_handler
                                .send_message(
                                    WebsocketMessage::builder(WebsocketEvent::TokenExpired).build(),
                                )
                                .await;

                            return Err(JwtError::Expired);
                        }

                        return Err(JwtError::CloseSocket);
                    }

                    let mut permissions = Vec::new();
                    for permission in jwt.permissions.iter() {
                        permissions.push(permission.to_str().to_compact_string());
                    }

                    websocket_handler
                        .send_message(
                            WebsocketMessage::builder(WebsocketEvent::AuthenticationSuccess)
                                .args(permissions)
                                .build(),
                        )
                        .await;

                    let has_console_read = jwt
                        .permissions
                        .has_calagopus_permission_or(Permission::ControlReadConsole, true);
                    server.user_permissions.set_permissions(
                        jwt.user_uuid,
                        jwt.permissions.clone(),
                        jwt.ignored_files.as_deref(),
                    );

                    if websocket_handler
                        .socket_jwt
                        .write()
                        .await
                        .replace(Arc::new(jwt))
                        .is_none()
                    {
                        websocket_handler
                            .send_message(
                                WebsocketMessage::builder(WebsocketEvent::ServerStatus)
                                    .arg(server.state.get_state().to_str())
                                    .build(),
                            )
                            .await;

                        if !has_console_read {
                            websocket_handler
                                .send_message(server.get_daemon_error("You are missing the `control.read-console` permission to view server logs and console output."))
                                .await;
                        }
                    }

                    if websocket_handler
                        .missed_targeted
                        .swap(false, std::sync::atomic::Ordering::Relaxed)
                    {
                        server.collab.resync_connection(websocket_handler).await;
                    }

                    Ok(None)
                }
                Err(err) => {
                    tracing::debug!(
                        server = %server.uuid,
                        "failed to verify jwt when connecting to websocket: {}",
                        err
                    );

                    Err(JwtError::CloseSocket)
                }
            }
        }
        _ => {
            if let Some(jwt) = websocket_handler.socket_jwt.read().await.as_ref() {
                if let Err(err) = jwt.base.validate(&state.config.jwt, Some("websocket")) {
                    return Err(JwtError::MiscStr(format!("invalid token: {err}")));
                }

                if !jwt.permissions.has_permission(Permission::WebsocketConnect) {
                    tracing::debug!(
                        server = %server.uuid,
                        "jwt does not have permission to connect to websocket: {:?}",
                        jwt.permissions
                    );

                    return Err(JwtError::CloseSocket);
                }

                Ok(Some(message))
            } else {
                tracing::debug!(
                    server = %server.uuid,
                    "jwt is not set when connecting to websocket",
                );

                Err(JwtError::CloseSocket)
            }
        }
    }
}

pub async fn listen_jwt(websocket_handler: &ServerWebsocketHandler) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let socket_jwt_guard = websocket_handler.socket_jwt.read().await;
        if let Some(jwt) = socket_jwt_guard.as_ref() {
            if let Some(expiration) = jwt.base.expiration_time {
                if expiration < chrono::Utc::now().timestamp() {
                    websocket_handler
                        .send_message(
                            WebsocketMessage::builder(WebsocketEvent::TokenExpired).build(),
                        )
                        .await;

                    drop(socket_jwt_guard);
                    websocket_handler.socket_jwt.write().await.take();

                    tracing::debug!("jwt expired for websocket connection, removing jwt");
                } else if expiration - 60 < chrono::Utc::now().timestamp() {
                    websocket_handler
                        .send_message(
                            WebsocketMessage::builder(WebsocketEvent::TokenExpiring).build(),
                        )
                        .await;

                    tracing::debug!(
                        "jwt is expiring soon for websocket connection, notifying client"
                    );
                }
            }
        } else {
            tracing::debug!("jwt is not set when connecting to websocket");
        }
    }
}
