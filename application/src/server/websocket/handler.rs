use crate::{
    response::ApiResponse,
    routes::GetState,
    server::{permissions::Permission, websocket},
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use compact_str::ToCompactString;
use futures::{SinkExt, StreamExt};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Mutex, RwLock, broadcast::error::RecvError};

const MAX_MISSED_PONGS: usize = 2;
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

pub async fn handle_ws(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    connect_info: ConnectInfo<SocketAddr>,
    state: GetState,
    Path(server): Path<uuid::Uuid>,
) -> Response {
    let server = match state.server_manager.get_server(server).await {
        Some(server) => server,
        None => {
            return ApiResponse::error("server not found")
                .with_status(StatusCode::NOT_FOUND)
                .into_response();
        }
    };

    let user_ip = state.config.find_ip(&headers, connect_info);

    let Some(mut limiter_guard) = state.websocket_limiter.acquire(user_ip) else {
        tracing::debug!(server = %server.uuid, %user_ip, "rejecting websocket, connection limit reached");

        return ApiResponse::error("too many connections")
            .with_status(StatusCode::TOO_MANY_REQUESTS)
            .into_response();
    };

    let config = state.config.load();
    let ws = ws
        .max_message_size(config.system.websocket.max_message_size as usize)
        .max_frame_size(config.system.websocket.max_frame_size as usize)
        .read_buffer_size(config.system.websocket.read_buffer_size as usize);
    let authentication_timeout = config.system.websocket.authentication_timeout;
    drop(config);

    ws.on_upgrade(move |socket| async move {
        let (sender, mut receiver) = socket.split();
        let sender = Arc::new(Mutex::new(sender));
        let socket_jwt = Arc::new(RwLock::new(None));
        let missed_pongs = Arc::new(AtomicUsize::new(0));

        let websocket_handler = Arc::new(super::ServerWebsocketHandler::new(
            Arc::clone(&sender),
            Arc::clone(&state),
            server.clone(),
            Arc::clone(&socket_jwt),
        ));

        let writer = {
            let state = Arc::clone(&state);
            let socket_jwt = Arc::clone(&socket_jwt);
            let websocket_handler = Arc::clone(&websocket_handler);
            let missed_pongs = Arc::clone(&missed_pongs);
            let server = server.clone();

            async move {
                loop {
                    let user_removal_fut: Pin<Box<dyn Future<Output = ()> + Send>> = if let Some(jwt) = socket_jwt.read().await.as_ref() {
                        Box::pin(server
                            .user_permissions
                            .wait_for_removal(jwt.user_uuid))
                    } else {
                        Box::pin(futures::future::pending())
                    };
                    let ws_data = tokio::select! {
                        _ = user_removal_fut => {
                            tracing::debug!(
                                server = %server.uuid,
                                "closing websocket due to user permissions removal",
                            );
                            if let Some(socket_jwt) = socket_jwt.read().await.as_ref() {
                                state.config.jwt.deny(socket_jwt.base.jwt_id.clone());
                            }
                            websocket_handler.close("permission revoked").await;
                            break;
                        }
                        data = receiver.next() => match data {
                            Some(Ok(data)) => {
                                if !matches!(data, Message::Ping(_)) {
                                    missed_pongs.store(0, Ordering::Relaxed);
                                }

                                data
                            }
                            Some(Err(err)) => {
                                tracing::debug!(
                                    server = %server.uuid,
                                    "error receiving websocket message: {}",
                                    err
                                );
                                break;
                            }
                            None => break,
                        }
                    };

                    if let Message::Close(_) = ws_data {
                        tracing::debug!(
                            server = %server.uuid,
                            "websocket closed",
                        );
                        break;
                    }

                    if matches!(ws_data, Message::Ping(_) | Message::Pong(_)) {
                        continue;
                    }

                    let jwt_result =
                        super::jwt::handle_jwt(&state, &server, &websocket_handler, ws_data).await;
                    if socket_jwt.read().await.is_some() {
                        limiter_guard.authenticated();
                    }

                    match jwt_result {
                        Ok(Some(message)) => {
                            match super::message_handler::handle_message(
                                &state, user_ip, &server, &websocket_handler, message,
                            )
                            .await
                            {
                                Ok(_) => {}
                                Err(err) => {
                                    tracing::error!(
                                        server = %server.uuid,
                                        "error handling websocket message: {}",
                                        err
                                    );
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(websocket::jwt::JwtError::CloseSocket) => {
                            tracing::debug!(
                                server = %server.uuid,
                                "closing websocket due to jwt error",
                            );
                            break;
                        }
                        Err(websocket::jwt::JwtError::Expired) => {
                            tracing::debug!(
                                server = %server.uuid,
                                "jwt expired on websocket, ignoring",
                            );
                        }
                        Err(websocket::jwt::JwtError::MiscStr(err)) => {
                            tracing::debug!(
                                server = %server.uuid,
                                "error handling jwt: {}",
                                err,
                            );

                            websocket_handler.send_message(
                                websocket::WebsocketMessage::builder(
                                    websocket::WebsocketEvent::JwtError,
                                )
                                .arg(err.to_compact_string())
                                .build(),
                            )
                            .await;
                        }
                        Err(websocket::jwt::JwtError::Misc(err)) => {
                            tracing::error!(
                                server = %server.uuid,
                                "error handling jwt: {}",
                                err,
                            );

                            websocket_handler.send_message(
                                websocket::WebsocketMessage::builder(
                                    websocket::WebsocketEvent::JwtError,
                                )
                                .arg(err.to_compact_string())
                                .build(),
                            )
                            .await;
                        }
                    }
                }
            }
        };

        let futures: [Pin<Box<dyn Future<Output = ()> + Send>>; 3] = [
            // Server Listener
            {
                let socket_jwt = Arc::clone(&socket_jwt);
                let websocket_handler = Arc::clone(&websocket_handler);
                let mut receiver = server.websocket.subscribe();
                let mut targeted_receiver = server.targeted_websocket.subscribe();
                let server = server.clone();

                Box::pin(async move {
                    loop {
                        tokio::select! {
                            data = receiver.recv() => {
                                match data {
                                    Ok(message) => {
                                        let run = async || -> Result<(), anyhow::Error> {
                                            if socket_jwt.read().await.is_none() {
                                                return Ok(());
                                            }

                                            let allowed = match message.event.broadcast_permission() {
                                                websocket::BroadcastPermission::Denied => false,
                                                websocket::BroadcastPermission::Authenticated => {
                                                    websocket_handler
                                                        .has_permission(Permission::WebsocketConnect).await?
                                                }
                                                websocket::BroadcastPermission::Required(permission) => {
                                                    websocket_handler.has_permission(permission).await?
                                                }
                                                websocket::BroadcastPermission::CalagopusOr(permission, default) => {
                                                    websocket_handler
                                                        .has_calagopus_permission_or(permission, default).await?
                                                }
                                            };

                                            if !allowed {
                                                return Ok(());
                                            }

                                            websocket_handler.send_message(message).await;

                                            Ok(())
                                        };

                                        if let Err(err) = run().await {
                                            tracing::debug!(
                                                server = %server.uuid,
                                                "error handling websocket message from server: {}",
                                                err
                                            );

                                            websocket_handler.send_message(
                                                websocket::WebsocketMessage::builder(
                                                    websocket::WebsocketEvent::JwtError,
                                                )
                                                .arg(err.to_compact_string())
                                                .build(),
                                            )
                                            .await;
                                        }
                                    }
                                    Err(RecvError::Closed) => {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "websocket channel closed, stopping listener"
                                        );
                                        break;
                                    }
                                    Err(RecvError::Lagged(_)) => {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "websocket lagged behind, messages dropped"
                                        );
                                    }
                                }
                            }
                            data = targeted_receiver.recv() => {
                                match data {
                                    Ok(message) => {
                                        let socket_jwt = socket_jwt.read().await;
                                        let socket_jwt = match socket_jwt.as_ref() {
                                            Some(jwt) => jwt,
                                            None => {
                                                tracing::debug!(
                                                    server = %server.uuid,
                                                    "no socket jwt found, ignoring targeted websocket message",
                                                );
                                                websocket_handler.missed_targeted.store(true, Ordering::Relaxed);
                                                continue;
                                            }
                                        };

                                        if let Err(err) = socket_jwt.base.validate(&state.config.jwt, Some("websocket")) {
                                            tracing::debug!(
                                                server = %server.uuid,
                                                "invalid jwt when receiving targeted websocket message: {}",
                                                err
                                            );
                                            websocket_handler.missed_targeted.store(true, Ordering::Relaxed);
                                            continue;
                                        }

                                        if message.matches(&websocket_handler.connection_id, &socket_jwt.user_uuid, &socket_jwt.permissions) {
                                            websocket_handler.send_message(
                                                message.into_message()
                                            ).await;
                                        }
                                    }
                                    Err(RecvError::Closed) => {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "targeted websocket channel closed, stopping listener"
                                        );
                                        break;
                                    }
                                    Err(RecvError::Lagged(_)) => {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "targeted websocket lagged behind, messages dropped"
                                        );
                                        server.collab.resync_connection(&websocket_handler).await;
                                    }
                                }
                            }
                        }
                    }
                })
            },
            // Stdout Listener
            {
                let websocket_handler = Arc::clone(&websocket_handler);
                let server = server.clone();

                Box::pin(async move {
                    'outer: loop {
                        if !websocket_handler.has_calagopus_permission_or(Permission::ControlReadConsole, true).await.is_ok_and(|h| h)
                        {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }

                        if let Some(mut stdout) = server.get_stdout_lines_ratelimited().await {
                            loop {
                                match stdout.recv().await {
                                    Ok(stdout) => {
                                        if !websocket_handler.has_calagopus_permission_or(Permission::ControlReadConsole, true).await.is_ok_and(|h| h)
                                        {
                                            websocket_handler
                                                .send_message(server.get_daemon_error("You are missing the `control.read-console` permission to view server logs and console output."))
                                                .await;

                                            continue 'outer;
                                        }

                                        websocket_handler.send_message(
                                            websocket::WebsocketMessage::builder(
                                                websocket::WebsocketEvent::ServerConsoleOutput,
                                            )
                                            .arg(stdout.to_compact_string())
                                            .build(),
                                        )
                                        .await;
                                    }
                                    Err(RecvError::Closed) => break,
                                    Err(RecvError::Lagged(_)) => {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "stdout lagged behind, messages dropped"
                                        );
                                    }
                                }
                            }
                        }

                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                })
            },
            // Jwt Listener
            {
                let websocket_handler = Arc::clone(&websocket_handler);

                Box::pin(async move {
                    super::jwt::listen_jwt(&websocket_handler).await;
                })
            },
        ];

        let pinger = {
            let sender = Arc::clone(&sender);
            let missed_pongs = Arc::clone(&missed_pongs);
            let socket_jwt = Arc::clone(&socket_jwt);
            let websocket_handler = Arc::clone(&websocket_handler);
            let server = server.clone();

            async move {
                let mut unauthenticated_for = 0;

                loop {
                    tokio::time::sleep(PING_INTERVAL).await;

                    if authentication_timeout > 0 {
                        if socket_jwt.read().await.is_some() {
                            unauthenticated_for = 0;
                        } else {
                            unauthenticated_for += PING_INTERVAL.as_secs();

                            if unauthenticated_for >= authentication_timeout {
                                tracing::debug!(
                                    server = %server.uuid,
                                    "closing websocket that stayed unauthenticated for {}s",
                                    unauthenticated_for,
                                );

                                websocket_handler.close("authentication timeout").await;
                                break;
                            }
                        }
                    }

                    if missed_pongs.fetch_add(1, Ordering::Relaxed) >= MAX_MISSED_PONGS {
                        tracing::debug!(
                            server = %server.uuid,
                            "websocket ping timeout, closing dead connection",
                        );
                        break;
                    }

                    let ping = sender
                        .lock()
                        .await
                        .send(Message::Ping(Bytes::from_static(&[1, 2, 3])))
                        .await;

                    if ping.is_err() {
                        tracing::debug!(
                            server = %server.uuid,
                            "websocket ping failed, closing dead connection",
                        );
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = writer => {
                tracing::debug!(
                    server = %server.uuid,
                    "websocket writer finished",
                );
            }
            _ = futures::future::join_all(futures) => {
                tracing::debug!(
                    server = %server.uuid,
                    "websocket handles finished",
                );
            }
            _ = pinger => {
                tracing::debug!(
                    server = %server.uuid,
                    "websocket pinger finished",
                );
            }
        }

        server.collab.disconnect(websocket_handler.connection_id).await;
    })
}
