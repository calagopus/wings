use super::{WebsocketEvent, WebsocketMessage};
use crate::server::{
    PowerActionError,
    activity::{Activity, ActivityEvent},
    collab::CollabError,
    permissions::Permission,
};
use compact_str::ToCompactString;
use futures::StreamExt;
use serde_json::json;
use std::{net::IpAddr, str::FromStr, sync::Arc};

pub async fn handle_message(
    state: &crate::routes::AppState,
    user_ip: IpAddr,
    server: &crate::server::Server,
    websocket_handler: &Arc<super::ServerWebsocketHandler>,
    message: super::WebsocketMessage,
) -> Result<(), anyhow::Error> {
    let user_ip = Some(user_ip);

    match message.event {
        WebsocketEvent::ConfigureSocket => {
            let Some(property_str) = message.args.first().map(|s| s.as_str()) else {
                return Ok(());
            };

            match property_str {
                "transmission mode" => {
                    let Some(mode_str) = message.args.get(1).map(|s| s.as_str()) else {
                        return Ok(());
                    };

                    match mode_str {
                        "binary" => {
                            websocket_handler.set_binary_mode(true);
                        }
                        "text" => {
                            websocket_handler.set_binary_mode(false);
                        }
                        _ => {
                            tracing::debug!(
                                server = %server.uuid,
                                "received unknown transmission mode: {}",
                                mode_str
                            );
                        }
                    }
                }
                _ => {
                    tracing::debug!(
                        server = %server.uuid,
                        "received unknown socket configuration property: {}",
                        property_str
                    );
                }
            }
        }
        WebsocketEvent::SendStats => {
            websocket_handler
                .send_message(
                    WebsocketMessage::builder(WebsocketEvent::ServerStats)
                        .structured_arg(server.resource_usage())
                        .build(),
                )
                .await;
            websocket_handler
                .send_message(
                    WebsocketMessage::builder(WebsocketEvent::ServerPendingRestart)
                        .arg(server.state.get_pending_restart().to_compact_string())
                        .build(),
                )
                .await;
        }
        WebsocketEvent::SendStatus => {
            websocket_handler
                .send_message(
                    WebsocketMessage::builder(WebsocketEvent::ServerStatus)
                        .arg(server.state.get_state().to_str())
                        .build(),
                )
                .await;
        }
        WebsocketEvent::SendServerLogs => {
            if server.state.get_state() != crate::server::state::ServerState::Offline
                || state.config.load().api.send_offline_server_logs
            {
                let socket_jwt = websocket_handler.get_jwt().await?;

                if !socket_jwt
                    .permissions
                    .has_calagopus_permission_or(Permission::ControlReadConsole, true)
                {
                    return Ok(());
                }
                drop(socket_jwt);

                let mut log_stream = server
                    .logs_lines(Some(state.config.load().system.websocket_log_count))
                    .await;

                while let Some(Ok(line)) = log_stream.next().await {
                    websocket_handler
                        .send_message(
                            WebsocketMessage::builder(WebsocketEvent::ServerConsoleOutput)
                                .arg(line.trim())
                                .build(),
                        )
                        .await;
                }
            }
        }
        WebsocketEvent::SetState => {
            let Some(action) = message.args.first().map(|s| s.as_str()) else {
                return Ok(());
            };
            let power_action = crate::models::ServerPowerAction::from_str(action)?;

            let socket_jwt = websocket_handler.get_jwt().await?;

            if !socket_jwt
                .permissions
                .has_permission(power_action.required_permission())
            {
                tracing::debug!(
                    server = %server.uuid,
                    "jwt does not have permission to {} server: {:?}",
                    power_action.to_str(),
                    socket_jwt.permissions
                );

                return Ok(());
            }
            drop(socket_jwt);

            match server.checked_power_action(power_action).await {
                Ok(()) => {
                    server.activity.log_activity(Activity {
                        event: power_action.activity_event(),
                        user: Some(websocket_handler.get_jwt().await?.user_uuid),
                        ip: user_ip,
                        metadata: None,
                        schedule: None,
                        timestamp: chrono::Utc::now(),
                    });
                }
                Err(PowerActionError::User(message)) => {
                    websocket_handler.send_error(message).await;
                }
                Err(PowerActionError::Internal(err)) => {
                    websocket_handler.send_admin_error(err).await;
                }
            }
        }
        WebsocketEvent::SendCommand => {
            let socket_jwt = websocket_handler.get_jwt().await?;

            if !socket_jwt
                .permissions
                .has_permission(Permission::ControlConsole)
            {
                tracing::debug!(
                    server = %server.uuid,
                    "jwt does not have permission to send command to server: {:?}",
                    socket_jwt.permissions
                );

                return Ok(());
            }
            drop(socket_jwt);

            let Some(raw_command) = message.args.first() else {
                return Ok(());
            };

            let mut command = raw_command.to_compact_string();
            command.push('\n');

            if let Err(err) = server.send_stdin(command.into()).await {
                tracing::error!(
                    server = %server.uuid,
                    "failed to send command to server: {}",
                    err
                );
            } else {
                server.activity.log_activity(Activity {
                    event: ActivityEvent::ConsoleCommand,
                    user: Some(websocket_handler.get_jwt().await?.user_uuid),
                    ip: user_ip,
                    metadata: Some(json!({
                        "command": raw_command,
                    })),
                    schedule: None,
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        WebsocketEvent::FileCollabSubscribe
        | WebsocketEvent::FileCollabUnsubscribe
        | WebsocketEvent::FileCollabUpdate
        | WebsocketEvent::FileCollabAwareness
        | WebsocketEvent::FileCollabSave
        | WebsocketEvent::FileCollabReload => {
            let Some(path) = message.args.first().cloned() else {
                return Ok(());
            };

            let socket_jwt = websocket_handler.get_jwt().await?;
            let user_uuid = socket_jwt.user_uuid;
            let user_name = socket_jwt
                .user_name
                .clone()
                .unwrap_or_else(|| user_uuid.to_compact_string());
            let user_avatar = socket_jwt.user_avatar.clone();
            drop(socket_jwt);

            let required_permission = match message.event {
                WebsocketEvent::FileCollabUpdate
                | WebsocketEvent::FileCollabSave
                | WebsocketEvent::FileCollabReload => Permission::FileUpdate,
                _ => Permission::FileReadContent,
            };
            if !websocket_handler
                .has_permission(required_permission)
                .await?
            {
                tracing::debug!(
                    server = %server.uuid,
                    "jwt does not have permission for collaborative editing: {:?}",
                    required_permission
                );

                websocket_handler
                    .send_message(
                        WebsocketMessage::builder(WebsocketEvent::FileCollabError)
                            .arg(path)
                            .arg("missing permission")
                            .build(),
                    )
                    .await;

                return Ok(());
            }

            let result = match message.event {
                WebsocketEvent::FileCollabSubscribe => {
                    server
                        .collab
                        .subscribe(
                            server,
                            websocket_handler,
                            user_uuid,
                            user_name,
                            user_avatar,
                            &path,
                            message.args.get(1).map(|s| s.as_str()),
                        )
                        .await
                }
                WebsocketEvent::FileCollabUnsubscribe => {
                    server
                        .collab
                        .unsubscribe(
                            server,
                            websocket_handler.connection_id,
                            user_uuid,
                            &path,
                            message.args.get(1).map(|s| s.as_str()),
                        )
                        .await
                }
                WebsocketEvent::FileCollabUpdate => {
                    let (Some(finished), Some(chunk)) = (
                        message.args.get(1).map(|s| s.as_str()),
                        message.args.get(2).map(|s| s.as_str()),
                    ) else {
                        return Ok(());
                    };

                    server
                        .collab
                        .apply_update(
                            server,
                            websocket_handler.connection_id,
                            user_uuid,
                            &path,
                            finished == "1",
                            chunk,
                            message.args.get(3).map(|s| s.as_str()),
                        )
                        .await
                }
                WebsocketEvent::FileCollabAwareness => {
                    let Some(payload) = message.args.get(1).map(|s| s.as_str()) else {
                        return Ok(());
                    };

                    server
                        .collab
                        .relay_awareness(
                            server,
                            websocket_handler.connection_id,
                            user_uuid,
                            &path,
                            payload,
                        )
                        .await
                }
                WebsocketEvent::FileCollabSave => {
                    let force = message.args.get(1).map(|s| s.as_str()) == Some("1");
                    let expected_hash = message.args.get(2).map(|s| s.as_str());

                    server
                        .collab
                        .save(
                            server,
                            websocket_handler.connection_id,
                            user_uuid,
                            user_ip,
                            &path,
                            force,
                            expected_hash,
                        )
                        .await
                }
                WebsocketEvent::FileCollabReload => {
                    server
                        .collab
                        .reload(server, websocket_handler.connection_id, user_uuid, &path)
                        .await
                }
                _ => return Ok(()),
            };

            match result {
                Ok(()) => {}
                Err(CollabError::User(err)) => {
                    websocket_handler
                        .send_message(
                            WebsocketMessage::builder(WebsocketEvent::FileCollabError)
                                .arg(path)
                                .arg(err)
                                .build(),
                        )
                        .await;
                }
                Err(CollabError::Internal(err)) => {
                    tracing::error!(
                        server = %server.uuid,
                        "error handling collaborative editing message: {:#}",
                        err
                    );

                    websocket_handler
                        .send_message(
                            WebsocketMessage::builder(WebsocketEvent::FileCollabError)
                                .arg(path)
                                .arg("an unexpected error occurred")
                                .build(),
                        )
                        .await;
                }
            }
        }
        WebsocketEvent::Ping => {
            websocket_handler
                .send_message(
                    WebsocketMessage::builder(WebsocketEvent::Pong)
                        .args(message.args.iter().cloned())
                        .build(),
                )
                .await;
        }
        _ => {
            tracing::debug!(
                "received websocket message that will not be handled: {:?}",
                message
            );
        }
    }

    Ok(())
}
