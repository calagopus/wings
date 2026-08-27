use crate::server::{
    activity::{Activity, ActivityEvent},
    permissions::Permission,
};
use russh::{Channel, server::Msg};
use serde_json::json;
use tokio::io::AsyncWriteExt;

pub struct ExecSession {
    pub server: crate::server::Server,

    pub user_ip: std::net::IpAddr,
    pub user_uuid: uuid::Uuid,
}

impl ExecSession {
    #[inline]
    fn has_permission(&self, permission: Permission) -> bool {
        self.server
            .user_permissions
            .has_permission(self.user_uuid, permission)
    }

    pub fn run(self, command: String, channel: Channel<Msg>) {
        tokio::spawn(async move {
            let run = async || -> Result<(), anyhow::Error> {
                channel.data(tokio::io::empty()).await?;

                if self.has_permission(Permission::ControlConsole) {
                    if self.server.state.get_state() != crate::server::state::ServerState::Offline {
                        if let Err(err) =
                            self.server.send_stdin(format!("{command}\n").into()).await
                        {
                            tracing::error!(
                                server = %self.server.uuid,
                                "failed to send command to server: {}",
                                err
                            );
                        } else {
                            self.server.activity.log_activity(Activity {
                                event: ActivityEvent::ConsoleCommand,
                                user: Some(self.user_uuid),
                                ip: Some(self.user_ip),
                                metadata: Some(json!({
                                    "command": command,
                                })),
                                schedule: None,
                                timestamp: chrono::Utc::now(),
                            });
                        }
                    } else {
                        channel
                            .make_writer()
                            .write_all(b"Server is not running.\r\n")
                            .await?;
                    }
                } else {
                    channel
                        .make_writer()
                        .write_all(b"Permission denied.\r\n")
                        .await?;
                }

                channel.exit_status(0).await?;
                channel.close().await?;

                Ok(())
            };

            if let Err(err) = run().await {
                tracing::error!(
                    server = %self.server.uuid,
                    "failed to execute command: {}",
                    err
                );

                channel.exit_status(1).await.unwrap_or_default();
                channel.close().await.unwrap_or_default();
            }
        });
    }
}
