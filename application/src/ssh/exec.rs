use crate::{
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        permissions::Permission,
    },
};
use russh::{Channel, server::Msg};
use serde_json::json;
use tokio::io::AsyncWriteExt;

pub struct ExecSession {
    pub state: State,
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

    async fn run_cli_command(&self, command: &str, channel: &Channel<Msg>) -> std::io::Result<u32> {
        let output = super::cli::CliContext {
            state: &self.state,
            server: &self.server,
            user_ip: self.user_ip,
            user_uuid: self.user_uuid,
            console_attached: false,
        }
        .run(command)
        .await;

        let mut writer = channel.make_writer();
        for line in output.lines {
            writer.write_all(format!("{line}\r\n").as_bytes()).await?;
        }

        Ok(if output.success { 0 } else { 1 })
    }

    async fn send_console_command(
        &self,
        command: &str,
        channel: &Channel<Msg>,
    ) -> std::io::Result<u32> {
        if !self.has_permission(Permission::ControlConsole) {
            channel
                .make_writer()
                .write_all(b"Permission denied.\r\n")
                .await?;
            return Ok(1);
        }

        if self.server.state.get_state() == crate::server::state::ServerState::Offline {
            channel
                .make_writer()
                .write_all(b"Server is not running.\r\n")
                .await?;
            return Ok(1);
        }

        if let Err(err) = self.server.send_stdin(format!("{command}\n").into()).await {
            tracing::error!(
                server = %self.server.uuid,
                "failed to send command to server: {}",
                err
            );
            return Ok(1);
        }

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

        Ok(0)
    }

    pub fn run(self, command: String, channel: Channel<Msg>) {
        tokio::spawn(async move {
            let run = async || -> Result<(), anyhow::Error> {
                channel.data(tokio::io::empty()).await?;

                let exit_status = if super::cli::is_cli_command(&self.state, &command) {
                    self.run_cli_command(&command, &channel).await?
                } else {
                    self.send_console_command(&command, &channel).await?
                };

                channel.exit_status(exit_status).await?;
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
