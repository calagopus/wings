use super::{super::shell::can_read_console, CliContext, SshCliCommand};
use crate::{
    models::ServerPowerAction,
    server::{PowerActionError, activity::Activity, permissions::Permission, state::ServerState},
};
use std::{str::FromStr, time::Duration};

const WAIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub struct PowerCommand;

#[async_trait::async_trait]
impl SshCliCommand for PowerCommand {
    fn name(&self) -> &'static str {
        "power"
    }

    fn about(&self) -> &'static str {
        "Send a power action to the server"
    }

    fn usage(&self) -> Option<&'static str> {
        Some("<start|restart|stop|kill> [--wait]")
    }

    async fn execute(&self, ctx: &CliContext<'_>, args: &[&str], out: &mut Vec<String>) -> bool {
        let (action, wait) = match args {
            [action] => (ServerPowerAction::from_str(action), false),
            [action, "--wait"] => (ServerPowerAction::from_str(action), true),
            _ => {
                out.push(ctx.usage_line(self));
                return false;
            }
        };
        let Ok(action) = action else {
            out.push(ctx.usage_line(self));
            return false;
        };

        let permission = action.required_permission();
        if !ctx.has_permission(permission) {
            out.push(format!(
                "You are missing the `{}` permission to do this.",
                permission.to_str()
            ));
            return false;
        }

        let states = ctx.server.state.subscribe();

        match ctx.server.checked_power_action(action).await {
            Ok(()) => {
                ctx.server.activity.log_activity(Activity {
                    event: action.activity_event(),
                    user: Some(ctx.user_uuid),
                    ip: Some(ctx.user_ip),
                    metadata: None,
                    schedule: None,
                    timestamp: chrono::Utc::now(),
                });

                if wait {
                    wait_for_action(ctx, action, states, out).await
                } else {
                    true
                }
            }
            Err(PowerActionError::User(message)) => {
                out.push(message.into());
                false
            }
            Err(PowerActionError::Reported(message)) => {
                if !ctx.console_attached || !can_read_console(ctx.server, ctx.user_uuid) {
                    out.push(message.into());
                }
                false
            }
            Err(PowerActionError::Internal(err)) => {
                if ctx.has_permission(Permission::AdminWebsocketErrors) {
                    out.push(format!("Failed to {} the server: {err:#}", action.to_str()));
                } else {
                    out.push(format!(
                        "An unexpected error occurred while trying to {} the server. Please contact an Administrator.",
                        action.to_str()
                    ));
                }
                false
            }
        }
    }
}

async fn wait_for_action(
    ctx: &CliContext<'_>,
    action: ServerPowerAction,
    mut states: tokio::sync::watch::Receiver<ServerState>,
    out: &mut Vec<String>,
) -> bool {
    let target = match action {
        ServerPowerAction::Start | ServerPowerAction::Restart => ServerState::Running,
        ServerPowerAction::Stop | ServerPowerAction::Kill => ServerState::Offline,
    };

    let reached = tokio::time::timeout(WAIT_TIMEOUT, async {
        let mut started = false;

        loop {
            states.changed().await.ok()?;

            match *states.borrow_and_update() {
                state if state == target => return Some(true),
                ServerState::Starting => started = true,
                ServerState::Offline if started => return Some(false),
                _ => {}
            }
        }
    })
    .await;

    match reached {
        Ok(Some(true)) => {
            out.push(format!("Server is now {}.", target.to_str()));
            true
        }
        Ok(Some(false)) => {
            out.push("Server stopped before it finished starting.".into());
            false
        }
        Ok(None) => {
            out.push("Server is no longer available.".into());
            false
        }
        Err(_) => {
            out.push(format!(
                "Timed out waiting for the server to become {} (currently {}).",
                target.to_str(),
                ctx.server.state.get_state().to_str()
            ));
            false
        }
    }
}
