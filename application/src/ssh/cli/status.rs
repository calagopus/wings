use super::{CliContext, SshCliCommand};
use serde_json::json;

pub struct StatusCommand;

#[async_trait::async_trait]
impl SshCliCommand for StatusCommand {
    fn name(&self) -> &'static str {
        "status"
    }

    fn about(&self) -> &'static str {
        "Show the server state"
    }

    fn usage(&self) -> Option<&'static str> {
        Some("[--json]")
    }

    async fn execute(&self, ctx: &CliContext<'_>, args: &[&str], out: &mut Vec<String>) -> bool {
        let state = ctx.server.state.get_state();
        let pending_restart = ctx.server.state.get_pending_restart();

        match args {
            [] => {
                out.push(format!("State: {}", state.to_str()));
                out.push(format!(
                    "Pending restart: {}",
                    if pending_restart { "yes" } else { "no" }
                ));
            }
            ["--json"] => {
                out.push(
                    json!({
                        "state": state,
                        "pending_restart": pending_restart,
                    })
                    .to_string(),
                );
            }
            _ => {
                out.push(ctx.usage_line(self));
                return false;
            }
        }

        true
    }
}
