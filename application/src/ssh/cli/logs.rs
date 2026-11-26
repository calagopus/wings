use super::{super::shell::can_read_console, CliContext, SshCliCommand};
use futures::StreamExt;

pub struct LogsCommand;

#[async_trait::async_trait]
impl SshCliCommand for LogsCommand {
    fn name(&self) -> &'static str {
        "logs"
    }

    fn about(&self) -> &'static str {
        "Show the last console lines"
    }

    fn usage(&self) -> Option<&'static str> {
        Some("[lines]")
    }

    async fn execute(&self, ctx: &CliContext<'_>, args: &[&str], out: &mut Vec<String>) -> bool {
        let lines = match args {
            [] => ctx.state.config.load().system.websocket_log_count,
            [lines] => match lines.parse::<usize>() {
                Ok(lines) if lines > 0 => lines,
                _ => {
                    out.push(ctx.usage_line(self));
                    return false;
                }
            },
            _ => {
                out.push(ctx.usage_line(self));
                return false;
            }
        };

        if !can_read_console(ctx.server, ctx.user_uuid) {
            out.push("You are missing the `control.read-console` permission to do this.".into());
            return false;
        }

        let mut log_stream = ctx.server.logs_lines(Some(lines)).await;
        while let Some(line) = log_stream.next().await {
            match line {
                Ok(line) => out.push(line.trim_end().into()),
                Err(err) => {
                    tracing::error!(
                        server = %ctx.server.uuid,
                        "failed to read server logs: {}",
                        err
                    );
                    out.push("Failed to read the server logs.".into());
                    return false;
                }
            }
        }

        true
    }
}
