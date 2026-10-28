use super::{CliContext, SshCliCommand};

pub struct StatsCommand;

#[async_trait::async_trait]
impl SshCliCommand for StatsCommand {
    fn name(&self) -> &'static str {
        "stats"
    }

    fn about(&self) -> &'static str {
        "Show server statistics"
    }

    fn usage(&self) -> Option<&'static str> {
        Some("[--json]")
    }

    async fn execute(&self, ctx: &CliContext<'_>, args: &[&str], out: &mut Vec<String>) -> bool {
        let resource_usage = ctx.server.resource_usage();

        match args {
            [] => {}
            ["--json"] => {
                return match serde_json::to_string(&resource_usage) {
                    Ok(json) => {
                        out.push(json);
                        true
                    }
                    Err(err) => {
                        tracing::error!(
                            server = %ctx.server.uuid,
                            "failed to serialize server stats: {}",
                            err
                        );
                        out.push("Failed to serialize server statistics.".into());
                        false
                    }
                };
            }
            _ => {
                out.push(ctx.usage_line(self));
                return false;
            }
        }

        let (cpu_limit, memory_limit) = {
            let configuration = ctx.server.configuration.read().await;
            (
                configuration.build.cpu_limit,
                configuration.build.memory_limit,
            )
        };
        let disk_limit = ctx.server.filesystem.disk_limit();

        out.push("Server Statistics:".into());
        out.push(format!(
            "  CPU Usage: {:.2}% / {}",
            resource_usage.cpu_absolute,
            if cpu_limit == 0 {
                "Unlimited".to_string()
            } else {
                format!("{cpu_limit}%")
            }
        ));
        out.push(format!(
            "  Memory Usage: {} / {} ({:.2}%)",
            human_bytes::human_bytes(resource_usage.memory_bytes as f64),
            if memory_limit == 0 {
                "Unlimited".to_string()
            } else {
                human_bytes::human_bytes((memory_limit * 1024 * 1024) as f64)
            },
            (resource_usage.memory_bytes as f64 / resource_usage.memory_limit_bytes as f64 * 100.0)
                .min(100.0)
        ));
        out.push(format!(
            "  Disk Usage: {} / {} ({:.2}%)",
            human_bytes::human_bytes(resource_usage.disk_bytes as f64),
            if disk_limit == 0 {
                "Unlimited".to_string()
            } else {
                human_bytes::human_bytes(disk_limit as f64)
            },
            (resource_usage.disk_bytes as f64 / disk_limit as f64 * 100.0).min(100.0)
        ));
        out.push("  Network Usage:".into());
        out.push(format!(
            "    Received: {}",
            human_bytes::human_bytes(resource_usage.network.rx_bytes as f64)
        ));
        out.push(format!(
            "    Sent: {}",
            human_bytes::human_bytes(resource_usage.network.tx_bytes as f64)
        ));

        true
    }
}
