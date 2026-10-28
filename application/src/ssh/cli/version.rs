use super::{CliContext, SshCliCommand};

pub struct VersionCommand;

#[async_trait::async_trait]
impl SshCliCommand for VersionCommand {
    fn name(&self) -> &'static str {
        "version"
    }

    fn about(&self) -> &'static str {
        "Show the current version"
    }

    async fn execute(&self, _ctx: &CliContext<'_>, _args: &[&str], out: &mut Vec<String>) -> bool {
        out.push(format!("Current version: {}", crate::VERSION));

        true
    }
}
