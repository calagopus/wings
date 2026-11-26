use super::{COMMANDS, CliContext, SshCliCommand};

pub struct HelpCommand;

#[async_trait::async_trait]
impl SshCliCommand for HelpCommand {
    fn name(&self) -> &'static str {
        "help"
    }

    fn about(&self) -> &'static str {
        "Show this help message"
    }

    async fn execute(&self, _ctx: &CliContext<'_>, _args: &[&str], out: &mut Vec<String>) -> bool {
        let width = COMMANDS
            .iter()
            .map(|command| command.name().len())
            .max()
            .unwrap_or_default();

        out.push("Available commands:".into());
        for command in COMMANDS {
            out.push(format!("  {:width$} - {}", command.name(), command.about()));
        }

        true
    }
}
