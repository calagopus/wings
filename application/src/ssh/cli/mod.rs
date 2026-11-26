use crate::{routes::State, server::permissions::Permission};

mod help;
mod logs;
mod permissions;
mod power;
mod stats;
mod status;
mod version;

#[async_trait::async_trait]
pub trait SshCliCommand: Sync {
    fn name(&self) -> &'static str;
    fn about(&self) -> &'static str;
    fn usage(&self) -> Option<&'static str> {
        None
    }

    async fn execute(&self, ctx: &CliContext<'_>, args: &[&str], out: &mut Vec<String>) -> bool;
}

pub static COMMANDS: &[&dyn SshCliCommand] = &[
    &help::HelpCommand,
    &version::VersionCommand,
    &status::StatusCommand,
    &power::PowerCommand,
    &stats::StatsCommand,
    &logs::LogsCommand,
    &permissions::PermissionsCommand,
];

pub struct CliContext<'a> {
    pub state: &'a State,
    pub server: &'a crate::server::Server,

    pub user_ip: std::net::IpAddr,
    pub user_uuid: uuid::Uuid,
    pub console_attached: bool,
}

pub struct CliOutput {
    pub lines: Vec<String>,
    pub success: bool,
}

pub fn is_cli_command(state: &State, line: &str) -> bool {
    line.split_whitespace().next() == Some(state.config.load().system.sftp.shell.cli.name.as_str())
}

impl CliContext<'_> {
    #[inline]
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.server
            .user_permissions
            .has_permission(self.user_uuid, permission)
    }

    pub fn prefix(&self) -> compact_str::CompactString {
        self.state
            .config
            .load()
            .system
            .sftp
            .shell
            .cli
            .name
            .as_str()
            .into()
    }

    pub fn usage_line(&self, command: &dyn SshCliCommand) -> String {
        match command.usage() {
            Some(usage) => format!("Usage: {} {} {usage}", self.prefix(), command.name()),
            None => format!("Usage: {} {}", self.prefix(), command.name()),
        }
    }

    pub async fn run(&self, line: &str) -> CliOutput {
        let mut segments = line.split_whitespace();
        segments.next();

        let mut lines = Vec::new();
        let name = segments.next();
        let args = segments.collect::<Vec<_>>();

        let success = match COMMANDS.iter().find(|command| Some(command.name()) == name) {
            Some(command) => command.execute(self, &args, &mut lines).await,
            None => {
                lines.push(format!(
                    "Unknown command. Type '{} help' for a list of commands.",
                    self.prefix()
                ));
                false
            }
        };

        CliOutput { lines, success }
    }
}
