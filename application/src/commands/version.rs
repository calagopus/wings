use chrono::Datelike;
use clap::Args;

#[derive(Args)]
pub struct VersionArgs;

pub struct VersionCommand;

impl crate::commands::CliCommand<VersionArgs> for VersionCommand {
    fn get_command(&self, command: clap::Command) -> clap::Command {
        command
    }

    fn get_executor(self) -> Box<crate::commands::ExecutorFunc> {
        Box::new(|_config, _arg_matches| {
            Box::pin(async move {
                println!(
                    "github.com/calagopus/wings {} ({})",
                    crate::full_version(),
                    crate::TARGET
                );
                println!(
                    "upgrades from {} {} ({})",
                    crate::upgrade::PROVIDER,
                    crate::upgrade::REPOSITORY,
                    crate::upgrade::API_URL
                );
                if !crate::bins::FUSEQUOTA_VERSION.is_empty() {
                    println!(
                        "github.com/calagopus/fusequota {} ({} compressed)",
                        crate::bins::FUSEQUOTA_VERSION,
                        human_bytes::human_bytes(crate::bins::FUSEQUOTA_BIN.len() as f64)
                    );
                }
                println!(
                    "copyright © 2025 - {} Calagopus, 0x7d8 & Contributors",
                    chrono::Local::now().year()
                );

                Ok(0)
            })
        })
    }
}
