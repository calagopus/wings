use clap::{Args, FromArgMatches, ValueEnum};
use colored::Colorize;
use std::path::Path;
use tokio::process::Command;

#[derive(ValueEnum, Clone, Default, PartialEq, Debug)]
pub enum InitSystem {
    #[default]
    Auto,
    Systemd,
    Openrc,
}

#[derive(Args)]
pub struct ServiceInstallArgs {
    #[arg(
        short = 'o',
        long = "override",
        help = "set to true to override an existing service file"
    )]
    r#override: bool,

    #[arg(
        short = 'i',
        long = "init",
        help = "specify the init system to install for (systemd, openrc, or auto)",
        default_value = "auto"
    )]
    init: InitSystem,
}

fn generate_systemd_service(binary_path: &Path) -> String {
    format!(
        r#"[Unit]
Description=Calagopus Wings Daemon
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
User=root
KillMode=process
LimitNOFILE=4096
PIDFile=/run/calagopus-wings/daemon.pid
ExecStart={}
Restart=on-failure
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s

[Install]
WantedBy=multi-user.target
"#,
        binary_path.display()
    )
}

fn generate_openrc_service(binary_path: &Path) -> String {
    format!(
        r#"#!/sbin/openrc-run

description="Calagopus Wings Daemon"

command="{}"
supervisor="supervise-daemon"
pidfile="/run/calagopus-wings.pid"
rc_ulimit="-n 4096"

respawn_delay=5
respawn_max=30
respawn_period=180

depend() {{
    need net docker
}}
"#,
        binary_path.display()
    )
}

pub struct ServiceInstallCommand;

impl crate::commands::CliCommand<ServiceInstallArgs> for ServiceInstallCommand {
    fn get_command(&self, command: clap::Command) -> clap::Command {
        command
    }

    fn get_executor(self) -> Box<crate::commands::ExecutorFunc> {
        Box::new(|config, arg_matches| {
            Box::pin(async move {
                let args = ServiceInstallArgs::from_arg_matches(&arg_matches)?;

                if std::env::consts::OS != "linux" {
                    eprintln!("{}", "this command is only available on Linux".red());
                    return Ok(1);
                }

                let binary = match std::env::current_exe() {
                    Ok(path) => path,
                    Err(_) => {
                        eprintln!("{}", "failed to get current executable path".red());
                        return Ok(1);
                    }
                };

                let awaiting_pairing = config.is_none() && crate::config::Config::find().is_none();
                let start = config.is_some() || awaiting_pairing;

                let mut init_system = args.init.clone();
                if init_system == InitSystem::Auto {
                    if Path::new("/run/systemd/system").exists() {
                        init_system = InitSystem::Systemd;
                    } else if Path::new("/run/openrc").exists()
                        || Path::new("/sbin/openrc-run").exists()
                    {
                        init_system = InitSystem::Openrc;
                    } else {
                        eprintln!("{}", "could not auto-detect init system, please specify explicitly via --init".red());
                        return Ok(1);
                    }
                }

                match init_system {
                    InitSystem::Systemd => {
                        if tokio::fs::metadata("/etc/systemd/system").await.is_err() {
                            eprintln!("{}", "systemd directory does not exist".red());
                            return Ok(1);
                        }

                        let service_path = Path::new("/etc/systemd/system/wings.service");
                        if tokio::fs::metadata(service_path).await.is_ok() && !args.r#override {
                            eprintln!("{}", "service file already exists".red());
                            return Ok(1);
                        }

                        let service_content = generate_systemd_service(&binary);

                        match tokio::fs::write(service_path, service_content).await {
                            Ok(_) => {
                                println!("systemd service file created successfully");

                                if let Err(err) = Command::new("systemctl")
                                    .arg("daemon-reload")
                                    .output()
                                    .await
                                {
                                    eprintln!("{}: {err}", "failed to reload systemd".red());
                                    return Ok(1);
                                }

                                println!("system daemons reloaded successfully");

                                if let Err(err) = Command::new("systemctl")
                                    .arg("enable")
                                    .args(if start { &["--now"] } else { &[] as &[&str] })
                                    .arg("wings.service")
                                    .output()
                                    .await
                                {
                                    eprintln!("{}: {err}", "failed to enable service".red());
                                    return Ok(1);
                                }

                                if start {
                                    println!("service enabled on startup and started");
                                } else {
                                    println!("service enabled on startup");
                                }

                                if awaiting_pairing {
                                    println!(
                                        "wings is waiting to be paired, run `journalctl -u wings` to see the pairing code"
                                    );
                                }
                            }
                            Err(err) => {
                                eprintln!("{}: {err}", "failed to write service file".red());
                                return Ok(1);
                            }
                        }
                    }
                    InitSystem::Openrc => {
                        if tokio::fs::metadata("/etc/init.d").await.is_err() {
                            eprintln!("{}", "/etc/init.d directory does not exist".red());
                            return Ok(1);
                        }

                        let service_path = Path::new("/etc/init.d/wings");
                        if tokio::fs::metadata(service_path).await.is_ok() && !args.r#override {
                            eprintln!("{}", "service file already exists".red());
                            return Ok(1);
                        }

                        let service_content = generate_openrc_service(&binary);

                        match tokio::fs::write(service_path, service_content).await {
                            Ok(_) => {
                                println!("openrc service file created successfully");

                                #[cfg(unix)]
                                if let Ok(meta) = tokio::fs::metadata(service_path).await {
                                    let mut perms = meta.permissions();
                                    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);

                                    if let Err(err) =
                                        tokio::fs::set_permissions(service_path, perms).await
                                    {
                                        eprintln!(
                                            "{}: {err}",
                                            "failed to make openrc script executable".red()
                                        );
                                        return Ok(1);
                                    }
                                }

                                if let Err(err) = Command::new("rc-update")
                                    .arg("add")
                                    .arg("wings")
                                    .arg("default")
                                    .output()
                                    .await
                                {
                                    eprintln!(
                                        "{}: {err}",
                                        "failed to add service to default runlevel".red()
                                    );
                                    return Ok(1);
                                }

                                if start {
                                    if let Err(err) = Command::new("rc-service")
                                        .arg("wings")
                                        .arg("start")
                                        .output()
                                        .await
                                    {
                                        eprintln!("{}: {err}", "failed to start service".red());
                                        return Ok(1);
                                    }
                                    println!("service enabled on startup and started");
                                } else {
                                    println!("service enabled on startup");
                                }

                                if awaiting_pairing {
                                    println!(
                                        "wings is waiting to be paired, generate an enrollment command in the panel and run it here"
                                    );
                                }
                            }
                            Err(err) => {
                                eprintln!("{}: {err}", "failed to write service file".red());
                                return Ok(1);
                            }
                        }
                    }
                    InitSystem::Auto => {
                        eprintln!("{}", "failed to detect init system".red());
                        return Ok(1);
                    }
                }

                Ok(0)
            })
        })
    }
}
