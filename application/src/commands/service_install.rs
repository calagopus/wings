use clap::{Args, FromArgMatches, ValueEnum};
use colored::Colorize;
use std::path::{Path, PathBuf};
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

    #[arg(
        long = "lxcfs",
        help = "install a dedicated lxcfs service for server containers instead of the wings service"
    )]
    lxcfs: bool,
}

const LXCFS_DIRECTORY: &str = "/var/lib/calagopus-wings/lxcfs";
const LXCFS_RUNTIME_DIRECTORY: &str = "/run/calagopus-wings-lxcfs";

fn lxcfs_args() -> String {
    format!(
        "--enable-cfs -p {LXCFS_RUNTIME_DIRECTORY}.pid --runtime-dir={LXCFS_RUNTIME_DIRECTORY} {LXCFS_DIRECTORY}"
    )
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

fn generate_systemd_lxcfs_service(lxcfs_path: &Path) -> String {
    format!(
        r#"[Unit]
Description=Calagopus Wings LXCFS
Before=docker.service

[Service]
OOMScoreAdjust=-1000
ExecStartPre=/bin/mkdir -p {LXCFS_DIRECTORY}
ExecStart={} {}
KillMode=process
Restart=on-failure
ExecStopPost=-/bin/umount -l {LXCFS_DIRECTORY}
Delegate=yes
ExecReload=/bin/kill -USR1 $MAINPID

[Install]
WantedBy=multi-user.target
"#,
        lxcfs_path.display(),
        lxcfs_args()
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

fn generate_openrc_lxcfs_service(lxcfs_path: &Path) -> String {
    format!(
        r#"#!/sbin/openrc-run

description="Calagopus Wings LXCFS"

command="{}"
command_args="{}"
supervisor="supervise-daemon"
pidfile="/run/calagopus-wings-lxcfs.supervise.pid"

respawn_delay=5

depend() {{
    before docker
}}

start_pre() {{
    checkpath -d {LXCFS_DIRECTORY}
}}

stop_post() {{
    umount -l {LXCFS_DIRECTORY} 2>/dev/null || true
}}
"#,
        lxcfs_path.display(),
        lxcfs_args()
    )
}

fn find_lxcfs() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join("lxcfs"))
        .find(|path| path.is_file())
}

async fn install_lxcfs(
    init_system: InitSystem,
    r#override: bool,
    config: Option<std::sync::Arc<crate::config::Config>>,
) -> Result<i32, anyhow::Error> {
    let Some(lxcfs_path) = find_lxcfs() else {
        eprintln!(
            "{}",
            "lxcfs was not found in PATH, install it with your package manager first".red()
        );
        return Ok(1);
    };

    let (service_path, service_content) = match init_system {
        InitSystem::Systemd => (
            Path::new("/etc/systemd/system/wings-lxcfs.service"),
            generate_systemd_lxcfs_service(&lxcfs_path),
        ),
        InitSystem::Openrc => (
            Path::new("/etc/init.d/wings-lxcfs"),
            generate_openrc_lxcfs_service(&lxcfs_path),
        ),
        InitSystem::Auto => {
            eprintln!("{}", "failed to detect init system".red());
            return Ok(1);
        }
    };

    if tokio::fs::metadata(service_path).await.is_ok() && !r#override {
        eprintln!("{}", "service file already exists".red());
        return Ok(1);
    }

    if let Err(err) = tokio::fs::write(service_path, service_content).await {
        eprintln!("{}: {err}", "failed to write service file".red());
        return Ok(1);
    }

    println!("lxcfs service file created successfully");

    let commands: &[&[&str]] = match init_system {
        InitSystem::Systemd => &[
            &["systemctl", "daemon-reload"],
            &["systemctl", "enable", "--now", "wings-lxcfs.service"],
        ],
        _ => {
            #[cfg(unix)]
            if let Err(err) = tokio::fs::set_permissions(
                service_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            )
            .await
            {
                eprintln!("{}: {err}", "failed to make openrc script executable".red());
                return Ok(1);
            }

            &[
                &["rc-update", "add", "wings-lxcfs", "default"],
                &["rc-service", "wings-lxcfs", "start"],
            ]
        }
    };

    for command in commands {
        let Some((program, args)) = command.split_first() else {
            continue;
        };

        match Command::new(program).args(args).output().await {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                eprintln!(
                    "{} `{}`: {}",
                    "failed to run".red(),
                    command.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                return Ok(1);
            }
            Err(err) => {
                eprintln!("{} `{}`: {err}", "failed to run".red(), command.join(" "));
                return Ok(1);
            }
        }
    }

    println!("lxcfs service enabled on startup and started");

    let Some(config) = config else {
        println!(
            "set `docker.lxcfs.enabled: true` and `docker.lxcfs.directory: {LXCFS_DIRECTORY}` in the wings config to use it"
        );
        return Ok(0);
    };

    let mut doc = serde_json::to_value(&**config.load())?;
    json_patch::merge(
        &mut doc,
        &serde_json::json!({
            "docker": {
                "lxcfs": {
                    "enabled": true,
                    "directory": LXCFS_DIRECTORY,
                },
            },
        }),
    );
    config.replace(serde_json::from_value(doc)?)?;

    println!(
        "wings config updated, restart wings and then each server for containers to pick up lxcfs"
    );

    Ok(0)
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

                if args.lxcfs {
                    return install_lxcfs(init_system, args.r#override, config).await;
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
