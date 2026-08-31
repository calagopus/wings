use crate::server::filesystem::{cap::CapFilesystem, limiter::DiskLimiterExt};
use clap::{Args, FromArgMatches};
use colored::Colorize;
use dialoguer::{Confirm, theme::ColorfulTheme};
use std::{path::Path, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetMode {
    BtrfsSubvolume,
    ZfsDataset,
}

#[derive(Args)]
pub struct MigrateDiskLimiterArgs {
    #[arg(
        long = "mode",
        help = "the disk limiter to migrate servers to (btrfs-subvolume or zfs-dataset). defaults to the disk_limiter_mode configured in the config file"
    )]
    pub mode: Option<String>,

    #[arg(
        long = "server",
        help = "only migrate the given server uuid(s). may be passed multiple times. defaults to all servers"
    )]
    pub server: Vec<uuid::Uuid>,

    #[arg(
        long = "dry-run",
        help = "only report what would be migrated without making any changes"
    )]
    pub dry_run: bool,

    #[arg(
        short = 'y',
        long = "yes",
        help = "skip the confirmation prompt (the wings daemon MUST be stopped before running)"
    )]
    pub yes: bool,
}

pub struct MigrateDiskLimiterCommand;

impl crate::commands::CliCommand<MigrateDiskLimiterArgs> for MigrateDiskLimiterCommand {
    fn get_command(&self, command: clap::Command) -> clap::Command {
        command
    }

    fn get_executor(self) -> Box<crate::commands::ExecutorFunc> {
        Box::new(|env, arg_matches| {
            Box::pin(async move {
                let args = MigrateDiskLimiterArgs::from_arg_matches(&arg_matches)?;

                let config = match env {
                    Some(config) => config,
                    None => {
                        eprintln!("{}", "no config found".red());
                        return Ok(1);
                    }
                };

                let mode = match args.mode.as_deref() {
                    Some("btrfs-subvolume" | "btrfs") => TargetMode::BtrfsSubvolume,
                    Some("zfs-dataset" | "zfs") => TargetMode::ZfsDataset,
                    Some(_) => {
                        eprintln!(
                            "{}",
                            "invalid --mode, expected 'btrfs-subvolume' or 'zfs-dataset'".red()
                        );
                        return Ok(1);
                    }
                    None => match config.load().system.disk_limiter_mode {
                        crate::server::filesystem::limiter::DiskLimiterMode::BtrfsSubvolume => {
                            TargetMode::BtrfsSubvolume
                        }
                        crate::server::filesystem::limiter::DiskLimiterMode::ZfsDataset => {
                            TargetMode::ZfsDataset
                        }
                        _ => {
                            eprintln!(
                                "{}",
                                "the configured disk_limiter_mode is not btrfs_subvolume or zfs_dataset; pass --mode explicitly".red()
                            );
                            return Ok(1);
                        }
                    },
                };

                if !args.yes {
                    println!(
                        "{}",
                        "the wings daemon must be stopped before migrating disk limiters, otherwise running servers may lose data.".yellow()
                    );

                    let confirm = Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("is the wings daemon stopped and do you want to continue?")
                        .default(false)
                        .interact()?;

                    if !confirm {
                        return Ok(1);
                    }
                }

                let raw_servers = match config.client.servers().await {
                    Ok(servers) => servers,
                    Err(err) => {
                        eprintln!(
                            "{} {:#?}",
                            "failed to fetch servers from remote:".red(),
                            err
                        );
                        return Ok(1);
                    }
                };

                let app_state = Arc::new(crate::routes::AppState {
                    start_time: std::time::Instant::now(),
                    container_type: crate::routes::AppContainerType::None,
                    version: crate::full_version(),

                    config: Arc::clone(&config),
                    executor: Arc::new(crate::server::executor::noop::NoopExecutor),
                    stats_manager: Arc::new(crate::stats::StatsManager::default()),
                    server_manager: Arc::new(crate::server::manager::ServerManager::new(
                        &raw_servers,
                    )),
                    backup_manager: Arc::new(
                        crate::server::backup::manager::BackupManager::default(),
                    ),
                    inotify_manager: Arc::new(
                        crate::server::filesystem::inotify::InotifyManager::new()
                            .expect("failed to initialize inotify manager"),
                    ),
                    websocket_limiter: Arc::new(
                        crate::server::websocket::limiter::WebsocketLimiter::new(Arc::clone(
                            &config,
                        )),
                    ),
                    mime_cache: moka::future::Cache::new(20480),
                    #[cfg(unix)]
                    tundra: None,
                });

                let mut migrated = 0;
                let mut skipped = 0;
                let mut failed = 0;

                for raw_server in raw_servers {
                    let uuid = raw_server.settings.uuid;
                    if !args.server.is_empty() && !args.server.contains(&uuid) {
                        continue;
                    }

                    let disk_limit = raw_server.settings.build.disk_space * 1024 * 1024;
                    let base_path = config.data_path(uuid);

                    if tokio::fs::metadata(&base_path).await.is_err() {
                        println!("{} {}", "skipping (no data directory):".dimmed(), uuid);
                        skipped += 1;
                        continue;
                    }

                    let already_migrated = match mode {
                        TargetMode::BtrfsSubvolume => tokio::fs::metadata(&base_path)
                            .await
                            .map(|m| std::os::unix::fs::MetadataExt::ino(&m) == 256),
                        TargetMode::ZfsDataset => tokio::process::Command::new("zfs")
                            .arg("list")
                            .arg("-H")
                            .arg("-o")
                            .arg("name")
                            .arg(&base_path)
                            .output()
                            .await
                            .map(|o| o.status.success()),
                    };
                    match already_migrated {
                        Ok(true) => {
                            println!("{} {}", "skipping (already migrated):".dimmed(), uuid);
                            skipped += 1;
                            continue;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            eprintln!("{} {}: {}", "failed to inspect, skipping:".red(), uuid, err);
                            failed += 1;
                            continue;
                        }
                    }

                    if args.dry_run {
                        println!("{} {} -> {:?}", "would migrate:".cyan(), uuid, mode);
                        migrated += 1;
                        continue;
                    }

                    let server = crate::server::Server::new(
                        raw_server.settings,
                        raw_server.process_configuration,
                        app_state.clone(),
                    );

                    server.filesystem.disk_checker.abort();

                    print!("{} {} ... ", "migrating".cyan(), uuid);

                    match migrate_server(mode, &server.filesystem, &base_path, disk_limit).await {
                        Ok(()) => {
                            println!("{}", "done".green());
                            migrated += 1;
                        }
                        Err(err) => {
                            println!("{}", "failed".red());
                            eprintln!("  {} {}", "error:".red(), err);
                            failed += 1;
                        }
                    }
                }

                println!(
                    "\n{} {} migrated, {} skipped, {} failed",
                    "summary:".bold(),
                    migrated,
                    skipped,
                    failed
                );

                Ok(if failed > 0 { 1 } else { 0 })
            })
        })
    }
}

async fn migrate_server(
    mode: TargetMode,
    filesystem: &crate::server::filesystem::Filesystem,
    base_path: &Path,
    disk_limit: u64,
) -> Result<(), anyhow::Error> {
    let mut staging_name = base_path.file_name().unwrap_or_default().to_os_string();
    staging_name.push(".migrating");
    let staging_path = match base_path.parent() {
        Some(parent) => parent.join(staging_name),
        None => staging_name.into(),
    };

    if tokio::fs::metadata(&staging_path).await.is_ok() {
        return Err(anyhow::anyhow!(
            "staging path {} already exists, refusing to migrate (clean it up manually)",
            staging_path.display()
        ));
    }

    let limiter: Box<dyn DiskLimiterExt> = match mode {
        TargetMode::BtrfsSubvolume => Box::new(
            crate::server::filesystem::limiter::btrfs_subvolume::BtrfsSubvolumeLimiter {
                filesystem,
            },
        ),
        TargetMode::ZfsDataset => Box::new(
            crate::server::filesystem::limiter::zfs_dataset::ZfsDatasetLimiter { filesystem },
        ),
    };

    tokio::fs::rename(base_path, &staging_path).await?;

    if let Err(err) = limiter.setup().await {
        let _ = tokio::fs::rename(&staging_path, base_path).await;
        return Err(anyhow::anyhow!("failed to create volume: {}", err));
    }

    let copy_result = async {
        let source = CapFilesystem::new(&staging_path).await?;
        let destination = CapFilesystem::new(base_path).await?;

        let source_dir = source.get_inner()?;
        let destination_dir = destination.get_inner()?;

        tokio::task::spawn_blocking(move || copy_tree(&source_dir, &destination_dir)).await?
    }
    .await;

    if let Err(err) = copy_result {
        let _ = limiter.destroy().await;
        let _ = tokio::fs::rename(&staging_path, base_path).await;
        return Err(anyhow::anyhow!("failed to copy data: {}", err));
    }

    if let Err(err) = limiter.update_disk_limit(disk_limit).await {
        return Err(anyhow::anyhow!(
            "data migrated but failed to apply disk limit (staging dir left at {}): {}",
            staging_path.display(),
            err
        ));
    }

    tokio::fs::remove_dir_all(&staging_path).await?;

    Ok(())
}

#[cfg(unix)]
fn copy_tree(
    source: &cap_std::fs::Dir,
    destination: &cap_std::fs::Dir,
) -> Result<(), anyhow::Error> {
    use std::os::fd::AsFd;

    let (guard, listener) = crate::io::abort::AbortGuard::new();

    for entry in source.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let file_type = entry.file_type()?;

        let stat =
            rustix::fs::statat(source.as_fd(), &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let mode = rustix::fs::Mode::from_raw_mode(stat.st_mode as _);
        let uid = rustix::fs::Uid::from_raw_unchecked(stat.st_uid as _);
        let gid = rustix::fs::Gid::from_raw_unchecked(stat.st_gid as _);

        if file_type.is_dir() {
            destination.create_dir(&name)?;

            let source_sub = source.open_dir(&name)?;
            let destination_sub = destination.open_dir(&name)?;
            copy_tree(&source_sub, &destination_sub)?;

            rustix::fs::chmodat(
                destination.as_fd(),
                &name,
                mode,
                rustix::fs::AtFlags::empty(),
            )?;
        } else if file_type.is_symlink() {
            let target = source.read_link(&name)?;
            destination.symlink(&target, &name)?;
        } else if file_type.is_file() {
            let mut reader = source.open(&name)?;
            let mut writer = destination.create(&name)?;

            crate::io::copy_file_progress(&mut reader, &mut writer, |_| Ok(()), listener.clone())?;

            rustix::fs::chmodat(
                destination.as_fd(),
                &name,
                mode,
                rustix::fs::AtFlags::empty(),
            )?;
        }

        rustix::fs::chownat(
            destination.as_fd(),
            &name,
            Some(uid),
            Some(gid),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
    }

    drop(guard);

    Ok(())
}

#[cfg(not(unix))]
fn copy_tree(
    _source: &cap_std::fs::Dir,
    _destination: &cap_std::fs::Dir,
) -> Result<(), anyhow::Error> {
    Err(anyhow::anyhow!(
        "disk limiter migration is only supported on unix"
    ))
}
