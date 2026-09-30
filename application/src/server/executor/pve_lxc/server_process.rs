use super::*;

pub(super) struct PveProcessHandle {
    vmid: u32,
    node: String,
    cli: PveCli,
    server: Weak<crate::server::InnerServer>,
    app_config: Arc<crate::config::Config>,
    firewall: Arc<dyn crate::server::firewall::FirewallBackend>,
    log_path: PathBuf,
    stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdout_ratelimited_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
    stdout_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
    started: Arc<AtomicBool>,
    status_task: tokio::task::JoinHandle<()>,
    stats_task: tokio::task::JoinHandle<()>,
    console_task: tokio::task::JoinHandle<()>,
}

impl PveProcessHandle {
    const EXIT_STATUS_FILE: &'static str = ".wings-exit-status";

    pub(super) fn observed_status(
        status: cli::ContainerStatus,
        start_succeeded: bool,
        seen_running: &mut bool,
        exit_status: Option<(i32, bool)>,
    ) -> Option<super::ProcessStatus> {
        match status {
            cli::ContainerStatus::Running => {
                *seen_running = true;
                Some(super::ProcessStatus::Running)
            }
            cli::ContainerStatus::Stopped if !*seen_running && !start_succeeded => None,
            cli::ContainerStatus::Stopped => {
                let (exit_code, oom_killed) = exit_status.unwrap_or((-1, false));
                Some(super::ProcessStatus::Stopped {
                    exit_code,
                    oom_killed,
                })
            }
        }
    }

    pub(super) fn parse_exit_status(contents: &str) -> Option<(i32, bool)> {
        let mut exit_code = None;
        let mut oom_killed = None;
        for line in contents.lines() {
            let (key, value) = line.split_once('=')?;
            match key {
                "exit_code" => exit_code = value.parse::<i32>().ok(),
                "oom_killed" => {
                    oom_killed = match value {
                        "0" => Some(false),
                        "1" => Some(true),
                        _ => None,
                    }
                }
                _ => {}
            }
        }
        Some((exit_code?, oom_killed?))
    }

    async fn read_exit_status(path: &std::path::Path) -> Option<(i32, bool)> {
        let contents = tokio::fs::read_to_string(path).await.ok()?;
        Self::parse_exit_status(&contents)
    }

    fn exit_status_path(server: &crate::server::InnerServer) -> PathBuf {
        std::path::Path::new(server.filesystem.base().as_str()).join(Self::EXIT_STATUS_FILE)
    }

    fn managed_file_stage_name(target: &str) -> Result<&'static str, anyhow::Error> {
        match target {
            "/etc/machine-id" => Ok("machine-id"),
            "/etc/hosts" => Ok("hosts"),
            "/etc/passwd" => Ok("passwd"),
            "/etc/group" => Ok("group"),
            "/calagopus-entrypoint" => Ok("entrypoint"),
            _ => Err(anyhow::anyhow!(
                "unsupported managed Proxmox file mount target: {target}"
            )),
        }
    }

    fn managed_file_stage_directory(
        app_config: &crate::config::Config,
        server_uuid: uuid::Uuid,
    ) -> Result<PathBuf, anyhow::Error> {
        let config = app_config.load();
        let root = config
            .runtime
            .pve_lxc
            .managed_file_directory
            .as_path(&config);
        if !root.is_absolute() {
            return Err(anyhow::anyhow!(
                "runtime.pve_lxc.managed_file_directory must be an absolute path"
            ));
        }
        Ok(root.join(server_uuid.to_compact_string()))
    }

    pub(super) async fn cleanup_managed_file_staging(
        app_config: &crate::config::Config,
        server_uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        let path = Self::managed_file_stage_directory(app_config, server_uuid)?;
        match tokio::fs::remove_dir_all(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to remove managed Proxmox file staging directory {}",
                    path.display()
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn new(
        vmid: u32,
        node: String,
        cli: PveCli,
        stats_sampler: Arc<super::cgroup::StatsSampler>,
        server: &crate::server::Server,
        app_config: Arc<crate::config::Config>,
        firewall: Arc<dyn crate::server::firewall::FirewallBackend>,
        status_tx: tokio::sync::mpsc::Sender<super::ProcessStatus>,
        fresh_log: bool,
        suppress_initial_stopped: bool,
    ) -> Result<Self, anyhow::Error> {
        let log_path = Self::runtime_log_path(&app_config, server.uuid);
        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if fresh_log {
            tokio::fs::File::create(&log_path).await?;
        } else {
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await?;
        }

        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(150);
        let websocket_log_count = app_config.load().system.websocket_log_count;
        let (stdout_ratelimited_tx, stdout_ratelimited_rx) =
            tokio::sync::broadcast::channel::<Arc<compact_str::CompactString>>(websocket_log_count);
        let (stdout_tx, stdout_rx) = tokio::sync::broadcast::channel::<
            Arc<compact_str::CompactString>,
        >(websocket_log_count * 2);

        let started = Arc::new(AtomicBool::new(!suppress_initial_stopped));
        let state_started = Arc::clone(&started);
        let state_cli = cli.clone();
        let state_server_uuid = server.uuid;
        let state_exit_status_path = Self::exit_status_path(server);
        let status_task = tokio::spawn(async move {
            let mut seen_running = state_started.load(Ordering::Acquire);
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tick.tick().await;
                let process_status = match state_cli.status(vmid).await {
                    Ok(status) => {
                        let exit_status = if status == cli::ContainerStatus::Stopped {
                            Self::read_exit_status(&state_exit_status_path).await
                        } else {
                            None
                        };
                        match Self::observed_status(
                            status,
                            state_started.load(Ordering::Acquire),
                            &mut seen_running,
                            exit_status,
                        ) {
                            Some(status) => status,
                            None => continue,
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            server = %state_server_uuid,
                            vmid,
                            "failed to read Proxmox LXC process state: {error:#}"
                        );
                        continue;
                    }
                };

                if status_tx.send(process_status).await.is_err() {
                    break;
                }
            }
        });

        let stats_cli = cli.clone();
        let stats_node = node.clone();
        let stats_usage = server.resource_usage.clone();
        let stats_server = Arc::downgrade(&**server);
        let stats_server_uuid = server.uuid;
        let disk_bytes = server.filesystem.limiter_usage().await;
        stats_usage.send_modify(|usage| {
            usage.wipe(server.state.get_state());
            usage.disk_bytes = disk_bytes;
        });
        let stats_task = tokio::spawn(async move {
            let mut samples: Option<super::cgroup::SampleReceiver> = None;
            let mut started_at: Option<std::time::Instant> = None;
            let mut previous_cpu_total = 0u64;
            let mut previous_sample_at: Option<std::time::Instant> = None;
            let mut warned_unresolved_cgroup = false;
            let mut resolve_tick = tokio::time::interval(std::time::Duration::from_secs(2));
            resolve_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                let Some(stats_server) = stats_server.upgrade() else {
                    break;
                };
                let state = stats_server.state.get_state();
                if state == crate::server::state::ServerState::Offline {
                    let disk_bytes = stats_server.filesystem.limiter_usage().await;
                    stats_usage.send_modify(|usage| {
                        usage.wipe(state);
                        usage.disk_bytes = disk_bytes;
                    });
                    samples = None;
                    started_at = None;
                    previous_cpu_total = 0;
                    previous_sample_at = None;
                    warned_unresolved_cgroup = false;
                    resolve_tick.tick().await;
                    continue;
                }

                if samples.is_none() {
                    resolve_tick.tick().await;

                    let runtime_status = match stats_cli.runtime_status(&stats_node, vmid).await {
                        Ok(status) => status,
                        Err(error) => {
                            tracing::warn!(
                                server = %stats_server_uuid,
                                vmid,
                                "failed to resolve Proxmox LXC runtime stats process: {error:#}"
                            );
                            continue;
                        }
                    };

                    if runtime_status.status != cli::ContainerStatus::Running {
                        let state = stats_server.state.get_state();
                        let disk_bytes = stats_server.filesystem.limiter_usage().await;
                        stats_usage.send_modify(|usage| {
                            usage.wipe(state);
                            usage.disk_bytes = disk_bytes;
                        });
                        continue;
                    }

                    let Some(pid) = runtime_status.pid else {
                        if !warned_unresolved_cgroup {
                            tracing::warn!(
                                server = %stats_server_uuid,
                                vmid,
                                "running Proxmox LXC status did not include an init PID; resource stats are unavailable until it does"
                            );
                            warned_unresolved_cgroup = true;
                        }
                        continue;
                    };
                    let Some(files) = super::cgroup::StatFiles::resolve(pid) else {
                        if !warned_unresolved_cgroup {
                            tracing::warn!(
                                server = %stats_server_uuid,
                                vmid,
                                pid,
                                "could not resolve the Proxmox LXC cgroup-v2 files; resource stats are unavailable until they can be resolved"
                            );
                            warned_unresolved_cgroup = true;
                        }
                        continue;
                    };

                    samples = Some(stats_sampler.register(files));
                    started_at = std::time::Instant::now().checked_sub(
                        std::time::Duration::from_secs(runtime_status.uptime_seconds),
                    );
                    previous_cpu_total = 0;
                    previous_sample_at = None;
                    warned_unresolved_cgroup = false;
                }

                let Some(receiver) = samples.as_mut() else {
                    continue;
                };
                let sample = match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    receiver.recv(),
                )
                .await
                {
                    Ok(Some(Ok(sample))) => sample,
                    Ok(Some(Err(error))) if error.kind() == std::io::ErrorKind::NotFound => {
                        samples = None;
                        started_at = None;
                        previous_cpu_total = 0;
                        previous_sample_at = None;
                        continue;
                    }
                    Ok(Some(Err(error))) => {
                        tracing::warn!(
                            server = %stats_server_uuid,
                            vmid,
                            "failed to read Proxmox LXC cgroup stats: {error}"
                        );
                        samples = None;
                        continue;
                    }
                    Ok(None) | Err(_) => {
                        tracing::warn!(
                            server = %stats_server_uuid,
                            vmid,
                            "Proxmox LXC cgroup stats sampler stopped delivering; resolving the container again"
                        );
                        samples = None;
                        continue;
                    }
                };

                let cpu_absolute = if let Some(previous_at) = previous_sample_at {
                    let cpu_delta_ns =
                        sample.cpu_total_ns.saturating_sub(previous_cpu_total) as f64;
                    let wall_delta_ns = sample.at.duration_since(previous_at).as_nanos() as f64;

                    if wall_delta_ns > 0.0 && cpu_delta_ns > 0.0 {
                        ((cpu_delta_ns / wall_delta_ns) * 100.0 * 1000.0).round() / 1000.0
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };
                previous_cpu_total = sample.cpu_total_ns;
                previous_sample_at = Some(sample.at);

                let disk_bytes = stats_server.filesystem.limiter_usage().await;
                let cpu_limit = stats_server.configuration.read().await.build.cpu_limit;
                let cpu_limit_absolute = if cpu_limit > 0 {
                    u32::try_from(cpu_limit).unwrap_or(u32::MAX)
                } else {
                    std::thread::available_parallelism().map_or(1, |threads| threads.get()) as u32
                        * 100
                };
                let uptime = started_at
                    .map(|started_at| {
                        u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
                    })
                    .unwrap_or(0);
                let state = stats_server.state.get_state();

                stats_usage.send_modify(|usage| {
                    usage.memory_bytes = sample.memory_bytes;
                    usage.memory_limit_bytes = sample.memory_limit_bytes;
                    usage.disk_bytes = disk_bytes;
                    usage.state = state;
                    usage.cpu_absolute = cpu_absolute;
                    usage.cpu_limit_absolute = cpu_limit_absolute;
                    usage.uptime = uptime;

                    if let Some((rx_bytes, rx_packets, tx_bytes, tx_packets)) = sample.network {
                        usage.network.rx_bytes = rx_bytes;
                        usage.network.rx_packets = rx_packets;
                        usage.network.tx_bytes = tx_bytes;
                        usage.network.tx_packets = tx_packets;
                    }
                });
            }
        });

        let console_cli = cli.clone();
        let console_app_config = Arc::clone(&app_config);
        let console_log_max_bytes = app_config.load().runtime.pve_lxc.console_log_max_bytes;
        let console_server = Arc::downgrade(&**server);
        let console_log_path = log_path.clone();
        let console_task = tokio::spawn(async move {
            let mut line_buffer = LineBuffer::new();
            let mut ratelimit_counter = 0;
            let mut ratelimit_start = std::time::Instant::now();

            loop {
                match console_cli.status(vmid).await {
                    Ok(cli::ContainerStatus::Running) => {}
                    Ok(cli::ContainerStatus::Stopped) => {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(
                            vmid,
                            "failed to read Proxmox LXC state before console attach: {error:#}"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                }

                let session = match console_cli.spawn_console(vmid) {
                    Ok(session) => session,
                    Err(error) => {
                        tracing::warn!(vmid, "failed to attach Proxmox LXC console: {error:#}");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };
                // `tokio::fs::File` serializes operations on a single handle.
                // A blocking PTY read would therefore prevent stdin writes
                // indefinitely if both directions shared one Tokio file.
                let cli::ConsoleSession {
                    mut child,
                    mut reader,
                    mut writer,
                } = session;
                let mut log = match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&console_log_path)
                    .await
                {
                    Ok(log) => log,
                    Err(error) => {
                        tracing::error!(vmid, "failed to open Proxmox LXC runtime log: {error:#}");
                        child.start_kill().ok();
                        break;
                    }
                };
                let mut log_size = log.metadata().await.map_or(0, |metadata| metadata.len());
                let mut buffer = vec![0u8; 8192];

                loop {
                    tokio::select! {
                        read = reader.read(&mut buffer) => {
                            match read {
                                Ok(0) => break,
                                Ok(read) => {
                                    let Some(data) = buffer.get(..read) else {
                                        tracing::error!(vmid, read, "Proxmox console returned an invalid read length");
                                        break;
                                    };
                                    line_buffer.extend(data);
                                    while let Some(line) = line_buffer.next_line() {
                                        if Self::is_pct_console_banner(line) {
                                            continue;
                                        }
                                        if let Err(error) = Self::write_bounded_log(
                                            &mut log,
                                            &mut log_size,
                                            console_log_max_bytes,
                                            line,
                                            true,
                                        ).await {
                                            tracing::error!(vmid, "failed to append Proxmox LXC runtime log: {error:#}");
                                        }
                                        let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
                                        let allow_ratelimit = {
                                            ratelimit_counter += 1;
                                            let config = console_app_config.load();
                                            if config.throttles.enabled
                                                && config.throttles.line_reset_interval > 0
                                                && ratelimit_counter >= config.throttles.lines
                                            {
                                                if ratelimit_start.elapsed()
                                                    < std::time::Duration::from_millis(
                                                        config.throttles.line_reset_interval,
                                                    )
                                                {
                                                    if ratelimit_counter == config.throttles.lines
                                                        && let Some(server) = console_server.upgrade()
                                                    {
                                                        server.log_daemon_with_prelude(
                                                            "Server is outputting console data too quickly -- throttling...",
                                                        );
                                                    }
                                                    false
                                                } else {
                                                    ratelimit_counter = 0;
                                                    ratelimit_start = std::time::Instant::now();
                                                    true
                                                }
                                            } else {
                                                true
                                            }
                                        };

                                        if allow_ratelimit {
                                            stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                                        }
                                        stdout_tx.send(line).ok();
                                    }
                                    line_buffer.compact();
                                }
                                Err(error) => {
                                    tracing::warn!(vmid, "failed to read Proxmox LXC console: {error:#}");
                                    break;
                                }
                            }
                        }
                        data = stdin_rx.recv() => {
                            let Some(data) = data else {
                                child.start_kill().ok();
                                return;
                            };
                            if let Err(error) = writer.write_all(&data).await {
                                tracing::warn!(vmid, "failed to write Proxmox LXC console stdin: {error:#}");
                                break;
                            }
                        }
                        result = child.wait() => {
                            if let Err(error) = result {
                                tracing::warn!(vmid, "failed waiting for Proxmox LXC console: {error:#}");
                            }
                            break;
                        }
                    }
                }

                child.start_kill().ok();
                if !matches!(
                    console_cli.status(vmid).await,
                    Ok(cli::ContainerStatus::Running)
                ) {
                    if let Some(line) = line_buffer.flush() {
                        if !Self::is_pct_console_banner(line)
                            && let Err(error) = Self::write_bounded_log(
                                &mut log,
                                &mut log_size,
                                console_log_max_bytes,
                                line,
                                false,
                            )
                            .await
                        {
                            tracing::error!(
                                vmid,
                                "failed to append final Proxmox LXC runtime log line: {error:#}"
                            );
                        }
                        let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
                        if !Self::is_pct_console_banner(line.as_bytes()) {
                            stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                            stdout_tx.send(line).ok();
                        }
                    }
                    line_buffer = LineBuffer::new();
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        });

        Ok(Self {
            vmid,
            node,
            cli,
            server: Arc::downgrade(&**server),
            app_config,
            firewall,
            log_path,
            stdin_tx,
            stdout_ratelimited_rx,
            stdout_rx,
            started,
            status_task,
            stats_task,
            console_task,
        })
    }

    fn runtime_log_path(app_config: &crate::config::Config, server_uuid: uuid::Uuid) -> PathBuf {
        app_config
            .resolve_as_path(|config| &config.system.log_directory)
            .join("pve-lxc")
            .join(format!("{server_uuid}.log"))
    }

    pub(super) async fn write_bounded_log(
        log: &mut tokio::fs::File,
        size: &mut u64,
        max_bytes: u64,
        line: &[u8],
        newline: bool,
    ) -> Result<(), std::io::Error> {
        let mut line = line;
        let mut write_size = u64::try_from(line.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(newline));
        if max_bytes > 0 && write_size > max_bytes {
            let newline_size = usize::from(newline);
            let keep = usize::try_from(max_bytes)
                .unwrap_or(usize::MAX)
                .saturating_sub(newline_size);
            let start = line.len().saturating_sub(keep);
            line = line.get(start..).unwrap_or_default();
            write_size = u64::try_from(line.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::from(newline));
        }
        if max_bytes > 0 && size.saturating_add(write_size) > max_bytes {
            log.set_len(0).await?;
            log.seek(std::io::SeekFrom::Start(0)).await?;
            *size = 0;
        }
        log.write_all(line).await?;
        if newline {
            log.write_all(b"\n").await?;
        }
        *size = size.saturating_add(write_size);
        Ok(())
    }

    /// `pct console` forwards terminal key input and expects Enter as a carriage
    /// return. Wings command producers use line feeds because Docker stdin is a
    /// byte stream, so normalize line endings only at the PVE PTY boundary.
    pub(super) fn normalize_console_input(data: Vec<u8>) -> Vec<u8> {
        let mut normalized = Vec::with_capacity(data.len());
        let mut previous_was_carriage_return = false;

        for byte in data {
            if byte == b'\n' {
                if !previous_was_carriage_return {
                    normalized.push(b'\r');
                }
                previous_was_carriage_return = false;
            } else {
                normalized.push(byte);
                previous_was_carriage_return = byte == b'\r';
            }
        }

        normalized
    }

    pub(super) fn is_pct_console_banner(line: &[u8]) -> bool {
        let line = String::from_utf8_lossy(line);
        let line = line.trim_matches(|character: char| character.is_whitespace());
        line.starts_with("Connected to tty ")
            || line.starts_with("Type <Ctrl+z q> to exit the console")
    }

    fn get_server(&self) -> Result<Arc<crate::server::InnerServer>, anyhow::Error> {
        self.server
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("server has been dropped"))
    }

    pub(super) fn halt_signal(stop_type: &str, stop_value: Option<&str>) -> Option<String> {
        if stop_type != "signal" {
            return None;
        }

        Some(
            match stop_value.map(str::to_uppercase).as_deref() {
                Some("SIGABRT") => "SIGABRT",
                Some("SIGINT") | Some("C") => "SIGINT",
                Some("SIGTERM") => "SIGTERM",
                Some("SIGQUIT") => "SIGQUIT",
                _ => "SIGKILL",
            }
            .to_string(),
        )
    }

    async fn managed_file_mounts(
        server: &crate::server::InnerServer,
        app_config: &crate::config::Config,
    ) -> Result<Vec<cli::ManagedFileMountSpec>, anyhow::Error> {
        #[cfg(not(unix))]
        {
            let _ = (server, app_config);
            return Err(anyhow::anyhow!(
                "managed Proxmox container files require a Unix host"
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let server_uuid = {
                let configuration = server.configuration.read().await;
                configuration.ensure_vmounts(app_config).await?;
                configuration.uuid
            };
            let (machine_id_enabled, tundra_enabled, passwd_enabled, passwd_directory) = {
                let config = app_config.load();
                (
                    config.system.machine_id.enabled,
                    config.tundra.enabled,
                    config.system.passwd.enabled,
                    config.system.passwd.directory.as_path(&config),
                )
            };

            let vmount_path = app_config.vmount_path(server_uuid);
            let mut files = Vec::with_capacity(4);
            if machine_id_enabled {
                files.push((vmount_path.join("machine-id"), "/etc/machine-id"));
            }
            if tundra_enabled {
                files.push((vmount_path.join("hosts"), "/etc/hosts"));
            }
            if passwd_enabled {
                files.push((passwd_directory.join("passwd"), "/etc/passwd"));
                files.push((passwd_directory.join("group"), "/etc/group"));
            }

            let stage_directory = Self::managed_file_stage_directory(app_config, server_uuid)?;
            let stage_root = stage_directory
                .parent()
                .context("managed Proxmox file staging directory did not have a parent")?;
            tokio::fs::create_dir_all(stage_root)
                .await
                .with_context(|| {
                    format!(
                        "failed to create managed Proxmox file staging root {}",
                        stage_root.display()
                    )
                })?;
            tokio::fs::set_permissions(stage_root, std::fs::Permissions::from_mode(0o711))
                .await
                .with_context(|| {
                    format!(
                        "failed to set managed Proxmox file staging root permissions on {}",
                        stage_root.display()
                    )
                })?;
            tokio::fs::create_dir_all(&stage_directory)
                .await
                .with_context(|| {
                    format!(
                        "failed to create managed Proxmox file staging directory {}",
                        stage_directory.display()
                    )
                })?;
            tokio::fs::set_permissions(&stage_directory, std::fs::Permissions::from_mode(0o711))
                .await
                .with_context(|| {
                    format!(
                        "failed to set managed Proxmox file staging permissions on {}",
                        stage_directory.display()
                    )
                })?;

            let mut mounts = Vec::with_capacity(files.len() + 1);
            for (source, target) in files {
                let source = tokio::fs::canonicalize(&source).await.with_context(|| {
                    format!(
                        "failed to resolve managed Proxmox container file {}",
                        source.display()
                    )
                })?;
                let metadata = tokio::fs::metadata(&source).await.with_context(|| {
                    format!(
                        "failed to inspect managed Proxmox container file {}",
                        source.display()
                    )
                })?;
                if !metadata.is_file() {
                    return Err(anyhow::anyhow!(
                        "managed Proxmox container file {} is not a regular file",
                        source.display()
                    ));
                }

                let staged_source = stage_directory.join(Self::managed_file_stage_name(target)?);
                tokio::fs::copy(&source, &staged_source)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to stage managed Proxmox container file {} at {}",
                            source.display(),
                            staged_source.display()
                        )
                    })?;
                tokio::fs::set_permissions(&staged_source, std::fs::Permissions::from_mode(0o644))
                    .await
                    .with_context(|| {
                        format!(
                            "failed to set managed Proxmox file permissions on {}",
                            staged_source.display()
                        )
                    })?;
                let staged_source =
                    tokio::fs::canonicalize(&staged_source)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to resolve staged managed Proxmox container file {}",
                                staged_source.display()
                            )
                        })?;
                let source_path = staged_source.into_os_string().into_string().map_err(|_| {
                    anyhow::anyhow!("managed Proxmox container file path is not valid UTF-8")
                })?;

                mounts.push(cli::ManagedFileMountSpec {
                    source_path,
                    target_path: target.to_string(),
                });
            }

            let entrypoint_target = "/calagopus-entrypoint";
            let entrypoint_source =
                stage_directory.join(Self::managed_file_stage_name(entrypoint_target)?);
            let entrypoint_script = r#"#!/bin/sh
attempt=0
while [ "$attempt" -lt 120 ]; do
    if grep -q '^eth0[[:space:]]*00000000[[:space:]]' /proc/net/route; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.25
done
if [ "$attempt" -ge 120 ]; then
    echo 'timed out waiting for Proxmox DHCP' >&2
    exit 1
fi

read_oom_kills() {
    value=0
    if [ -r /sys/fs/cgroup/memory.events ]; then
        while read -r key count; do
            if [ "$key" = oom_kill ]; then
                value=$count
                break
            fi
        done < /sys/fs/cgroup/memory.events
    fi
    printf '%s' "$value"
}

child=0
child_group=0
forward_signal() {
    if [ "$child" -gt 0 ]; then
        if [ "$child_group" -eq 1 ]; then
            kill "-$1" "-$child" 2>/dev/null || true
        else
            kill "-$1" "$child" 2>/dev/null || true
        fi
    fi
}
trap 'forward_signal HUP' HUP
trap 'forward_signal INT' INT
trap 'forward_signal QUIT' QUIT
trap 'forward_signal ABRT' ABRT
trap 'forward_signal TERM' TERM

oom_before=$(read_oom_kills)
if command -v setsid >/dev/null 2>&1; then
    setsid "$@" <&0 &
    child_group=1
else
    "$@" <&0 &
fi
child=$!
while :; do
    wait "$child"
    status=$?
    if ! kill -0 "$child" 2>/dev/null; then
        break
    fi
done
oom_after=$(read_oom_kills)
oom_killed=0
if [ "$oom_after" -gt "$oom_before" ]; then
    oom_killed=1
fi

marker=__WINGS_EXIT_STATUS_PATH__
temporary="${marker}.tmp.$$"
(
    umask 077
    printf 'exit_code=%s\noom_killed=%s\n' "$status" "$oom_killed" > "$temporary"
)
mv -f "$temporary" "$marker"
exit "$status"
"#
            .replace(
                "__WINGS_EXIT_STATUS_PATH__",
                &format!(
                    "{}/{}",
                    PveLxcExecutor::DATA_MOUNT_TARGET,
                    Self::EXIT_STATUS_FILE
                ),
            );
            tokio::fs::write(&entrypoint_source, entrypoint_script)
                .await
                .context("failed to stage Proxmox network-ready entrypoint")?;
            tokio::fs::set_permissions(&entrypoint_source, std::fs::Permissions::from_mode(0o755))
                .await
                .context("failed to make Proxmox network-ready entrypoint executable")?;
            let entrypoint_source = tokio::fs::canonicalize(&entrypoint_source)
                .await
                .context("failed to resolve staged Proxmox network-ready entrypoint")?;
            let source_path = entrypoint_source
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    anyhow::anyhow!("managed Proxmox entrypoint path is not valid UTF-8")
                })?;
            mounts.push(cli::ManagedFileMountSpec {
                source_path,
                target_path: entrypoint_target.to_string(),
            });

            Ok(mounts)
        }
    }

    pub(super) async fn runtime_config(
        server: &crate::server::InnerServer,
        app_config: &crate::config::Config,
        cli: &PveCli,
        vmid: u32,
    ) -> Result<cli::RuntimeConfigSpec, anyhow::Error> {
        let (
            environment,
            panel_entrypoint,
            cpuset_cpus,
            io_weight,
            memory_unlimited,
            swap_unlimited,
        ) = {
            let configuration = server.configuration.read().await;
            let resources = PveCli::panel_resources(
                configuration.build.memory_limit,
                configuration.build.overhead_memory,
                configuration.build.swap,
                configuration.build.cpu_limit,
                configuration.build.threads.as_deref(),
            )?;
            (
                configuration.environment(app_config),
                configuration.entrypoint.clone(),
                resources.cpuset_cpus.clone(),
                PveCli::cgroup2_io_weight(configuration.build.io_weight)?,
                resources.memory_unlimited,
                resources.swap_unlimited,
            )
        };
        let pids_limit = PveLxcExecutor::pids_limit(app_config);
        let managed_file_mounts = Self::managed_file_mounts(server, app_config).await?;
        let process = server.process_configuration.read().await;
        let halt_signal = Self::halt_signal(&process.stop.r#type, process.stop.value.as_deref());
        let mut init_arguments = vec!["/calagopus-entrypoint".to_string()];
        if let Some(entrypoint) = panel_entrypoint {
            if entrypoint.is_empty() {
                return Err(anyhow::anyhow!("panel entrypoint override cannot be empty"));
            }
            init_arguments.extend(entrypoint);
        } else {
            let image_entrypoint = cli.oci_entrypoint(vmid).await?;
            init_arguments.extend(
                shell_words::split(&image_entrypoint)
                    .context("failed to parse OCI entrypoint for Proxmox LXC")?,
            );
        }
        let init_command = PveCli::encode_init_command(&init_arguments)?;

        Ok(cli::RuntimeConfigSpec {
            vmid,
            environment,
            halt_signal,
            init_command: Some(init_command),
            console_logfile: None,
            cpuset_cpus,
            pids_limit,
            io_weight,
            memory_unlimited,
            swap_unlimited,
            managed_file_mounts: Some(managed_file_mounts),
        })
    }

    pub(super) async fn sync_firewall(&self, wait_for_address: bool) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;
        let has_rules = !server.configuration.read().await.firewall.is_empty();
        let edge_forwarding = PveLxcExecutor::edge_forwarding_config(&self.app_config)?.is_some();
        let running = self.cli.status(self.vmid).await? == cli::ContainerStatus::Running;

        let container_ips = if running && (has_rules || edge_forwarding) {
            let mut last_error = None;
            let mut addresses = Vec::new();
            let attempts = if wait_for_address { 40 } else { 1 };

            for attempt in 0..attempts {
                match self.cli.interfaces(&self.node, self.vmid).await {
                    Ok(interfaces) => {
                        addresses = PveCli::container_addresses(&interfaces);
                        if !addresses.is_empty() {
                            break;
                        }
                        last_error = None;
                    }
                    Err(error) => last_error = Some(error),
                }

                if attempt + 1 < attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }

            if addresses.is_empty() {
                if let Some(error) = last_error {
                    return Err(error.context(
                        "failed to resolve Proxmox LXC address for firewall and edge forwarding",
                    ));
                }
                return Err(anyhow::anyhow!(
                    "running Proxmox LXC container {} has no usable bridged address; refusing to leave firewall or edge forwarding unapplied",
                    self.vmid
                ));
            }

            addresses
        } else {
            Vec::new()
        };

        let (mut spec, edge_forward) = {
            let configuration = server.configuration.read().await;
            let destination = container_ips.iter().find_map(|address| match address {
                IpAddr::V4(address) => Some(*address),
                IpAddr::V6(_) => None,
            });
            let edge_forward = if edge_forwarding && running {
                Some(PveLxcExecutor::edge_forward_payload(
                    &configuration,
                    destination
                        .context("running Proxmox LXC has no IPv4 address for edge forwarding")?,
                )?)
            } else {
                None
            };
            (
                PveLxcExecutor::firewall_spec(&configuration, container_ips, Some(self.vmid)),
                edge_forward,
            )
        };
        spec.files = Some(PveLxcExecutor::firewall_file_access(&server));
        self.firewall.sync(&spec).await?;
        if edge_forwarding {
            let (public_ip, payload) = edge_forward.flatten().unzip();
            PveLxcExecutor::sync_edge_forwarding(&self.app_config, server.uuid, public_ip, payload)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn stop_after_firewall_failure(
        &self,
        error: anyhow::Error,
        context: &'static str,
    ) -> anyhow::Error {
        match self.cli.stop(self.vmid).await {
            Ok(()) => error.context(format!("{context}; container was stopped")),
            Err(stop_error) => error.context(format!(
                "{context} and failed to stop the exposed container: {stop_error:#}"
            )),
        }
    }
}

impl Drop for PveProcessHandle {
    fn drop(&mut self) {
        self.status_task.abort();
        self.stats_task.abort();
        self.console_task.abort();
    }
}

#[async_trait::async_trait]
impl ProcessHandle for PveProcessHandle {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, anyhow::Error> {
        if let Some(lines) = lines {
            let file = match tokio::fs::File::open(&self.log_path).await {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Box::new(Cursor::new(Vec::new())));
                }
                Err(error) => return Err(error.into()),
            };
            return Ok(Box::new(crate::io::tail::async_tail(file, lines).await?));
        }

        Ok(Box::new(tokio::fs::File::open(&self.log_path).await?))
    }

    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.stdin_tx
            .send(Self::normalize_console_input(data))
            .await
            .map_err(Into::into)
    }

    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>
    {
        Ok(self.stdout_ratelimited_rx.resubscribe())
    }

    async fn subscribe_stdout_lines(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>
    {
        Ok(self.stdout_rx.resubscribe())
    }

    async fn sync_configuration(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;
        let resources = {
            let configuration = server.configuration.read().await;
            PveCli::panel_resources(
                configuration.build.memory_limit,
                configuration.build.overhead_memory,
                configuration.build.swap,
                configuration.build.cpu_limit,
                configuration.build.threads.as_deref(),
            )?
        };
        self.cli.set_resources(self.vmid, &resources).await?;
        self.cli
            .apply_runtime_config(
                &Self::runtime_config(&server, &self.app_config, &self.cli, self.vmid).await?,
            )
            .await?;
        if let Err(error) = self.sync_firewall(true).await {
            let configuration = server.configuration.read().await;
            let requires_network_policy = !configuration.firewall.is_empty()
                || (configuration.allocations.default.is_some()
                    && PveLxcExecutor::edge_forwarding_config(&self.app_config)?.is_some());
            drop(configuration);
            if requires_network_policy {
                return Err(self
                    .stop_after_firewall_failure(
                        error,
                        "failed to synchronize Proxmox LXC network policy after configuration update",
                    )
                    .await);
            }

            tracing::warn!(
                vmid = self.vmid,
                "failed to clear Proxmox LXC firewall state after configuration update: {error:#}"
            );
        }
        Ok(())
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;
        let exit_status_path = Self::exit_status_path(&server);
        match tokio::fs::remove_file(&exit_status_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to clear stale Proxmox LXC exit status {}",
                        exit_status_path.display()
                    )
                });
            }
        }
        self.cli.start(self.vmid).await?;
        self.started.store(true, Ordering::Release);

        if let Err(error) = self.sync_firewall(true).await {
            let requires_network_policy = match self.get_server() {
                Ok(server) => {
                    let configuration = server.configuration.read().await;
                    !configuration.firewall.is_empty()
                        || (configuration.allocations.default.is_some()
                            && PveLxcExecutor::edge_forwarding_config(&self.app_config)?.is_some())
                }
                Err(_) => true,
            };

            if requires_network_policy {
                return Err(self
                    .stop_after_firewall_failure(
                        error,
                        "failed to apply Proxmox LXC network policy",
                    )
                    .await);
            }

            tracing::warn!(
                vmid = self.vmid,
                "failed to clear Proxmox LXC firewall state for a server without rules: {error:#}"
            );
        }

        Ok(())
    }

    async fn stop(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;
        let process = server.process_configuration.read().await;
        let stop_type = process.stop.r#type.clone();
        let stop_value = process.stop.value.clone();
        drop(process);

        if stop_type == "command" {
            let mut command = stop_value
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default();
            command.push(b'\n');
            self.stdin_tx.send(command).await.map_err(Into::into)
        } else {
            self.cli.request_shutdown(self.vmid).await
        }
    }

    async fn kill(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;
        let exit_status_path = Self::exit_status_path(&server);
        if self.cli.status(self.vmid).await? == cli::ContainerStatus::Stopped {
            return Ok(());
        }
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&exit_status_path)
            .await
        {
            Ok(mut marker) => marker
                .write_all(b"exit_code=137\noom_killed=0\n")
                .await
                .with_context(|| {
                    format!(
                        "failed to record forced Proxmox LXC exit status {}",
                        exit_status_path.display()
                    )
                })?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create forced Proxmox LXC exit status {}",
                        exit_status_path.display()
                    )
                });
            }
        }
        self.cli.stop(self.vmid).await
    }
}
