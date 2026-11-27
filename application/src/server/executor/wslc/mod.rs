use super::docker::{container_name, container_server, registry_credentials};
use crate::server::resources::ResourceUsageWatchExt;
use cli::{Cli, StatSamples};
use futures::StreamExt;
use rand::distr::SampleString;
use std::{
    collections::HashMap,
    process::Stdio,
    sync::{Arc, Weak},
};
use tokio::io::AsyncWriteExt;

mod cli;

type StatusReceiver = tokio::sync::mpsc::Receiver<super::ProcessStatus>;
type OutputChannel = (
    super::OutputSender,
    tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
);

const STATS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const START_POLL: std::time::Duration = std::time::Duration::from_millis(200);

const DROPPED_CAPABILITIES: &[&str] = &[
    "setpcap",
    "mknod",
    "audit_write",
    "net_raw",
    "dac_override",
    "fowner",
    "fsetid",
    "net_bind_service",
    "sys_chroot",
    "setfcap",
    "sys_ptrace",
];

fn push_resources(args: &mut Vec<String>, resources: &bollard::models::Resources) {
    if let Some(memory) = resources.memory.filter(|memory| *memory > 0) {
        args.extend(["--memory".to_string(), memory.to_string()]);
    }

    if let Some(quota) = resources.cpu_quota.filter(|quota| *quota > 0) {
        let period = resources.cpu_period.unwrap_or(100_000).max(1);

        args.extend([
            "--cpus".to_string(),
            format!("{:.3}", quota as f64 / period as f64),
        ]);
    }
}

fn push_mount(args: &mut Vec<String>, source: &str, target: &str, read_only: bool) {
    args.extend([
        "--volume".to_string(),
        if read_only {
            format!("{source}:{target}:ro")
        } else {
            format!("{source}:{target}")
        },
    ]);
}

fn push_labels(args: &mut Vec<String>, config: &crate::config::Config, container_type: &str) {
    args.extend([
        "--label".to_string(),
        format!("Service={}", config.load().app_name),
        "--label".to_string(),
        format!("ContainerType={container_type}"),
    ]);
}

fn push_network(args: &mut Vec<String>, config: &crate::config::Config) {
    let config = config.load();

    for dns in &config.docker.network.dns {
        args.extend(["--dns".to_string(), dns.clone()]);
    }
    for option in &config.docker.network.dns_options {
        args.extend(["--dns-option".to_string(), option.clone()]);
    }
}

fn user(config: &crate::config::Config) -> String {
    let config = config.load();

    format!("{}:{}", config.system.user.uid, config.system.user.gid)
}

impl crate::server::configuration::ServerConfiguration {
    /// wslc only publishes on loopback unless told otherwise, so every allocation carries its
    /// address.
    fn wslc_publish_args(&self, config: &crate::config::Config) -> Vec<String> {
        let config = config.load();
        let mut args = Vec::new();

        for (ip, ports) in &self.allocations.mappings {
            let ip = match ip.parse::<std::net::IpAddr>() {
                Ok(_) if config.docker.network.disable_interface_binding => "0.0.0.0".to_string(),
                Ok(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
                Ok(std::net::IpAddr::V4(ip)) => ip.to_string(),
                Err(_) => continue,
            };

            for port in ports {
                args.extend([
                    "--publish".to_string(),
                    format!("{ip}:{port}:{port}/tcp"),
                    "--publish".to_string(),
                    format!("{ip}:{port}:{port}/udp"),
                ]);
            }
        }

        args
    }

    async fn wslc_create_args(
        &self,
        config: &crate::config::Config,
        filesystem: &crate::server::filesystem::Filesystem,
        name: &str,
    ) -> Vec<String> {
        let mut args = vec![
            "create".to_string(),
            "--name".to_string(),
            name.to_string(),
            "--pull".to_string(),
            "never".to_string(),
            "--interactive".to_string(),
            "--tty".to_string(),
            "--hostname".to_string(),
            self.uuid.to_string(),
            "--user".to_string(),
            user(config),
        ];

        if let Some(domainname) = super::docker::string_to_option(&config.load().docker.domainname)
        {
            args.extend(["--domainname".to_string(), domainname]);
        }

        push_resources(&mut args, &self.convert_container_resources(config));
        push_network(&mut args, config);
        args.extend(self.wslc_publish_args(config));

        for mount in self.mounts(config, filesystem).await {
            push_mount(&mut args, &mount.source, &mount.target, mount.read_only);
        }

        args.extend([
            "--tmpfs".to_string(),
            format!(
                "/tmp:rw,exec,nosuid,size={}M",
                config.load().docker.tmpfs_size.as_mib()
            ),
        ]);
        match config.load().docker.shm_size.as_bytes() {
            0 => {}
            size => args.extend(["--shm-size".to_string(), size.to_string()]),
        }

        for capability in DROPPED_CAPABILITIES {
            args.extend(["--cap-drop".to_string(), capability.to_string()]);
        }

        for (key, value) in &self.labels {
            args.extend(["--label".to_string(), format!("{key}={value}")]);
        }
        push_labels(&mut args, config, "server_process");

        for variable in self.environment(config) {
            args.extend(["--env".to_string(), variable]);
        }

        let mut entrypoint = self.entrypoint.iter().flatten();
        if let Some(executable) = entrypoint.next() {
            args.extend(["--entrypoint".to_string(), executable.clone()]);
        }

        args.push(self.container.image.trim_end_matches('~').to_string());
        args.extend(entrypoint.cloned());

        args
    }
}

struct Console {
    stdin: tokio::sync::Mutex<Option<tokio::process::ChildStdin>>,
    stderr: parking_lot::Mutex<String>,
    exits: tokio::sync::watch::Sender<u64>,
    refresh: tokio::sync::Notify,
}

struct WslcProcessHandle {
    container: String,
    cli: Cli,
    server: Weak<super::super::InnerServer>,
    tty: bool,
    attach_stdin: bool,

    resource_usage: tokio::sync::watch::Sender<super::super::resources::ResourceUsage>,
    publish_resource_usage: bool,
    console: Arc<Console>,
    output: parking_lot::Mutex<Option<(super::OutputSender, super::OutputSender)>>,
    stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdout_ratelimited_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
    stdout_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,

    state_task: tokio::task::JoinHandle<()>,
    stats_task: tokio::task::JoinHandle<()>,
    stdin_task: tokio::task::JoinHandle<()>,
}

impl WslcProcessHandle {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        container: String,
        cli: Cli,
        server: &super::super::Server,
        app_config: &crate::config::Config,
        mut stats: tokio::sync::watch::Receiver<StatSamples>,
        status_tx: tokio::sync::mpsc::Sender<super::ProcessStatus>,
        publish_resource_usage: bool,
        tty: bool,
        attach_stdin: bool,
    ) -> Self {
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(150);
        let (stdout_ratelimited_tx, stdout_ratelimited_rx): OutputChannel =
            tokio::sync::broadcast::channel(app_config.load().system.websocket_log_count);
        let (stdout_tx, stdout_rx): OutputChannel =
            tokio::sync::broadcast::channel(app_config.load().system.websocket_log_count * 2);

        let resource_usage = server.resource_usage.clone();
        if publish_resource_usage {
            let disk_bytes = server.filesystem.limiter_usage().await;
            resource_usage.send_modify(|usage| {
                usage.wipe(server.state.get_state());
                usage.disk_bytes = disk_bytes;
            });
        }

        let console = Arc::new(Console {
            stdin: tokio::sync::Mutex::new(None),
            stderr: parking_lot::Mutex::new(String::new()),
            exits: tokio::sync::watch::Sender::new(0),
            refresh: tokio::sync::Notify::new(),
        });

        let stdin_task = tokio::spawn({
            let console = Arc::clone(&console);

            async move {
                while let Some(data) = stdin_rx.recv().await {
                    let mut stdin = console.stdin.lock().await;
                    let Some(stdin) = stdin.as_mut() else {
                        continue;
                    };

                    if let Err(err) = stdin.write_all(&data).await {
                        tracing::error!(error = %err, "failed to write to container stdin");
                    }
                }
            }
        });

        let stats_task = tokio::spawn({
            let container = container.clone();
            let usage = resource_usage.clone();
            let server = server.clone();

            async move {
                if !publish_resource_usage {
                    return;
                }

                while stats.changed().await.is_ok() {
                    let sample = stats.borrow_and_update().get(&container).copied();
                    let disk_bytes = server.filesystem.limiter_usage().await;
                    let state = server.state.get_state();

                    usage.send_modify(|usage| {
                        usage.disk_bytes = disk_bytes;
                        usage.state = state;

                        if state != super::super::state::ServerState::Offline
                            && let Some(sample) = sample
                        {
                            usage.memory_bytes = sample.memory_bytes;
                            usage.memory_limit_bytes = sample.memory_limit_bytes;
                            usage.network.rx_bytes = sample.network_rx_bytes;
                            usage.network.tx_bytes = sample.network_tx_bytes;
                            usage.disk.read_bytes = sample.disk_read_bytes;
                            usage.disk.write_bytes = sample.disk_write_bytes;
                            usage.cpu_absolute = sample.cpu_absolute;
                        }
                    });
                }
            }
        });

        let state_task = tokio::spawn({
            let container = container.clone();
            let cli = cli.clone();
            let usage = resource_usage.clone();
            let console = Arc::clone(&console);
            let mut exits = console.exits.subscribe();

            async move {
                const RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
                let host_cpu_limit = std::thread::available_parallelism()
                    .map_or(1, |threads| threads.get()) as u32
                    * 100;

                struct CachedState {
                    status: String,
                    started_at: Option<chrono::DateTime<chrono::Utc>>,
                    started_instant: Option<std::time::Instant>,
                    exit_code: i32,
                    cpu_limit: u32,
                }

                let mut cached: Option<CachedState> = None;
                let mut last_inspect: Option<std::time::Instant> = None;
                let mut tick = crate::utils::aligned_interval(std::time::Duration::from_secs(1));

                loop {
                    let changed = tokio::select! {
                        _ = exits.changed() => true,
                        _ = console.refresh.notified() => true,
                        _ = tick.tick() => false,
                    };

                    if changed
                        || cached.is_none()
                        || last_inspect.is_none_or(|at| at.elapsed() >= RECONCILE_INTERVAL)
                    {
                        let inspect = match cli.inspect(&container).await {
                            Ok(inspect) => inspect.unwrap_or_default(),
                            Err(err) => {
                                tracing::warn!(
                                    container = %container,
                                    "failed to inspect container for state: {:#}",
                                    err
                                );
                                continue;
                            }
                        };
                        last_inspect = Some(std::time::Instant::now());

                        let started_at = inspect.started_at();
                        let started_instant = match &cached {
                            Some(previous) if previous.started_at == started_at => {
                                previous.started_instant
                            }
                            _ => started_at.map(|started_at| {
                                let now = std::time::Instant::now();
                                let elapsed = (chrono::Utc::now() - started_at)
                                    .to_std()
                                    .unwrap_or_default();

                                now.checked_sub(elapsed).unwrap_or(now)
                            }),
                        };

                        cached = Some(CachedState {
                            status: inspect.state.status,
                            started_at,
                            started_instant,
                            exit_code: inspect.state.exit_code,
                            cpu_limit: (inspect.host_config.nano_cpus / 10_000_000) as u32,
                        });
                    }

                    let Some(state) = &cached else {
                        continue;
                    };

                    let process_status = match state.status.as_str() {
                        "running" => {
                            if publish_resource_usage
                                && let Some(started_instant) = state.started_instant
                            {
                                usage.send_modify(|usage| {
                                    usage.started_at = Some(started_instant);
                                    usage.cpu_limit_absolute = if state.cpu_limit > 0 {
                                        state.cpu_limit
                                    } else {
                                        host_cpu_limit
                                    };
                                });
                            }

                            super::ProcessStatus::Running
                        }
                        "paused" => super::ProcessStatus::Paused,
                        _ if state.started_at.is_none() => continue,
                        _ => {
                            if publish_resource_usage {
                                usage.send_if_modified(|usage| usage.started_at.take().is_some());
                            }

                            // wslc does not report whether the kernel oom killer ended the container
                            super::ProcessStatus::Stopped {
                                exit_code: state.exit_code,
                                oom_killed: false,
                            }
                        }
                    };

                    if status_tx.send(process_status).await.is_err() {
                        break;
                    }
                }
            }
        });

        Self {
            container,
            cli,
            server: Arc::downgrade(&**server),
            tty,
            attach_stdin,
            resource_usage,
            publish_resource_usage,
            console,
            output: parking_lot::Mutex::new(Some((stdout_ratelimited_tx, stdout_tx))),
            stdin_tx,
            stdout_ratelimited_rx,
            stdout_rx,
            state_task,
            stats_task,
            stdin_task,
        }
    }

    fn get_server(&self) -> Result<Arc<super::super::InnerServer>, anyhow::Error> {
        self.server
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("server has been dropped"))
    }

    /// Runs a wslc client connected to the container console, the client lives until the
    /// container exits or its output is no longer consumed.
    async fn connect_console(&self, args: &[&str]) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;
        let Some((stdout_ratelimited_tx, stdout_tx)) = self.output.lock().take() else {
            return Err(anyhow::anyhow!(
                "the container console has already been connected"
            ));
        };

        let mut command = self.cli.command();
        command
            .args(args)
            .arg(&self.container)
            .stdin(if self.attach_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stdout of wslc"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stderr of wslc"))?;
        *self.console.stdin.lock().await = child.stdin.take();

        let stdout = tokio_util::io::ReaderStream::new(stdout);
        let stderr = tokio_util::io::ReaderStream::new(stderr);

        // without a tty the container's stderr arrives on the client's, with one only the
        // client's own messages do
        let output = if self.tty {
            let console = Arc::clone(&self.console);

            tokio::spawn(async move {
                let mut stderr = stderr;

                while let Some(Ok(data)) = stderr.next().await {
                    let mut buffer = console.stderr.lock();
                    if buffer.len() < 4096 {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                    }
                }
            });

            stdout.left_stream()
        } else {
            futures::stream::select(stdout, stderr).right_stream()
        };

        // intentionally not aborted on drop so that it can finish writing any remaining logs to the channel
        tokio::spawn({
            let console = Arc::clone(&self.console);
            let app_config = Arc::clone(&server.app_state.config);

            async move {
                super::pump_output(server, app_config, output, stdout_ratelimited_tx, stdout_tx)
                    .await;

                console.stdin.lock().await.take();
                child.wait().await.ok();
                console.exits.send_modify(|exits| *exits += 1);
            }
        });

        Ok(())
    }
}

impl Drop for WslcProcessHandle {
    fn drop(&mut self) {
        self.state_task.abort();
        self.stats_task.abort();
        self.stdin_task.abort();

        if self.publish_resource_usage
            && let Some(server) = self.server.upgrade()
        {
            self.resource_usage.wipe(server.state.get_state());
        }
    }
}

/// Keeps the wslc client alive for as long as its output is being read.
struct LogsReader {
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl tokio::io::AsyncRead for LogsReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

#[async_trait::async_trait]
impl super::ProcessHandle for WslcProcessHandle {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, anyhow::Error> {
        let mut command = self.cli.command();
        command.arg("logs");
        if let Some(lines) = lines {
            command.arg("--tail").arg(lines.to_string());
        }
        command
            .arg(&self.container)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stdout of wslc"))?;

        Ok(Box::new(LogsReader {
            stdout,
            _child: child,
        }))
    }

    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.stdin_tx.send(data).await.map_err(Into::into)
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
        tracing::debug!(
            container = %self.container,
            "wslc cannot update a running container, new limits apply on the next start"
        );

        Ok(())
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        let previous_start = self
            .cli
            .inspect(&self.container)
            .await?
            .ok_or_else(|| anyhow::anyhow!("container {} does not exist", self.container))?
            .started_at();
        let mut exits = self.console.exits.subscribe();

        if self.attach_stdin {
            self.connect_console(&["start", "--attach", "--interactive"])
                .await?;
        } else {
            self.connect_console(&["start", "--attach"]).await?;
        }

        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        loop {
            let exited = tokio::select! {
                _ = exits.changed() => true,
                _ = tokio::time::sleep(START_POLL) => false,
            };

            let started = self
                .cli
                .inspect(&self.container)
                .await?
                .is_some_and(|inspect| inspect.started_at() != previous_start);
            if started {
                break;
            }

            if exited {
                return Err(anyhow::anyhow!(
                    "failed to start container {}: {}",
                    self.container,
                    self.console.stderr.lock().trim()
                ));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "timed out starting container {}",
                    self.container
                ));
            }
        }

        self.console.refresh.notify_one();

        Ok(())
    }

    async fn stop(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;

        let process_config = server.process_configuration.read().await;
        let stop_type = process_config.stop.r#type.clone();
        let stop_value = process_config.stop.value.clone();
        drop(process_config);

        match stop_type.as_str() {
            "signal" => {
                let signal = match stop_value.as_deref().map(str::to_uppercase).as_deref() {
                    Some("SIGABRT") => "SIGABRT",
                    Some("SIGINT") | Some("C") => "SIGINT",
                    Some("SIGTERM") => "SIGTERM",
                    Some("SIGQUIT") => "SIGQUIT",
                    _ => "SIGKILL",
                };

                self.cli
                    .run(&["kill", "--signal", signal, &self.container])
                    .await
                    .map(|_| ())
            }
            "command" => {
                let mut command = stop_value
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                command.push(b'\n');
                self.stdin_tx
                    .send(command)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
            _ => self
                .cli
                .run(&["stop", "--time", "-1", &self.container])
                .await
                .map(|_| ()),
        }
    }

    async fn kill(&self) -> Result<(), anyhow::Error> {
        match self.cli.run(&["kill", &self.container]).await {
            Ok(_) => Ok(()),
            Err(err)
                if [cli::CONTAINER_NOT_RUNNING, cli::CONTAINER_NOT_FOUND]
                    .iter()
                    .any(|code| err.to_string().contains(code)) =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

pub struct WslcExecutor {
    app_config: Arc<crate::config::Config>,
    cli: Cli,
    stats: tokio::sync::watch::Sender<StatSamples>,
}

impl WslcExecutor {
    pub fn new(app_config: Arc<crate::config::Config>) -> Self {
        Self {
            cli: Cli,
            app_config,
            stats: tokio::sync::watch::Sender::new(Arc::new(HashMap::new())),
        }
    }

    async fn pull_image(
        &self,
        image: &str,
        server: &super::super::Server,
        quiet: bool,
    ) -> Result<(), anyhow::Error> {
        static LAST_PULLS: parking_lot::Mutex<
            Option<HashMap<compact_str::CompactString, std::time::Instant>>,
        > = parking_lot::Mutex::new(None);

        if image.ends_with('~') {
            return Ok(());
        }

        let cache_config = self.app_config.load().docker.registry_image_fetch_cache;
        let exists = self.cli.image_exists(image).await;
        let recently_pulled = cache_config.enabled
            && LAST_PULLS
                .lock()
                .as_ref()
                .and_then(|pulls| pulls.get(image))
                .is_some_and(|pulled_at| pulled_at.elapsed().as_secs() < cache_config.duration);

        if exists && recently_pulled {
            tracing::debug!(
                server = %server.uuid,
                image = %image,
                "image pull skipped, cached as recently pulled"
            );

            return Ok(());
        }

        if let Some(credentials) = registry_credentials(&self.app_config.load(), image)
            && let (Some(registry), Some(username), Some(password)) = (
                credentials.serveraddress,
                credentials.username,
                credentials.password,
            )
        {
            self.cli
                .run_with_input(
                    &[
                        "login",
                        "--username",
                        &username,
                        "--password-stdin",
                        &registry,
                    ],
                    Some(password.as_bytes()),
                )
                .await?;
        }

        if !quiet {
            server.log_daemon_with_prelude(
                "Pulling Docker container image, this could take a few minutes to complete...",
            );
        }

        let mut command = self.cli.command();
        command
            .args(["pull", image])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stdout of wslc"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stderr of wslc"))?;

        let (_, stderr, status) = tokio::join!(
            async {
                let mut lines =
                    tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stdout));

                while let Ok(Some(line)) = lines.next_line().await {
                    if !quiet {
                        server.log_daemon_install(line.into());
                    }
                }
            },
            async {
                let mut output = String::new();
                tokio::io::AsyncReadExt::read_to_string(
                    &mut tokio::io::BufReader::new(stderr),
                    &mut output,
                )
                .await
                .ok();

                output
            },
            child.wait(),
        );

        if !status.is_ok_and(|status| status.success()) {
            let err = anyhow::anyhow!("failed to pull image {image}: {}", stderr.trim());

            tracing::error!(server = %server.uuid, image = %image, "{:#}", err);
            if !quiet {
                server.log_daemon_error(&err.to_string());
            }

            if !exists {
                return Err(err);
            }

            tracing::warn!(
                server = %server.uuid,
                image = %image,
                "image already exists locally, ignoring pull error"
            );
        } else {
            LAST_PULLS
                .lock()
                .get_or_insert_default()
                .insert(image.into(), std::time::Instant::now());
        }

        if !quiet {
            server.log_daemon_with_prelude("Finished pulling Docker container image");
        }

        Ok(())
    }

    async fn create(&self, args: Vec<String>) -> Result<(), anyhow::Error> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();

        self.cli.run(&args).await.map(|_| ())
    }

    async fn handle(
        &self,
        container: String,
        server: &super::super::Server,
        publish_resource_usage: bool,
        interactive: bool,
    ) -> (Arc<WslcProcessHandle>, StatusReceiver) {
        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = WslcProcessHandle::new(
            container,
            self.cli.clone(),
            server,
            &self.app_config,
            self.stats.subscribe(),
            status_tx,
            publish_resource_usage,
            interactive,
            interactive,
        )
        .await;

        (Arc::new(handle), status_rx)
    }

    async fn attach(
        &self,
        container: &str,
        container_type: &str,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        if !self.cli.inspect(container).await?.is_some_and(|inspect| {
            inspect.state.status == "running"
                && inspect.labels.get("ContainerType").map(String::as_str) == Some(container_type)
        }) {
            return Err(anyhow::anyhow!(
                "no running {container_type} container found"
            ));
        }

        let (handle, status_rx) = self.handle(container.to_string(), server, true, true).await;
        handle.connect_console(&["attach"]).await?;

        Ok((handle, status_rx))
    }

    /// Arguments of a container that runs a staged script against the server directory.
    #[allow(clippy::too_many_arguments)]
    async fn script_args(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
        name: &str,
        hostname: &str,
        container_type: &str,
        staging_dir: &std::path::Path,
        staging_target: &str,
        script_file: &str,
        extra_environment: &[String],
        interactive: bool,
    ) -> Vec<String> {
        let server_config = server.configuration.read().await;

        let mut args = vec![
            "create".to_string(),
            "--name".to_string(),
            name.to_string(),
            "--pull".to_string(),
            "never".to_string(),
            "--hostname".to_string(),
            hostname.to_string(),
        ];
        if interactive {
            args.extend(["--interactive".to_string(), "--tty".to_string()]);
        }

        push_resources(
            &mut args,
            &server_config.installer_resources(&self.app_config),
        );
        push_network(&mut args, &self.app_config);
        push_mount(&mut args, &server.filesystem.base(), "/mnt/server", false);
        push_mount(
            &mut args,
            &staging_dir.to_string_lossy(),
            staging_target,
            false,
        );
        args.extend([
            "--tmpfs".to_string(),
            format!(
                "/tmp:rw,exec,nosuid,size={}M",
                self.app_config.load().docker.tmpfs_size.as_mib()
            ),
        ]);
        push_labels(&mut args, &self.app_config, container_type);

        let mut environment = server_config.environment(&self.app_config);
        for (key, value) in &script.environment {
            environment.push(format!(
                "{key}={}",
                match value {
                    serde_json::Value::String(value) => value.clone(),
                    other => other.to_string(),
                }
            ));
        }
        environment.extend_from_slice(extra_environment);
        for variable in environment {
            args.extend(["--env".to_string(), variable]);
        }

        args.extend([
            "--entrypoint".to_string(),
            script.entrypoint.to_string(),
            script.container_image.trim_end_matches('~').to_string(),
            format!("{staging_target}/{script_file}"),
        ]);

        args
    }

    async fn remove_matching(
        &self,
        server: uuid::Uuid,
        matches: impl Fn(&str) -> bool,
    ) -> Result<(), anyhow::Error> {
        for container in self.cli.list(true).await? {
            if !matches(&container.names) {
                continue;
            }

            if let Err(err) = self.cli.remove(&container.id).await {
                tracing::error!(
                    server = %server,
                    container = %container.id,
                    "failed to remove container: {:#}",
                    err
                );
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ServerExecutor for WslcExecutor {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        let version = self.cli.run(&["version"]).await.map_err(|err| {
            err.context("failed to run wslc, is the wsl container feature installed")
        })?;
        tracing::info!(
            "using {}",
            version.lines().next().unwrap_or_default().trim()
        );

        tokio::spawn({
            let cli = self.cli.clone();
            let stats = self.stats.clone();

            async move {
                let mut tick = crate::utils::aligned_interval(STATS_INTERVAL);

                loop {
                    tick.tick().await;

                    if stats.receiver_count() == 0 {
                        continue;
                    }

                    match cli.stats().await {
                        Ok(samples) => {
                            stats.send_replace(Arc::new(samples));
                        }
                        Err(err) => {
                            tracing::warn!("failed to get container stats: {:#}", err);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn setup_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let image = server.configuration.read().await.container.image.clone();

        self.pull_image(&image, server, false).await?;

        let container_name = container_name(&self.app_config, server).await;

        server.filesystem.ensure_trash_directory().await;

        let configuration = server.configuration.read().await;
        if !configuration.firewall.is_empty() {
            return Err(anyhow::anyhow!(
                "server firewalls are not supported by the wslc executor"
            ));
        }

        let args = configuration
            .wslc_create_args(&self.app_config, &server.filesystem, &container_name)
            .await;
        configuration.ensure_vmounts(&self.app_config).await?;
        drop(configuration);

        self.create(args).await?;

        let (handle, status_rx) = self.handle(container_name, server, true, true).await;

        Ok((handle, status_rx))
    }

    async fn attach_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let container_name = container_name(&self.app_config, server).await;

        self.attach(&container_name, "server_process", server).await
    }

    async fn cleanup_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let uuid = server.uuid;

        // `[<name>.]<uuid>` (see container_name) but not `<uuid>_installer` etc.
        self.remove_matching(uuid, |name| {
            container_server(Some(&[name.to_string()])) == Some(uuid)
        })
        .await
    }

    async fn setup_installation_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        self.pull_image(&script.container_image, server, false)
            .await?;

        let tmp_dir = self.app_config.tmp_data_path(server.uuid);
        async {
            tokio::fs::create_dir_all(&tmp_dir).await?;
            tokio::fs::write(
                tmp_dir.join("install.sh"),
                script.script.replace("\r\n", "\n"),
            )
            .await?;
            tokio::fs::write(
                tmp_dir.join(super::super::installation::INSTALL_STATUS_FILE_NAME),
                "",
            )
            .await?;
            tokio::fs::write(
                tmp_dir.join(super::super::installation::INSTALL_PROGRESS_FILE_NAME),
                "",
            )
            .await
        }
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to prepare install staging directory {}: {err}",
                tmp_dir.display()
            )
        })?;

        server.filesystem.ensure_trash_directory().await;

        let container_name = format!("{}_installer", server.uuid);
        let args = self
            .script_args(
                server,
                script,
                &container_name,
                "installer",
                "server_installer",
                &tmp_dir,
                "/mnt/install",
                "install.sh",
                &[
                    format!(
                        "INSTALL_STATUS_FILE=/mnt/install/{}",
                        super::super::installation::INSTALL_STATUS_FILE_NAME
                    ),
                    format!(
                        "INSTALL_PROGRESS_FILE=/mnt/install/{}",
                        super::super::installation::INSTALL_PROGRESS_FILE_NAME
                    ),
                ],
                true,
            )
            .await;
        self.create(args).await?;

        let (handle, status_rx) = self.handle(container_name, server, true, true).await;

        Ok((handle, status_rx))
    }

    async fn attach_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        self.attach(
            &format!("{}_installer", server.uuid),
            "server_installer",
            server,
        )
        .await
    }

    async fn cleanup_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let container_name = format!("{}_installer", server.uuid);

        self.remove_matching(server.uuid, |name| name == container_name)
            .await
    }

    async fn setup_script_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
        timeout: Option<std::time::Duration>,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        self.pull_image(&script.container_image, server, true)
            .await?;

        let suffix = rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 8);
        let script_dir = self
            .app_config
            .tmp_data_path(server.uuid)
            .join(format!("script-{suffix}"));
        let staged = async {
            tokio::fs::create_dir_all(&script_dir).await?;
            tokio::fs::write(
                script_dir.join("script.sh"),
                script.script.replace("\r\n", "\n"),
            )
            .await
        }
        .await;
        if let Err(err) = staged {
            tokio::fs::remove_dir_all(&script_dir).await.ok();
            return Err(anyhow::anyhow!(
                "failed to prepare script staging directory {}: {err}",
                script_dir.display()
            ));
        }

        server.filesystem.ensure_trash_directory().await;

        let container_name = format!("{}_script_runner_{suffix}", server.uuid);
        let args = self
            .script_args(
                server,
                script,
                &container_name,
                "script",
                "script_runner",
                &script_dir,
                "/mnt/script",
                "script.sh",
                &[],
                false,
            )
            .await;
        if let Err(err) = self.create(args).await {
            tokio::fs::remove_dir_all(&script_dir).await.ok();
            return Err(err);
        }

        let (handle, status_rx) = self
            .handle(container_name.clone(), server, false, false)
            .await;

        tokio::spawn({
            let cli = self.cli.clone();
            let server = server.uuid;
            let mut exits = handle.console.exits.subscribe();

            async move {
                let start_deadline = tokio::time::sleep(std::time::Duration::from_secs(120));
                tokio::pin!(start_deadline);
                let mut start_checked = false;
                let run_deadline = tokio::time::sleep(timeout.unwrap_or_default());
                tokio::pin!(run_deadline);

                loop {
                    tokio::select! {
                        _ = exits.changed() => break,
                        _ = &mut run_deadline, if timeout.is_some() => {
                            tracing::warn!(
                                server = %server,
                                container = %container_name,
                                "script timed out, killing container"
                            );
                            break;
                        }
                        _ = &mut start_deadline, if !start_checked => {
                            start_checked = true;
                            let never_started = match cli.inspect(&container_name).await {
                                Ok(Some(inspect)) => inspect.started_at().is_none(),
                                Ok(None) => true,
                                Err(_) => false,
                            };
                            if never_started {
                                break;
                            }
                        }
                    }
                }

                if let Err(err) = cli.remove(&container_name).await {
                    tracing::error!(
                        server = %server,
                        container = %container_name,
                        "failed to remove script container: {:#}",
                        err
                    );
                }

                tokio::fs::remove_dir_all(&script_dir).await.ok();
            }
        });

        Ok((handle, status_rx))
    }

    /// Containers are only reachable from the host through their published ports.
    async fn resolve_internal_target(
        &self,
        server: &super::super::Server,
        port: u16,
    ) -> Result<Option<std::net::SocketAddr>, anyhow::Error> {
        let container_name = container_name(&self.app_config, server).await;
        if !self
            .cli
            .inspect(&container_name)
            .await?
            .is_some_and(|inspect| inspect.state.status == "running")
        {
            return Ok(None);
        }

        let configuration = server.configuration.read().await;
        let Some(binding_ip) = configuration
            .allocations
            .mappings
            .iter()
            .find(|(_, ports)| ports.contains(&port))
            .and_then(|(ip, _)| ip.parse::<std::net::IpAddr>().ok())
        else {
            return Ok(None);
        };

        let target_ip = if binding_ip.is_unspecified()
            || self
                .app_config
                .load()
                .docker
                .network
                .disable_interface_binding
        {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            binding_ip
        };

        Ok(Some(std::net::SocketAddr::new(target_ip, port)))
    }

    async fn resolve_published_address(
        &self,
        _server: &super::super::Server,
    ) -> Option<std::net::IpAddr> {
        None
    }

    async fn container_refs(
        &self,
        servers: &[super::super::Server],
    ) -> HashMap<uuid::Uuid, String> {
        let mut running = HashMap::new();
        for container in self.cli.list(false).await.unwrap_or_default() {
            if let Some(server) = container_server(Some(std::slice::from_ref(&container.names))) {
                running.insert(server, container.id);
            }
        }

        let mut refs = HashMap::with_capacity(servers.len());
        for server in servers {
            let container = match running.remove(&server.uuid) {
                Some(id) => id,
                None => container_name(&self.app_config, server).await,
            };

            refs.insert(server.uuid, container);
        }

        refs
    }

    async fn used_ports(
        &self,
        ips: &[std::net::IpAddr],
    ) -> Result<HashMap<std::net::IpAddr, Vec<super::UsedPort>>, anyhow::Error> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }

        let mut used: HashMap<std::net::IpAddr, HashMap<u16, Option<uuid::Uuid>>> =
            ips.iter().map(|ip| (*ip, HashMap::new())).collect();

        for container in self.cli.list(false).await? {
            let server = container_server(Some(std::slice::from_ref(&container.names)));

            for (host_ip, port) in container.published_ports() {
                for (ip, ports) in &mut used {
                    if ip.is_unspecified()
                        || host_ip.is_none_or(|host_ip| host_ip.is_unspecified() || host_ip == *ip)
                    {
                        ports.entry(port).or_insert(server);
                    }
                }
            }
        }

        Ok(used
            .into_iter()
            .map(|(ip, ports)| {
                let mut ports: Vec<super::UsedPort> = ports
                    .into_iter()
                    .map(|(port, server)| super::UsedPort { port, server })
                    .collect();
                ports.sort_unstable_by_key(|port| port.port);

                (ip, ports)
            })
            .collect())
    }

    fn bandwidth(&self) -> Option<&crate::server::bandwidth::Bandwidth> {
        None
    }
}
