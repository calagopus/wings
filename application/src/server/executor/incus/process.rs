use super::super::{ProcessHandle, ProcessStatus, StatusReceiver};
use super::{
    IncusExecutor, InstanceState,
    boost::Cpu,
    client::{self, segment},
    configuration::Role,
    console,
    storage::Storage,
    terminal::Terminal,
};
use crate::io::line_buffer::LineBuffer;
use crate::server::executor::docker::cgroup;
use anyhow::{Context, ensure};
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    fd::OwnedFd,
    process::{Pid, PidfdFlags},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc, watch};

/// Runs inside the instance around the game process, because Incus reports neither the exit code
/// nor out-of-memory kills of an application container.
///
/// A shell starts background commands with SIGINT and SIGQUIT ignored, which would silently break
/// those stop signals. GNU `env` can restore them; without it the game runs in the foreground.
pub(super) const SUPERVISOR: &str = concat!(
    "dir=/opt/wings-control/process; rm -f $dir/exit; ",
    "if env --default-signal=INT,QUIT true >/dev/null 2>&1; then ",
    "exec 3<&0; ",
    r#"env --default-signal=INT,QUIT "$@" <&3 3<&- & child=$!; exec 3<&-; "#,
    r#"printf '%s\n' "$child" > $dir/pid; "#,
    r#"trap 'kill -TERM "$child" 2>/dev/null' TERM; "#,
    r#"trap 'kill -INT "$child" 2>/dev/null' INT; "#,
    r#"trap 'kill -QUIT "$child" 2>/dev/null' QUIT; "#,
    r#"while :; do wait "$child"; code=$?; kill -0 "$child" 2>/dev/null || break; done; "#,
    "else ",
    "trap : INT QUIT TERM; ",
    r#"/bin/sh -c 'echo $$ > /opt/wings-control/process/pid; exec "$@"' wings-child "$@"; code=$?; "#,
    "fi; ",
    "oom=0; if [ -r /sys/fs/cgroup/memory.events ]; then ",
    r#"while read -r key value; do [ "$key" = oom_kill ] && oom=$value; done < /sys/fs/cgroup/memory.events; "#,
    "fi; ",
    r#"printf '%s %s\n' "$code" "$oom" > $dir/exit.tmp; mv $dir/exit.tmp $dir/exit; exit "$code""#,
);

const TAIL_INTERVAL: Duration = Duration::from_millis(50);
/// How often output is looked for just after input, so that replies appear at once.
const REPLY_INTERVAL: Duration = Duration::from_millis(2);
const REPLY_WINDOW: Duration = Duration::from_millis(100);
const STATE_INTERVAL: Duration = Duration::from_millis(250);
/// Asking Incus for an instance's state is expensive for it, so a process that is seen to be
/// alive is only asked about this often, to notice changes such as a freeze.
const WATCHED_STATE_INTERVAL: Duration = Duration::from_secs(5);
const STOPPING_STATE_INTERVAL: Duration = Duration::from_millis(50);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);
/// The number of lines forwarded before listeners are given a chance to take them.
const PACE_LINES: usize = 64;
const PACE_PAUSE: Duration = Duration::from_millis(1);

/// A handle on the instance's first process, which becomes readable once it has exited.
fn watch_process(pid: u32) -> Option<OwnedFd> {
    let pid = Pid::from_raw(i32::try_from(pid).ok()?)?;
    rustix::process::pidfd_open(pid, PidfdFlags::empty()).ok()
}

fn has_exited(process: &OwnedFd) -> bool {
    let mut ready = [PollFd::new(process, PollFlags::IN)];
    rustix::event::poll(&mut ready, Some(&Timespec::default())).is_ok_and(|count| count > 0)
}

pub(super) fn encode_argv(args: &[String]) -> anyhow::Result<String> {
    ensure!(
        !args.is_empty() && args.iter().all(|arg| !arg.contains('\0')),
        "invalid OCI argv"
    );
    Ok(args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" "))
}

/// The instance's entrypoint script. With `terminal` the process talks to the console directly;
/// without it, as for docker script containers, it writes into a pipe and gets no input.
pub(super) fn launch_script(args: &[String], terminal: bool) -> anyhow::Result<String> {
    let command = encode_argv(args)?;
    let script = if terminal {
        format!("#!/bin/sh\nexec </dev/console >/dev/console 2>&1\nexec {command}\n")
    } else {
        format!("#!/bin/sh\nexec </dev/null >/dev/console 2>&1\n{command} 2>&1 | cat\n")
    };
    ensure!(script.len() <= 262144, "OCI launch script exceeds 256 KiB");
    Ok(script)
}

/// A console terminal sends a carriage return for the enter key.
fn console_input(data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(data.len());
    let mut previous = None;
    for &byte in data {
        if byte == b'\n' {
            if previous != Some(b'\r') {
                input.push(b'\r');
            }
        } else {
            input.push(byte);
        }
        previous = Some(byte);
    }
    input
}

/// The exit code and whether the kernel killed anything for running out of memory.
fn parse_exit(data: &str) -> Option<(i32, bool)> {
    let mut fields = data.split_whitespace();
    let code = fields.next()?.parse().ok()?;
    let oom = fields
        .next()
        .and_then(|count| count.parse::<u64>().ok())
        .unwrap_or(0);
    Some((code, oom > 0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// Created but not yet seen running.
    Created,
    Running {
        pid: u32,
    },
    Stopped,
}

/// What the handle and its background tasks share.
pub(super) struct Shared {
    pub executor: IncusExecutor,
    pub name: String,
    pub server: Weak<crate::server::InnerServer>,
    pub started: AtomicBool,
    pub phase: watch::Sender<Phase>,
    pub cpu: Cpu,
    /// Held while the instance starts: Incus reports it as stopped until the start has finished,
    /// even though its process is already running, so a kill in between would be lost.
    pub starting: tokio::sync::Mutex<()>,
    /// Signalled after console input has been typed.
    pub typed: tokio::sync::Notify,
}

impl Shared {
    pub(super) fn pid(&self) -> Option<u32> {
        match *self.phase.borrow() {
            Phase::Running { pid } => Some(pid),
            _ => None,
        }
    }
}

pub(super) struct Handle {
    shared: Arc<Shared>,
    role: Role,
    stdin: mpsc::Sender<Vec<u8>>,
    lines: broadcast::Sender<Arc<compact_str::CompactString>>,
    limited: broadcast::Sender<Arc<compact_str::CompactString>>,
    log: PathBuf,
    detached: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        // The output pump is not aborted: it delivers the last output first, and for script
        // instances it outlives the handle, which callers drop as soon as the script starts.
        let _ = self.detached.send(true);
        for task in &self.tasks {
            task.abort();
        }
        if self.role == Role::Server
            && let Some(server) = self.shared.server.upgrade()
        {
            use crate::server::resources::ResourceUsageWatchExt;
            server.resource_usage.wipe(server.state.get_state());
        }
    }
}

impl Handle {
    pub(super) async fn connect(
        executor: IncusExecutor,
        server: &crate::server::Server,
        name: String,
        attached: bool,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let role = Role::of(&name);
        let capacity = executor.config.load().system.websocket_log_count.max(1);
        let (stdin, stdin_rx) = mpsc::channel(150);
        let (lines, _) = broadcast::channel(capacity * 2);
        let (limited, _) = broadcast::channel(capacity);
        let (status, status_rx) = mpsc::channel(8);
        let (detached, detached_rx) = watch::channel(false);
        let log = executor.console_log_path(&name);
        let tail = if attached {
            console::Tail::from_end(log.clone()).await
        } else {
            console::clear(&log)
                .await
                .context("removing earlier console output")?;
            console::Tail::from_start(log.clone())
        };
        if role == Role::Server {
            use crate::server::resources::ResourceUsageWatchExt;
            let disk = server.filesystem.limiter_usage().await;
            server.resource_usage.wipe(server.state.get_state());
            server.resource_usage.publish_disk_usage(disk);
        }
        let shared = Arc::new(Shared {
            executor,
            name,
            server: Arc::downgrade(server),
            started: AtomicBool::new(attached),
            phase: watch::channel(Phase::Created).0,
            cpu: Cpu::default(),
            starting: tokio::sync::Mutex::new(()),
            typed: tokio::sync::Notify::new(),
        });

        tokio::spawn(
            Pump {
                shared: Arc::clone(&shared),
                role,
                tail,
                output: Output {
                    config: Arc::clone(&shared.executor.config),
                    server: Arc::downgrade(server),
                    buffer: LineBuffer::new(),
                    lines: lines.clone(),
                    limited: limited.clone(),
                    count: 0,
                    since: Instant::now(),
                },
                status,
                detached: detached_rx,
            }
            .run(),
        );

        let mut tasks = Vec::new();
        if role == Role::Server {
            tasks.push(tokio::spawn(input_task(Arc::clone(&shared), stdin_rx)));
            tasks.push(tokio::spawn(super::stats::run(Arc::clone(&shared))));
        }

        Ok((
            Arc::new(Self {
                shared,
                role,
                stdin,
                lines,
                limited,
                log,
                detached,
                tasks,
            }),
            status_rx,
        ))
    }

    /// Delivers a signal to the game process, leaving the instance to stop once it exits.
    async fn signal(&self, signal: &str) -> anyhow::Result<()> {
        let shared = &self.shared;
        let path = shared
            .executor
            .storage
            .file_path(&Storage::control_name(&shared.name), "process/pid");
        // The supervisor records the PID moments after the instance starts.
        let deadline = Instant::now() + Duration::from_secs(3);
        let pid = loop {
            let state = shared.executor.instance_state(&shared.name).await?;
            if state.status == "Stopped" {
                return Ok(());
            }
            let pid = shared
                .executor
                .client
                .read_file(&path)
                .await
                .ok()
                .and_then(|data| String::from_utf8(data).ok())
                .and_then(|data| data.trim().parse::<u32>().ok())
                .filter(|pid| *pid > 1);
            if let Some(pid) = pid {
                break pid;
            }
            ensure!(
                Instant::now() < deadline,
                "the process has not reported its PID, kill the server instead"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let result = shared
            .executor
            .client
            .mutate(
                reqwest::Method::POST,
                &format!("/1.0/instances/{}/exec", segment(&shared.name)),
                json!({
                    "command": ["/bin/sh", "-c", format!("kill -s {signal} {pid}")],
                    "wait-for-websocket": false,
                    "interactive": false,
                    "user": 0,
                    "group": 0,
                }),
            )
            .await?;
        ensure!(
            result.pointer("/metadata/return").and_then(Value::as_i64) == Some(0),
            "SIG{signal} could not be delivered to the process"
        );
        Ok(())
    }
}

struct Output {
    config: Arc<crate::config::Config>,
    server: Weak<crate::server::InnerServer>,
    buffer: LineBuffer,
    lines: broadcast::Sender<Arc<compact_str::CompactString>>,
    limited: broadcast::Sender<Arc<compact_str::CompactString>>,
    count: u64,
    since: Instant,
}

impl Output {
    /// Whether a listener has not yet taken the last batch of lines.
    fn backlogged(&self) -> bool {
        self.lines.len() >= PACE_LINES || self.limited.len() >= PACE_LINES
    }

    async fn push(&mut self, data: &[u8]) {
        self.buffer.extend(data);
        let mut sent = 0usize;
        while let Some(line) = self.buffer.next_line() {
            let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
            Self::emit(
                &self.config,
                &self.server,
                &mut self.count,
                &mut self.since,
                &self.limited,
                &line,
            );
            let _ = self.lines.send(line);
            // A burst is read from the log all at once. Listeners keep only a few hundred lines,
            // so pass it on at a rate they can follow, as reading from docker's stream does.
            sent += 1;
            if sent.is_multiple_of(PACE_LINES) {
                tokio::task::yield_now().await;
                if self.backlogged() {
                    tokio::time::sleep(PACE_PAUSE).await;
                }
            }
        }
        self.buffer.compact();
    }

    fn flush(&mut self) {
        if let Some(line) = self.buffer.flush() {
            let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
            let _ = self.limited.send(Arc::clone(&line));
            let _ = self.lines.send(line);
        }
        self.buffer = LineBuffer::new();
    }

    /// Forwards a line to the throttled stream, applying the same limit as the docker runtime.
    fn emit(
        config: &crate::config::Config,
        server: &Weak<crate::server::InnerServer>,
        count: &mut u64,
        since: &mut Instant,
        limited: &broadcast::Sender<Arc<compact_str::CompactString>>,
        line: &Arc<compact_str::CompactString>,
    ) {
        let config = config.load();
        let interval = config.throttles.line_reset_interval;
        *count += 1;
        if config.throttles.enabled && interval > 0 && *count >= config.throttles.lines {
            if since.elapsed() < Duration::from_millis(interval) {
                if *count == config.throttles.lines
                    && let Some(server) = server.upgrade()
                {
                    server.log_daemon_with_prelude(
                        "Server is outputting console data too quickly -- throttling...",
                    );
                }
                return;
            }
            *count = 0;
            *since = Instant::now();
        }
        let _ = limited.send(Arc::clone(line));
    }
}

struct Pump {
    shared: Arc<Shared>,
    role: Role,
    tail: console::Tail,
    output: Output,
    status: mpsc::Sender<ProcessStatus>,
    detached: watch::Receiver<bool>,
}

impl Pump {
    /// Reads everything currently in the log.
    async fn drain(&mut self) {
        loop {
            match self.tail.next().await {
                Ok(Some(data)) => self.output.push(&data).await,
                Ok(None) => return,
                Err(err) => {
                    tracing::warn!(instance = %self.shared.name, "could not read console output: {err}");
                    return;
                }
            }
        }
    }

    /// Reports the process as running, or paused, to whoever follows its status.
    async fn report(&self, state: &InstanceState) {
        if self.role == Role::Server {
            super::stats::publish_started(&self.shared, state).await;
        }
        let status = if state.status == "Frozen" {
            ProcessStatus::Paused
        } else {
            ProcessStatus::Running
        };
        // Script callers do not listen for statuses.
        let _ = self.status.send(status).await;
    }

    async fn run(mut self) {
        let mut more_output = false;
        let mut reply_until = Instant::now();
        // The running process and a handle on it, and one already seen to have exited.
        let mut process = None::<(u32, OwnedFd)>;
        let mut exited = None::<u32>;
        let mut running = None::<InstanceState>;
        let mut next_state = Instant::now();
        let mut next_status = Instant::now();
        let mut seen_running = false;
        let mut oom_events = None::<PathBuf>;
        let mut oom_seen = false;
        let mut failures = 0u64;

        loop {
            if !more_output {
                let interval = if Instant::now() < reply_until {
                    REPLY_INTERVAL
                } else {
                    TAIL_INTERVAL
                };
                tokio::select! {
                    () = tokio::time::sleep(interval) => {}
                    () = self.shared.typed.notified() => {
                        reply_until = Instant::now() + REPLY_WINDOW;
                    }
                }
            }
            more_output = match self.tail.next().await {
                Ok(Some(data)) => {
                    self.output.push(&data).await;
                    true
                }
                Ok(None) => false,
                Err(err) => {
                    tracing::debug!(instance = %self.shared.name, "could not read console output: {err}");
                    false
                }
            };
            if let Some(path) = &oom_events
                && !oom_seen
            {
                oom_seen = tokio::fs::read_to_string(path).await.is_ok_and(|events| {
                    cgroup::StatFiles::parse_keyed(&events, "oom_kill").unwrap_or(0) > 0
                });
            }
            let detached = *self.detached.borrow();
            if detached && self.role != Role::Script {
                self.drain().await;
                return;
            }
            if let Some((pid, handle)) = &process
                && has_exited(handle)
            {
                exited = Some(*pid);
                process = None;
                running = None;
                next_state = Instant::now();
            }
            if let Some(state) = &running
                && Instant::now() >= next_status
            {
                next_status = Instant::now() + STATUS_INTERVAL;
                self.report(state).await;
            }
            if Instant::now() < next_state {
                continue;
            }
            next_state = Instant::now()
                + if exited.is_some() {
                    STOPPING_STATE_INTERVAL
                } else {
                    STATE_INTERVAL
                };

            let started = self.shared.started.load(Ordering::SeqCst);
            let state = match self.shared.executor.instance_state(&self.shared.name).await {
                Ok(state) => state,
                Err(err) if client::is_status(&err, reqwest::StatusCode::NOT_FOUND) => {
                    if started || seen_running {
                        InstanceState::stopped()
                    } else if detached {
                        return;
                    } else {
                        continue;
                    }
                }
                Err(err) => {
                    // Incus briefly cannot report on an instance that is starting or stopping.
                    failures += 1;
                    if failures.is_multiple_of(40) {
                        tracing::warn!(instance = %self.shared.name, "could not read Incus process state: {err:#}");
                    }
                    continue;
                }
            };
            failures = 0;

            match state.status.as_str() {
                // Incus still calls it running while it tears the instance down.
                "Running" | "Frozen" if Some(state.pid) == exited => {}
                "Running" | "Frozen" if state.pid > 0 => {
                    if !seen_running || self.shared.pid() != Some(state.pid) {
                        oom_events =
                            cgroup::StatFiles::resolve(i64::from(state.pid)).and_then(|files| {
                                Some(files.memory_current.parent()?.join("memory.events"))
                            });
                        self.shared
                            .phase
                            .send_replace(Phase::Running { pid: state.pid });
                    }
                    seen_running = true;
                    exited = None;
                    if process.as_ref().is_none_or(|(pid, _)| *pid != state.pid) {
                        process = watch_process(state.pid).map(|handle| (state.pid, handle));
                    }
                    if process.is_some() {
                        next_state = Instant::now() + WATCHED_STATE_INTERVAL;
                    }
                    if running
                        .as_ref()
                        .is_none_or(|previous| previous.status != state.status)
                    {
                        next_status = Instant::now() + STATUS_INTERVAL;
                        self.report(&state).await;
                    }
                    running = Some(state);
                }
                "Stopped" if started || seen_running => {
                    self.finish(seen_running, oom_seen).await;
                    return;
                }
                "Stopped" if detached => return,
                _ => {}
            }
        }
    }

    async fn finish(mut self, seen_running: bool, oom_seen: bool) {
        self.drain().await;
        self.output.flush();
        let executor = self.shared.executor.clone();
        let name = self.shared.name.clone();
        let exit = executor
            .client
            .read_file(
                &executor
                    .storage
                    .file_path(&Storage::control_name(&name), "process/exit"),
            )
            .await
            .ok()
            .and_then(|data| parse_exit(&String::from_utf8_lossy(&data)));
        // Without a record the supervisor was killed along with the process.
        let (exit_code, oom_recorded) = exit.unwrap_or((137, false));
        if self.role == Role::Server
            && let Some(server) = self.shared.server.upgrade()
        {
            server
                .resource_usage
                .send_if_modified(|usage| usage.started_at.take().is_some());
        }
        self.shared.phase.send_replace(Phase::Stopped);
        if self.role == Role::Script
            && let Err(error) = executor.remove_instance(&name).await
        {
            tracing::warn!(instance = %name, "could not clean up Incus script instance: {error:#}");
        }
        // Installers wait to see their process run. A server must not: after a kill it is
        // already offline, and a late report would show it as running again.
        if !seen_running && self.role != Role::Server {
            let _ = self.status.send(ProcessStatus::Running).await;
        }
        let _ = self
            .status
            .send(ProcessStatus::Stopped {
                exit_code,
                oom_killed: oom_recorded || oom_seen,
            })
            .await;
    }
}

/// Types console input into the instance as it arrives.
async fn input_task(shared: Arc<Shared>, mut stdin: mpsc::Receiver<Vec<u8>>) {
    let mut phase = shared.phase.subscribe();
    let mut open: Option<(u32, Arc<Terminal>)> = None;
    while let Some(input) = stdin.recv().await {
        // Input sent while the instance starts waits for it, and input for a stopped one is lost.
        let pid = match phase
            .wait_for(|phase| !matches!(phase, Phase::Created))
            .await
            .map(|phase| *phase)
        {
            Ok(Phase::Running { pid }) => pid,
            _ => return,
        };
        let cached = open.take().filter(|(of, _)| *of == pid);
        let name = shared.name.clone();
        let written = tokio::task::spawn_blocking(move || {
            let terminal = match cached {
                Some((_, terminal)) => terminal,
                None => Arc::new(Terminal::open(pid, &name)?),
            };
            terminal.write(&input)?;
            anyhow::Ok(terminal)
        })
        .await;
        shared.typed.notify_one();
        match written {
            Ok(Ok(terminal)) => open = Some((pid, terminal)),
            // The instance stopped while the input was queued.
            Ok(Err(_))
                if tokio::fs::metadata(format!("/proc/{pid}/root/dev/console"))
                    .await
                    .is_err() => {}
            Ok(Err(err)) => {
                tracing::warn!(instance = %shared.name, "could not send console input: {err:#}");
                if let Some(server) = shared.server.upgrade() {
                    server.log_daemon_error(&format!("could not send console input: {err:#}"));
                }
            }
            Err(err) => {
                tracing::error!(instance = %shared.name, "console input task failed: {err}");
            }
        }
    }
}

#[async_trait::async_trait]
impl ProcessHandle for Handle {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> anyhow::Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
        let mut data = console::history(&self.log).await?;
        if let Some(lines) = lines {
            data = console::last_lines(&data, lines).to_vec();
        }
        Ok(Box::new(std::io::Cursor::new(data)))
    }

    async fn send_stdin(&self, data: Vec<u8>) -> anyhow::Result<()> {
        ensure!(self.role == Role::Server, "this process takes no input");
        ensure!(data.len() <= 65536, "console input exceeds 64 KiB");
        ensure!(
            *self.shared.phase.borrow() != Phase::Stopped,
            "the server is not running"
        );
        self.stdin
            .send_timeout(console_input(&data), Duration::from_secs(5))
            .await
            .map_err(|_| anyhow::anyhow!("the server console is not accepting input"))
    }

    async fn subscribe_stdout_lines(
        &self,
    ) -> anyhow::Result<broadcast::Receiver<Arc<compact_str::CompactString>>> {
        Ok(self.lines.subscribe())
    }

    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> anyhow::Result<broadcast::Receiver<Arc<compact_str::CompactString>>> {
        Ok(self.limited.subscribe())
    }

    async fn sync_configuration(&self) -> anyhow::Result<()> {
        if self.role == Role::Server
            && let Some(server) = self.shared.server.upgrade()
        {
            let _guard = self.shared.cpu.lock.lock().await;
            self.shared.cpu.clear_burst(self.shared.pid());
            self.shared
                .executor
                .sync_server(&server, &self.shared.name)
                .await?;
            self.shared
                .cpu
                .apply_burst(&self.shared.executor.config, self.shared.pid());
        }
        Ok(())
    }

    async fn start(&self) -> anyhow::Result<()> {
        let shared = &self.shared;
        let _starting = shared.starting.lock().await;
        // Held until the instance runs, so a server starting alongside cannot take its ports.
        let _ports = match self.role {
            Role::Server => Some(shared.executor.claim_ports(&shared.name).await?),
            Role::Installer | Role::Script => None,
        };
        if let Err(err) = shared
            .executor
            .client
            .state(&shared.name, "start", false)
            .await
        {
            return Err(err.context(shared.executor.start_failure_detail(&shared.name).await));
        }
        shared.started.store(true, Ordering::SeqCst);
        if self.role == Role::Server
            && let Some(server) = shared.server.upgrade()
        {
            super::boost::on_start(shared, &server).await;
        }
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        let stop = match self.shared.server.upgrade() {
            Some(server) if self.role == Role::Server => {
                let config = server.process_configuration.read().await;
                Some((config.stop.r#type.clone(), config.stop.value.clone()))
            }
            _ => None,
        };
        match stop.as_ref().map(|(kind, value)| (kind.as_str(), value)) {
            Some(("command", value)) => {
                let mut command = value.as_deref().unwrap_or_default().as_bytes().to_vec();
                command.push(b'\n');
                self.send_stdin(command).await
            }
            Some(("signal", value)) => match value.as_deref().map(str::to_uppercase).as_deref() {
                Some("SIGABRT") => self.signal("ABRT").await,
                Some("SIGINT" | "C") => self.signal("INT").await,
                Some("SIGTERM") => self.signal("TERM").await,
                Some("SIGQUIT") => self.signal("QUIT").await,
                _ => self.kill().await,
            },
            _ => self.signal("TERM").await,
        }
    }

    async fn kill(&self) -> anyhow::Result<()> {
        let _starting = self.shared.starting.lock().await;
        self.shared.executor.force_stop(&self.shared.name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_records_carry_the_code_and_oom_flag() {
        assert_eq!(parse_exit("0 0\n"), Some((0, false)));
        assert_eq!(parse_exit("137 2\n"), Some((137, true)));
        assert_eq!(parse_exit(""), None);
    }

    #[test]
    fn an_exited_process_is_noticed() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("child process");
        let handle = watch_process(child.id()).expect("process handle");
        assert!(!has_exited(&handle));
        child.kill().expect("kill");
        child.wait().expect("wait");
        assert!(has_exited(&handle));
    }

    #[test]
    fn console_input_uses_terminal_line_endings() {
        assert_eq!(console_input(b"stop\n"), b"stop\r");
        assert_eq!(console_input(b"a\r\nb\n"), b"a\rb\r");
    }

    fn run_supervisor(script: &str) -> (i32, String) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().to_str().expect("utf8 path");
        let supervisor = SUPERVISOR.replace("/opt/wings-control", root);
        std::fs::create_dir(directory.path().join("process")).expect("process directory");
        let status = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                &supervisor,
                "wings-supervisor",
                "/bin/sh",
                "-c",
                script,
            ])
            .status()
            .expect("supervisor should run");
        let exit =
            std::fs::read_to_string(directory.path().join("process/exit")).expect("exit record");
        (status.code().unwrap_or(-1), exit)
    }

    #[test]
    fn supervisor_records_the_exit_code_and_leaves_signals_deliverable() {
        let (code, record) = run_supervisor("exit 7");
        assert_eq!(code, 7);
        assert_eq!(parse_exit(&record).map(|(code, _)| code), Some(7));

        // SIGINT must terminate a child that installs no handler of its own.
        let (code, _) = run_supervisor("kill -INT $$; exit 0");
        assert_eq!(code, 130);
    }
}
