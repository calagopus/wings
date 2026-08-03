use compact_str::ToCompactString;
use serde_json::json;
use std::{
    ops::Deref,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, RwLock};

pub mod activity;
pub mod backup;
pub mod collab;
pub mod configuration;
pub mod diff;
pub mod executor;
pub mod filesystem;
pub mod installation;
pub mod manager;
pub mod permissions;
pub mod resources;
pub mod schedule;
pub mod script;
pub mod state;
pub mod transfer;
pub mod tunnel;
pub mod websocket;

pub struct InnerServer {
    pub uuid: uuid::Uuid,
    app_state: crate::routes::State,

    pub configuration: RwLock<configuration::ServerConfiguration>,
    pub process_configuration: RwLock<configuration::process::ProcessConfiguration>,

    pub websocket: tokio::sync::broadcast::Sender<websocket::WebsocketMessage>,
    // Dummy receiver to avoid channel being closed
    _websocket_receiver: tokio::sync::broadcast::Receiver<websocket::WebsocketMessage>,
    status_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
    pub targeted_websocket: tokio::sync::broadcast::Sender<websocket::TargetedWebsocketMessage>,
    // Dummy receiver to avoid channel being closed
    _targeted_websocket_receiver:
        tokio::sync::broadcast::Receiver<websocket::TargetedWebsocketMessage>,

    resource_usage: tokio::sync::watch::Sender<resources::ResourceUsage>,
    process_handle: RwLock<Option<Arc<dyn executor::ProcessHandle>>>,
    process_startup_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
    pub schedules: Arc<schedule::manager::ScheduleManager>,
    pub collab: collab::manager::CollabManager,
    pub diff: diff::manager::DiffManager,
    pub activity: activity::ActivityManager,

    pub state: state::ServerStateLock,
    pub outgoing_transfer: RwLock<Option<transfer::OutgoingServerTransfer>>,
    pub incoming_transfer: RwLock<Option<transfer::IncomingServerTransfer>>,
    pub installer: RwLock<Option<Arc<installation::ServerInstaller>>>,

    suspended: AtomicBool,
    installing: AtomicBool,
    restoring: AtomicBool,
    pub transferring: AtomicBool,

    pub restarting: AtomicBool,
    stopping: AtomicBool,
    last_crash: Mutex<Option<std::time::Instant>>,
    crash_handled: AtomicBool,

    pub user_permissions: permissions::UserPermissionsMap,
    pub filesystem: filesystem::Filesystem,
}

impl Drop for InnerServer {
    fn drop(&mut self) {
        tracing::info!(
            server = %self.uuid,
            "dropping server instance"
        );

        if let Some(startup_task) = self.process_startup_task.get_mut().take() {
            startup_task.abort();
        }
        if let Some(status_task) = self.status_task.get_mut().take() {
            status_task.abort();
        }
    }
}

#[repr(transparent)]
pub struct Server(Arc<InnerServer>);

impl Server {
    pub fn new(
        configuration: configuration::ServerConfiguration,
        process_configuration: configuration::process::ProcessConfiguration,
        app_state: crate::routes::State,
    ) -> Self {
        tracing::info!(
            server = %configuration.uuid,
            "creating server instance"
        );

        let (websocket_tx, websocket_rx) = tokio::sync::broadcast::channel(128);
        let (targeted_websocket_tx, targeted_websocket_rx) = tokio::sync::broadcast::channel(128);
        let (resource_usage, _) = tokio::sync::watch::channel(resources::ResourceUsage::default());

        let filesystem = filesystem::Filesystem::new(
            configuration.uuid,
            app_state.clone(),
            configuration.build.disk_space * 1024 * 1024,
            websocket_tx.clone(),
            resource_usage.clone(),
            Arc::clone(&app_state.config),
            &configuration.egg.file_denylist,
        );

        let activity = activity::ActivityManager::new(configuration.uuid, &app_state.config);
        let collab = collab::manager::CollabManager::new(
            configuration.uuid,
            targeted_websocket_tx.clone(),
            &app_state.config,
        );
        let diff = diff::manager::DiffManager::new(configuration.uuid, &app_state.config);
        let schedules = Arc::new(schedule::manager::ScheduleManager::new(Arc::clone(
            &app_state.config,
        )));

        let server = Self(Arc::new(InnerServer {
            uuid: configuration.uuid,
            app_state,

            configuration: RwLock::new(configuration),
            process_configuration: RwLock::new(process_configuration),

            websocket: websocket_tx.clone(),
            _websocket_receiver: websocket_rx,
            status_task: RwLock::new(None),
            targeted_websocket: targeted_websocket_tx,
            _targeted_websocket_receiver: targeted_websocket_rx,

            resource_usage,
            process_handle: RwLock::new(None),
            process_startup_task: RwLock::new(None),
            schedules: Arc::clone(&schedules),
            collab,
            diff,
            activity,

            state: state::ServerStateLock::new(websocket_tx, schedules),
            outgoing_transfer: RwLock::new(None),
            incoming_transfer: RwLock::new(None),
            installer: RwLock::new(None),

            suspended: AtomicBool::new(false),
            installing: AtomicBool::new(false),
            restoring: AtomicBool::new(false),
            transferring: AtomicBool::new(false),

            restarting: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            last_crash: Mutex::new(None),
            crash_handled: AtomicBool::new(false),

            user_permissions: permissions::UserPermissionsMap::default(),
            filesystem,
        }));

        server.spawn_stats_forwarder();

        server
    }

    fn spawn_stats_forwarder(&self) {
        let weak = Arc::downgrade(&self.0);
        let mut usage_rx = self.resource_usage.subscribe();

        tokio::spawn(async move {
            while usage_rx.changed().await.is_ok() {
                let Some(server) = weak.upgrade() else {
                    break;
                };

                let mut usage = *usage_rx.borrow_and_update();
                usage.state = server.state.get_state();

                server
                    .websocket
                    .send(
                        websocket::WebsocketMessage::builder(
                            websocket::WebsocketEvent::ServerStats,
                        )
                        .structured_arg(usage)
                        .build(),
                    )
                    .ok();
                drop(server);

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    #[cfg(test)]
    pub fn mock(uuid: uuid::Uuid, app_state: crate::routes::State) -> Self {
        Self::new(
            configuration::ServerConfiguration::mock(uuid),
            configuration::process::ProcessConfiguration::mock(),
            app_state,
        )
    }

    pub async fn initialize_schedules(&self) {
        self.schedules.update_schedules(self.clone()).await;
    }

    async fn setup_startup_task(&self, process_handle: &dyn executor::ProcessHandle) {
        let server = self.clone();
        let startup_configuration = self.process_configuration.read().await.startup.clone();

        let mut stdout_lines = match process_handle.subscribe_stdout_lines().await {
            Ok(stdout_lines) => stdout_lines,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "failed to subscribe to process stdout for startup task: {}",
                    err
                );
                return;
            }
        };

        let old_task = self
            .process_startup_task
            .write()
            .await
            .replace(tokio::spawn(async move {
                let check_startup = async |line: &str| {
                    if server.state.get_state() != state::ServerState::Starting {
                        return true;
                    }

                    if let Some(done_vec) = &startup_configuration.done {
                        if startup_configuration.strip_ansi {
                            let mut result_line =
                                compact_str::CompactString::with_capacity(line.len());
                            let mut chars = line.chars().peekable();

                            while let Some(c) = chars.next() {
                                if c == '\u{1b}' {
                                    while let Some(&next) = chars.peek() {
                                        chars.next();

                                        if next.is_ascii_alphabetic() {
                                            break;
                                        }
                                    }
                                } else {
                                    result_line.push(c);
                                }
                            }

                            for done in done_vec {
                                if result_line.contains(&**done) {
                                    server.state.set_state(state::ServerState::Running).await;
                                    return true;
                                }
                            }
                        } else {
                            for done in done_vec {
                                if line.contains(&**done) {
                                    server.state.set_state(state::ServerState::Running).await;
                                    return true;
                                }
                            }
                        }
                    } else {
                        server.state.set_state(state::ServerState::Running).await;
                        return true;
                    }

                    false
                };

                loop {
                    match stdout_lines.recv().await {
                        Ok(line) => {
                            if check_startup(&line).await {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::debug!(
                                server = %server.uuid,
                                "stdout lines channel closed, ending startup task"
                            );
                            break;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(
                                server = %server.uuid,
                                "lagged {} lines behind in stdout lines channel",
                                count
                            );
                        }
                    }
                }
            }));

        if let Some(old_task) = old_task {
            old_task.abort();
        }
    }

    fn setup_status_task(
        &self,
        mut status_rx: tokio::sync::mpsc::Receiver<executor::ProcessStatus>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        tracing::debug!(
            server = %self.uuid,
            "setting up status task"
        );
        let server = self.clone();

        Box::pin(async move {
            let old_sender = server.clone().status_task.write().await.replace(tokio::spawn(async move {
                loop {
                    let process_status = match status_rx.recv().await {
                        Some(process_status) => process_status,
                        None => break,
                    };

                    server.filesystem.disk_checker_state_dirty.store(true, Ordering::Relaxed);

                    if server.filesystem.is_full().await
                        && server.state.get_state() != state::ServerState::Offline
                        && !server.stopping.load(Ordering::SeqCst)
                    {
                        server.log_daemon_with_prelude("Server is exceeding the assigned disk space limit, stopping process now.");

                        let server_clone = server.clone();
                        tokio::spawn(async move {
                            if let Err(err) = server_clone
                                .stop_with_kill_timeout(
                                    std::time::Duration::from_secs(30),
                                    false,
                                )
                                .await
                            {
                                tracing::error!(
                                    server = %server_clone.uuid,
                                    "failed to stop server: {:#?}",
                                    err
                                );
                            }
                        });
                    }

                    match process_status {
                        executor::ProcessStatus::Running
                            if !matches!(
                                server.state.get_state(),
                                state::ServerState::Running
                                    | state::ServerState::Starting
                                    | state::ServerState::Stopping,
                            ) => {
                                server.state.set_state(state::ServerState::Running).await;
                            }
                        executor::ProcessStatus::Stopped { exit_code, oom_killed } => {
                            server.state.set_state(state::ServerState::Offline).await;

                            tracing::info!(
                                server = %server.uuid,
                                restarting = %server.restarting.load(Ordering::SeqCst),
                                stopping = %server.stopping.load(Ordering::SeqCst),
                                crash_handled = %server.crash_handled.load(Ordering::SeqCst),
                                exit_code = %exit_code,
                                oom_killed = %oom_killed,
                                "container stopped, handling crash"
                            );

                            if server.restarting.load(Ordering::SeqCst) {
                                server
                                    .crash_handled
                                    .store(true, Ordering::SeqCst);
                                server
                                    .restarting
                                    .store(false, Ordering::SeqCst);
                                server
                                    .stopping
                                    .store(false, Ordering::SeqCst);

                                let server = server.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = server.start(Some(std::time::Duration::from_secs(5)), false).await {
                                        tracing::error!(
                                            server = %server.uuid,
                                            "failed to start server after stopping to restart: {}",
                                            err
                                        );
                                    }
                                });
                            } else if server.stopping.load(Ordering::SeqCst) {
                                server
                                    .crash_handled
                                    .store(true, Ordering::SeqCst);
                                server
                                    .stopping
                                    .store(false, Ordering::SeqCst);
                                if server.app_state.config.load().docker.delete_container_on_stop {
                                    tokio::spawn({
                                        let server = server.clone();
                                        async move {
                                            if let Err(err) = server.filesystem.get_disk_limiter().shutdown().await {
                                                tracing::error!(
                                                    server = %server.uuid,
                                                    "failed to shutdown disk limiter on server stop: {}",
                                                    err
                                                );
                                            }
                                        }
                                    });

                                    server.destroy_container().await;
                                }
                            } else if server.app_state.config.load().system.crash_detection.enabled
                                && !server
                                    .crash_handled
                                    .load(Ordering::SeqCst)
                            {
                                server
                                    .crash_handled
                                    .store(true, Ordering::SeqCst);

                                if exit_code == 0
                                    && !oom_killed
                                    && !server.app_state
                                        .config
                                        .load()
                                        .system
                                        .crash_detection
                                        .detect_clean_exit_as_crash
                                {
                                    tracing::debug!(
                                        server = %server.uuid,
                                        "container exited cleanly, not restarting due to crash detection settings"
                                    );
                                    if server.app_state.config.load().docker.delete_container_on_stop {
                                        tokio::spawn({
                                            let server = server.clone();
                                            async move {
                                                if let Err(err) = server.filesystem.get_disk_limiter().shutdown().await {
                                                    tracing::error!(
                                                        server = %server.uuid,
                                                        "failed to shutdown disk limiter on server stop: {}",
                                                        err
                                                    );
                                                }
                                            }
                                        });

                                        server.destroy_container().await;
                                    }

                                    return;
                                }

                                server.activity.log_activity(activity::Activity {
                                    event: activity::ActivityEvent::CrashDetected,
                                    user: None,
                                    ip: None,
                                    metadata: Some(json!({
                                        "exit_code": exit_code,
                                        "oom_killed": oom_killed,
                                    })),
                                    schedule: None,
                                    timestamp: chrono::Utc::now(),
                                });

                                server.schedules.execute_crash_trigger().await;

                                server.log_daemon_with_prelude("---------- Detected server process in a crashed state! ----------");
                                server
                                    .log_daemon_with_prelude(&format!(
                                        "Exit code: {}",
                                        exit_code
                                    ));
                                server
                                    .log_daemon_with_prelude(&format!(
                                        "Out of memory: {}",
                                        oom_killed
                                    ));

                                if oom_killed {
                                    tracing::info!(
                                        server = %server.uuid,
                                        "container has been oom killed"
                                    );
                                }

                                let mut last_crash_lock = server.last_crash.lock().await;
                                if let Some(last_crash) = *last_crash_lock {
                                    if last_crash.elapsed().as_secs()
                                        < server.app_state.config.load().system.crash_detection.timeout
                                    {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "last crash was less than {} seconds ago, aborting automatic restart",
                                            server.app_state.config.load().system.crash_detection.timeout
                                        );

                                        server.log_daemon_with_prelude(
                                            &format!(
                                                "Aborting automatic restart, last crash occurred less than {} seconds ago.",
                                                server.app_state.config.load().system.crash_detection.timeout
                                            ),
                                        );
                                        if server.app_state.config.load().docker.delete_container_on_stop {
                                            tokio::spawn({
                                                let server = server.clone();
                                                async move {
                                                    if let Err(err) = server.filesystem.get_disk_limiter().shutdown().await {
                                                        tracing::error!(
                                                            server = %server.uuid,
                                                            "failed to shutdown disk limiter on server stop: {}",
                                                            err
                                                        );
                                                    }
                                                }
                                            });

                                            server.destroy_container().await;
                                        }

                                        return;
                                    } else {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "last crash was more than {} seconds ago, restarting server",
                                            server.app_state.config.load().system.crash_detection.timeout
                                        );

                                        last_crash_lock.replace(std::time::Instant::now());
                                    }
                                } else {
                                    tracing::debug!(
                                        server = %server.uuid,
                                        "no previous crash recorded, restarting server"
                                    );

                                    last_crash_lock.replace(std::time::Instant::now());
                                }

                                drop(last_crash_lock);

                                tracing::info!(
                                    server = %server.uuid,
                                    "restarting server due to crash"
                                );

                                let server = server.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = server.start(Some(std::time::Duration::from_secs(5)), false).await {
                                        tracing::error!(
                                            server = %server.uuid,
                                            "failed to start server after crash: {}",
                                            err
                                        );
                                    }
                                });
                            }

                            break;
                        }
                        _ => {}
                    }
                }
            }));

            if let Some(old_sender) = old_sender {
                old_sender.abort();
            }
        })
    }

    pub async fn send_stdin(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        match self.process_handle.read().await.as_ref() {
            Some(container) => container.send_stdin(data).await,
            None => Err(anyhow::anyhow!("server has no active process")),
        }
    }

    pub async fn get_stdout_lines_ratelimited(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>> {
        if let Some(container) = self.process_handle.read().await.as_ref() {
            match container.subscribe_stdout_lines_ratelimited().await {
                Ok(rx) => return Some(rx),
                Err(err) => {
                    tracing::error!(
                        server = %self.uuid,
                        "failed to subscribe to container stdout: {}",
                        err
                    );
                }
            }
        }

        None
    }

    pub async fn get_stdout_lines(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>> {
        if let Some(container) = self.process_handle.read().await.as_ref() {
            match container.subscribe_stdout_lines().await {
                Ok(rx) => return Some(rx),
                Err(err) => {
                    tracing::error!(
                        server = %self.uuid,
                        "failed to subscribe to container stdout: {}",
                        err
                    );
                }
            }
        }

        None
    }

    pub fn subscribe_resource_usage(
        &self,
    ) -> tokio::sync::watch::Receiver<resources::ResourceUsage> {
        self.resource_usage.subscribe()
    }

    pub fn resource_usage(&self) -> resources::ResourceUsage {
        let mut usage = *self.resource_usage.borrow();
        usage.state = self.state.get_state();

        usage
    }

    pub async fn update_configuration(
        &self,
        configuration: configuration::ServerConfiguration,
        process_configuration: configuration::process::ProcessConfiguration,
        skip_pending_restart_check: bool,
    ) {
        self.filesystem
            .update_ignored(&configuration.egg.file_denylist)
            .await;
        self.suspended
            .store(configuration.suspended, Ordering::SeqCst);
        {
            let mut configuration_lock = self.configuration.write().await;
            let old_configuration = std::mem::replace(&mut *configuration_lock, configuration);

            if !skip_pending_restart_check
                && !self.state.get_pending_restart()
                && (old_configuration.invocation != configuration_lock.invocation
                    || old_configuration.entrypoint != configuration_lock.entrypoint
                    || old_configuration.environment != configuration_lock.environment
                    || old_configuration.allocations != configuration_lock.allocations
                    || old_configuration.mounts != configuration_lock.mounts
                    || old_configuration.container != configuration_lock.container
                    || old_configuration
                        .build
                        .has_pending_restart(&configuration_lock.build))
            {
                self.state.set_pending_restart(true);
            }
        }
        *self.process_configuration.write().await = process_configuration;
        self.schedules.update_schedules(self.clone()).await;

        if let Err(err) = self.sync_container().await {
            tracing::error!(
                server = %self.uuid,
                "failed to sync container: {}",
                err
            );
        }
    }

    pub async fn sync_configuration(&self, skip_pending_restart_check: bool) {
        match self.app_state.config.client.server(self.uuid).await {
            Ok(configuration) => {
                self.update_configuration(
                    configuration.settings,
                    configuration.process_configuration,
                    skip_pending_restart_check,
                )
                .await;
            }
            Err(err) => {
                tracing::error!(
                    server = %self.uuid,
                    "failed to sync server configuration: {}",
                    err
                );
            }
        }
    }

    pub async fn reset_state(&self) {
        self.state.set_state(state::ServerState::Offline).await;
    }

    #[inline]
    pub fn locked_state(&self) -> Option<&'static str> {
        if self.suspended.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: suspended"
            );
            return Some("suspended");
        }
        if self.installing.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: installing"
            );
            return Some("installing");
        }
        if self.restoring.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: restoring"
            );
            return Some("restoring");
        }
        if self.transferring.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: transferring"
            );
            return Some("transferring");
        }

        None
    }

    #[inline]
    pub fn is_system_locked_state(&self) -> bool {
        if !self.app_state.config.load().debug {
            return self.installing.load(Ordering::Relaxed)
                || self.restoring.load(Ordering::Relaxed)
                || self.transferring.load(Ordering::Relaxed);
        }

        if self.installing.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at system state check: installing"
            );
            return true;
        }
        if self.restoring.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at system state check: restoring"
            );
            return true;
        }
        if self.transferring.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at system state check: transferring"
            );
            return true;
        }

        false
    }

    pub async fn setup_container(&self) -> Result<(), anyhow::Error> {
        self.crash_handled.store(false, Ordering::SeqCst);

        if self.process_handle.read().await.is_some() {
            return Ok(());
        }

        tracing::info!(
            server = %self.uuid,
            "setting up container"
        );

        let (process_handle, status_rx) = self
            .app_state
            .executor
            .setup_server_process(&self.clone())
            .await?;

        self.setup_status_task(status_rx).await;
        self.setup_startup_task(&*process_handle).await;
        *self.process_handle.write().await = Some(process_handle);

        Ok(())
    }

    pub async fn attach_container(&self) -> Result<(), anyhow::Error> {
        if self.process_handle.read().await.is_some() {
            return Ok(());
        }

        tracing::info!(
            server = %self.uuid,
            "attaching to container"
        );

        match self
            .app_state
            .executor
            .attach_server_process(&self.clone())
            .await
        {
            Ok((process_handle, status_rx)) => {
                self.crash_handled.store(true, Ordering::SeqCst);
                self.setup_status_task(status_rx).await;
                self.setup_startup_task(&*process_handle).await;
                *self.process_handle.write().await = Some(process_handle);

                tokio::spawn({
                    let server = self.clone();
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        if server.state.get_state() != state::ServerState::Offline {
                            server.crash_handled.store(false, Ordering::SeqCst);
                        }
                    }
                });
            }
            Err(err) => {
                tracing::debug!(server = %self.uuid, "no running container to attach to: {}", err);
            }
        }

        Ok(())
    }

    pub async fn sync_container(&self) -> Result<(), anyhow::Error> {
        self.filesystem
            .update_disk_limit(self.configuration.read().await.build.disk_space * 1024 * 1024)
            .await;

        if let Some(process_handle) = self.process_handle.read().await.as_ref() {
            process_handle.sync_configuration().await?;
        }

        Ok(())
    }

    pub async fn logs(&self, lines: Option<usize>) -> Box<dyn tokio::io::AsyncRead + Unpin + Send> {
        if let Some(process_handle) = self.process_handle.read().await.as_ref() {
            match process_handle.logs(lines).await {
                Ok(reader) => Box::new(reader),
                Err(_) => {
                    Box::new(tokio::io::empty()) as Box<dyn tokio::io::AsyncRead + Unpin + Send>
                }
            }
        } else {
            Box::new(tokio::io::empty()) as Box<dyn tokio::io::AsyncRead + Unpin + Send>
        }
    }

    pub async fn logs_lines(
        &self,
        lines: Option<usize>,
    ) -> Box<
        dyn futures::Stream<Item = Result<compact_str::CompactString, anyhow::Error>>
            + Unpin
            + Send,
    > {
        let process_handle = match &*self.process_handle.read().await {
            Some(c) => Arc::clone(c),
            None => {
                return Box::new(futures::stream::empty())
                    as Box<
                        dyn futures::Stream<
                                Item = Result<compact_str::CompactString, anyhow::Error>,
                            > + Unpin
                            + Send,
                    >;
            }
        };

        let reader = match process_handle.logs(lines).await {
            Ok(reader) => reader,
            Err(_) => {
                return Box::new(futures::stream::empty())
                    as Box<
                        dyn futures::Stream<
                                Item = Result<compact_str::CompactString, anyhow::Error>,
                            > + Unpin
                            + Send,
                    >;
            }
        };

        let stream = futures::stream::try_unfold(
            tokio::io::BufReader::new(reader),
            |mut reader| async move {
                use tokio::io::AsyncBufReadExt;
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) => Ok(None),
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\n', '\r']);
                        Ok(Some((compact_str::CompactString::from(trimmed), reader)))
                    }
                    Err(e) => Err(anyhow::Error::from(e)),
                }
            },
        );

        let pinned: Pin<
            Box<
                dyn futures::Stream<Item = Result<compact_str::CompactString, anyhow::Error>>
                    + Send,
            >,
        > = Box::pin(stream);
        Box::new(pinned)
    }

    pub fn log_daemon(&self, message: compact_str::CompactString) {
        self.websocket
            .send(
                websocket::WebsocketMessage::builder(
                    websocket::WebsocketEvent::ServerDaemonMessage,
                )
                .arg(message)
                .build(),
            )
            .ok();
    }

    pub fn log_daemon_install(&self, message: compact_str::CompactString) {
        self.websocket
            .send(
                websocket::WebsocketMessage::builder(
                    websocket::WebsocketEvent::ServerInstallOutput,
                )
                .arg(message)
                .build(),
            )
            .ok();
    }

    pub fn log_daemon_with_prelude(&self, message: &str) {
        let prelude = self.app_state.config.daemon_prelude();

        self.websocket
            .send(
                websocket::WebsocketMessage::builder(
                    websocket::WebsocketEvent::ServerConsoleOutput,
                )
                .arg(compact_str::format_compact!(
                    "{} {}",
                    prelude,
                    nu_ansi_term::Style::new().bold().paint(message)
                ))
                .build(),
            )
            .ok();
    }

    pub fn log_daemon_error(&self, message: &str) {
        self.log_daemon(
            nu_ansi_term::Style::new()
                .bold()
                .on(nu_ansi_term::Color::Red)
                .paint(message)
                .to_compact_string(),
        );
    }

    pub fn get_daemon_error(&self, message: &str) -> websocket::WebsocketMessage {
        websocket::WebsocketMessage::builder(websocket::WebsocketEvent::ServerDaemonMessage)
            .arg(
                nu_ansi_term::Style::new()
                    .bold()
                    .on(nu_ansi_term::Color::Red)
                    .paint(message)
                    .to_compact_string(),
            )
            .build()
    }

    pub async fn start(
        &self,
        aquire_timeout: Option<std::time::Duration>,
        skip_schedules: bool,
    ) -> Result<(), anyhow::Error> {
        if let Some(state) = self.locked_state() {
            return Err(anyhow::anyhow!(
                "Server is in a locked state ({state}), cannot start the server."
            ));
        }

        if self.state.get_state() != state::ServerState::Offline {
            return Err(anyhow::anyhow!("Server is already running."));
        }

        tracing::info!(
            server = %self.uuid,
            "starting server"
        );

        let server = self.clone();
        tokio::spawn(async move {
            match server
                .state
                .execute_action(
                    state::ServerState::Starting,
                    async || {
                        server.filesystem.setup().await;
                        server.filesystem.get_disk_limiter().startup().await?;

                        server.destroy_container().await;

                        server.sync_configuration(true).await;

                        if !server.filesystem.disk_checker_state_dirty.load(std::sync::atomic::Ordering::Relaxed) {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let last_check = server.filesystem.last_disk_check.load(std::sync::atomic::Ordering::Relaxed);
                            if now.saturating_sub(last_check) > server.app_state.config.load().system.disk_check_interval {
                                tracing::info!(
                                    server = %server.uuid,
                                    "disk usage check is stale (last check was {} seconds ago), doing foreground check before starting server",
                                    now.saturating_sub(last_check)
                                );

                                server.log_daemon_with_prelude(
                                    "Recalculating disk usage before startup, this may take a moment...",
                                );
                                server.filesystem.rerun_disk_checker();
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_secs(
                                        server.app_state.config.load().system.disk_check_interval.min(30),
                                    ),
                                    server.filesystem.disk_check_completed.notified(),
                                )
                                .await;
                            }
                        }

                        if server.filesystem.is_full().await {
                            return Err(anyhow::anyhow!(
                                "Disk space is full, cannot start the server."
                            ));
                        }

                        server.log_daemon_with_prelude("Updating process configuration files...");
                        if let Err(err) = server.process_configuration
                            .read()
                            .await
                            .update_files(&server)
                            .await {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to update process configuration files: {}",
                                err
                            );
                        }

                        if server.app_state.config.load().system.check_permissions_on_boot {
                            tracing::debug!(
                                server = %server.uuid,
                                "checking permissions on boot"
                            );
                            server.log_daemon_with_prelude(
                                "Ensuring file permissions are set correctly, this could take a few seconds...",
                            );

                            server.filesystem.async_chown_path_recursive(&server.filesystem.base_path).await?;
                        }

                        server.setup_container().await?;

                        let process_handle = match server.process_handle.read().await.as_ref() {
                            Some(c) => Arc::clone(c),
                            None => return Ok(()),
                        };

                        process_handle.start().await?;

                        Ok(())
                    },
                    aquire_timeout,
                )
                .await {
                    Ok(true) => {
                        if !skip_schedules {
                            server.schedules.execute_power_action_trigger(crate::models::ServerPowerAction::Start).await;
                        }

                        Ok(())
                    },
                    Ok(false) => {
                        Err(anyhow::anyhow!(
                            "Another power action is currently being processed for this server, please try again later."
                        ))
                    },
                    Err(err) => Err(err),
                }
        })
        .await?
    }

    pub async fn kill(&self, skip_schedules: bool) -> Result<(), anyhow::Error> {
        if self.state.get_state() == state::ServerState::Offline {
            return Ok(());
        }

        let process_handle = match &*self.process_handle.read().await {
            Some(c) => Arc::clone(c),
            None => return Ok(()),
        };

        tracing::info!(
            server = %self.uuid,
            "killing server"
        );

        let server = self.clone();
        tokio::spawn(async move {
            server.stopping.store(true, Ordering::SeqCst);
            if process_handle.kill().await.is_ok() {
                if !skip_schedules {
                    server
                        .schedules
                        .execute_power_action_trigger(crate::models::ServerPowerAction::Kill)
                        .await;
                }
                server.reset_state().await;
            }

            Ok(())
        })
        .await?
    }

    pub async fn stop(
        &self,
        aquire_timeout: Option<std::time::Duration>,
        skip_schedules: bool,
    ) -> Result<(), anyhow::Error> {
        if self.state.get_state() == state::ServerState::Offline {
            return Err(anyhow::anyhow!("Server is already stopped."));
        }

        if self.state.get_state() == state::ServerState::Stopping {
            return Err(anyhow::anyhow!("Server is already stopping."));
        }

        tracing::info!(
            server = %self.uuid,
            "stopping server"
        );

        let server = self.clone();
        tokio::spawn(async move {
            match server
                .state
                .execute_action(
                    state::ServerState::Stopping,
                    async || {
                        server.stopping.store(true, Ordering::SeqCst);

                        if let Some(process_handle) = server.process_handle.read().await.as_ref()
                            && let Err(err) = process_handle.stop().await
                        {
                            tracing::warn!(
                                server = %server.uuid,
                                "stop command returned error (container may have already stopped): {}",
                                err
                            );
                        }

                        Ok(())
                    },
                    aquire_timeout,
                )
                .await {
                    Ok(true) => {
                        if !skip_schedules {
                            server.schedules.execute_power_action_trigger(crate::models::ServerPowerAction::Stop).await;
                        }

                        Ok(())
                    },
                    Ok(false) => {
                        server.stopping.store(false, Ordering::SeqCst);

                        Err(anyhow::anyhow!(
                            "Another power action is currently being processed for this server, please try again later."
                        ))
                    },
                    Err(err) => {
                        server.stopping.store(false, Ordering::SeqCst);

                        Err(err)
                    }
                }
        })
        .await?
    }

    pub async fn restart(
        &self,
        aquire_timeout: Option<std::time::Duration>,
    ) -> Result<(), anyhow::Error> {
        if self.restarting.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Server is already restarting."));
        }

        tracing::info!(
            server = %self.uuid,
            "restarting server"
        );

        let server = self.clone();
        tokio::spawn(async move {
            if server.state.get_state() != state::ServerState::Offline {
                server.restarting.store(true, Ordering::SeqCst);

                if server.state.get_state() != state::ServerState::Stopping
                    && let Err(err) = server.stop(aquire_timeout, true).await
                {
                    server.restarting.store(false, Ordering::SeqCst);

                    return Err(err);
                }
            } else {
                server.start(aquire_timeout, true).await?;
            }

            server
                .schedules
                .execute_power_action_trigger(crate::models::ServerPowerAction::Restart)
                .await;

            Ok(())
        })
        .await?
    }

    pub async fn restart_with_kill_timeout(
        &self,
        aquire_timeout: Option<std::time::Duration>,
        timeout: std::time::Duration,
    ) -> Result<(), anyhow::Error> {
        if self.restarting.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Server is already restarting."));
        }

        tracing::info!(
            server = %self.uuid,
            "restarting server with kill timeout {}s",
            timeout.as_secs()
        );

        let server = self.clone();
        tokio::spawn(async move {
            if server.state.get_state() != state::ServerState::Offline {
                server.restarting.store(true, Ordering::SeqCst);

                if server.state.get_state() != state::ServerState::Stopping
                    && let Err(err) = server.stop(None, true).await
                {
                    server.restarting.store(false, Ordering::SeqCst);

                    return Err(err);
                }

                if !server
                    .state
                    .wait_while_state(state::ServerState::Stopping, timeout)
                    .await
                {
                    tracing::info!(
                        server = %server.uuid,
                        "kill timeout reached during restart, killing server"
                    );
                    if let Err(err) = server.kill(true).await {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to kill server during restart: {}",
                            err
                        );
                    }
                }
            } else {
                server.start(aquire_timeout, true).await?;
            }

            server
                .schedules
                .execute_power_action_trigger(crate::models::ServerPowerAction::Restart)
                .await;

            Ok(())
        })
        .await?
    }

    pub async fn stop_with_kill_timeout(
        &self,
        timeout: std::time::Duration,
        skip_schedules: bool,
    ) -> Result<(), anyhow::Error> {
        if self.state.get_state() == state::ServerState::Offline {
            return Ok(());
        }

        tracing::info!(
            server = %self.uuid,
            "stopping server with kill timeout {}s",
            timeout.as_secs()
        );

        self.log_daemon(format!("Killing server after {} seconds...", timeout.as_secs()).into());

        let server = self.clone();
        tokio::spawn(async move {
            if server.state.get_state() != state::ServerState::Stopping {
                server.stop(None, skip_schedules).await?;
            }

            if server
                .state
                .wait_for_state(state::ServerState::Offline, timeout)
                .await
            {
                return Ok(());
            }

            tracing::info!(
                server = %server.uuid,
                "kill timeout reached, killing server"
            );

            server.kill(skip_schedules).await
        })
        .await?
    }

    pub async fn destroy_container(&self) {
        tracing::info!(
            server = %self.uuid,
            "destroying container"
        );

        if let Err(err) = self
            .app_state
            .executor
            .cleanup_server_process(&self.clone())
            .await
        {
            tracing::error!(server = %self.uuid, "failed to cleanup server process: {}", err);
        }

        self.process_handle.write().await.take();
        if let Some(handle) = self.status_task.write().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.process_startup_task.write().await.take() {
            handle.abort();
        }
    }

    pub async fn destroy(&self) {
        tracing::info!(
            server = %self.uuid,
            "destroying server"
        );

        self.suspended.store(true, Ordering::SeqCst);
        self.kill(true).await.ok();
        self.destroy_container().await;
        self.configuration
            .read()
            .await
            .remove_vmounts(&self.app_state.config)
            .await;

        crate::server::installation::ServerInstaller::delete_install_logs(self).await;

        self.diff.close().await;

        tokio::spawn({
            let server = self.clone();

            async move {
                server.diff.destroy().await;
                server.filesystem.destroy().await;
                server.filesystem.close();

                if let Some(installer) = server.installer.read().await.as_ref() {
                    installer.abort();
                }
            }
        });
    }

    pub async fn to_api_response(&self) -> serde_json::Value {
        json!({
            "state": self.state.get_state(),
            "is_suspended": self.suspended.load(Ordering::SeqCst),
            "utilization": self.resource_usage(),
            "configuration": *self.configuration.read().await,
        })
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Deref for Server {
    type Target = Arc<InnerServer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
