use bollard::secret::ContainerStateStatusEnum;
use compact_str::ToCompactString;
use futures_util::StreamExt;
use serde_json::json;
use std::{
    collections::HashMap,
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
pub mod configuration;
pub mod container;
pub mod filesystem;
pub mod installation;
pub mod manager;
pub mod permissions;
pub mod resources;
pub mod schedule;
pub mod script;
pub mod state;
pub mod transfer;
pub mod websocket;

pub struct InnerServer {
    pub uuid: uuid::Uuid,
    app_state: crate::routes::State,

    pub configuration: RwLock<configuration::ServerConfiguration>,
    pub process_configuration: RwLock<configuration::process::ProcessConfiguration>,

    pub websocket: tokio::sync::broadcast::Sender<websocket::WebsocketMessage>,
    // Dummy receiver to avoid channel being closed
    _websocket_receiver: tokio::sync::broadcast::Receiver<websocket::WebsocketMessage>,
    websocket_sender: RwLock<Option<tokio::task::JoinHandle<()>>>,
    pub targeted_websocket: tokio::sync::broadcast::Sender<websocket::TargetedWebsocketMessage>,
    // Dummy receiver to avoid channel being closed
    _targeted_websocket_receiver:
        tokio::sync::broadcast::Receiver<websocket::TargetedWebsocketMessage>,

    pub container: RwLock<Option<Arc<container::Container>>>,
    pub schedules: Arc<schedule::manager::ScheduleManager>,
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

        let filesystem = filesystem::Filesystem::new(
            configuration.uuid,
            app_state.clone(),
            configuration.build.disk_space * 1024 * 1024,
            websocket_tx.clone(),
            Arc::clone(&app_state.config),
            &configuration.egg.file_denylist,
        );

        let activity = activity::ActivityManager::new(configuration.uuid, &app_state.config);
        let schedules = Arc::new(schedule::manager::ScheduleManager::new(Arc::clone(
            &app_state.config,
        )));

        Self(Arc::new(InnerServer {
            uuid: configuration.uuid,
            app_state,

            configuration: RwLock::new(configuration),
            process_configuration: RwLock::new(process_configuration),

            websocket: websocket_tx.clone(),
            _websocket_receiver: websocket_rx,
            websocket_sender: RwLock::new(None),
            targeted_websocket: targeted_websocket_tx,
            _targeted_websocket_receiver: targeted_websocket_rx,

            container: RwLock::new(None),
            schedules: Arc::clone(&schedules),
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
        }))
    }

    pub async fn initialize_schedules(&self) {
        self.schedules.update_schedules(self.clone()).await;
    }

    pub fn setup_websocket_sender(
        &self,
        container: Arc<container::Container>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        tracing::debug!(
            server = %self.uuid,
            "setting up websocket sender"
        );
        let server = self.clone();

        Box::pin(async move {
            let old_sender = server.clone().websocket_sender.write().await.replace(tokio::spawn(async move {
                let mut prev_usage = resources::ResourceUsage::default();

                let mut container_channel = match container.update_reciever.lock().await.take() {
                    Some(channel) => channel,
                    None => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to get container channel"
                        );
                        return;
                    }
                };

                loop {
                    let (container_state, usage) = match container_channel.recv().await {
                        Some((container_state, usage)) => (container_state, usage),
                        None => break,
                    };

                    if usage != prev_usage {
                        let message = websocket::WebsocketMessage::new(
                            websocket::WebsocketEvent::ServerStats,
                            [serde_json::to_string(&usage).unwrap().into()].into(),
                        );

                        if let Err(err) = server.websocket.send(message) {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to send websocket message: {}",
                                err
                            );
                        }

                        prev_usage = usage;
                    }

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

                    match container_state.status {
                        Some(ContainerStateStatusEnum::RUNNING) => {
                            if !matches!(
                                server.state.get_state(),
                                state::ServerState::Running
                                    | state::ServerState::Starting
                                    | state::ServerState::Stopping,
                            ) {
                                server.state.set_state(state::ServerState::Running).await;
                            }
                        }
                        Some(ContainerStateStatusEnum::EMPTY)
                        | Some(ContainerStateStatusEnum::DEAD)
                        | Some(ContainerStateStatusEnum::EXITED)
                        | None => {
                            server.state.set_state(state::ServerState::Offline).await;

                            tracing::info!(
                                server = %server.uuid,
                                restarting = %server.restarting.load(Ordering::SeqCst),
                                stopping = %server.stopping.load(Ordering::SeqCst),
                                crash_handled = %server.crash_handled.load(Ordering::SeqCst),
                                "container state changed to {:?}, handling crash",
                                container_state.status
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
                            } else if server.stopping.load(Ordering::SeqCst)
                            {
                                server
                                    .crash_handled
                                    .store(true, Ordering::SeqCst);
                                server
                                    .stopping
                                    .store(false, Ordering::SeqCst);
                                if server.app_state.config.docker.delete_container_on_stop {
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
                            } else if server.app_state.config.system.crash_detection.enabled
                                && !server
                                    .crash_handled
                                    .load(Ordering::SeqCst)
                            {
                                server
                                    .crash_handled
                                    .store(true, Ordering::SeqCst);

                                if container_state.exit_code.is_some_and(|code| code == 0)
                                    && !container_state.oom_killed.unwrap_or(false)
                                    && !server.app_state
                                        .config
                                        .system
                                        .crash_detection
                                        .detect_clean_exit_as_crash
                                {
                                    tracing::debug!(
                                        server = %server.uuid,
                                        "container exited cleanly, not restarting due to crash detection settings"
                                    );
                                    if server.app_state.config.docker.delete_container_on_stop {
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

                                server.schedules.execute_crash_trigger().await;

                                server.log_daemon_with_prelude("---------- Detected server process in a crashed state! ----------");
                                server
                                    .log_daemon_with_prelude(&format!(
                                        "Exit code: {}",
                                        container_state.exit_code.unwrap_or_default()
                                    ));
                                server
                                    .log_daemon_with_prelude(&format!(
                                        "Out of memory: {}",
                                        container_state.oom_killed.unwrap_or(false)
                                    ));

                                if container_state.oom_killed == Some(true) {
                                    tracing::info!(
                                        server = %server.uuid,
                                        "container has been oom killed"
                                    );
                                }

                                let mut last_crash_lock = server.last_crash.lock().await;
                                if let Some(last_crash) = *last_crash_lock {
                                    if last_crash.elapsed().as_secs()
                                        < server.app_state.config.system.crash_detection.timeout
                                    {
                                        tracing::debug!(
                                            server = %server.uuid,
                                            "last crash was less than {} seconds ago, aborting automatic restart",
                                            server.app_state.config.system.crash_detection.timeout
                                        );

                                        server.log_daemon_with_prelude(
                                            &format!(
                                                "Aborting automatic restart, last crash occurred less than {} seconds ago.",
                                                server.app_state.config.system.crash_detection.timeout
                                            ),
                                        );
                                        if server.app_state.config.docker.delete_container_on_stop {
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
                                            server.app_state.config.system.crash_detection.timeout
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

    pub async fn container_stdin(
        &self,
    ) -> Option<tokio::sync::mpsc::Sender<compact_str::CompactString>> {
        self.container
            .read()
            .await
            .as_ref()
            .map(|c| c.stdin.clone())
    }

    pub async fn container_stdout(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>> {
        self.container
            .read()
            .await
            .as_ref()
            .map(|c| c.stdout.resubscribe())
    }

    pub async fn resource_usage(&self) -> resources::ResourceUsage {
        if let Some(container) = self.container.read().await.as_ref() {
            *container.resource_usage.read().await
        } else {
            resources::ResourceUsage {
                disk_bytes: self.filesystem.limiter_usage().await,
                state: self.state.get_state(),
                ..Default::default()
            }
        }
    }

    pub async fn update_configuration(
        &self,
        configuration: configuration::ServerConfiguration,
        process_configuration: configuration::process::ProcessConfiguration,
    ) {
        self.filesystem
            .update_ignored(&configuration.egg.file_denylist)
            .await;
        self.suspended
            .store(configuration.suspended, Ordering::SeqCst);
        *self.configuration.write().await = configuration;
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

    pub async fn sync_configuration(&self) {
        match self.app_state.config.client.server(self.uuid).await {
            Ok(configuration) => {
                self.update_configuration(
                    configuration.settings,
                    configuration.process_configuration,
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
    pub fn is_locked_state(&self) -> bool {
        if !self.app_state.config.debug {
            return self.suspended.load(Ordering::Relaxed)
                || self.installing.load(Ordering::Relaxed)
                || self.restoring.load(Ordering::Relaxed)
                || self.transferring.load(Ordering::Relaxed);
        }

        if self.suspended.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: suspended"
            );
            return true;
        }
        if self.installing.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: installing"
            );
            return true;
        }
        if self.restoring.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: restoring"
            );
            return true;
        }
        if self.transferring.load(Ordering::Relaxed) {
            tracing::debug!(
                server = %self.uuid,
                "server locked at state check: transferring"
            );
            return true;
        }

        false
    }

    #[inline]
    pub fn is_system_locked_state(&self) -> bool {
        if !self.app_state.config.debug {
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

    pub async fn setup_container(&self) -> Result<(), bollard::errors::Error> {
        self.crash_handled.store(false, Ordering::SeqCst);

        if self.container.read().await.is_some() {
            return Ok(());
        }

        tracing::info!(
            server = %self.uuid,
            "setting up container"
        );

        let container = self
            .app_state
            .docker
            .create_container(
                Some(bollard::container::CreateContainerOptions {
                    name: if self.app_state.config.docker.server_name_in_container_name {
                        let name = &self.configuration.read().await.meta.name;
                        let mut name_filtered = String::new();
                        for c in name.chars() {
                            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                                name_filtered.push(c);
                            }
                        }

                        name_filtered.truncate(63 - 1 - 36);

                        format!("{}.{}", name_filtered, self.configuration.read().await.uuid)
                    } else {
                        self.configuration.read().await.uuid.to_string()
                    },
                    ..Default::default()
                }),
                self.configuration
                    .read()
                    .await
                    .container_config(
                        &self.app_state.config,
                        &self.app_state.docker,
                        &self.filesystem,
                    )
                    .await,
            )
            .await?;

        let container = Arc::new(
            container::Container::new(
                container.id.clone(),
                self.process_configuration.read().await.startup.clone(),
                Arc::clone(&self.app_state.docker),
                self.clone(),
            )
            .await?,
        );

        self.setup_websocket_sender(Arc::clone(&container)).await;
        *self.container.write().await = Some(container);

        Ok(())
    }

    pub async fn attach_container(&self) -> Result<(), bollard::errors::Error> {
        if self.container.read().await.is_some() {
            return Ok(());
        }

        tracing::info!(
            server = %self.uuid,
            "attaching to container"
        );

        if let Ok(containers) = self
            .app_state
            .docker
            .list_containers(Some(bollard::container::ListContainersOptions {
                all: true,
                filters: HashMap::from([("name".to_string(), vec![self.uuid.to_string()])]),
                ..Default::default()
            }))
            .await
        {
            for container in containers {
                if container
                    .names
                    .as_ref()
                    .is_some_and(|names| names.iter().any(|name| name.contains("installer")))
                {
                    tracing::debug!(
                        server = %self.uuid,
                        "installer container found, skipping attachment"
                    );

                    continue;
                }

                if container
                    .state
                    .is_none_or(|s| s.to_lowercase() != "running")
                {
                    tracing::debug!(
                        server = %self.uuid,
                        "container is not running, skipping attachment"
                    );

                    continue;
                }

                let container = match container.id {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            server = %self.uuid,
                            "container ID is missing, cannot attach"
                        );
                        continue;
                    }
                };
                let container = Arc::new(
                    container::Container::new(
                        container.to_string(),
                        self.process_configuration.read().await.startup.clone(),
                        Arc::clone(&self.app_state.docker),
                        self.clone(),
                    )
                    .await?,
                );

                self.crash_handled.store(true, Ordering::SeqCst);
                self.setup_websocket_sender(Arc::clone(&container)).await;
                *self.container.write().await = Some(container);

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
        }

        Ok(())
    }

    pub async fn sync_container(&self) -> Result<(), bollard::errors::Error> {
        self.filesystem
            .update_disk_limit(self.configuration.read().await.build.disk_space * 1024 * 1024)
            .await;

        if let Some(container) = self.container.read().await.as_ref() {
            self.app_state
                .docker
                .update_container(
                    &container.docker_id,
                    self.configuration
                        .read()
                        .await
                        .container_update_config(&self.app_state.config),
                )
                .await?;
        }

        Ok(())
    }

    pub async fn read_log(
        &self,
        lines: Option<usize>,
    ) -> Box<
        dyn futures::Stream<Item = Result<compact_str::CompactString, anyhow::Error>>
            + Unpin
            + Send,
    > {
        let container = match &*self.container.read().await {
            Some(container) => container.docker_id.clone(),
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

        let logs_stream = self.app_state.docker.logs(
            &container,
            Some(bollard::container::LogsOptions {
                follow: false,
                stdout: true,
                stderr: true,
                timestamps: false,
                tail: lines.map_or_else(|| "all".to_string(), |l| l.to_string()),
                ..Default::default()
            }),
        );

        Box::new(logs_stream.map(|log| match log {
            Ok(log) => Ok(compact_str::CompactString::from_utf8_lossy(
                &log.into_bytes(),
            )),
            Err(err) => Err(err.into()),
        }))
    }

    pub fn log_daemon(&self, message: compact_str::CompactString) {
        self.websocket
            .send(websocket::WebsocketMessage::new(
                websocket::WebsocketEvent::ServerDaemonMessage,
                [message].into(),
            ))
            .ok();
    }

    pub fn log_daemon_install(&self, message: compact_str::CompactString) {
        self.websocket
            .send(websocket::WebsocketMessage::new(
                websocket::WebsocketEvent::ServerInstallOutput,
                [message].into(),
            ))
            .ok();
    }

    pub fn log_daemon_with_prelude(&self, message: &str) {
        let prelude = ansi_term::Color::Yellow
            .bold()
            .paint(format!("[{} Daemon]:", self.app_state.config.app_name));

        self.websocket
            .send(websocket::WebsocketMessage::new(
                websocket::WebsocketEvent::ServerConsoleOutput,
                [compact_str::format_compact!(
                    "{} {}",
                    prelude,
                    ansi_term::Style::new().bold().paint(message)
                )]
                .into(),
            ))
            .ok();
    }

    pub fn log_daemon_error(&self, message: &str) {
        self.log_daemon(
            ansi_term::Style::new()
                .bold()
                .on(ansi_term::Color::Red)
                .paint(message)
                .to_compact_string(),
        );
    }

    pub fn get_daemon_error(&self, message: &str) -> websocket::WebsocketMessage {
        websocket::WebsocketMessage::new(
            websocket::WebsocketEvent::ServerDaemonMessage,
            [ansi_term::Style::new()
                .bold()
                .on(ansi_term::Color::Red)
                .paint(message)
                .to_compact_string()]
            .into(),
        )
    }

    pub async fn pull_image(&self, image: &str, quiet: bool) -> Result<(), bollard::errors::Error> {
        tracing::info!(
            server = %self.uuid,
            image = %image,
            "pulling image"
        );

        if !quiet {
            self.log_daemon_with_prelude(
                "Pulling Docker container image, this could take a few minutes to complete...",
            );
        }

        if !image.ends_with("~") {
            let mut registry_auth = None;
            for (registry, config) in self.app_state.config.docker.registries.iter() {
                if image.starts_with(registry) {
                    registry_auth = Some(bollard::auth::DockerCredentials {
                        username: Some(config.username.clone()),
                        password: Some(config.password.clone()),
                        ..Default::default()
                    });
                    break;
                }
            }

            let (image, tag) = image.split_once(':').unwrap_or((image, "latest"));

            let mut stream = self.app_state.docker.create_image(
                Some(bollard::image::CreateImageOptions {
                    from_image: image,
                    tag,
                    ..Default::default()
                }),
                None,
                registry_auth,
            );

            while let Some(status) = stream.next().await {
                match status {
                    Ok(status) => {
                        if let Some(id) = status.id {
                            match status.status.as_ref().map(|s| s.to_lowercase()).as_deref() {
                                Some("downloading") => {
                                    if let Some(progress_detail) = &status.progress_detail {
                                        self.websocket
                                            .send(websocket::WebsocketMessage::new(
                                                websocket::WebsocketEvent::ServerImagePullProgress,
                                                [
                                                    id.into(),
                                                    serde_json::to_string(&crate::models::PullProgress {
                                                        status: crate::models::PullProgressStatus::Pulling,
                                                        progress: progress_detail.current.unwrap_or_default(),
                                                        total: progress_detail.total.unwrap_or_default()
                                                    })
                                                    .unwrap()
                                                    .into()
                                                ].into(),
                                            ))
                                            .ok();
                                    }
                                }
                                Some("extracting") => {
                                    if let Some(progress_detail) = &status.progress_detail {
                                        self.websocket
                                            .send(websocket::WebsocketMessage::new(
                                                websocket::WebsocketEvent::ServerImagePullProgress,
                                                [
                                                    id.into(),
                                                    serde_json::to_string(&crate::models::PullProgress {
                                                        status: crate::models::PullProgressStatus::Extracting,
                                                        progress: progress_detail.current.unwrap_or_default(),
                                                        total: progress_detail.total.unwrap_or_default()
                                                    })
                                                    .unwrap()
                                                    .into()
                                                ].into(),
                                            ))
                                            .ok();
                                    }
                                }
                                Some("pull complete") => {
                                    self.websocket
                                        .send(websocket::WebsocketMessage::new(
                                            websocket::WebsocketEvent::ServerImagePullCompleted,
                                            [id.into()].into(),
                                        ))
                                        .ok();
                                }
                                _ => {}
                            }
                        }

                        if let Some(status_str) = status.status {
                            if let Some(progress_detail) = status.progress_detail {
                                self.log_daemon_install(
                                    format!(
                                        "{status_str} {} of {}",
                                        crate::utils::draw_progress_bar(
                                            50usize.saturating_sub(status_str.len()),
                                            progress_detail.current.unwrap_or_default() as f64,
                                            progress_detail.total.unwrap_or_default() as f64
                                        ),
                                        human_bytes::human_bytes(
                                            progress_detail.total.unwrap_or_default() as f64
                                        ),
                                    )
                                    .into(),
                                );
                            } else {
                                self.log_daemon_install(status_str.into());
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            server = %self.uuid,
                            image = %image,
                            "failed to pull image: {:?}",
                            err
                        );

                        if !quiet {
                            self.log_daemon_error(&format!("failed to pull image: {err}"));
                        }

                        if let Ok(images) = self
                            .app_state
                            .docker
                            .list_images(Some(bollard::image::ListImagesOptions {
                                all: true,
                                filters: HashMap::from([("reference", vec![image])]),
                                ..Default::default()
                            }))
                            .await
                        {
                            if images.is_empty() {
                                return Err(err);
                            } else {
                                tracing::error!(
                                    server = %self.uuid,
                                    image = %image,
                                    "image already exists, ignoring error: {}",
                                    err
                                );
                            }
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
        }

        if !quiet {
            self.log_daemon_with_prelude("Finished pulling Docker container image");
        }

        tracing::info!(
            server = %self.uuid,
            image = %image,
            "finished pulling image"
        );

        Ok(())
    }

    pub async fn start(
        &self,
        aquire_timeout: Option<std::time::Duration>,
        skip_schedules: bool,
    ) -> Result<(), anyhow::Error> {
        if self.is_locked_state() {
            return Err(anyhow::anyhow!(
                "Server is in a locked state, cannot start the server."
            ));
        }

        if self.state.get_state() != state::ServerState::Offline {
            return Err(anyhow::anyhow!("Server is already running."));
        }

        if self.filesystem.is_full().await {
            return Err(anyhow::anyhow!(
                "Disk space is full, cannot start the server."
            ));
        }

        tracing::info!(
            server = %self.uuid,
            "starting server"
        );

        self.configuration
            .read()
            .await
            .ensure_vmounts(&self.app_state.config)
            .await?;

        let server = self.clone();
        tokio::spawn(async move {
            match server
                .state
                .execute_action(
                    state::ServerState::Starting,
                    |_| async {
                        server.filesystem.setup().await;
                        server.filesystem.get_disk_limiter().startup().await?;
                        server.destroy_container().await;

                        server.sync_configuration().await;

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

                        if server.app_state.config.system.check_permissions_on_boot {
                            tracing::debug!(
                                server = %server.uuid,
                                "checking permissions on boot"
                            );
                            server.log_daemon_with_prelude(
                                "Ensuring file permissions are set correctly, this could take a few seconds...",
                            );

                            server.filesystem.chown_path(&server.filesystem.base_path).await?;
                        }

                        server.pull_image(
                            &server.configuration.read().await.container.image,
                            false,
                        )
                        .await?;

                        server.setup_container().await?;

                        let container = match &*server.container.read().await {
                            Some(container) => container.docker_id.clone(),
                            None => return Ok(())
                        };

                        if let Err(err) = server.app_state.docker.start_container::<String>(&container, None).await {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to start container: {}",
                                err
                            );

                            return Err(anyhow::anyhow!(err));
                        }

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

        let container = match &*self.container.read().await {
            Some(container) => container.docker_id.clone(),
            None => return Ok(()),
        };

        tracing::info!(
            server = %self.uuid,
            "killing server"
        );

        let server = self.clone();
        tokio::spawn(async move {
            server.stopping.store(true, Ordering::SeqCst);
            if server
                .app_state
                .docker
                .kill_container(
                    &container,
                    Some(bollard::container::KillContainerOptions {
                        signal: "SIGKILL".to_string(),
                    }),
                )
                .await
                .is_ok()
            {
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

        let container = match &*self.container.read().await {
            Some(container) => container.docker_id.clone(),
            None => return Ok(()),
        };

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
                    |_| async {
                        server.stopping.store(true, Ordering::SeqCst);

                        let stop = &server.process_configuration.read().await.stop;

                        match stop.r#type.as_str() {
                            "signal" => {
                                crate::spawn_handled({
                                    let container = container.clone();
                                    let value = stop.value.clone();
                                    let server = server.clone();

                                    async move {
                                        server.app_state.docker
                                            .kill_container(
                                                &container,
                                                Some(bollard::container::KillContainerOptions {
                                                    signal: match value {
                                                        Some(signal) => {
                                                            match signal.to_uppercase().as_str() {
                                                                "SIGABRT" => "SIGABRT".to_string(),
                                                                "SIGINT" => "SIGINT".to_string(),
                                                                "SIGTERM" => "SIGTERM".to_string(),
                                                                "SIGQUIT" => "SIGQUIT".to_string(),
                                                                "SIGKILL" => "SIGKILL".to_string(),
                                                                "C" => "SIGINT".to_string(),
                                                                _ => {
                                                                    tracing::error!(
                                                                        server = %server.uuid,
                                                                        "invalid signal: {}, defaulting to SIGKILL",
                                                                        signal
                                                                    );

                                                                    "SIGKILL".to_string()
                                                                }
                                                            }
                                                        }
                                                        _ => "SIGKILL".to_string(),
                                                    },
                                                }),
                                            )
                                            .await
                                    }
                                });

                                Ok(())
                            }
                            "command" => {
                                if let Some(stdin) = server.container_stdin().await {
                                    let mut command = stop.value.clone().unwrap_or_default();
                                    command.push('\n');

                                    if let Err(err) = stdin.send(command).await {
                                        tracing::error!(
                                            server = %server.uuid,
                                            "failed to send command to container stdin: {}",
                                            err
                                        );
                                    }
                                } else {
                                    tracing::error!(
                                        server = %server.uuid,
                                        "failed to get container stdin"
                                    );
                                }

                                Ok(())
                            }
                            _ => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "invalid stop type: {}, defaulting to docker stop",
                                    stop.r#type
                                );

                                crate::spawn_handled({
                                    let client = Arc::clone(&server.app_state.docker);
                                    let container = container.clone();

                                    async move {
                                        client
                                            .stop_container(
                                                &container,
                                                Some(bollard::container::StopContainerOptions {
                                                    t: -1,
                                                }),
                                            )
                                            .await
                                    }
                                });

                                Ok(())
                            }
                        }
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
                if server.state.get_state() != state::ServerState::Stopping {
                    server.stop(aquire_timeout, true).await?;
                }

                server.restarting.store(true, Ordering::SeqCst);
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
                if server.state.get_state() != state::ServerState::Stopping {
                    server.stop_with_kill_timeout(timeout, true).await?;
                }

                server.restarting.store(true, Ordering::SeqCst);
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
            let mut stream = server.app_state.docker.wait_container::<String>(
                match &server.container.read().await.as_ref() {
                    Some(container) => &container.docker_id,
                    None => return Ok(()),
                },
                None,
            );

            if server.state.get_state() != state::ServerState::Stopping {
                server.stop(None, skip_schedules).await?;
            }

            if tokio::time::timeout(timeout, stream.next()).await.is_err() {
                tracing::info!(
                    server = %server.uuid,
                    "kill timeout reached, killing server"
                );

                server.kill(skip_schedules).await?;
            }

            Ok(())
        })
        .await?
    }

    pub async fn destroy_container(&self) {
        tracing::info!(
            server = %self.uuid,
            "destroying container"
        );

        if let Ok(containers) = self
            .app_state
            .docker
            .list_containers(Some(bollard::container::ListContainersOptions {
                all: true,
                filters: HashMap::from([("name".to_string(), vec![self.uuid.to_string()])]),
                ..Default::default()
            }))
            .await
        {
            for container in containers {
                let container = match container.id {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            server = %self.uuid,
                            "container ID is missing, cannot remove"
                        );
                        continue;
                    }
                };

                if let Err(err) = self
                    .app_state
                    .docker
                    .remove_container(
                        &container,
                        Some(bollard::container::RemoveContainerOptions {
                            force: true,
                            ..Default::default()
                        }),
                    )
                    .await
                {
                    tracing::error!(
                        server = %self.uuid,
                        container = %container,
                        "failed to remove container: {}",
                        err
                    );
                }
            }
        }

        self.container.write().await.take();
        if let Some(handle) = self.websocket_sender.write().await.take() {
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

        tokio::spawn({
            let server = self.clone();

            async move {
                let pool = &server.app_state.config.system.transfers.storage_pool;
                let skip_file_removal = pool.enabled
                    && !pool.pool_name.is_empty()
                    && server.transferring.load(Ordering::SeqCst);

                if !skip_file_removal {
                    server.filesystem.destroy().await;
                }
            }
        });
    }

    pub async fn to_api_response(&self) -> serde_json::Value {
        json!({
            "state": self.state.get_state(),
            "is_suspended": self.suspended.load(Ordering::SeqCst),
            "utilization": self.resource_usage().await,
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
