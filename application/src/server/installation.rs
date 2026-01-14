use super::configuration::string_to_option;
use anyhow::Context;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, atomic::Ordering},
};
use tokio::{io::AsyncWriteExt, sync::Mutex};
use utoipa::ToSchema;

#[derive(ToSchema, Deserialize, Serialize, Clone)]
pub struct InstallationScript {
    pub container_image: compact_str::CompactString,
    pub entrypoint: compact_str::CompactString,

    #[serde(deserialize_with = "crate::deserialize::deserialize_defaultable")]
    pub script: String,
    #[serde(default)]
    pub environment: HashMap<compact_str::CompactString, serde_json::Value>,
}

pub struct ServerInstaller {
    pub reinstall: bool,
    environment: Vec<String>,
    server: super::Server,
    installation_script: Option<Arc<InstallationScript>>,

    container_id: Arc<Mutex<Option<String>>>,

    abort_notify: Arc<tokio::sync::Notify>,
}

impl ServerInstaller {
    pub async fn new(
        server: &super::Server,
        reinstall: bool,
        installation_script: Option<InstallationScript>,
    ) -> Self {
        Self {
            reinstall,
            environment: server
                .configuration
                .read()
                .await
                .environment(&server.app_state.config),
            server: server.clone(),
            installation_script: installation_script.map(Arc::new),
            container_id: Arc::new(Mutex::new(None)),
            abort_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn get_install_logs_path(server: &super::Server) -> std::path::PathBuf {
        std::path::PathBuf::from(&server.app_state.config.system.log_directory)
            .join(server.uuid.to_string())
            .join("install.log")
    }

    pub async fn get_install_logs(
        server: &super::Server,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let log_path = Self::get_install_logs_path(server);

        tokio::fs::File::open(&log_path).await
    }

    pub async fn create_install_logs(
        server: &super::Server,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let log_path = Self::get_install_logs_path(server);

        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::File::create(&log_path).await
    }

    pub async fn delete_install_logs(server: &super::Server) {
        let log_path = Self::get_install_logs_path(server);

        tokio::fs::remove_file(&log_path).await.ok();

        if let Some(parent) = log_path.parent() {
            // Remove the parent directory if it's empty
            tokio::fs::remove_dir(parent).await.ok();
        }
    }

    pub fn get_installation_script(&self) -> Result<Arc<InstallationScript>, anyhow::Error> {
        match &self.installation_script {
            Some(installation_script) => Ok(Arc::clone(installation_script)),
            None => Err(anyhow::anyhow!(
                "server install process has not been started"
            )),
        }
    }

    #[inline]
    pub fn abort(&self) {
        self.abort_notify.notify_one();
    }

    pub async fn unset_installing(&self, successful: bool) -> Result<(), anyhow::Error> {
        self.server.installing.store(false, Ordering::SeqCst);
        self.server.installer.write().await.take();

        self.cleanup_container().await?;

        tokio::fs::remove_dir_all(
            Path::new(&self.server.app_state.config.system.tmp_directory)
                .join(self.server.uuid.to_string()),
        )
        .await
        .ok();
        if let Err(err) = self
            .server
            .app_state
            .config
            .client
            .set_server_install(self.server.uuid, successful, self.reinstall)
            .await
        {
            tracing::error!(
                server = %self.server.uuid,
                "failed to set server install status: {}",
                err
            );
        }

        self.server
            .websocket
            .send(super::websocket::WebsocketMessage::new(
                super::websocket::WebsocketEvent::ServerInstallCompleted,
                [successful.to_string()].into(),
            ))?;

        if successful
            && !self.reinstall
            && self
                .server
                .configuration
                .read()
                .await
                .start_on_completion
                .is_some_and(|s| s)
            && let Err(err) = self.server.start(None, false).await
        {
            tracing::error!(
                server = %self.server.uuid,
                "failed to start server after initial install: {}",
                err
            );
        }

        self.server.filesystem.rerun_disk_checker();

        Ok(())
    }

    pub async fn start(self: &mut Arc<Self>, force: bool) -> Result<(), anyhow::Error> {
        if self.server.is_locked_state() {
            return Err(anyhow::anyhow!("server is in a locked state"));
        }

        self.server.installing.store(true, Ordering::SeqCst);
        self.server
            .websocket
            .send(super::websocket::WebsocketMessage::new(
                super::websocket::WebsocketEvent::ServerInstallStarted,
                [].into(),
            ))?;

        tracing::info!(
            server = %self.server.uuid,
            "starting installation process"
        );

        self.server
            .log_daemon(
                "Starting installation process, this could take a few minutes...".to_string(),
            )
            .await;

        if self.server.configuration.read().await.skip_egg_scripts && !force {
            self.unset_installing(true).await?;
            tracing::info!(
                server = %self.server.uuid,
                "skipping installation script execution as per configuration"
            );

            return Ok(());
        }

        let container_script = match &self.installation_script {
            Some(container_script) => container_script.clone(),
            None => {
                let container_script = match self
                    .server
                    .app_state
                    .config
                    .client
                    .server_install_script(self.server.uuid)
                    .await
                    .context("Failed to fetch installation script")
                {
                    Ok(container_script) => Arc::new(container_script),
                    Err(err) => {
                        self.unset_installing(false).await?;
                        return Err(err);
                    }
                };

                match Arc::get_mut(self) {
                    Some(installer) => {
                        installer
                            .installation_script
                            .replace(Arc::clone(&container_script));
                    }
                    None => {
                        self.unset_installing(false).await?;
                        return Err(anyhow::anyhow!(
                            "unable to get mutable reference to server installer"
                        ));
                    }
                }

                container_script
            }
        };

        if container_script.script.is_empty() {
            tracing::info!(
                server = %self.server.uuid,
                "no installation script provided, marking server as installed"
            );

            self.unset_installing(true).await?;
            return Ok(());
        }

        tokio::spawn({
            let installer = Arc::clone(self);

            async move {
                let run = async || {
                    if let Err(err) = installer
                        .server
                        .pull_image(&container_script.container_image, false)
                        .await
                        .context("Failed to pull installation container image")
                    {
                        installer.unset_installing(false).await?;
                        return Err(err);
                    }

                    let container = match installer
                        .server
                        .app_state
                        .docker
                        .create_container(
                            Some(bollard::container::CreateContainerOptions {
                                name: format!("{}_installer", installer.server.uuid),
                                ..Default::default()
                            }),
                            match installer.container_config().await {
                                Ok(config) => config,
                                Err(err) => {
                                    installer.unset_installing(false).await?;
                                    return Err(err);
                                }
                            },
                        )
                        .await
                        .context("Failed to create installation container")
                    {
                        Ok(container) => container,
                        Err(err) => {
                            installer.unset_installing(false).await?;
                            return Err(err);
                        }
                    };

                    *installer.container_id.lock().await = Some(container.id.clone());

                    tokio::select! {
                        result = tokio::time::timeout(
                            if installer
                                .server
                                .app_state
                                .config
                                .docker
                                .installer_limits
                                .timeout
                                > 0
                            {
                                std::time::Duration::from_secs(
                                    installer
                                        .server
                                        .app_state
                                        .config
                                        .docker
                                        .installer_limits
                                        .timeout,
                                )
                            } else {
                                std::time::Duration::MAX
                            },
                            {
                                let installer = Arc::clone(&installer);

                                async move {
                                    let thread = async {
                                        let mut stream = installer
                                            .server
                                            .app_state
                                            .docker
                                            .attach_container::<String>(
                                                &container.id,
                                                Some(bollard::container::AttachContainerOptions {
                                                    stdout: Some(true),
                                                    stderr: Some(true),
                                                    stream: Some(true),
                                                    ..Default::default()
                                                }),
                                            )
                                            .await?;

                                        let mut buffer = Vec::with_capacity(1024);
                                        let mut line_start = 0;

                                        while let Some(Ok(data)) = stream.output.next().await {
                                            buffer.extend_from_slice(&data.into_bytes());

                                            let mut search_start = line_start;

                                            loop {
                                                if let Some(pos) = buffer[search_start..]
                                                    .iter()
                                                    .position(|&b| b == b'\n')
                                                {
                                                    let newline_pos = search_start + pos;

                                                    if newline_pos - line_start <= 512 {
                                                        let line = String::from_utf8_lossy(
                                                            &buffer[line_start..newline_pos],
                                                        )
                                                        .trim()
                                                        .to_string();
                                                        installer
                                                            .server
                                                            .websocket
                                                            .send(super::websocket::WebsocketMessage::new(
                                                                super::websocket::WebsocketEvent::ServerInstallOutput,
                                                                [line].into(),
                                                            ))
                                                            .ok();

                                                        line_start = newline_pos + 1;
                                                        search_start = line_start;
                                                    } else {
                                                        let line = String::from_utf8_lossy(
                                                            &buffer[line_start..(line_start + 512)],
                                                        )
                                                        .trim()
                                                        .to_string();
                                                        installer
                                                            .server
                                                            .websocket
                                                            .send(super::websocket::WebsocketMessage::new(
                                                                super::websocket::WebsocketEvent::ServerInstallOutput,
                                                                [line].into(),
                                                            ))
                                                            .ok();

                                                        line_start += 512;
                                                        search_start = line_start;
                                                    }
                                                } else {
                                                    let current_line_length = buffer.len() - line_start;
                                                    if current_line_length > 512 {
                                                        let line = String::from_utf8_lossy(
                                                            &buffer[line_start..(line_start + 512)],
                                                        )
                                                        .trim()
                                                        .to_string();
                                                        installer
                                                            .server
                                                            .websocket
                                                            .send(super::websocket::WebsocketMessage::new(
                                                                super::websocket::WebsocketEvent::ServerInstallOutput,
                                                                [line].into(),
                                                            ))
                                                            .ok();

                                                        line_start += 512;
                                                        search_start = line_start;
                                                    } else {
                                                        break;
                                                    }
                                                }
                                            }

                                            if line_start > 1024 && line_start > buffer.len() / 2 {
                                                buffer.drain(0..line_start);
                                                line_start = 0;
                                            }
                                        }

                                        if line_start < buffer.len() {
                                            let line = String::from_utf8_lossy(&buffer[line_start..])
                                                .trim()
                                                .to_string();
                                            installer
                                                .server
                                                .websocket
                                                .send(super::websocket::WebsocketMessage::new(
                                                    super::websocket::WebsocketEvent::ServerInstallOutput,
                                                    [line].into(),
                                                ))
                                                .ok();
                                        }

                                        tracing::info!(server = ?installer.server.uuid, "ending server installation process by attach end");

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    installer.server.app_state.docker
                                        .start_container::<String>(&container.id, None)
                                        .await?;

                                    let wait_thread = async {
                                        let mut stream = installer
                                            .server
                                            .app_state
                                            .docker
                                            .wait_container(
                                                &container.id,
                                                Some(bollard::container::WaitContainerOptions {
                                                    condition: "not-running"
                                                })
                                            );

                                        if let Some(result) = stream.next().await {
                                            tracing::info!(server = ?installer.server.uuid, "ending server installation process by container exit: {:?}", result);
                                            let result = result?;

                                            if let Some(err) = result.error && let Some(message) = err.message {
                                                return Err(anyhow::anyhow!(message));
                                            }

                                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    tokio::select! {
                                        result = thread => result,
                                        result = wait_thread => result,
                                    }
                                }
                            }
                        ) => match result {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "failed to start installation container: {}",
                                    err
                                ));
                            }
                            Err(err) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "timeout while waiting for installation: {:#?}",
                                    err
                                ));
                            }
                        },
                        _ = installer.abort_notify.notified() => {
                            tracing::info!(
                                server = %installer.server.uuid,
                                "installation script aborted"
                            );
                        }
                    }

                    installer.unset_installing(true).await?;

                    Ok(())
                };

                if let Err(err) = run().await {
                    tracing::error!(
                        server = %installer.server.uuid,
                        "generic installation script error: {:#?}",
                        err
                    );
                }
            }
        });

        Ok(())
    }

    pub async fn attach(self: &mut Arc<Self>) -> Result<(), anyhow::Error> {
        self.server.installing.store(true, Ordering::SeqCst);
        self.server
            .websocket
            .send(super::websocket::WebsocketMessage::new(
                super::websocket::WebsocketEvent::ServerInstallStarted,
                [].into(),
            ))?;

        if let Ok(containers) = self
            .server
            .app_state
            .docker
            .list_containers(Some(bollard::container::ListContainersOptions {
                all: true,
                filters: HashMap::from([("name".to_string(), vec![self.server.uuid.to_string()])]),
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
                    let current_container_id = match container.id {
                        Some(id) => id,
                        None => continue,
                    };

                    if container
                        .state
                        .is_some_and(|s| s.to_lowercase() == "running")
                    {
                        tracing::info!(
                            server = %self.server.uuid,
                            "attaching to existing installation container {}",
                            current_container_id
                        );

                        *self.container_id.lock().await = Some(current_container_id);
                    } else {
                        tracing::info!(
                            server = %self.server.uuid,
                            "found existing installation container {} but it is not running, deleting it",
                            current_container_id
                        );

                        self.server
                            .app_state
                            .docker
                            .remove_container(
                                &current_container_id,
                                Some(bollard::container::RemoveContainerOptions {
                                    force: true,
                                    ..Default::default()
                                }),
                            )
                            .await
                            .ok();
                    }
                }
            }
        }

        tokio::spawn({
            let installer = Arc::clone(self);

            async move {
                let run = async || {
                    tokio::select! {
                        result = tokio::time::timeout(
                            if installer
                                .server
                                .app_state
                                .config
                                .docker
                                .installer_limits
                                .timeout
                                > 0
                            {
                                std::time::Duration::from_secs(
                                    installer
                                        .server
                                        .app_state
                                        .config
                                        .docker
                                        .installer_limits
                                        .timeout,
                                )
                            } else {
                                std::time::Duration::MAX
                            },
                            {
                                let installer = Arc::clone(&installer);
                                let docker_id = installer
                                    .container_id
                                    .lock()
                                    .await
                                    .as_ref()
                                    .ok_or_else(|| anyhow::anyhow!("unable to retrieve container id"))?
                                    .clone();

                                async move {
                                    let mut stream = installer
                                        .server
                                        .app_state
                                        .docker
                                        .attach_container::<String>(
                                            &docker_id,
                                            Some(bollard::container::AttachContainerOptions {
                                                stdout: Some(true),
                                                stderr: Some(true),
                                                stream: Some(true),
                                                ..Default::default()
                                            }),
                                        )
                                        .await?;

                                    let mut buffer = Vec::with_capacity(1024);
                                    let mut line_start = 0;

                                    while let Some(Ok(data)) = stream.output.next().await {
                                        buffer.extend_from_slice(&data.into_bytes());

                                        let mut search_start = line_start;

                                        loop {
                                            if let Some(pos) = buffer[search_start..]
                                                .iter()
                                                .position(|&b| b == b'\n')
                                            {
                                                let newline_pos = search_start + pos;

                                                if newline_pos - line_start <= 512 {
                                                    let line = String::from_utf8_lossy(
                                                        &buffer[line_start..newline_pos],
                                                    )
                                                    .trim()
                                                    .to_string();
                                                    installer
                                                        .server
                                                        .websocket
                                                        .send(super::websocket::WebsocketMessage::new(
                                                            super::websocket::WebsocketEvent::ServerInstallOutput,
                                                            [line].into(),
                                                        ))
                                                        .ok();

                                                    line_start = newline_pos + 1;
                                                    search_start = line_start;
                                                } else {
                                                    let line = String::from_utf8_lossy(
                                                        &buffer[line_start..(line_start + 512)],
                                                    )
                                                    .trim()
                                                    .to_string();
                                                    installer
                                                        .server
                                                        .websocket
                                                        .send(super::websocket::WebsocketMessage::new(
                                                            super::websocket::WebsocketEvent::ServerInstallOutput,
                                                            [line].into(),
                                                        ))
                                                        .ok();

                                                    line_start += 512;
                                                    search_start = line_start;
                                                }
                                            } else {
                                                let current_line_length = buffer.len() - line_start;
                                                if current_line_length > 512 {
                                                    let line = String::from_utf8_lossy(
                                                        &buffer[line_start..(line_start + 512)],
                                                    )
                                                    .trim()
                                                    .to_string();
                                                    installer
                                                        .server
                                                        .websocket
                                                        .send(super::websocket::WebsocketMessage::new(
                                                            super::websocket::WebsocketEvent::ServerInstallOutput,
                                                            [line].into(),
                                                        ))
                                                        .ok();

                                                    line_start += 512;
                                                    search_start = line_start;
                                                } else {
                                                    break;
                                                }
                                            }
                                        }

                                        if line_start > 1024 && line_start > buffer.len() / 2 {
                                            buffer.drain(0..line_start);
                                            line_start = 0;
                                        }
                                    }

                                    if line_start < buffer.len() {
                                        let line = String::from_utf8_lossy(&buffer[line_start..])
                                            .trim()
                                            .to_string();
                                        installer
                                            .server
                                            .websocket
                                            .send(super::websocket::WebsocketMessage::new(
                                                super::websocket::WebsocketEvent::ServerInstallOutput,
                                                [line].into(),
                                            ))
                                            .ok();
                                    }

                                    Ok::<_, anyhow::Error>(())
                                }
                            }
                        ) => match result {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "failed to start installation container: {}",
                                    err
                                ));
                            }
                            Err(err) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "timeout while waiting for installation: {:#?}",
                                    err
                                ));
                            }
                        },
                        _ = installer.abort_notify.notified() => {
                            tracing::info!(
                                server = %installer.server.uuid,
                                "installation script aborted"
                            );
                        }
                    }

                    installer.unset_installing(true).await?;

                    Ok(())
                };

                if let Err(err) = run().await {
                    tracing::error!(
                        server = %installer.server.uuid,
                        "generic installation script error: {:#?}",
                        err
                    );
                }
            }
        });

        Ok(())
    }

    async fn cleanup_container(&self) -> Result<(), anyhow::Error> {
        let Some(container_id) = &*self.container_id.lock().await else {
            return Ok(());
        };
        let container_script = self.get_installation_script()?;

        let mut logs_stream = self.server.app_state.docker.logs::<String>(
            container_id,
            Some(bollard::container::LogsOptions {
                follow: false,
                stdout: true,
                stderr: true,
                timestamps: false,
                ..Default::default()
            }),
        );

        let mut env = String::new();
        for var in &self.environment {
            env.push_str(&format!("  {var}\n"));
        }

        let mut file = ServerInstaller::create_install_logs(&self.server).await?;
        file.write_all(
            format!(
                r"Server Installation Log

|
| Details
| ------------------------------
  Server UUID:          {}
  Container Image:      {}
  Container Entrypoint: {}

|
| Environment Variables
| ------------------------------
{env}

|
| Script Output
| ------------------------------
",
                self.server.uuid, container_script.container_image, container_script.entrypoint,
            )
            .as_bytes(),
        )
        .await?;

        while let Some(Ok(log)) = logs_stream.next().await {
            file.write_all(&log.into_bytes()).await?;
        }

        file.shutdown().await?;

        Ok(self
            .server
            .app_state
            .docker
            .remove_container(
                container_id,
                Some(bollard::container::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?)
    }

    async fn container_config(&self) -> Result<bollard::container::Config<String>, anyhow::Error> {
        let container_script = self.get_installation_script()?;
        let mut env = self.environment.clone();
        env.reserve_exact(container_script.environment.len());

        for (k, v) in &container_script.environment {
            env.push(format!(
                "{k}={}",
                match v {
                    serde_json::Value::String(s) => s.clone(),
                    _ => v.to_string(),
                }
            ));
        }

        let labels = HashMap::from([
            (
                "Service".to_string(),
                self.server.app_state.config.app_name.clone(),
            ),
            ("ContainerType".to_string(), "server_installer".to_string()),
        ]);

        let mut resources = self
            .server
            .configuration
            .read()
            .await
            .convert_container_resources(&self.server.app_state.config);

        if resources.memory_reservation.is_some_and(|m| {
            m > 0
                && m < self.server.app_state.config.docker.installer_limits.memory as i64
                    * 1024
                    * 1024
        }) {
            resources.memory = None;
            resources.memory_reservation = Some(
                self.server.app_state.config.docker.installer_limits.memory as i64 * 1024 * 1024,
            );
            resources.memory_swap = None;
        }

        if resources.cpu_quota.is_some_and(|c| {
            c > 0 && c < self.server.app_state.config.docker.installer_limits.cpu as i64 * 1000
        }) {
            resources.cpu_quota =
                Some(self.server.app_state.config.docker.installer_limits.cpu as i64 * 1000);
        }

        let tmp_dir = Path::new(&self.server.app_state.config.system.tmp_directory)
            .join(self.server.uuid.to_string());
        tokio::fs::create_dir_all(&tmp_dir).await?;
        tokio::fs::write(
            tmp_dir.join("install.sh"),
            container_script.script.replace("\r\n", "\n"),
        )
        .await?;
        tokio::fs::set_permissions(&tmp_dir, Permissions::from_mode(0o755)).await?;

        Ok(bollard::container::Config {
            host_config: Some(bollard::secret::HostConfig {
                memory: resources.memory,
                memory_reservation: resources.memory_reservation,
                memory_swap: resources.memory_swap,
                cpu_quota: resources.cpu_quota,
                cpu_period: resources.cpu_period,
                cpu_shares: resources.cpu_shares,
                cpuset_cpus: resources.cpuset_cpus,
                pids_limit: resources.pids_limit,
                blkio_weight: resources.blkio_weight,
                oom_kill_disable: resources.oom_kill_disable,

                mounts: Some(vec![
                    bollard::models::Mount {
                        typ: Some(bollard::secret::MountTypeEnum::BIND),
                        source: Some(self.server.filesystem.base().into()),
                        target: Some("/mnt/server".to_string()),
                        ..Default::default()
                    },
                    bollard::models::Mount {
                        typ: Some(bollard::secret::MountTypeEnum::BIND),
                        source: Some(tmp_dir.to_string_lossy().to_string()),
                        target: Some("/mnt/install".to_string()),
                        ..Default::default()
                    },
                ]),
                network_mode: Some(self.server.app_state.config.docker.network.mode.clone()),
                dns: Some(self.server.app_state.config.docker.network.dns.clone()),
                tmpfs: Some(HashMap::from([(
                    "/tmp".to_string(),
                    format!(
                        "rw,exec,nosuid,size={}M",
                        self.server.app_state.config.docker.tmpfs_size
                    ),
                )])),
                log_config: Some(bollard::secret::HostConfigLogConfig {
                    typ: Some(
                        self.server
                            .app_state
                            .config
                            .docker
                            .log_config
                            .r#type
                            .clone(),
                    ),
                    config: Some(
                        self.server
                            .app_state
                            .config
                            .docker
                            .log_config
                            .config
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    ),
                }),
                userns_mode: string_to_option(&self.server.app_state.config.docker.userns_mode),
                ..Default::default()
            }),
            cmd: Some(vec![
                container_script.entrypoint.to_string(),
                "/mnt/install/install.sh".to_string(),
            ]),
            hostname: Some("installer".to_string()),
            image: Some(
                container_script
                    .container_image
                    .trim_end_matches('~')
                    .to_string(),
            ),
            env: Some(env),
            labels: Some(labels),
            attach_stdin: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            open_stdin: Some(true),
            tty: Some(true),
            ..Default::default()
        })
    }
}

impl Drop for ServerInstaller {
    fn drop(&mut self) {
        self.abort_notify.notify_one();
    }
}
