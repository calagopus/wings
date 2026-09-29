use anyhow::Context;
use serde::Serialize;
use std::{collections::HashMap, net::IpAddr, path::Path, process::Stdio, sync::Arc};
use utoipa::ToSchema;

pub mod cgroup;
pub mod docker;
pub mod noop;
pub mod pve_lxc;

pub struct Runtime {
    pub executor: Arc<dyn ServerExecutor>,
    /// Transitional escape hatch for Docker-only subsystems such as Tundra.
    /// New runtime-neutral code should use `executor` instead.
    pub docker: Option<Arc<bollard::Docker>>,
}

pub async fn create_runtime(config: Arc<crate::config::Config>) -> Result<Runtime, anyhow::Error> {
    let backend = resolve_backend(&config).await?;

    match backend {
        crate::config::RuntimeBackend::Auto => Err(anyhow::anyhow!(
            "automatic runtime selection was not resolved"
        )),
        crate::config::RuntimeBackend::Docker => {
            tracing::info!("connecting to docker");
            let docker = Arc::new(docker_client(&config.load().docker.socket)?);

            let own_container = docker::DockerExecutor::own_container(&docker).await;
            let firewall =
                crate::server::firewall::create(&config, &docker, own_container.as_ref()).await;
            let executor: Arc<dyn ServerExecutor> = Arc::new(docker::DockerExecutor::new(
                Arc::clone(&docker),
                config,
                firewall,
            ));

            Ok(Runtime {
                executor,
                docker: Some(docker),
            })
        }
        crate::config::RuntimeBackend::PveLxc => {
            tracing::info!("initializing Proxmox VE LXC runtime");
            let cli = {
                let snapshot = config.load();
                pve_lxc::PveCli::from_config(&snapshot.runtime.pve_lxc)
            };
            let firewall = pve_lxc::create_firewall(&config, &cli).await?;
            let executor: Arc<dyn ServerExecutor> =
                Arc::new(pve_lxc::PveLxcExecutor::new(config, cli, firewall));

            Ok(Runtime {
                executor,
                docker: None,
            })
        }
    }
}

fn docker_client(socket: &str) -> Result<bollard::Docker, anyhow::Error> {
    if socket.starts_with("http://") || socket.starts_with("tcp://") {
        bollard::Docker::connect_with_http(socket, 120, bollard::API_DEFAULT_VERSION)
    } else {
        bollard::Docker::connect_with_local(socket, 120, bollard::API_DEFAULT_VERSION)
    }
    .context("failed to connect to docker")
}

async fn docker_available(socket: &str) -> bool {
    match docker_client(socket) {
        Ok(docker) => tokio::time::timeout(std::time::Duration::from_secs(3), docker.version())
            .await
            .is_ok_and(|result| result.is_ok()),
        Err(_) => false,
    }
}

async fn pve_lxc_available(runtime: &crate::config::PveLxcRuntime) -> bool {
    if !Path::new(&runtime.pct_path).is_file() || !Path::new(&runtime.pveversion_path).is_file() {
        return false;
    }

    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new(&runtime.pveversion_path)
            .arg("--verbose")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .is_some_and(|status| status.success())
}

async fn resolve_backend(
    config: &Arc<crate::config::Config>,
) -> Result<crate::config::RuntimeBackend, anyhow::Error> {
    let snapshot = config.load();
    if snapshot.runtime.backend != crate::config::RuntimeBackend::Auto {
        return Ok(snapshot.runtime.backend);
    }

    let docker_socket = snapshot.docker.socket.clone();
    let pve_lxc = snapshot.runtime.pve_lxc.clone();
    drop(snapshot);

    let selected = if docker_available(&docker_socket).await {
        crate::config::RuntimeBackend::Docker
    } else if pve_lxc_available(&pve_lxc).await {
        crate::config::RuntimeBackend::PveLxc
    } else {
        anyhow::bail!(
            "runtime.backend is auto but neither Docker nor a local Proxmox VE LXC runtime is available"
        );
    };

    let mut persisted: crate::config::InnerConfig =
        serde_json::from_value(serde_json::to_value(&**config.load())?)?;
    persisted.runtime.backend = selected;
    config.replace(persisted)?;
    tracing::info!(runtime_backend = ?selected, "automatically selected and persisted runtime backend");

    Ok(selected)
}

type StatusReceiver = tokio::sync::mpsc::Receiver<ProcessStatus>;

#[derive(ToSchema, Serialize, Debug, Clone, Copy)]
pub struct UsedPort {
    pub port: u16,
    pub server: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessStatus {
    Running,
    Paused,
    Stopped { exit_code: i32, oom_killed: bool },
}

#[async_trait::async_trait]
pub trait ProcessHandle: Send + Sync {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, anyhow::Error>;

    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), anyhow::Error>;
    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>;
    async fn subscribe_stdout_lines(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>;

    async fn sync_configuration(&self) -> Result<(), anyhow::Error>;

    async fn start(&self) -> Result<(), anyhow::Error>;
    async fn stop(&self) -> Result<(), anyhow::Error>;
    async fn kill(&self) -> Result<(), anyhow::Error>;
}

#[async_trait::async_trait]
pub trait ServerExecutor: Send + Sync {
    async fn boot(&self) -> Result<(), anyhow::Error>;

    async fn reconcile_firewall(
        &self,
        _servers: &[crate::remote::servers::RawServer],
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn setup_server_process(
        &self,
        server: &super::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error>;
    async fn attach_server_process(
        &self,
        server: &super::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error>;
    async fn cleanup_server_process(&self, server: &super::Server) -> Result<(), anyhow::Error>;

    async fn setup_installation_process(
        &self,
        server: &super::Server,
        script: &super::installation::InstallationScript,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error>;
    async fn attach_installation_process(
        &self,
        server: &super::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error>;
    async fn cleanup_installation_process(
        &self,
        server: &super::Server,
    ) -> Result<(), anyhow::Error>;

    async fn setup_script_process(
        &self,
        server: &super::Server,
        script: &super::installation::InstallationScript,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error>;

    async fn resolve_internal_target(
        &self,
        server: &super::Server,
        port: u16,
    ) -> Result<Option<std::net::SocketAddr>, anyhow::Error>;
    async fn resolve_published_address(&self, server: &super::Server) -> Option<IpAddr>;

    async fn container_refs(&self, servers: &[super::Server]) -> HashMap<uuid::Uuid, String>;

    async fn used_ports(
        &self,
        ips: &[IpAddr],
    ) -> Result<HashMap<IpAddr, Vec<UsedPort>>, anyhow::Error>;
}
