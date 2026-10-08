use serde::Serialize;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use utoipa::ToSchema;

pub mod docker;
#[cfg(target_os = "linux")]
pub mod incus;
pub mod noop;

pub struct Runtime {
    pub executor: Arc<dyn ServerExecutor>,
    pub docker: Option<Arc<bollard::Docker>>,
}

pub async fn create_runtime(config: Arc<crate::config::Config>) -> anyhow::Result<Runtime> {
    use crate::config::RuntimeBackend;
    match config.load().runtime.backend {
        RuntimeBackend::Docker => {
            tracing::info!("connecting to docker");
            let socket = config.load().docker.socket.clone();
            let docker = Arc::new(
                if socket.starts_with("http://") || socket.starts_with("tcp://") {
                    bollard::Docker::connect_with_http(&socket, 120, bollard::API_DEFAULT_VERSION)?
                } else {
                    bollard::Docker::connect_with_local(&socket, 120, bollard::API_DEFAULT_VERSION)?
                },
            );
            let own_container = docker::DockerExecutor::own_container(&docker).await;
            let firewall =
                crate::server::firewall::create(&config, &docker, own_container.as_ref()).await;
            let executor = Arc::new(docker::DockerExecutor::new(
                Arc::clone(&docker),
                Arc::clone(&config),
                firewall,
            ));
            Ok(Runtime {
                executor,
                docker: Some(docker),
            })
        }
        RuntimeBackend::Incus => {
            #[cfg(target_os = "linux")]
            {
                tracing::info!("initializing Incus LXC runtime");
                Ok(Runtime {
                    executor: Arc::new(incus::IncusExecutor::new(Arc::clone(&config))?),
                    docker: None,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("Incus runtime requires Linux")
            }
        }
    }
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
