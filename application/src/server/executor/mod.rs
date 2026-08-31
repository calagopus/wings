use serde::Serialize;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use utoipa::ToSchema;

pub mod docker;
pub mod noop;

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
