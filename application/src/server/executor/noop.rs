use super::{ProcessHandle, ServerExecutor, StatusReceiver};
use std::{collections::HashMap, sync::Arc};

pub struct NoopExecutor;

impl NoopExecutor {
    fn unsupported<T>() -> Result<T, anyhow::Error> {
        Err(anyhow::anyhow!(
            "container operations are not supported by the no-op executor"
        ))
    }
}

#[async_trait::async_trait]
impl ServerExecutor for NoopExecutor {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn setup_server_process(
        &self,
        _server: &crate::server::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        Self::unsupported()
    }

    async fn attach_server_process(
        &self,
        _server: &crate::server::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        Self::unsupported()
    }

    async fn cleanup_server_process(
        &self,
        _server: &crate::server::Server,
    ) -> Result<(), anyhow::Error> {
        Self::unsupported()
    }

    async fn setup_installation_process(
        &self,
        _server: &crate::server::Server,
        _script: &crate::server::installation::InstallationScript,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        Self::unsupported()
    }

    async fn attach_installation_process(
        &self,
        _server: &crate::server::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        Self::unsupported()
    }

    async fn cleanup_installation_process(
        &self,
        _server: &crate::server::Server,
    ) -> Result<(), anyhow::Error> {
        Self::unsupported()
    }

    async fn setup_script_process(
        &self,
        _server: &crate::server::Server,
        _script: &crate::server::installation::InstallationScript,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        Self::unsupported()
    }

    async fn resolve_internal_target(
        &self,
        _server: &crate::server::Server,
        _port: u16,
    ) -> Result<Option<std::net::SocketAddr>, anyhow::Error> {
        Self::unsupported()
    }
    async fn resolve_published_address(
        &self,
        _server: &crate::server::Server,
    ) -> Option<std::net::IpAddr> {
        None
    }

    async fn container_refs(
        &self,
        _servers: &[crate::server::Server],
    ) -> HashMap<uuid::Uuid, String> {
        HashMap::new()
    }

    async fn used_ports(
        &self,
        ips: &[std::net::IpAddr],
    ) -> Result<std::collections::HashMap<std::net::IpAddr, Vec<super::UsedPort>>, anyhow::Error>
    {
        Ok(ips.iter().map(|ip| (*ip, Vec::new())).collect())
    }
}
