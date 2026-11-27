use crate::io::line_buffer::LineBuffer;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use utoipa::ToSchema;

pub mod docker;
#[cfg(any(unix, test))]
pub mod noop;
#[cfg(windows)]
pub mod wslc;

type StatusReceiver = tokio::sync::mpsc::Receiver<ProcessStatus>;
type OutputSender = tokio::sync::broadcast::Sender<Arc<compact_str::CompactString>>;

#[derive(ToSchema, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    #[default]
    Docker,
    #[cfg(windows)]
    Wslc,
}

async fn pump_output(
    server: Arc<super::InnerServer>,
    app_config: Arc<crate::config::Config>,
    mut output: impl futures::Stream<Item = Result<impl AsRef<[u8]>, impl Sized>> + Unpin,
    stdout_ratelimited_tx: OutputSender,
    stdout_tx: OutputSender,
) {
    let mut line_buffer = LineBuffer::new();

    let mut ratelimit_counter = 0;
    let mut ratelimit_start = std::time::Instant::now();

    let mut allow_ratelimit = || {
        ratelimit_counter += 1;

        let config = app_config.load();

        if config.throttles.enabled
            && config.throttles.line_reset_interval > 0
            && ratelimit_counter >= config.throttles.lines
        {
            if ratelimit_start.elapsed()
                < std::time::Duration::from_millis(config.throttles.line_reset_interval)
            {
                if ratelimit_counter == config.throttles.lines {
                    tracing::debug!(
                        server = %server.uuid,
                        lines = config.throttles.lines,
                        reset_interval = config.throttles.line_reset_interval,
                        "ratelimit reached for server output"
                    );

                    server.log_daemon_with_prelude(
                        "Server is outputting console data too quickly -- throttling...",
                    );
                }

                return false;
            } else {
                ratelimit_counter = 0;
                ratelimit_start = std::time::Instant::now();
            }
        }

        true
    };

    let mut emit = |slice: &[u8]| {
        let line = Arc::new(compact_str::CompactString::from_utf8_lossy(slice));

        if allow_ratelimit() {
            stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
        }
        stdout_tx.send(line).ok();
    };

    while let Some(Ok(data)) = output.next().await {
        line_buffer.extend(data.as_ref());

        while let Some(line) = line_buffer.next_line() {
            emit(line);
        }

        line_buffer.compact();
    }

    if let Some(line) = line_buffer.flush() {
        emit(line);
    }

    tracing::debug!(server = %server.uuid, "stdout task ended");
}

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
        timeout: Option<std::time::Duration>,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error>;

    async fn resolve_internal_target(
        &self,
        server: &super::Server,
        port: u16,
    ) -> Result<Option<std::net::SocketAddr>, anyhow::Error>;
    #[cfg_attr(not(unix), allow(dead_code))]
    async fn resolve_published_address(&self, server: &super::Server) -> Option<IpAddr>;

    #[cfg_attr(not(unix), allow(dead_code))]
    async fn container_refs(&self, servers: &[super::Server]) -> HashMap<uuid::Uuid, String>;

    async fn used_ports(
        &self,
        ips: &[IpAddr],
    ) -> Result<HashMap<IpAddr, Vec<UsedPort>>, anyhow::Error>;

    fn bandwidth(&self) -> Option<&super::bandwidth::Bandwidth>;
}
