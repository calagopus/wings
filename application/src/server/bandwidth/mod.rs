pub mod limits;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::limits::BandwidthLimits;
    use anyhow::{bail, ensure};

    pub async fn ready(_rootless: bool) -> Result<(), anyhow::Error> {
        bail!("bandwidth limits are only supported on linux")
    }

    pub async fn apply(
        _pid: u32,
        limits: BandwidthLimits,
        _rootless: bool,
    ) -> Result<(), anyhow::Error> {
        ensure!(
            !limits.is_limited(),
            "bandwidth limits are only supported on linux"
        );

        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{HELPER_ARG, helper_main};

use crate::server::firewall::runner::{CommandRunner, DockerHelper, HelperContainer};
use anyhow::{Context, bail, ensure};
use limits::BandwidthLimits;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

pub const IFB_DEVICE: &str = "wings-dl";
pub const CONTAINER_ARG: &str = "__wings-bandwidth-container";

const HELPER: HelperContainer = HelperContainer {
    name: "calagopus-wings-bandwidth",
    container_type: "bandwidth_helper",
    network_mode: "none",
    pid_mode: Some("host"),
    cap_add: &["NET_ADMIN", "SYS_ADMIN"],
};

const UNREACHABLE: &str = "wings runs in a container without the host pid namespace, where server network namespaces are out of reach - set docker.bandwidth.backend to container, or give the wings container the host pid namespace";

#[derive(ToSchema, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BandwidthBackendKind {
    #[default]
    Auto,
    Local,
    Container,
    Disabled,
}

const BYPASS_CAPABILITIES: [(u32, &str); 3] =
    [(12, "NET_ADMIN"), (13, "NET_RAW"), (21, "SYS_ADMIN")];

fn capability_mask(status: &str, field: &str) -> Result<u64, anyhow::Error> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .with_context(|| format!("failed to read {field} capabilities"))
}

fn validate_capabilities(status: &str) -> Result<(), anyhow::Error> {
    let bounding = capability_mask(status, "CapBnd")?;

    for (bit, name) in BYPASS_CAPABILITIES {
        ensure!(
            bounding & (1 << bit) == 0,
            "bandwidth limits require a container without {name}"
        );
    }

    Ok(())
}

enum Backend {
    Disabled,
    Local {
        rootless: bool,
    },
    Container {
        runner: CommandRunner,
        binary: String,
    },
    Unusable(String),
}

pub struct Bandwidth {
    backend: Backend,
}

impl Bandwidth {
    pub async fn create(
        config: &crate::config::Config,
        docker: &Arc<bollard::Docker>,
        own_container: Option<&(String, bollard::models::ContainerInspectResponse)>,
    ) -> Self {
        let rootless = config.load().system.user.rootless.enabled;
        let reachable = own_container.is_none_or(|(_, inspect)| {
            inspect
                .host_config
                .as_ref()
                .and_then(|host_config| host_config.pid_mode.as_deref())
                == Some("host")
        });

        if let Err(err) =
            DockerHelper::remove_stale(docker, &HELPER, own_container.map(|(id, _)| id.as_str()))
                .await
        {
            tracing::warn!("failed to remove stale bandwidth helper containers: {err:#}");
        }

        let backend = match config.load().docker.bandwidth.backend {
            BandwidthBackendKind::Disabled => Backend::Disabled,
            BandwidthBackendKind::Local if !reachable => {
                tracing::warn!("{UNREACHABLE}");

                Backend::Unusable(UNREACHABLE.to_string())
            }
            BandwidthBackendKind::Local => Backend::Local { rootless },
            BandwidthBackendKind::Auto
                if reachable
                    && (rootless
                        || own_container.is_none()
                        || linux::ready(false).await.is_ok()) =>
            {
                Backend::Local { rootless }
            }
            BandwidthBackendKind::Auto | BandwidthBackendKind::Container => {
                match container_helper(config, docker, own_container, rootless).await {
                    Ok((runner, binary)) => {
                        tracing::info!("applying bandwidth limits through a helper container");

                        Backend::Container { runner, binary }
                    }
                    Err(err) => {
                        tracing::warn!(
                            "failed to set up the bandwidth helper container, bandwidth limits will not be applied: {err:#}"
                        );

                        Backend::Unusable(format!("{err:#}"))
                    }
                }
            }
        };

        Self { backend }
    }

    #[inline]
    pub fn enabled(&self) -> bool {
        !matches!(self.backend, Backend::Disabled)
    }

    pub async fn ready(&self) -> Result<(), anyhow::Error> {
        match &self.backend {
            Backend::Disabled => bail!("docker.bandwidth.backend is disabled"),
            Backend::Local { rootless } => linux::ready(*rootless).await,
            Backend::Container { .. } => Ok(()),
            Backend::Unusable(reason) => bail!("{reason}"),
        }
    }

    pub async fn apply(
        &self,
        docker: &bollard::Docker,
        container_id: &str,
        limits: BandwidthLimits,
    ) -> Result<(), anyhow::Error> {
        match &self.backend {
            Backend::Disabled => {
                if limits.is_limited() {
                    tracing::warn!(
                        container = container_id,
                        "docker.bandwidth.backend is disabled, running the server without its bandwidth limits"
                    );
                }

                Ok(())
            }
            Backend::Unusable(reason) => {
                ensure!(!limits.is_limited(), "{reason}");

                Ok(())
            }
            Backend::Local { rootless } => {
                let Some(pid) = shaped_pid(docker, container_id, limits).await? else {
                    return Ok(());
                };

                apply_pid(pid, limits, *rootless).await
            }
            Backend::Container { runner, binary } => {
                let Some(pid) = shaped_pid(docker, container_id, limits).await? else {
                    return Ok(());
                };

                runner
                    .run(
                        binary,
                        &[
                            CONTAINER_ARG,
                            "apply",
                            &pid.to_string(),
                            &limits.upload.to_string(),
                            &limits.download.to_string(),
                        ],
                        None,
                    )
                    .await?;

                Ok(())
            }
        }
    }
}

async fn container_helper(
    config: &crate::config::Config,
    docker: &Arc<bollard::Docker>,
    own_container: Option<&(String, bollard::models::ContainerInspectResponse)>,
    rootless: bool,
) -> Result<(CommandRunner, String), anyhow::Error> {
    ensure!(
        !rootless,
        "the container bandwidth backend is not supported with rootless container engines"
    );
    let Some((own_id, inspect)) = own_container else {
        bail!(
            "the container bandwidth backend needs wings to run as a container of the connected container engine"
        );
    };
    let image = inspect
        .image
        .clone()
        .context("own container inspect carries no image id")?;
    let binary = std::env::current_exe()
        .context("failed to resolve the wings binary")?
        .to_str()
        .context("the wings binary path is not valid utf-8")?
        .to_string();

    let helper = DockerHelper::new(
        Arc::clone(docker),
        &HELPER,
        own_id,
        image,
        config.load().app_name.clone(),
    );
    helper.ensure().await?;

    let runner = CommandRunner::Docker(helper);
    if let Err(err) = runner.run(&binary, &[CONTAINER_ARG, "ready"], None).await {
        if let CommandRunner::Docker(helper) = &runner
            && let Err(err) = helper.remove().await
        {
            tracing::debug!("failed to remove the unusable bandwidth helper container: {err}");
        }

        return Err(err.context("bandwidth limits are not usable inside the helper container"));
    }

    Ok((runner, binary))
}

async fn shaped_pid(
    docker: &bollard::Docker,
    container_id: &str,
    limits: BandwidthLimits,
) -> Result<Option<u32>, anyhow::Error> {
    let container = docker
        .inspect_container(container_id, None)
        .await
        .with_context(|| format!("failed to inspect container {container_id}"))?;

    let Some(pid) = container
        .state
        .filter(|state| state.running == Some(true))
        .and_then(|state| state.pid)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
    else {
        return Ok(None);
    };

    let host_config = container.host_config.unwrap_or_default();
    let network_mode = host_config.network_mode.as_deref().unwrap_or_default();
    if matches!(network_mode, "host" | "none") || network_mode.starts_with("container:") {
        ensure!(
            !limits.is_limited(),
            "bandwidth limits require a bridge network"
        );

        return Ok(None);
    }

    Ok(Some(pid))
}

async fn apply_pid(pid: u32, limits: BandwidthLimits, rootless: bool) -> Result<(), anyhow::Error> {
    if limits.is_limited() {
        let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
            .await
            .with_context(|| format!("failed to read capabilities of pid {pid}"))?;
        validate_capabilities(&status)?;
    }

    linux::apply(pid, limits, rootless).await
}

#[cfg(target_os = "linux")]
pub fn container_main(args: &[std::ffi::OsString]) -> i32 {
    let result = (|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        match args {
            [command] if command == "ready" => runtime.block_on(linux::ready(false)),
            [command, pid, upload, download] if command == "apply" => {
                let pid = pid.to_str().context("invalid pid")?.parse()?;
                let limits = BandwidthLimits {
                    upload: upload.to_str().context("invalid upload rate")?.parse()?,
                    download: download
                        .to_str()
                        .context("invalid download rate")?
                        .parse()?,
                };

                runtime.block_on(apply_pid(pid, limits, false))
            }
            _ => bail!("expected ready, or apply with a pid and upload and download rates"),
        }
    })();

    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // validate_capabilities

    fn status(bounding: &str) -> String {
        format!("Name:\tjava\nCapEff:\t0000000000000000\nCapBnd:\t{bounding}\n")
    }

    #[test]
    fn capabilities_that_bypass_shaping_are_rejected() {
        assert!(validate_capabilities(&status("00000000000000e1")).is_ok());
        assert!(validate_capabilities(&status("00000000000004e1")).is_ok());
        assert!(validate_capabilities(&status("00000000000020e1")).is_err());
        assert!(validate_capabilities(&status("00000000000010e1")).is_err());
        assert!(validate_capabilities(&status("00000000002000e1")).is_err());
        assert!(validate_capabilities(&status("000001ffffffffff")).is_err());
        assert!(validate_capabilities("Name:\tjava\n").is_err());
    }
}
