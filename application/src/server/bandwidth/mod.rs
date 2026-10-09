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

use anyhow::{Context, ensure};
use limits::BandwidthLimits;

pub const IFB_DEVICE: &str = "wings-dl";

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

pub async fn ready(config: &crate::config::Config) -> Result<(), anyhow::Error> {
    linux::ready(config.load().system.user.rootless.enabled).await
}

pub async fn apply(
    config: &crate::config::Config,
    docker: &bollard::Docker,
    container_id: &str,
    limits: BandwidthLimits,
) -> Result<(), anyhow::Error> {
    if !config.load().docker.bandwidth.enabled {
        if limits.is_limited() {
            tracing::warn!(
                container = container_id,
                "docker.bandwidth is disabled, running the server without its bandwidth limits"
            );
        }

        return Ok(());
    }

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
        return Ok(());
    };

    let host_config = container.host_config.unwrap_or_default();
    let network_mode = host_config.network_mode.as_deref().unwrap_or_default();
    if matches!(network_mode, "host" | "none") || network_mode.starts_with("container:") {
        ensure!(
            !limits.is_limited(),
            "bandwidth limits require a bridge network"
        );

        return Ok(());
    }

    if limits.is_limited() {
        let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
            .await
            .with_context(|| format!("failed to read capabilities of pid {pid}"))?;
        validate_capabilities(&status)?;
    }

    linux::apply(pid, limits, config.load().system.user.rootless.enabled).await
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
