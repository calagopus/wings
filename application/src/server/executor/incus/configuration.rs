use super::{IncusExecutor, image, process};
use crate::server::configuration::ServerConfiguration;
use anyhow::{Context, ensure};
use std::collections::BTreeMap;

impl IncusExecutor {
    pub(super) fn validate_server(config: &ServerConfiguration) -> anyhow::Result<()> {
        ensure!(
            !config.allocations.force_outgoing_ip,
            "Incus force_outgoing_ip requires an explicit SNAT design; unsupported"
        );
        ensure!(
            !config.build.oom_disabled,
            "Incus does not support disabling the OOM killer"
        );
        ensure!(
            config.devices.is_empty()
                && !config.container.kvm_passthrough_enabled
                && !config.container.hugepages_passthrough_enabled,
            "Incus device passthrough is not implemented"
        );
        ensure!(
            config.container.seccomp.remove_allowed.is_empty(),
            "Incus custom seccomp policy is not implemented"
        );
        if let Some(weight) = config.build.io_weight {
            ensure!(
                weight == 10 || ((100..=1000).contains(&weight) && weight.is_multiple_of(100)),
                "Incus I/O weight must be 10 or a multiple of 100 through 1000"
            );
        }
        ensure!(
            config.features.startup_cpu_boost.is_none()
                && config.features.runtime_cpu_boost.is_none(),
            "Incus CPU boost configuration is not implemented"
        );
        Ok(())
    }
    pub(super) fn resources(
        &self,
        config: &ServerConfiguration,
        installer: bool,
    ) -> anyhow::Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        let cfg = self.config.load();
        let memory = if installer {
            cfg.docker.installer_limits.memory.as_mib() as i64
        } else if config.build.memory_limit <= 0 {
            0
        } else {
            config
                .build
                .memory_limit
                .saturating_add(config.build.overhead_memory)
                .max(0)
        };
        let cpu = if installer {
            cfg.docker.installer_limits.cpu as i64
        } else {
            config.build.cpu_limit
        };
        if memory > 0 {
            result.insert("limits.memory".into(), format!("{memory}MiB"));
        }
        if cpu > 0 {
            result.insert("limits.cpu.allowance".into(), format!("{cpu}ms/100ms"));
        }
        if !installer && let Some(threads) = config.build.threads.as_ref() {
            ensure!(
                threads
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b',' | b'-')),
                "invalid CPU pinning list"
            );
            result.insert("limits.cpu".into(), threads.to_string());
        }
        if !installer && let Some(weight) = config.build.io_weight {
            result.insert("limits.disk.priority".into(), (weight / 100).to_string());
        }
        if cfg.docker.container_pid_limit > 0 {
            result.insert(
                "limits.processes".into(),
                cfg.docker.container_pid_limit.to_string(),
            );
        }
        if !installer {
            result.insert(
                "limits.memory.swap".into(),
                match config.build.swap {
                    0 => "false".into(),
                    -1 => "true".into(),
                    value if value > 0 => format!("{value}MiB"),
                    _ => anyhow::bail!("invalid swap limit"),
                },
            );
        }
        Ok(result)
    }
    pub(super) fn process_config(
        &self,
        config: &ServerConfiguration,
        image: &image::Image,
        installer: bool,
        command: Option<Vec<String>>,
    ) -> anyhow::Result<BTreeMap<String, String>> {
        let mut result = self.resources(config, installer)?;
        let args = match command {
            Some(command) => command,
            None => match config.entrypoint.as_ref() {
                Some(entrypoint) => {
                    let mut args = entrypoint.clone();
                    args.extend(image.cmd.clone());
                    args
                }
                None => image.args.clone(),
            },
        };
        let mut supervised = vec![
            "/bin/sh".into(),
            "-c".into(),
            process::SUPERVISOR.into(),
            "wings-supervisor".into(),
        ];
        supervised.extend(args);
        result.insert(
            "user.wings.launch".into(),
            process::launch_script(&supervised)?,
        );
        result.insert(
            "oci.entrypoint".into(),
            process::encode_argv(&["/bin/sh".into(), "/opt/wings-control/process/launch".into()])?,
        );
        result.insert(
            "oci.cwd".into(),
            if installer {
                "/mnt/server"
            } else {
                "/home/container"
            }
            .into(),
        );
        result.insert(
            "oci.uid".into(),
            if installer { 0 } else { image.uid }.to_string(),
        );
        result.insert(
            "oci.gid".into(),
            if installer { 0 } else { image.gid }.to_string(),
        );
        result.insert("security.privileged".into(), "false".into());
        result.insert("security.nesting".into(), "false".into());
        result.insert("security.idmap.isolated".into(), "true".into());
        result.insert("security.guestapi".into(), "false".into());
        result.insert("boot.autostart".into(), "false".into());
        for (key, value) in &image.environment {
            result.insert(format!("environment.{key}"), value.clone());
        }
        for entry in config.environment(&self.config) {
            let (key, value) = entry.split_once('=').context("invalid environment entry")?;
            result.insert(format!("environment.{key}"), value.into());
        }
        Ok(result)
    }
}
