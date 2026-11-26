//! Translates a Wings server configuration into Incus instance configuration.
//!
//! The `docker.*` settings are read on purpose: they are what the panel generates, and they must
//! mean the same thing whichever runtime a node uses.

use super::{Devices, image::Image, process, seccomp};
use crate::config::{Config, InnerConfig};
use crate::server::Server;
use crate::server::configuration::{AllowedDevices, ServerConfiguration};
use crate::server::executor::docker;
use anyhow::{Context, ensure};
use bollard::models::Resources;
use std::{
    collections::{BTreeMap, HashMap},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) const CONTAINER_HOME: &str = "/home/container";
pub(super) const INSTALL_HOME: &str = "/mnt/server";

/// The instance settings Wings owns that Incus can change while the instance runs.
pub(super) const LIVE_LIMITS: [&str; 6] = [
    "limits.cpu",
    "limits.cpu.allowance",
    "limits.disk.priority",
    "limits.memory",
    "limits.memory.swap",
    "limits.processes",
];

/// Capabilities docker leaves a server container after Wings drops the rest.
const SERVER_CAPABILITIES: [&str; 4] = ["CAP_CHOWN", "CAP_KILL", "CAP_SETGID", "CAP_SETUID"];
/// Docker's default capability set, used by installation and script containers.
const HELPER_CAPABILITIES: [&str; 14] = [
    "CAP_AUDIT_WRITE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_MKNOD",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_RAW",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT",
];
const DROPPED_CAPABILITIES: &str = "setpcap mknod audit_write net_raw dac_override fowner fsetid \
     net_bind_service sys_chroot setfcap sys_ptrace";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Server,
    Installer,
    Script,
}

impl Role {
    pub(super) fn of(name: &str) -> Self {
        if name.starts_with("wgs-") {
            Self::Server
        } else if name.starts_with("wgi-") {
            Self::Installer
        } else {
            Self::Script
        }
    }

    pub(super) fn home(self) -> &'static str {
        match self {
            Self::Server => CONTAINER_HOME,
            Self::Installer | Self::Script => INSTALL_HOME,
        }
    }
}

/// Limits for an instance, derived from the same resources docker would be given.
pub(super) fn limit_config(resources: &Resources, swap_sizes: bool) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();

    let memory = resources.memory.filter(|memory| *memory > 0);
    if let Some(memory) = memory {
        result.insert("limits.memory".into(), memory.to_string());
    }
    // Docker's `memory_swap` is memory and swap combined, with -1 meaning unlimited.
    let swap = match (memory, resources.memory_swap) {
        (Some(memory), Some(total)) if total >= 0 => {
            let swap = total.saturating_sub(memory).max(0);
            match swap {
                0 => "false".to_string(),
                swap if swap_sizes => swap.to_string(),
                _ => "true".to_string(),
            }
        }
        _ => "true".to_string(),
    };
    result.insert("limits.memory.swap".into(), swap);

    if let Some(quota) = resources.cpu_quota.filter(|quota| *quota > 0) {
        let period = (resources.cpu_period.unwrap_or(100_000) / 1000).max(1);
        let quota = (quota.saturating_add(999) / 1000).max(1);
        result.insert(
            "limits.cpu.allowance".into(),
            format!("{quota}ms/{period}ms"),
        );
    }
    if let Some(cpus) = resources.cpuset_cpus.as_deref().filter(|c| !c.is_empty()) {
        result.insert("limits.cpu".into(), pinned_cpus(cpus));
    }
    if let Some(weight) = resources.blkio_weight.filter(|weight| *weight > 0) {
        result.insert(
            "limits.disk.priority".into(),
            ((u32::from(weight) + 50) / 100).min(10).to_string(),
        );
    }
    if let Some(pids) = resources.pids_limit.filter(|pids| *pids > 0) {
        result.insert("limits.processes".into(), pids.to_string());
    }

    result
}

/// Incus reads a lone number as a CPU *count*, so single CPUs are written as one-wide ranges.
fn pinned_cpus(list: &str) -> String {
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            if entry.contains('-') {
                entry.to_string()
            } else {
                format!("{entry}-{entry}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A docker size such as `5m` as liblxc writes it.
fn console_log_size(config: &InnerConfig) -> String {
    let bytes = config
        .docker
        .log_config
        .config
        .get("max-size")
        .and_then(|size| {
            let size = size.trim().to_ascii_lowercase();
            let size = size.strip_suffix('b').unwrap_or(&size);
            let (digits, unit) = match size.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
                Some((at, _)) => size.split_at(at),
                None => (size, ""),
            };
            let unit: u64 = match unit {
                "" => 1,
                "k" => 1 << 10,
                "m" => 1 << 20,
                "g" => 1 << 30,
                _ => return None,
            };
            digits.parse::<u64>().ok()?.checked_mul(unit)
        })
        .unwrap_or(5 << 20)
        .max(1 << 16);

    format!("{}KB", bytes / 1024)
}

fn disk(source: &str, path: &str, read_only: bool) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("type".into(), "disk".into()),
        ("source".into(), source.into()),
        ("path".into(), path.into()),
        ("readonly".into(), read_only.to_string()),
    ])
}

/// Places a host file over one Incus manages itself. Incus mounts its own `resolv.conf` and
/// `hosts` over anything a disk device puts there, so the file is attached elsewhere in the
/// instance and bound into place afterwards.
fn stage_file(
    devices: &mut Devices,
    lxc: &mut Vec<String>,
    name: &str,
    source: &Path,
    target: &str,
) -> anyhow::Result<()> {
    let staged = format!("opt/wings-{name}");
    devices.insert(
        format!("wings-{name}"),
        disk(
            source.to_str().context("non UTF-8 vmount path")?,
            &format!("/{staged}"),
            true,
        ),
    );
    lxc.push(format!(
        "lxc.mount.entry = {staged} {target} none bind,ro,relative,create=file 0 0"
    ));
    Ok(())
}

/// Everything needed to describe a new instance, besides its network and storage.
pub(super) struct Blueprint {
    pub config: BTreeMap<String, String>,
    pub devices: Devices,
    /// The user the process runs as, inside the instance.
    pub uid: u32,
    pub gid: u32,
}

pub(super) struct BlueprintOptions<'a> {
    pub role: Role,
    pub image: &'a Image,
    pub command: Option<Vec<String>>,
    pub extra_env: &'a HashMap<compact_str::CompactString, serde_json::Value>,
    pub swap_sizes: bool,
}

pub(super) fn resources(
    config: &Arc<Config>,
    server: &ServerConfiguration,
    role: Role,
) -> Resources {
    match role {
        Role::Server => server.convert_container_resources(config),
        Role::Installer | Role::Script => server.installer_resources(config),
    }
}

pub(super) async fn blueprint(
    config: &Arc<Config>,
    server: &Server,
    cfg: &ServerConfiguration,
    options: BlueprintOptions<'_>,
) -> anyhow::Result<Blueprint> {
    let BlueprintOptions {
        role,
        image,
        command,
        extra_env,
        swap_sizes,
    } = options;
    let is_server = role == Role::Server;
    let resources = resources(config, cfg, role);
    let ulimits = if is_server {
        docker::convert_ulimits(config)
    } else {
        None
    };
    let sysctls = docker::convert_sysctls(config, "bridge");

    cfg.ensure_vmounts(config).await?;
    let vmounts = config.vmount_path(cfg.uuid);
    tokio::fs::create_dir_all(&vmounts).await?;
    let inner = config.load();

    let (uid, gid) = if is_server {
        (inner.system.user.uid, inner.system.user.gid)
    } else {
        (0, 0)
    };

    let mut result = limit_config(&resources, swap_sizes);
    for ulimit in ulimits.into_iter().flatten() {
        let (Some(name), Some(soft), Some(hard)) = (ulimit.name, ulimit.soft, ulimit.hard) else {
            continue;
        };
        let value = |limit: i64| {
            if limit < 0 {
                "unlimited".to_string()
            } else {
                limit.to_string()
            }
        };
        result.insert(
            format!("limits.kernel.{name}"),
            format!("{}:{}", value(soft), value(hard)),
        );
    }
    for (key, value) in sysctls.into_iter().flatten() {
        result.insert(format!("linux.sysctl.{key}"), value);
    }
    if is_server && !inner.docker.domainname.is_empty() {
        result.insert(
            "linux.sysctl.kernel.domainname".into(),
            inner.docker.domainname.clone(),
        );
    }

    let mut devices = Devices::new();
    let hostname = match role {
        Role::Server => cfg.uuid.to_string(),
        Role::Installer => "installer".into(),
        Role::Script => "script".into(),
    };
    let mut lxc = vec![
        format!("lxc.console.size = {}", console_log_size(&inner)),
        "lxc.console.rotate = 1".into(),
        format!("lxc.uts.name = {hostname}"),
        "lxc.no_new_privs = 1".into(),
    ];
    if !inner.docker.container_apparmor_profile.is_empty() {
        ensure!(
            !inner.docker.container_apparmor_profile.contains('\n'),
            "invalid AppArmor profile name"
        );
        lxc.push(format!(
            "lxc.apparmor.profile = {}",
            inner.docker.container_apparmor_profile
        ));
    }
    if let Some(reservation) = resources.memory_reservation.filter(|bytes| *bytes > 0) {
        lxc.push(format!("lxc.cgroup2.memory.low = {reservation}"));
    }
    if let Some(nodes) = resources.cpuset_mems.as_deref().filter(|n| !n.is_empty()) {
        lxc.push(format!("lxc.cgroup2.cpuset.mems = {nodes}"));
    }

    let home = role.home().trim_start_matches('/');
    lxc.push(format!(
        "lxc.mount.entry = tmpfs tmp tmpfs rw,exec,nosuid,nodev,size={}M,mode=1777,create=dir 0 0",
        inner.docker.tmpfs_size.as_mib()
    ));
    lxc.push(format!(
        "lxc.mount.entry = tmpfs {home}/{} tmpfs {},create=dir 0 0",
        crate::server::filesystem::trash::TRASH_DIRECTORY,
        docker::TRASH_TMPFS_OPTIONS
    ));
    if is_server && inner.docker.shm_size.as_bytes() > 0 {
        lxc.push(format!(
            "lxc.mount.entry = tmpfs dev/shm tmpfs rw,nosuid,nodev,noexec,size={},mode=1777,create=dir 0 0",
            inner.docker.shm_size.as_bytes()
        ));
    }

    if !inner.docker.network.dns.is_empty() {
        let mut resolv = String::new();
        for server in &inner.docker.network.dns {
            resolv.push_str(&format!("nameserver {server}\n"));
        }
        if !inner.docker.network.dns_options.is_empty() {
            resolv.push_str(&format!(
                "options {}\n",
                inner.docker.network.dns_options.join(" ")
            ));
        }
        let path = vmounts.join("resolv.conf");
        tokio::fs::write(&path, resolv).await?;
        stage_file(&mut devices, &mut lxc, "resolv", &path, "etc/resolv.conf")?;
    }

    if is_server {
        lxc.push(format!("lxc.cap.drop = {DROPPED_CAPABILITIES}"));
        // The root filesystem is read-only once everything is mounted, as with docker.
        lxc.push(
            "lxc.hook.mount = /bin/sh -c 'mount -o remount,bind,ro \"$LXC_ROOTFS_MOUNT\"'".into(),
        );

        let mut index = 0;
        for mount in cfg.mounts(config, &server.filesystem).await {
            if mount.target == CONTAINER_HOME {
                continue;
            }
            let source = Path::new(mount.source.as_str());
            ensure!(
                source.is_absolute() && source.exists(),
                "mount source {} is missing",
                mount.source
            );
            if mount.target == "/etc/hosts" {
                stage_file(&mut devices, &mut lxc, "hosts", source, "etc/hosts")?;
                continue;
            }
            let mut target = PathBuf::from(mount.target.as_str());
            // sysfs paths such as the DMI product UUID are symlinks on real hardware, which
            // liblxc refuses to mount over. Resolve them, and skip those this host lacks.
            if target.starts_with("/sys") {
                match tokio::fs::canonicalize(&target).await {
                    Ok(resolved) => target = resolved,
                    Err(err) => {
                        tracing::debug!(
                            server = %cfg.uuid,
                            "not mounting {}, this host does not have it: {}",
                            target.display(),
                            err
                        );
                        continue;
                    }
                }
            }
            devices.insert(
                format!("mount-{index}"),
                disk(
                    &mount.source,
                    target.to_str().context("non UTF-8 mount target")?,
                    mount.read_only,
                ),
            );
            index += 1;
        }

        let mut passthrough: Vec<(PathBuf, String, bool)> = Vec::new();
        if cfg.container.kvm_passthrough_enabled {
            passthrough.push(("/dev/kvm".into(), "/dev/kvm".into(), true));
        }
        if !cfg.devices.is_empty() {
            let allowed = AllowedDevices::load(config).await;
            for device in &cfg.devices {
                match device.resolve_allowed_source(&allowed).await {
                    Ok(source) => passthrough.push((
                        source,
                        device.target.to_string(),
                        device.permissions.contains('w'),
                    )),
                    Err(err) => tracing::warn!(
                        server = %cfg.uuid,
                        "not binding device {} -> {}: {:#}",
                        device.source,
                        device.target,
                        err
                    ),
                }
            }
        }
        for (index, (source, target, writable)) in passthrough.into_iter().enumerate() {
            let kind = match tokio::fs::metadata(&source).await {
                Ok(metadata) if metadata.file_type().is_char_device() => "unix-char",
                Ok(metadata) if metadata.file_type().is_block_device() => "unix-block",
                _ => {
                    tracing::warn!(
                        server = %cfg.uuid,
                        "not binding device {}, it is not a character or block device",
                        source.display()
                    );
                    continue;
                }
            };
            devices.insert(
                format!("device-{index}"),
                BTreeMap::from([
                    ("type".into(), kind.into()),
                    ("source".into(), source.display().to_string()),
                    ("path".into(), target),
                    ("uid".into(), uid.to_string()),
                    ("gid".into(), gid.to_string()),
                    ("mode".into(), if writable { "0660" } else { "0440" }.into()),
                ]),
            );
        }
    }

    if inner.docker.container_apply_seccomp {
        let capabilities: &[&str] = if is_server {
            &SERVER_CAPABILITIES
        } else {
            &HELPER_CAPABILITIES
        };
        result.insert(
            "raw.seccomp".into(),
            seccomp::profile(&cfg.container.seccomp.remove_allowed, capabilities),
        );
    }

    // Docker replaces both the image entrypoint and its default arguments when overridden.
    let args = command.unwrap_or_else(|| match cfg.entrypoint.as_ref() {
        Some(entrypoint) if !entrypoint.is_empty() => entrypoint.clone(),
        _ => image.args.clone(),
    });
    let mut supervised = vec![
        "/bin/sh".into(),
        "-c".into(),
        process::SUPERVISOR.into(),
        "wings-supervisor".into(),
    ];
    supervised.extend(args);
    result.insert(
        "user.wings.launch".into(),
        process::launch_script(&supervised, role != Role::Script)?,
    );
    result.insert(
        "oci.entrypoint".into(),
        process::encode_argv(&["/bin/sh".into(), "/opt/wings-control/process/launch".into()])?,
    );
    result.insert(
        "oci.cwd".into(),
        image
            .workdir
            .clone()
            .filter(|dir| dir.starts_with('/'))
            .unwrap_or_else(|| "/".into()),
    );
    result.insert("oci.uid".into(), uid.to_string());
    result.insert("oci.gid".into(), gid.to_string());
    // Files in the server directory belong to the Wings data user on the host.
    result.insert(
        "raw.idmap".into(),
        format!(
            "uid {} {uid}\ngid {} {gid}",
            inner.system.user.uid, inner.system.user.gid
        ),
    );
    for (key, value) in [
        ("security.privileged", "false"),
        ("security.nesting", "false"),
        ("security.idmap.isolated", "true"),
        ("security.guestapi", "false"),
        ("boot.autostart", "false"),
    ] {
        result.insert(key.into(), value.into());
    }

    let mut environment = BTreeMap::from([
        // The supervisor is process 1, so an image's `tini` has to reap as a subreaper.
        ("TINI_SUBREAPER".to_string(), "1".to_string()),
        ("HOSTNAME".to_string(), hostname),
        (
            "TERM".to_string(),
            if role == Role::Script {
                "dumb"
            } else {
                "xterm"
            }
            .to_string(),
        ),
        (
            "HOME".to_string(),
            if is_server { "/" } else { "/root" }.to_string(),
        ),
    ]);
    if is_server && inner.system.passwd.enabled {
        environment.insert("HOME".into(), CONTAINER_HOME.into());
    }
    drop(inner);
    environment.extend(image.environment.clone());
    for entry in cfg.environment(config) {
        let (key, value) = entry.split_once('=').context("invalid environment entry")?;
        environment.insert(key.into(), value.into());
    }
    for (key, value) in extra_env {
        environment.insert(
            key.to_string(),
            value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned),
        );
    }
    for (key, value) in environment {
        // Incus passes the environment to liblxc one line per variable.
        if value.contains(['\n', '\r']) {
            tracing::warn!(
                server = %cfg.uuid,
                "line breaks in environment variable {key} were replaced with spaces, Incus cannot pass them through"
            );
        }
        result.insert(
            format!("environment.{key}"),
            value.replace("\r\n", " ").replace(['\n', '\r'], " "),
        );
    }

    ensure!(
        lxc.iter().all(|line| !line.contains('\n')),
        "invalid instance setting"
    );
    result.insert("raw.lxc".into(), lxc.join("\n") + "\n");

    for device in devices.values() {
        if let Some(path) = device.get("path") {
            ensure!(path.starts_with('/'), "mount targets must be absolute");
        }
    }

    Ok(Blueprint {
        config: result,
        devices,
        uid,
        gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_follow_docker_resources() {
        let limits = limit_config(
            &Resources {
                memory: Some(1 << 30),
                memory_swap: Some((1 << 30) + (1 << 20)),
                cpu_quota: Some(150_000),
                cpu_period: Some(100_000),
                cpuset_cpus: Some("2,4-6".into()),
                blkio_weight: Some(500),
                pids_limit: Some(512),
                ..Default::default()
            },
            true,
        );
        let get = |key: &str| limits.get(key).map(String::as_str);
        assert_eq!(get("limits.memory"), Some("1073741824"));
        assert_eq!(get("limits.memory.swap"), Some("1048576"));
        assert_eq!(get("limits.cpu.allowance"), Some("150ms/100ms"));
        assert_eq!(get("limits.cpu"), Some("2-2,4-6"));
        assert_eq!(get("limits.disk.priority"), Some("5"));
        assert_eq!(get("limits.processes"), Some("512"));
        assert!(limits.keys().all(|key| LIVE_LIMITS.contains(&key.as_str())));
    }

    #[test]
    fn unlimited_resources_set_no_limits() {
        let limits = limit_config(
            &Resources {
                cpu_quota: Some(-1),
                ..Default::default()
            },
            true,
        );
        assert_eq!(limits.len(), 1);
        assert_eq!(
            limits.get("limits.memory.swap").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn swap_matches_docker() {
        let swap = |total, sizes| {
            limit_config(
                &Resources {
                    memory: Some(100),
                    memory_swap: Some(total),
                    ..Default::default()
                },
                sizes,
            )
            .remove("limits.memory.swap")
        };
        assert_eq!(swap(100, true).as_deref(), Some("false"));
        assert_eq!(swap(-1, true).as_deref(), Some("true"));
        assert_eq!(swap(300, false).as_deref(), Some("true"));
        assert_eq!(swap(300, true).as_deref(), Some("200"));
    }
}
