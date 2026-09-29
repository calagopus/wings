use anyhow::Context;
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    path::{Component, Path, PathBuf},
    process::Output,
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

const TASK_POLL_INTERVAL: Duration = Duration::from_millis(500);
const TASK_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const CONFIG_HELPER_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const START_SETTLE_ATTEMPTS: usize = 20;
const START_SETTLE_DELAY: Duration = Duration::from_millis(500);
const MANAGED_FILE_TARGETS: [&str; 5] = [
    "/etc/machine-id",
    "/etc/hosts",
    "/etc/passwd",
    "/etc/group",
    "/calagopus-entrypoint",
];

mod scripts;

use scripts::{APPLY_FIREWALL_CONFIG_PERL, APPLY_RUNTIME_CONFIG_PERL};

#[derive(Debug, Clone)]
pub struct PveCli {
    pct_path: PathBuf,
    pvesh_path: PathBuf,
    pveversion_path: PathBuf,
    pvesm_path: PathBuf,
    #[allow(dead_code)]
    lxc_attach_path: PathBuf,
    lxc_stop_path: PathBuf,
    perl_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateContainerSpec {
    pub vmid: u32,
    pub template: String,
    pub hostname: String,
    pub rootfs_storage: String,
    pub rootfs_size_gib: u64,
    pub memory_mib: u64,
    pub swap_mib: u64,
    /// Panel CPU limit expressed as a percentage where 100 means one CPU of time.
    pub cpu_limit_percent: Option<u64>,
    pub cores: Option<u64>,
    /// Complete Proxmox `net0` value, including static allocation details when
    /// a server has a primary panel allocation.
    pub network: String,
    pub tags: Vec<String>,
    pub unprivileged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMountSpec {
    pub vmid: u32,
    pub data_path: String,
    /// UID used by the game process inside the container.
    pub container_uid: u32,
    /// GID used by the game process inside the container.
    pub container_gid: u32,
    /// UID that owns the server data on the Proxmox host.
    pub host_data_uid: u32,
    /// GID that owns the server data on the Proxmox host.
    pub host_data_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBindMountSpec {
    pub slot: u8,
    pub source_path: String,
    pub target_path: String,
    pub read_only: bool,
    /// UID that owns the bind source on the Proxmox host.
    pub host_uid: u32,
    /// GID that owns the bind source on the Proxmox host.
    pub host_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountSpec {
    pub slot: u8,
    pub source_path: String,
    pub target_path: String,
    pub read_only: bool,
    pub container_uid: u32,
    pub container_gid: u32,
    pub host_uid: u32,
    pub host_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDevicePassthroughSpec {
    pub slot: u8,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub deny_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePassthroughSpec {
    pub slot: u8,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub deny_write: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerOciUser {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerResources {
    pub memory_mib: u64,
    pub swap_mib: u64,
    pub memory_unlimited: bool,
    pub swap_unlimited: bool,
    pub cpu_limit_percent: Option<u64>,
    pub cores: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachProcessSpec {
    pub vmid: u32,
    pub uid: u32,
    pub gid: u32,
    pub environment: Vec<String>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFileMountSpec {
    pub source_path: String,
    pub target_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigSpec {
    pub vmid: u32,
    pub environment: Vec<String>,
    pub halt_signal: Option<String>,
    pub init_command: Option<String>,
    pub console_logfile: Option<String>,
    /// Exact host CPUs assigned through the panel's `build.threads` setting.
    /// `None` removes a previously managed CPU set.
    pub cpuset_cpus: Option<String>,
    /// Maximum process count for the container. `None` removes the managed
    /// cgroup limit.
    pub pids_limit: Option<u64>,
    /// cgroup v2 I/O weight in the kernel's 1..=10000 range.
    pub io_weight: Option<u64>,
    pub memory_unlimited: bool,
    pub swap_unlimited: bool,
    /// `None` leaves low-level LXC file mounts untouched. `Some`, including an
    /// empty vector, reconciles all Wings-reserved managed-file targets.
    pub managed_file_mounts: Option<Vec<ManagedFileMountSpec>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FirewallRuleSpec {
    pub r#type: String,
    pub action: String,
    pub iface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FirewallPolicySpec {
    pub vmid: u32,
    pub managed_prefix: String,
    pub rules: Vec<FirewallRuleSpec>,
    pub ipsets: std::collections::BTreeMap<String, Vec<String>>,
}

pub struct ConsoleSession {
    pub child: tokio::process::Child,
    pub reader: tokio::fs::File,
    pub writer: tokio::fs::File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterContainer {
    pub vmid: u32,
    pub node: String,
    pub status: Option<ContainerStatus>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerRuntimeStatus {
    pub status: ContainerStatus,
    pub pid: Option<i64>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInterface {
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageContent {
    pub volid: String,
    pub content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LxcStorage {
    pub name: String,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciTemplatePullSpec {
    pub node: String,
    pub storage: String,
    pub reference: String,
    pub filename: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciTemplate {
    pub volid: String,
    pub revision: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskStatus {
    pub state: TaskState,
    pub exit_status: Option<String>,
}

impl PveCli {
    pub fn from_config(config: &crate::config::PveLxcRuntime) -> Self {
        Self {
            pct_path: config.pct_path.clone().into(),
            pvesh_path: config.pvesh_path.clone().into(),
            pveversion_path: config.pveversion_path.clone().into(),
            pvesm_path: config.pvesm_path.clone().into(),
            lxc_attach_path: config.lxc_attach_path.clone().into(),
            lxc_stop_path: config.lxc_stop_path.clone().into(),
            perl_path: config.perl_path.clone().into(),
        }
    }

    pub fn panel_resources(
        memory_limit: i64,
        overhead_memory: i64,
        swap: i64,
        cpu_limit: i64,
        threads: Option<&str>,
    ) -> Result<ContainerResources, anyhow::Error> {
        if memory_limit < 0 {
            return Err(anyhow::anyhow!(
                "invalid negative memory limit for Proxmox LXC: {memory_limit}"
            ));
        }
        if overhead_memory < 0 {
            return Err(anyhow::anyhow!(
                "server overhead memory cannot be negative for the Proxmox LXC runtime"
            ));
        }
        let memory_unlimited = memory_limit == 0;
        let memory_mib = if memory_unlimited {
            // PVE requires a regular memory property even when a low-level LXC
            // cgroup override removes the limit before the first start.
            16
        } else {
            let memory_mib = memory_limit
                .checked_add(overhead_memory)
                .context("server memory plus overhead overflowed")?;
            if memory_mib < 16 {
                return Err(anyhow::anyhow!(
                    "Proxmox LXC requires at least 16 MiB of memory, resolved server limit was {memory_mib} MiB"
                ));
            }
            u64::try_from(memory_mib).context("server memory limit was negative")?
        };

        let swap_unlimited = memory_unlimited || swap == -1;
        let swap_mib = match swap {
            -1 => 0,
            value if value < 0 => {
                return Err(anyhow::anyhow!(
                    "invalid negative swap limit for Proxmox LXC: {value}"
                ));
            }
            value => u64::try_from(value).context("server swap limit exceeded u64")?,
        };

        let cpu_limit_percent = match cpu_limit {
            value if value < 0 => {
                return Err(anyhow::anyhow!(
                    "invalid negative CPU limit for Proxmox LXC: {value}"
                ));
            }
            0 => None,
            value => Some(u64::try_from(value).context("server CPU limit exceeded u64")?),
        };

        let _cpuset_cpus = threads
            .filter(|threads| !threads.trim().is_empty())
            .map(Self::normalize_cpuset)
            .transpose()?;

        Ok(ContainerResources {
            memory_mib,
            swap_mib,
            memory_unlimited,
            swap_unlimited,
            cpu_limit_percent,
            cores: None,
        })
    }

    pub(crate) fn normalize_cpuset(value: &str) -> Result<String, anyhow::Error> {
        let value = value.trim();
        if value.is_empty() {
            return Err(anyhow::anyhow!("CPU set cannot be empty"));
        }

        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(anyhow::anyhow!("CPU set contains an empty item"));
            }
            let (start, end) = match part.split_once('-') {
                Some((start, end)) => (start, Some(end)),
                None => (part, None),
            };
            let start = start
                .parse::<u32>()
                .with_context(|| format!("invalid CPU set item: {part}"))?;
            if let Some(end) = end {
                let end = end
                    .parse::<u32>()
                    .with_context(|| format!("invalid CPU set item: {part}"))?;
                if end < start {
                    return Err(anyhow::anyhow!("invalid descending CPU set range: {part}"));
                }
            }
        }

        Ok(value.to_string())
    }

    pub(crate) fn cgroup2_io_weight(weight: Option<u16>) -> Result<Option<u64>, anyhow::Error> {
        let Some(weight) = weight else {
            return Ok(None);
        };
        if !(10..=1000).contains(&weight) {
            return Err(anyhow::anyhow!(
                "block I/O weight must be between 10 and 1000, got {weight}"
            ));
        }

        // Match opencontainers/cgroups' conversion from the cgroup v1 API
        // range used by Docker to the cgroup v2 io.weight range.
        Ok(Some(1 + (u64::from(weight) - 10) * 9999 / 990))
    }

    async fn run(program: &std::path::Path, args: &[String]) -> Result<Output, anyhow::Error> {
        let mut command = tokio::process::Command::new(program);
        command.args(args).kill_on_drop(true);
        let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
            .await
            .with_context(|| format!("timed out executing {}", program.display()))?
            .with_context(|| format!("failed to execute {}", program.display()))?;

        if output.status.success() {
            return Ok(output);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "{} exited with {}: {}",
            program.display(),
            output.status,
            stderr.trim()
        ))
    }

    async fn run_with_stdin(
        program: &std::path::Path,
        args: &[String],
        input: &[u8],
    ) -> Result<Output, anyhow::Error> {
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to execute {}", program.display()))?;

        let mut stdin = child
            .stdin
            .take()
            .context("spawned Proxmox helper did not expose stdin")?;
        let operation = async move {
            stdin.write_all(input).await?;
            drop(stdin);
            child.wait_with_output().await
        };
        let output = tokio::time::timeout(CONFIG_HELPER_TIMEOUT, operation)
            .await
            .with_context(|| format!("timed out executing {}", program.display()))??;
        if output.status.success() {
            return Ok(output);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "{} exited with {}: {}",
            program.display(),
            output.status,
            stderr.trim()
        ))
    }

    fn runtime_config_payload(spec: &RuntimeConfigSpec) -> Result<Vec<u8>, anyhow::Error> {
        for variable in &spec.environment {
            let Some((name, _)) = variable.split_once('=') else {
                return Err(anyhow::anyhow!(
                    "runtime environment entry must be KEY=VALUE: {variable}"
                ));
            };
            if name.is_empty()
                || variable.contains('\0')
                || variable.contains('\n')
                || variable.contains('\r')
            {
                return Err(anyhow::anyhow!(
                    "runtime environment entry cannot be represented safely in an LXC config: {variable}"
                ));
            }
        }
        if spec
            .halt_signal
            .as_deref()
            .is_some_and(|signal| signal.is_empty() || signal.chars().any(char::is_control))
        {
            return Err(anyhow::anyhow!("invalid LXC halt signal"));
        }
        if spec.init_command.as_deref().is_some_and(|command| {
            command.is_empty()
                || command.contains('\0')
                || command.contains('\n')
                || command.contains('\r')
        }) {
            return Err(anyhow::anyhow!("invalid LXC init command"));
        }
        if spec.console_logfile.as_deref().is_some_and(|path| {
            !path.starts_with('/')
                || path.contains('\0')
                || path.contains('\n')
                || path.contains('\r')
        }) {
            return Err(anyhow::anyhow!("invalid LXC console logfile path"));
        }
        if let Some(cpuset) = spec.cpuset_cpus.as_deref() {
            Self::normalize_cpuset(cpuset)?;
        }
        if spec.pids_limit == Some(0) {
            return Err(anyhow::anyhow!("LXC PID limit must be positive"));
        }
        if spec
            .io_weight
            .is_some_and(|weight| !(1..=10_000).contains(&weight))
        {
            return Err(anyhow::anyhow!(
                "cgroup v2 I/O weight must be between 1 and 10000"
            ));
        }

        let (managed_file_mounts, managed_file_targets) =
            if let Some(mounts) = &spec.managed_file_mounts {
                let mut seen_targets = std::collections::HashSet::with_capacity(mounts.len());
                let mut encoded = Vec::with_capacity(mounts.len());

                for mount in mounts {
                    if !MANAGED_FILE_TARGETS.contains(&mount.target_path.as_str()) {
                        return Err(anyhow::anyhow!(
                            "unsupported managed Proxmox file mount target: {}",
                            mount.target_path
                        ));
                    }
                    if !seen_targets.insert(mount.target_path.as_str()) {
                        return Err(anyhow::anyhow!(
                            "duplicate managed Proxmox file mount target: {}",
                            mount.target_path
                        ));
                    }

                    let source = Self::encode_lxc_mount_field(&mount.source_path, false)?;
                    let target = Self::encode_lxc_mount_field(&mount.target_path, true)?;
                    encoded.push(serde_json::json!({
                        "target": target,
                        "entry": format!("{source} {target} none bind,ro,create=file 0 0"),
                    }));
                }

                let targets = MANAGED_FILE_TARGETS
                    .iter()
                    .map(|target| Self::encode_lxc_mount_field(target, true))
                    .collect::<Result<Vec<_>, _>>()?;
                (Some(encoded), Some(targets))
            } else {
                (None, None)
            };

        serde_json::to_vec(&serde_json::json!({
            "vmid": spec.vmid,
            "environment": spec.environment,
            "halt_signal": spec.halt_signal,
            "init_command": spec.init_command,
            "console_logfile": spec.console_logfile,
            "cpuset_cpus": spec.cpuset_cpus,
            "pids_limit": spec.pids_limit,
            "io_weight": spec.io_weight,
            "memory_unlimited": spec.memory_unlimited,
            "swap_unlimited": spec.swap_unlimited,
            "managed_file_mounts": managed_file_mounts,
            "managed_file_targets": managed_file_targets,
        }))
        .context("failed to serialize Proxmox runtime configuration")
    }

    fn encode_lxc_mount_field(path: &str, relative_target: bool) -> Result<String, anyhow::Error> {
        if !path.starts_with('/')
            || path.contains('\0')
            || path.contains('\n')
            || path.contains('\r')
        {
            return Err(anyhow::anyhow!(
                "invalid LXC managed file mount path: {path}"
            ));
        }

        let value = if relative_target {
            path.strip_prefix('/').unwrap_or(path)
        } else {
            path
        };
        if value.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid empty LXC managed file mount target"
            ));
        }

        let mut encoded = String::with_capacity(value.len());
        for character in value.chars() {
            match character {
                '\\' => encoded.push_str("\\134"),
                ' ' => encoded.push_str("\\040"),
                '\t' => encoded.push_str("\\011"),
                _ => encoded.push(character),
            }
        }
        Ok(encoded)
    }

    /// LXC's `lxc.init.cmd` parser supports whole-word single or double quotes,
    /// but does not support escape sequences inside a quoted word.
    pub fn encode_init_command(arguments: &[String]) -> Result<String, anyhow::Error> {
        if arguments.is_empty() {
            return Err(anyhow::anyhow!("LXC init command cannot be empty"));
        }

        let mut encoded = Vec::with_capacity(arguments.len());
        for argument in arguments {
            if argument.contains('\0') || argument.contains('\n') || argument.contains('\r') {
                return Err(anyhow::anyhow!(
                    "LXC init command argument contains an unsupported control character"
                ));
            }

            if !argument.is_empty()
                && !argument.chars().any(char::is_whitespace)
                && !argument.starts_with('\'')
                && !argument.starts_with('"')
            {
                encoded.push(argument.clone());
            } else if !argument.contains('"') {
                encoded.push(format!("\"{argument}\""));
            } else if !argument.contains('\'') {
                encoded.push(format!("'{argument}'"));
            } else {
                return Err(anyhow::anyhow!(
                    "LXC init command argument cannot be represented safely: {argument}"
                ));
            }
        }

        Ok(encoded.join(" "))
    }

    /// Applies dynamic Wings runtime settings without putting the NUL-separated
    /// PVE `env` value on a Unix argv. The helper edits the regular PVE LXC
    /// config under Proxmox's own config lock, preserving all unrelated options.
    pub async fn apply_runtime_config(
        &self,
        spec: &RuntimeConfigSpec,
    ) -> Result<(), anyhow::Error> {
        let payload = Self::runtime_config_payload(spec)?;
        Self::run_with_stdin(
            &self.perl_path,
            &["-e".to_string(), APPLY_RUNTIME_CONFIG_PERL.to_string()],
            &payload,
        )
        .await?;
        Ok(())
    }

    pub async fn apply_firewall_config(
        &self,
        spec: &FirewallPolicySpec,
    ) -> Result<(), anyhow::Error> {
        let payload = serde_json::to_vec(spec).context("failed to serialize Proxmox firewall")?;
        Self::run_with_stdin(
            &self.perl_path,
            &["-e".to_string(), APPLY_FIREWALL_CONFIG_PERL.to_string()],
            &payload,
        )
        .await?;
        Ok(())
    }

    pub fn request_shutdown_args(vmid: u32) -> Vec<String> {
        vec![
            "-n".to_string(),
            vmid.to_string(),
            "--nowait".to_string(),
            "--nokill".to_string(),
        ]
    }

    /// Requests the container init process to stop and returns immediately.
    /// `lxc.signal.halt` determines which signal init receives.
    pub async fn request_shutdown(&self, vmid: u32) -> Result<(), anyhow::Error> {
        Self::run(&self.lxc_stop_path, &Self::request_shutdown_args(vmid)).await?;
        Ok(())
    }

    pub fn console_args(vmid: u32) -> Vec<String> {
        vec![
            "console".to_string(),
            vmid.to_string(),
            "--escape".to_string(),
            "^z".to_string(),
        ]
    }

    /// Starts `pct console` on a real pseudo-terminal. `pct console` is an
    /// interactive terminal client and does not behave correctly when wired to
    /// ordinary pipes.
    #[cfg(target_os = "linux")]
    pub fn spawn_console(&self, vmid: u32) -> Result<ConsoleSession, anyhow::Error> {
        use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
        use std::os::unix::process::CommandExt;

        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let controller = openpt(flags).context("failed to allocate Proxmox console PTY")?;
        grantpt(&controller).context("failed to grant Proxmox console PTY")?;
        unlockpt(&controller).context("failed to unlock Proxmox console PTY")?;
        let user = ioctl_tiocgptpeer(&controller, flags)
            .context("failed to open Proxmox console PTY peer")?;

        let stdin = std::fs::File::from(user);
        let stdout = stdin.try_clone()?;
        let stderr = stdin.try_clone()?;
        let controller = std::fs::File::from(controller);
        let controller_writer = controller
            .try_clone()
            .context("failed to clone Proxmox console PTY controller")?;

        let mut command = tokio::process::Command::new(&self.pct_path);
        command
            .args(Self::console_args(vmid))
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);

        // `pct console` is an interactive terminal client. Merely connecting
        // its stdio to a PTY is enough to receive output, but keyboard input is
        // ignored unless the slave is also the child's controlling terminal.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                rustix::process::setsid()?;
                rustix::process::ioctl_tiocsctty(std::io::stdin())?;
                Ok(())
            });
        }

        let child = command
            .spawn()
            .with_context(|| format!("failed to execute {} console", self.pct_path.display()))?;

        Ok(ConsoleSession {
            child,
            reader: tokio::fs::File::from_std(controller),
            writer: tokio::fs::File::from_std(controller_writer),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn_console(&self, _vmid: u32) -> Result<ConsoleSession, anyhow::Error> {
        Err(anyhow::anyhow!(
            "Proxmox LXC console attachment is only supported on Linux"
        ))
    }

    pub async fn version(&self) -> Result<String, anyhow::Error> {
        let output = Self::run(&self.pveversion_path, &[]).await?;
        Ok(String::from_utf8(output.stdout)
            .context("pveversion returned non-UTF8 output")?
            .trim()
            .to_string())
    }

    pub async fn next_vmid(&self) -> Result<u32, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            "/cluster/nextid".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse Proxmox nextid response")?;
        let raw = value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
            .context("Proxmox nextid response was not a VMID")?;
        u32::try_from(raw).context("Proxmox nextid response exceeded the VMID range")
    }

    pub async fn local_node(&self) -> Result<String, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            "/cluster/status".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        Self::parse_local_node(&output.stdout)
    }

    pub async fn cluster_firewall_enabled(&self) -> Result<bool, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            "/cluster/firewall/options".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse Proxmox cluster firewall options")?;
        Ok(value
            .get("enable")
            .and_then(|value| value.as_u64())
            .is_some_and(|value| value != 0)
            || value
                .get("enable")
                .and_then(|value| value.as_bool())
                .unwrap_or(false))
    }

    /// Lists active LXC rootfs storages ordered by free capacity, so callers can
    /// place a container on the largest pool that can satisfy its requested size.
    pub async fn available_lxc_storages(
        &self,
        node: &str,
    ) -> Result<Vec<LxcStorage>, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            format!("/nodes/{node}/storage"),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        Self::parse_available_lxc_storages(&output.stdout)
    }

    fn parse_local_node(output: &[u8]) -> Result<String, anyhow::Error> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(output)
            .context("failed to parse Proxmox cluster status response")?;

        rows.iter()
            .find(|row| {
                row.get("type").and_then(serde_json::Value::as_str) == Some("node")
                    && row.get("local").is_some_and(|local| {
                        local.as_bool() == Some(true) || local.as_u64() == Some(1)
                    })
            })
            .and_then(|row| row.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .context("Proxmox cluster status did not identify the local node")
    }

    fn parse_available_lxc_storages(output: &[u8]) -> Result<Vec<LxcStorage>, anyhow::Error> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(output)
            .context("failed to parse Proxmox node storage response")?;

        let mut storages = rows
            .iter()
            .filter(|row| {
                row.get("active").and_then(serde_json::Value::as_u64) == Some(1)
                    && row.get("enabled").and_then(serde_json::Value::as_u64) == Some(1)
                    && row
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|content| content.split(',').any(|kind| kind == "rootdir"))
            })
            .map(|row| {
                Ok(LxcStorage {
                    name: row
                        .get("storage")
                        .and_then(serde_json::Value::as_str)
                        .context("Proxmox LXC storage response did not include a name")?
                        .to_string(),
                    available_bytes: row
                        .get("avail")
                        .and_then(serde_json::Value::as_u64)
                        .context(
                            "Proxmox LXC storage response did not include available capacity",
                        )?,
                })
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;
        storages.sort_unstable_by_key(|storage| std::cmp::Reverse(storage.available_bytes));
        Ok(storages)
    }

    pub async fn list_containers(&self) -> Result<Vec<ClusterContainer>, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            "/cluster/resources".to_string(),
            "--type".to_string(),
            "vm".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        Self::parse_containers(&output.stdout)
    }

    pub fn interfaces_args(node: &str, vmid: u32) -> Vec<String> {
        vec![
            "get".to_string(),
            format!("/nodes/{node}/lxc/{vmid}/interfaces"),
            "--output-format".to_string(),
            "json".to_string(),
        ]
    }

    pub async fn interfaces(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<ContainerInterface>, anyhow::Error> {
        let output = Self::run(&self.pvesh_path, &Self::interfaces_args(node, vmid)).await?;
        Self::parse_interfaces(&output.stdout)
    }

    pub fn runtime_status_args(node: &str, vmid: u32) -> Vec<String> {
        vec![
            "get".to_string(),
            format!("/nodes/{node}/lxc/{vmid}/status/current"),
            "--output-format".to_string(),
            "json".to_string(),
        ]
    }

    pub async fn runtime_status(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<ContainerRuntimeStatus, anyhow::Error> {
        let output = Self::run(&self.pvesh_path, &Self::runtime_status_args(node, vmid)).await?;
        Self::parse_runtime_status(&output.stdout)
    }

    fn parse_runtime_status(output: &[u8]) -> Result<ContainerRuntimeStatus, anyhow::Error> {
        let value: serde_json::Value = serde_json::from_slice(output)
            .context("failed to parse Proxmox LXC runtime status response")?;
        let status = value
            .get("status")
            .and_then(serde_json::Value::as_str)
            .and_then(ContainerStatus::from_word)
            .context("Proxmox LXC runtime status did not include a known status")?;
        let pid = value.get("pid").and_then(|pid| {
            pid.as_i64()
                .or_else(|| pid.as_str().and_then(|pid| pid.parse().ok()))
        });
        let uptime_seconds = value
            .get("uptime")
            .and_then(|uptime| {
                uptime
                    .as_u64()
                    .or_else(|| uptime.as_str().and_then(|uptime| uptime.parse().ok()))
            })
            .unwrap_or(0);

        Ok(ContainerRuntimeStatus {
            status,
            pid,
            uptime_seconds,
        })
    }

    fn parse_interfaces(output: &[u8]) -> Result<Vec<ContainerInterface>, anyhow::Error> {
        let rows: Option<Vec<serde_json::Value>> = serde_json::from_slice(output)
            .context("failed to parse Proxmox LXC interface response")?;

        rows.unwrap_or_default()
            .into_iter()
            .map(|row| {
                let name = row
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .context("Proxmox LXC interface row did not include a name")?
                    .to_string();
                let addresses = row
                    .get("ip-addresses")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|address| address.get("ip-address"))
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|address| address.parse::<IpAddr>().ok())
                    .collect();

                Ok(ContainerInterface { name, addresses })
            })
            .collect()
    }

    pub fn primary_container_address(interfaces: &[ContainerInterface]) -> Option<IpAddr> {
        let mut addresses = Self::container_addresses(interfaces).into_iter();

        addresses
            .clone()
            .find(IpAddr::is_ipv4)
            .or_else(|| addresses.find(IpAddr::is_ipv6))
    }

    pub fn container_addresses(interfaces: &[ContainerInterface]) -> Vec<IpAddr> {
        fn usable(address: IpAddr) -> bool {
            match address {
                IpAddr::V4(address) => {
                    !address.is_loopback()
                        && !address.is_unspecified()
                        && !address.is_multicast()
                        && !address.is_link_local()
                }
                IpAddr::V6(address) => {
                    !address.is_loopback()
                        && !address.is_unspecified()
                        && !address.is_multicast()
                        && !address.is_unicast_link_local()
                }
            }
        }

        let mut addresses = interfaces
            .iter()
            .filter(|interface| interface.name != "lo")
            .flat_map(|interface| interface.addresses.iter().copied())
            .filter(|address| usable(*address))
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    pub async fn list_storage_content(
        &self,
        node: &str,
        storage: &str,
    ) -> Result<Vec<StorageContent>, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            format!("/nodes/{node}/storage/{storage}/content"),
            "--content".to_string(),
            "vztmpl".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        Self::parse_storage_content(&output.stdout)
    }

    fn parse_storage_content(output: &[u8]) -> Result<Vec<StorageContent>, anyhow::Error> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(output)
            .context("failed to parse Proxmox storage content response")?;

        rows.into_iter()
            .map(|row| {
                let volid = row
                    .get("volid")
                    .and_then(serde_json::Value::as_str)
                    .context("Proxmox storage content row did not include a volid")?
                    .to_string();
                let content = row
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);

                Ok(StorageContent { volid, content })
            })
            .collect()
    }

    pub fn normalize_oci_reference(reference: &str) -> Result<String, anyhow::Error> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(anyhow::anyhow!("OCI image reference cannot be empty"));
        }
        if reference.contains('@') {
            return Err(anyhow::anyhow!(
                "Proxmox OCI registry pull currently requires a tagged image reference, not a digest reference: {reference}"
            ));
        }

        let last_slash = reference.rfind('/');
        let last_colon = reference.rfind(':');
        let has_tag = match (last_slash, last_colon) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(slash), Some(colon)) => colon > slash,
        };

        if has_tag {
            Ok(reference.to_string())
        } else {
            Ok(format!("{reference}:latest"))
        }
    }

    pub fn oci_cache_filename(reference: &str) -> String {
        let digest = Sha256::digest(reference.as_bytes());
        format!("calagopus-oci-{}", hex::encode(digest))
    }

    pub fn oci_template_volid(storage: &str, reference: &str) -> String {
        format!(
            "{storage}:vztmpl/{}.tar",
            Self::oci_cache_filename(reference)
        )
    }

    pub fn oci_revision_tag(revision: &str) -> Result<String, anyhow::Error> {
        let revision = revision.strip_prefix("sha256:").unwrap_or(revision);
        let short = revision
            .get(..32)
            .context("OCI image revision digest was unexpectedly short")?;
        if !short.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!(
                "OCI image revision was not a SHA-256 digest"
            ));
        }
        Ok(format!("calagopus-image-{short}"))
    }

    async fn template_path(&self, volid: &str) -> Result<PathBuf, anyhow::Error> {
        let output = Self::run(&self.pvesm_path, &["path".to_string(), volid.to_string()]).await?;
        let path =
            String::from_utf8(output.stdout).context("pvesm path returned non-UTF8 output")?;
        let path = path.trim();
        if path.is_empty() {
            return Err(anyhow::anyhow!(
                "pvesm path returned an empty path for {volid}"
            ));
        }
        Ok(path.into())
    }

    async fn template_revision(&self, volid: &str) -> Result<String, anyhow::Error> {
        let path = self.template_path(volid).await?;
        tokio::task::spawn_blocking(move || {
            use std::io::Read;

            let file = std::fs::File::open(&path)
                .with_context(|| format!("failed to open OCI template {}", path.display()))?;
            let mut archive = tar::Archive::new(file);
            for entry in archive
                .entries()
                .context("failed to read OCI template archive")?
            {
                let mut entry = entry.context("failed to read OCI template entry")?;
                if entry.path()?.as_ref() != std::path::Path::new("index.json") {
                    continue;
                }
                let mut index = String::new();
                entry.read_to_string(&mut index)?;
                let value: serde_json::Value = serde_json::from_str(&index)
                    .context("failed to parse OCI template index.json")?;
                return value
                    .get("manifests")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|manifests| manifests.first())
                    .and_then(|manifest| manifest.get("digest"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .context("OCI template index did not include a manifest digest");
            }
            Err(anyhow::anyhow!("OCI template did not contain index.json"))
        })
        .await
        .context("OCI template inspection task failed")?
    }

    async fn template_is_fresh(
        &self,
        volid: &str,
        max_age: Duration,
    ) -> Result<bool, anyhow::Error> {
        if max_age.is_zero() {
            return Ok(false);
        }
        let path = self.template_path(volid).await?;
        let modified = tokio::fs::metadata(&path).await?.modified()?;
        Ok(modified.elapsed().is_ok_and(|age| age < max_age))
    }

    async fn remove_template(&self, volid: &str) -> Result<(), anyhow::Error> {
        Self::run(&self.pvesm_path, &["free".to_string(), volid.to_string()]).await?;
        Ok(())
    }

    pub fn pull_oci_args(spec: &OciTemplatePullSpec) -> Vec<String> {
        vec![
            "create".to_string(),
            format!(
                "/nodes/{}/storage/{}/oci-registry-pull",
                spec.node, spec.storage
            ),
            "--reference".to_string(),
            spec.reference.clone(),
            "--filename".to_string(),
            spec.filename.clone(),
            "--output-format".to_string(),
            "json".to_string(),
        ]
    }

    pub async fn pull_oci_template(
        &self,
        spec: &OciTemplatePullSpec,
    ) -> Result<String, anyhow::Error> {
        let output = Self::run(&self.pvesh_path, &Self::pull_oci_args(spec)).await?;
        Self::parse_oci_pull_task(&output.stdout)
    }

    fn parse_oci_pull_task(output: &[u8]) -> Result<String, anyhow::Error> {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(output)
            && let Some(upid) = value.as_str().filter(|upid| upid.starts_with("UPID:"))
        {
            return Ok(upid.to_string());
        }

        let output = std::str::from_utf8(output)
            .context("Proxmox OCI pull response contained non-UTF8 output")?;
        for line in output
            .lines()
            .rev()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
                && let Some(upid) = value.as_str().filter(|upid| upid.starts_with("UPID:"))
            {
                return Ok(upid.to_string());
            }
            if line.starts_with("UPID:") {
                return Ok(line.to_string());
            }
        }

        Err(anyhow::anyhow!(
            "Proxmox OCI pull response did not contain a task UPID"
        ))
    }

    pub async fn task_status(&self, node: &str, upid: &str) -> Result<TaskStatus, anyhow::Error> {
        let args = vec![
            "get".to_string(),
            format!("/nodes/{node}/tasks/{upid}/status"),
            "--output-format".to_string(),
            "json".to_string(),
        ];
        let output = Self::run(&self.pvesh_path, &args).await?;
        Self::parse_task_status(&output.stdout)
    }

    fn parse_task_status(output: &[u8]) -> Result<TaskStatus, anyhow::Error> {
        let value: serde_json::Value = serde_json::from_slice(output)
            .context("failed to parse Proxmox task status response")?;
        let state = match value.get("status").and_then(serde_json::Value::as_str) {
            Some("running") => TaskState::Running,
            Some("stopped") => TaskState::Stopped,
            Some(status) => {
                return Err(anyhow::anyhow!(
                    "unknown Proxmox task status response: {status}"
                ));
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Proxmox task status response did not include status"
                ));
            }
        };
        let exit_status = value
            .get("exitstatus")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(TaskStatus { state, exit_status })
    }

    pub async fn wait_for_task(&self, node: &str, upid: &str) -> Result<(), anyhow::Error> {
        tokio::time::timeout(TASK_TIMEOUT, async {
            loop {
                let status = self.task_status(node, upid).await?;
                match status.state {
                    TaskState::Running => tokio::time::sleep(TASK_POLL_INTERVAL).await,
                    TaskState::Stopped => {
                        return match status.exit_status.as_deref() {
                            Some("OK") => Ok(()),
                            Some(exit_status) => Err(anyhow::anyhow!(
                                "Proxmox task {upid} failed with exit status {exit_status}"
                            )),
                            None => Err(anyhow::anyhow!(
                                "Proxmox task {upid} stopped without an exit status"
                            )),
                        };
                    }
                }
            }
        })
        .await
        .with_context(|| format!("timed out waiting for Proxmox task {upid}"))?
    }

    fn validate_absolute_path(path: &str, label: &str) -> Result<(), anyhow::Error> {
        let path = Path::new(path);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
            || path
                .as_os_str()
                .as_encoded_bytes()
                .iter()
                .any(|byte| matches!(byte, 0 | b',' | b'\n' | b'\r'))
        {
            return Err(anyhow::anyhow!(
                "invalid Proxmox {label} path: {}",
                path.display()
            ));
        }
        Ok(())
    }

    pub async fn ensure_oci_template(
        &self,
        node: &str,
        storage: &str,
        reference: &str,
        max_age: Duration,
    ) -> Result<OciTemplate, anyhow::Error> {
        let reference = Self::normalize_oci_reference(reference)?;
        let filename = Self::oci_cache_filename(&reference);
        let volid = Self::oci_template_volid(storage, &reference);
        let exists = self
            .list_storage_content(node, storage)
            .await?
            .into_iter()
            .any(|entry| entry.volid == volid);
        if exists && self.template_is_fresh(&volid, max_age).await? {
            return Ok(OciTemplate {
                revision: self.template_revision(&volid).await?,
                volid,
            });
        }
        if exists {
            self.remove_template(&volid)
                .await
                .with_context(|| format!("failed to remove stale Proxmox OCI template {volid}"))?;
        }

        let upid = self
            .pull_oci_template(&OciTemplatePullSpec {
                node: node.to_string(),
                storage: storage.to_string(),
                reference,
                filename,
            })
            .await?;
        self.wait_for_task(node, &upid).await?;

        let exists = self
            .list_storage_content(node, storage)
            .await?
            .into_iter()
            .any(|entry| entry.volid == volid);
        if exists {
            Ok(OciTemplate {
                revision: self.template_revision(&volid).await?,
                volid,
            })
        } else {
            Err(anyhow::anyhow!(
                "Proxmox OCI pull task completed but template {volid} was not present in storage"
            ))
        }
    }

    fn parse_containers(output: &[u8]) -> Result<Vec<ClusterContainer>, anyhow::Error> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(output)
            .context("failed to parse Proxmox cluster resources response")?;
        let mut containers = Vec::new();

        for row in rows {
            if row.get("type").and_then(serde_json::Value::as_str) != Some("lxc") {
                continue;
            }

            let raw_vmid = row
                .get("vmid")
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                })
                .context("Proxmox LXC resource did not include a VMID")?;
            let vmid = u32::try_from(raw_vmid).context("Proxmox LXC VMID exceeded u32")?;
            let node = row
                .get("node")
                .and_then(serde_json::Value::as_str)
                .context("Proxmox LXC resource did not include a node")?
                .to_string();
            let status = row
                .get("status")
                .and_then(serde_json::Value::as_str)
                .and_then(ContainerStatus::from_word);
            let tags = row
                .get("tags")
                .and_then(serde_json::Value::as_str)
                .map(|tags| {
                    tags.split(';')
                        .map(str::trim)
                        .filter(|tag| !tag.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();

            containers.push(ClusterContainer {
                vmid,
                node,
                status,
                tags,
            });
        }

        Ok(containers)
    }

    pub async fn status(&self, vmid: u32) -> Result<ContainerStatus, anyhow::Error> {
        let args = vec!["status".to_string(), vmid.to_string()];
        let output = Self::run(&self.pct_path, &args).await?;
        ContainerStatus::parse(&String::from_utf8_lossy(&output.stdout))
    }

    pub async fn start(&self, vmid: u32) -> Result<(), anyhow::Error> {
        let args = ["start".to_string(), vmid.to_string()];
        let mut last_error = None;

        for attempt in 0..START_SETTLE_ATTEMPTS {
            match Self::run(&self.pct_path, &args).await {
                Ok(_) => return Ok(()),
                Err(error) => {
                    let message = error.to_string();
                    if !message.contains("monitor socket")
                        && !message.contains("got timeout")
                        && !message.contains("unable to get PID for CT")
                    {
                        return Err(error);
                    }
                    tokio::time::sleep(START_SETTLE_DELAY).await;
                    // A failed pct client can still have started the container.
                    // Reissuing pct start in that case would produce "already running".
                    if matches!(self.status(vmid).await, Ok(ContainerStatus::Running)) {
                        return Ok(());
                    }
                    last_error = Some(error);
                    if attempt + 1 < START_SETTLE_ATTEMPTS {
                        tracing::warn!(
                            vmid,
                            attempt = attempt + 1,
                            "retrying Proxmox LXC start after monitor teardown"
                        );
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("failed to start LXC container")))
    }

    #[allow(dead_code)]
    pub async fn shutdown(&self, vmid: u32, timeout_seconds: u64) -> Result<(), anyhow::Error> {
        Self::run(
            &self.pct_path,
            &[
                "shutdown".to_string(),
                vmid.to_string(),
                "--timeout".to_string(),
                timeout_seconds.to_string(),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn stop(&self, vmid: u32) -> Result<(), anyhow::Error> {
        Self::run(&self.pct_path, &["stop".to_string(), vmid.to_string()]).await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if self.status(vmid).await? == ContainerStatus::Stopped {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .with_context(|| format!("timed out waiting for Proxmox LXC {vmid} to stop"))?
    }

    pub async fn destroy(&self, vmid: u32) -> Result<(), anyhow::Error> {
        Self::run(
            &self.pct_path,
            &[
                "destroy".to_string(),
                vmid.to_string(),
                "--purge".to_string(),
                "1".to_string(),
            ],
        )
        .await?;
        Ok(())
    }

    pub fn create_args(spec: &CreateContainerSpec) -> Vec<String> {
        let mut args = vec![
            "create".to_string(),
            spec.vmid.to_string(),
            spec.template.clone(),
            "--hostname".to_string(),
            spec.hostname.clone(),
            "--rootfs".to_string(),
            format!("{}:{}", spec.rootfs_storage, spec.rootfs_size_gib),
            "--memory".to_string(),
            spec.memory_mib.to_string(),
            "--swap".to_string(),
            spec.swap_mib.to_string(),
            "--net0".to_string(),
            spec.network.clone(),
            "--unprivileged".to_string(),
            u8::from(spec.unprivileged).to_string(),
            "--cmode".to_string(),
            "console".to_string(),
            "--onboot".to_string(),
            "0".to_string(),
        ];

        if let Some(cores) = spec.cores {
            args.extend(["--cores".to_string(), cores.to_string()]);
        }
        if let Some(cpu_limit_percent) = spec.cpu_limit_percent {
            args.extend([
                "--cpulimit".to_string(),
                Self::format_cpu_limit_percent(cpu_limit_percent),
            ]);
        }
        if !spec.tags.is_empty() {
            args.extend(["--tags".to_string(), spec.tags.join(";")]);
        }

        args
    }

    fn format_cpu_limit_percent(percent: u64) -> String {
        let whole = percent / 100;
        let fractional = percent % 100;
        if fractional == 0 {
            return whole.to_string();
        }
        if fractional.is_multiple_of(10) {
            format!("{whole}.{}", fractional / 10)
        } else {
            format!("{whole}.{fractional:02}")
        }
    }

    pub async fn create(&self, spec: &CreateContainerSpec) -> Result<(), anyhow::Error> {
        Self::run(&self.pct_path, &Self::create_args(spec)).await?;
        Ok(())
    }

    pub fn set_resources_args(vmid: u32, resources: &ContainerResources) -> Vec<String> {
        let mut args = vec![
            "set".to_string(),
            vmid.to_string(),
            "--memory".to_string(),
            resources.memory_mib.to_string(),
            "--swap".to_string(),
            resources.swap_mib.to_string(),
            "--cpulimit".to_string(),
            resources
                .cpu_limit_percent
                .map(Self::format_cpu_limit_percent)
                .unwrap_or_else(|| "0".to_string()),
        ];

        if let Some(cores) = resources.cores {
            args.extend(["--cores".to_string(), cores.to_string()]);
        }

        args
    }

    pub async fn set_resources(
        &self,
        vmid: u32,
        resources: &ContainerResources,
    ) -> Result<(), anyhow::Error> {
        Self::run(&self.pct_path, &Self::set_resources_args(vmid, resources)).await?;
        Ok(())
    }

    pub async fn set_network(&self, vmid: u32, network: &str) -> Result<(), anyhow::Error> {
        Self::run(
            &self.pct_path,
            &[
                "set".to_string(),
                vmid.to_string(),
                "--net0".to_string(),
                network.to_string(),
            ],
        )
        .await?;
        Ok(())
    }

    pub fn network_with_firewall(config: &str) -> Result<Option<String>, anyhow::Error> {
        let network = config
            .lines()
            .find_map(|line| line.strip_prefix("net0:"))
            .map(str::trim)
            .context("Proxmox LXC config has no net0 interface")?;
        let mut options: Vec<&str> = network
            .split(',')
            .filter(|option| !option.starts_with("firewall="))
            .collect();
        options.push("firewall=1");
        let wanted = options.join(",");

        Ok((wanted != network).then_some(wanted))
    }

    pub async fn enable_network_firewall(&self, vmid: u32) -> Result<(), anyhow::Error> {
        let config = self.config(vmid).await?;
        if let Some(network) = Self::network_with_firewall(&config)? {
            self.set_network(vmid, &network).await?;
        }
        Ok(())
    }

    pub fn set_tags_args(vmid: u32, tags: &[String]) -> Vec<String> {
        vec![
            "set".to_string(),
            vmid.to_string(),
            "--tags".to_string(),
            tags.join(";"),
        ]
    }

    pub async fn set_tags(&self, vmid: u32, tags: &[String]) -> Result<(), anyhow::Error> {
        Self::run(&self.pct_path, &Self::set_tags_args(vmid, tags)).await?;
        Ok(())
    }

    pub async fn config(&self, vmid: u32) -> Result<String, anyhow::Error> {
        let output = Self::run(&self.pct_path, &["config".to_string(), vmid.to_string()]).await?;
        Self::decode_config_output(output.stdout)
    }

    fn decode_config_output(stdout: Vec<u8>) -> Result<String, anyhow::Error> {
        let mut config =
            String::from_utf8(stdout).context("pct config returned non-UTF8 output")?;
        config.retain(|character| character != '\0');
        Ok(config)
    }

    fn parse_oci_user(config: &str) -> Result<ContainerOciUser, anyhow::Error> {
        let mut uid = None;
        let mut gid = None;

        for line in config.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "lxc.init.uid" => {
                    uid = Some(
                        value
                            .parse::<u32>()
                            .with_context(|| format!("invalid lxc.init.uid value: {value}"))?,
                    );
                }
                "lxc.init.gid" => {
                    gid = Some(
                        value
                            .parse::<u32>()
                            .with_context(|| format!("invalid lxc.init.gid value: {value}"))?,
                    );
                }
                _ => {}
            }
        }

        Ok(ContainerOciUser {
            uid: uid.unwrap_or(0),
            gid: gid.unwrap_or(0),
        })
    }

    pub async fn oci_user(&self, vmid: u32) -> Result<ContainerOciUser, anyhow::Error> {
        let config = self.config(vmid).await?;
        Self::parse_oci_user(&config)
    }

    pub async fn oci_entrypoint(&self, vmid: u32) -> Result<String, anyhow::Error> {
        let config = self.config(vmid).await?;
        let entrypoint = config
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "entrypoint").then(|| value.trim().to_string())
            })
            .filter(|value| !value.is_empty())
            .context("OCI-backed Proxmox container does not define an entrypoint")?;
        if entrypoint.contains('\0') || entrypoint.contains('\n') || entrypoint.contains('\r') {
            return Err(anyhow::anyhow!(
                "OCI-backed Proxmox container entrypoint contains an unsupported control character"
            ));
        }
        Ok(entrypoint)
    }

    pub fn set_data_mount_args(spec: &DataMountSpec) -> Result<Vec<String>, anyhow::Error> {
        Self::set_bind_mount_args(
            spec.vmid,
            &[BindMountSpec {
                slot: 0,
                source_path: spec.data_path.clone(),
                target_path: "/home/container".to_string(),
                read_only: false,
                container_uid: spec.container_uid,
                container_gid: spec.container_gid,
                host_uid: spec.host_data_uid,
                host_gid: spec.host_data_gid,
            }],
        )
    }

    #[allow(dead_code)]
    pub async fn set_data_mount(&self, spec: &DataMountSpec) -> Result<(), anyhow::Error> {
        Self::run(&self.pct_path, &Self::set_data_mount_args(spec)?).await?;
        Ok(())
    }

    pub fn set_bind_mount_args(
        vmid: u32,
        mounts: &[BindMountSpec],
    ) -> Result<Vec<String>, anyhow::Error> {
        let mut args = vec!["set".to_string(), vmid.to_string()];
        let mut slots = std::collections::HashSet::new();

        for mount in mounts {
            if !slots.insert(mount.slot) {
                return Err(anyhow::anyhow!(
                    "duplicate Proxmox bind mount slot mp{}",
                    mount.slot
                ));
            }
            for (label, path) in [
                ("source", mount.source_path.as_str()),
                ("target", mount.target_path.as_str()),
            ] {
                Self::validate_absolute_path(path, &format!("bind mount {label}"))?;
            }

            let idmap = format!(
                "u:{}:{}:1;g:{}:{}:1",
                mount.container_uid, mount.host_uid, mount.container_gid, mount.host_gid
            );
            let read_only = if mount.read_only { ",ro=1" } else { "" };
            args.extend([
                format!("--mp{}", mount.slot),
                format!(
                    "{},mp={},backup=0,idmap={idmap}{read_only}",
                    mount.source_path, mount.target_path,
                ),
            ]);
        }

        Ok(args)
    }

    #[allow(dead_code)]
    pub async fn set_bind_mounts(
        &self,
        vmid: u32,
        mounts: &[BindMountSpec],
    ) -> Result<(), anyhow::Error> {
        Self::run(&self.pct_path, &Self::set_bind_mount_args(vmid, mounts)?).await?;
        Ok(())
    }

    pub fn set_devices_args(
        vmid: u32,
        devices: &[DevicePassthroughSpec],
    ) -> Result<Vec<String>, anyhow::Error> {
        let mut args = vec!["set".to_string(), vmid.to_string()];
        let mut slots = std::collections::HashSet::new();

        for device in devices {
            if !slots.insert(device.slot) {
                return Err(anyhow::anyhow!(
                    "duplicate Proxmox device passthrough slot dev{}",
                    device.slot
                ));
            }
            Self::validate_absolute_path(&device.path, "device passthrough")?;
            if device.mode > 0o777 {
                return Err(anyhow::anyhow!(
                    "invalid Proxmox device passthrough mode {:o}; only permission bits are supported",
                    device.mode
                ));
            }

            let mut value = format!(
                "path={},uid={},gid={},mode={:04o}",
                device.path, device.uid, device.gid, device.mode
            );
            if device.deny_write {
                value.push_str(",deny-write=1");
            }
            args.extend([format!("--dev{}", device.slot), value]);
        }

        Ok(args)
    }

    #[allow(dead_code)]
    pub async fn set_devices(
        &self,
        vmid: u32,
        devices: &[DevicePassthroughSpec],
    ) -> Result<(), anyhow::Error> {
        if devices.is_empty() {
            return Ok(());
        }
        Self::run(&self.pct_path, &Self::set_devices_args(vmid, devices)?).await?;
        Ok(())
    }

    fn configured_slots(config: &str, prefix: &str) -> std::collections::BTreeSet<u8> {
        config
            .lines()
            .filter_map(|line| line.split_once(':').map(|(key, _)| key.trim()))
            .filter_map(|key| key.strip_prefix(prefix))
            .filter_map(|slot| slot.parse::<u8>().ok())
            .collect()
    }

    pub fn reconcile_mounts_and_devices_args(
        vmid: u32,
        current_config: &str,
        mounts: &[BindMountSpec],
        devices: &[DevicePassthroughSpec],
    ) -> Result<Vec<String>, anyhow::Error> {
        let mut args = vec!["set".to_string(), vmid.to_string()];

        let mount_args = Self::set_bind_mount_args(vmid, mounts)?;
        args.extend(mount_args.into_iter().skip(2));
        let device_args = Self::set_devices_args(vmid, devices)?;
        args.extend(device_args.into_iter().skip(2));

        let desired_mounts = mounts
            .iter()
            .map(|mount| mount.slot)
            .collect::<std::collections::BTreeSet<_>>();
        let desired_devices = devices
            .iter()
            .map(|device| device.slot)
            .collect::<std::collections::BTreeSet<_>>();

        let mut stale = Self::configured_slots(current_config, "mp")
            .difference(&desired_mounts)
            .map(|slot| format!("mp{slot}"))
            .collect::<Vec<_>>();
        stale.extend(
            Self::configured_slots(current_config, "dev")
                .difference(&desired_devices)
                .map(|slot| format!("dev{slot}")),
        );
        if !stale.is_empty() {
            args.extend(["--delete".to_string(), stale.join(",")]);
        }

        Ok(args)
    }

    pub async fn create_with_bind_mounts(
        &self,
        spec: &CreateContainerSpec,
        mounts: &[HostBindMountSpec],
    ) -> Result<ContainerOciUser, anyhow::Error> {
        self.create_with_bind_mounts_and_devices(spec, mounts, &[])
            .await
    }

    pub async fn create_with_bind_mounts_and_devices(
        &self,
        spec: &CreateContainerSpec,
        mounts: &[HostBindMountSpec],
        devices: &[HostDevicePassthroughSpec],
    ) -> Result<ContainerOciUser, anyhow::Error> {
        self.create(spec).await?;

        let result = async {
            let user = self.oci_user(spec.vmid).await?;
            self.configure_mounts_and_devices(spec.vmid, user, mounts, devices)
                .await?;
            Ok(user)
        }
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(error) => match self.destroy(spec.vmid).await {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(anyhow::anyhow!(
                    "{error:#}; additionally failed to destroy newly created container {}: {cleanup_error:#}",
                    spec.vmid
                )),
            },
        }
    }

    pub async fn configure_mounts_and_devices(
        &self,
        vmid: u32,
        user: ContainerOciUser,
        mounts: &[HostBindMountSpec],
        devices: &[HostDevicePassthroughSpec],
    ) -> Result<(), anyhow::Error> {
        let mounts = mounts
            .iter()
            .map(|mount| BindMountSpec {
                slot: mount.slot,
                source_path: mount.source_path.clone(),
                target_path: mount.target_path.clone(),
                read_only: mount.read_only,
                container_uid: user.uid,
                container_gid: user.gid,
                host_uid: mount.host_uid,
                host_gid: mount.host_gid,
            })
            .collect::<Vec<_>>();

        let devices = devices
            .iter()
            .map(|device| DevicePassthroughSpec {
                slot: device.slot,
                path: device.path.clone(),
                uid: device.uid,
                gid: device.gid,
                mode: device.mode,
                deny_write: device.deny_write,
            })
            .collect::<Vec<_>>();

        let current_config = self.config(vmid).await?;
        let args =
            Self::reconcile_mounts_and_devices_args(vmid, &current_config, &mounts, &devices)?;
        if args.len() > 2 {
            Self::run(&self.pct_path, &args).await?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn create_with_data_mount(
        &self,
        spec: &CreateContainerSpec,
        data_path: &str,
        host_data_uid: u32,
        host_data_gid: u32,
    ) -> Result<ContainerOciUser, anyhow::Error> {
        self.create_with_bind_mounts(
            spec,
            &[HostBindMountSpec {
                slot: 0,
                source_path: data_path.to_string(),
                target_path: "/home/container".to_string(),
                read_only: false,
                host_uid: host_data_uid,
                host_gid: host_data_gid,
            }],
        )
        .await
    }

    pub fn attach_args(spec: &AttachProcessSpec) -> Result<Vec<String>, anyhow::Error> {
        if spec.command.is_empty() {
            return Err(anyhow::anyhow!("attached process command cannot be empty"));
        }

        let mut args = vec![
            "-n".to_string(),
            spec.vmid.to_string(),
            "--clear-env".to_string(),
            "-u".to_string(),
            spec.uid.to_string(),
            "-g".to_string(),
            spec.gid.to_string(),
        ];

        for variable in &spec.environment {
            let Some((name, _)) = variable.split_once('=') else {
                return Err(anyhow::anyhow!(
                    "attached process environment entry must be KEY=VALUE: {variable}"
                ));
            };
            if name.is_empty() || name.contains('\0') || variable.contains('\0') {
                return Err(anyhow::anyhow!(
                    "attached process environment entry has an invalid name: {variable}"
                ));
            }
            args.extend(["-v".to_string(), variable.clone()]);
        }

        if spec.command.iter().any(|argument| argument.contains('\0')) {
            return Err(anyhow::anyhow!(
                "attached process command contains a NUL byte"
            ));
        }

        args.push("--".to_string());
        args.extend(spec.command.iter().cloned());

        Ok(args)
    }

    #[allow(dead_code)]
    pub fn spawn_attached_process(
        &self,
        spec: &AttachProcessSpec,
    ) -> Result<tokio::process::Child, anyhow::Error> {
        let args = Self::attach_args(spec)?;
        tokio::process::Command::new(&self.lxc_attach_path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to execute {}", self.lxc_attach_path.display()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Running,
    Stopped,
}

impl ContainerStatus {
    fn from_word(value: &str) -> Option<Self> {
        match value {
            "running" => Some(Self::Running),
            "stopped" => Some(Self::Stopped),
            _ => None,
        }
    }

    fn parse(value: &str) -> Result<Self, anyhow::Error> {
        let value = value.trim();
        let status = value.strip_prefix("status: ").unwrap_or(value);
        Self::from_word(status)
            .ok_or_else(|| anyhow::anyhow!("unknown pct status response: {value}"))
    }
}

#[cfg(test)]
mod tests;
