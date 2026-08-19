use crate::{
    io::{SafeSliceExt, line_buffer::LineBuffer},
    server::resources::ResourceUsageWatchExt,
};
use bollard::errors::Error::DockerResponseServerError;
use futures::StreamExt;
use rand::distr::SampleString;
use std::{
    collections::HashMap,
    path::Path,
    pin::Pin,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncWriteExt, ReadBuf};

pub mod cgroup;
pub mod host_mounts;

#[inline]
pub fn string_to_option(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn selinux_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();

    *ENABLED.get_or_init(|| Path::new("/sys/fs/selinux/enforce").exists())
}

fn is_relabelable(source: &str) -> bool {
    let source = Path::new(source);

    !source.starts_with("/dev") && !source.starts_with("/proc") && !source.starts_with("/sys")
}

fn split_selinux_binds(
    mounts: Vec<bollard::models::Mount>,
) -> (Vec<bollard::models::Mount>, Option<Vec<String>>) {
    split_binds_for_relabel(mounts, selinux_enabled())
}

fn split_binds_for_relabel(
    mounts: Vec<bollard::models::Mount>,
    relabel: bool,
) -> (Vec<bollard::models::Mount>, Option<Vec<String>>) {
    if !relabel {
        return (mounts, None);
    }

    let mut binds = Vec::new();
    let mut structured = Vec::new();

    for mount in mounts {
        match (mount.source.as_deref(), mount.target.as_deref()) {
            (Some(source), Some(target)) if is_relabelable(source) => {
                let mode = if mount.read_only.unwrap_or(false) {
                    "ro"
                } else {
                    "rw"
                };

                binds.push(format!("{source}:{target}:{mode},z"));
            }
            _ => structured.push(mount),
        }
    }

    (structured, (!binds.is_empty()).then_some(binds))
}

#[cfg(target_os = "linux")]
fn nofile_ceiling(requested: u64) -> u64 {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let current = getrlimit(Resource::Nofile);
    let current_hard = current.maximum.unwrap_or(u64::MAX);
    if requested <= current_hard {
        return requested;
    }

    let probe = Rlimit {
        current: current.current,
        maximum: Some(requested),
    };

    match setrlimit(Resource::Nofile, probe) {
        Ok(()) => {
            setrlimit(Resource::Nofile, current).ok();

            requested
        }
        Err(_) => current_hard,
    }
}

#[cfg(not(target_os = "linux"))]
fn nofile_ceiling(requested: u64) -> u64 {
    requested
}

fn convert_ulimits(
    config: &crate::config::Config,
) -> Option<Vec<bollard::models::ResourcesUlimits>> {
    static WARNED_CLAMP: OnceLock<()> = OnceLock::new();

    let config = config.load();
    if config.docker.container_ulimits.is_empty() {
        return None;
    }

    Some(
        config
            .docker
            .container_ulimits
            .iter()
            .map(|ulimit| {
                let (mut soft, mut hard) = (ulimit.soft, ulimit.hard);
                if ulimit.name == "nofile" && hard > 0 {
                    let ceiling = nofile_ceiling(hard as u64) as i64;
                    if ceiling < hard {
                        if WARNED_CLAMP.set(()).is_ok() {
                            tracing::warn!(
                                "configured nofile ulimit {} exceeds what this host can set, clamping to {}",
                                hard,
                                ceiling
                            );
                        }

                        hard = ceiling;
                        soft = soft.min(ceiling);
                    }
                }

                bollard::models::ResourcesUlimits {
                    name: Some(ulimit.name.clone()),
                    soft: Some(soft),
                    hard: Some(hard),
                }
            })
            .collect(),
    )
}

fn convert_sysctls(
    config: &crate::config::Config,
    network_mode: &str,
) -> Option<HashMap<String, String>> {
    let config = config.load();
    if config.docker.container_sysctls.is_empty() {
        return None;
    }

    let foreign_netns = network_mode == "host" || network_mode.starts_with("container:");
    let sysctls: HashMap<String, String> = config
        .docker
        .container_sysctls
        .iter()
        .filter(|(key, _)| {
            if key.starts_with("net.") && foreign_netns {
                tracing::debug!(
                    sysctl = %key,
                    network_mode = %network_mode,
                    "skipping net sysctl, container shares a foreign network namespace"
                );

                return false;
            }

            true
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    if sysctls.is_empty() {
        None
    } else {
        Some(sysctls)
    }
}

enum HostBinding {
    Wildcard,
    Address(std::net::IpAddr),
    Unbound,
}

impl HostBinding {
    fn resolve(network: &crate::config::DockerNetwork, ip: std::net::IpAddr) -> Self {
        if network.disable_interface_binding {
            return Self::Wildcard;
        }

        if ip == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            if network.ispn {
                return Self::Unbound;
            }

            return match network.interface.parse::<std::net::IpAddr>() {
                Ok(interface) if interface.is_unspecified() => Self::Wildcard,
                Ok(interface) => Self::Address(interface),
                Err(_) => Self::Wildcard,
            };
        }

        if ip.is_unspecified() {
            return Self::Wildcard;
        }

        Self::Address(ip)
    }

    fn collides_with(&self, host_ip: Option<&str>) -> bool {
        let address = match self {
            Self::Unbound => return false,
            Self::Wildcard => return true,
            Self::Address(address) => address,
        };

        match host_ip.and_then(|host_ip| host_ip.parse::<std::net::IpAddr>().ok()) {
            Some(host_ip) => host_ip.is_unspecified() || host_ip == *address,
            None => true,
        }
    }
}

fn container_server(names: Option<&[String]>) -> Option<uuid::Uuid> {
    for name in names.unwrap_or_default() {
        let name = name.trim_start_matches('/');

        if let Ok(uuid) = name.parse::<uuid::Uuid>() {
            return Some(uuid);
        }

        if let Some((_, uuid)) = name.rsplit_once('.')
            && let Ok(uuid) = uuid.parse::<uuid::Uuid>()
        {
            return Some(uuid);
        }
    }

    None
}

#[async_trait::async_trait]
trait DockerServerConfigurationExt {
    async fn convert_mounts(
        &self,
        config: &crate::config::Config,
        filesystem: &crate::server::filesystem::Filesystem,
        host_mounts: Option<&host_mounts::HostMountTable>,
    ) -> Vec<bollard::plugin::Mount>;

    #[cfg(unix)]
    fn convert_devices(&self) -> Vec<bollard::models::DeviceMapping>;

    fn convert_allocations_bindings(&self) -> bollard::models::PortMap;
    fn convert_allocations_docker_bindings(
        &self,
        config: &crate::config::Config,
    ) -> bollard::models::PortMap;
    fn convert_allocations_exposed(&self) -> Vec<String>;

    async fn container_config(
        &self,
        config: &crate::config::Config,
        client: &bollard::Docker,
        filesystem: &crate::server::filesystem::Filesystem,
        host_mounts: Option<&host_mounts::HostMountTable>,
    ) -> Result<bollard::plugin::ContainerCreateBody, anyhow::Error>;
    fn container_update_config(
        &self,
        config: &crate::config::Config,
    ) -> bollard::plugin::ContainerUpdateBody;

    fn installer_resources(&self, config: &crate::config::Config) -> bollard::models::Resources;
}

#[async_trait::async_trait]
impl DockerServerConfigurationExt for crate::server::configuration::ServerConfiguration {
    async fn convert_mounts(
        &self,
        config: &crate::config::Config,
        filesystem: &crate::server::filesystem::Filesystem,
        host_mounts: Option<&host_mounts::HostMountTable>,
    ) -> Vec<bollard::models::Mount> {
        self.mounts(config, filesystem)
            .await
            .into_iter()
            .map(|mount| bollard::models::Mount {
                typ: Some(bollard::plugin::MountType::BIND),
                target: Some(mount.target.into()),
                source: Some(host_mounts::translate_source(host_mounts, &mount.source)),
                read_only: Some(mount.read_only),
                ..Default::default()
            })
            .collect()
    }

    #[cfg(unix)]
    fn convert_devices(&self) -> Vec<bollard::models::DeviceMapping> {
        let mut devices = Vec::new();

        if self.container.kvm_passthrough_enabled {
            devices.push(bollard::models::DeviceMapping {
                path_on_host: Some("/dev/kvm".into()),
                path_in_container: Some("/dev/kvm".into()),
                cgroup_permissions: Some("rwm".into()),
            });
        }

        devices
    }

    fn convert_allocations_bindings(&self) -> bollard::models::PortMap {
        let mut map = HashMap::new();

        for (ip, ports) in &self.allocations.mappings {
            for port in ports {
                let binding = bollard::models::PortBinding {
                    host_ip: Some(ip.to_string()),
                    host_port: Some(port.to_string()),
                };

                if let Some(tcp_bindings) = map
                    .entry(format!("{port}/tcp"))
                    .or_insert_with(|| Some(Vec::new()))
                {
                    tcp_bindings.push(binding.clone());
                }

                if let Some(udp_bindings) = map
                    .entry(format!("{port}/udp"))
                    .or_insert_with(|| Some(Vec::new()))
                {
                    udp_bindings.push(binding);
                }
            }
        }

        map
    }

    fn convert_allocations_docker_bindings(
        &self,
        config: &crate::config::Config,
    ) -> bollard::models::PortMap {
        let config = config.load();
        let iface = &config.docker.network.interface;
        let mut map = self.convert_allocations_bindings();

        for binds in map.values_mut().flatten() {
            let mut i = 0;
            while i < binds.len() {
                let Some(binding) = binds.get_mut(i) else {
                    break;
                };
                if config.docker.network.disable_interface_binding {
                    binding.host_ip = None;
                }

                if binding.host_ip.as_deref() == Some("127.0.0.1") {
                    if config.docker.network.ispn {
                        binds.remove(i);

                        continue;
                    } else {
                        binding.host_ip = Some(iface.clone());
                    }
                }

                i += 1;
            }
        }

        map
    }

    fn convert_allocations_exposed(&self) -> Vec<String> {
        let mut exposed = Vec::new();

        for ports in self.allocations.mappings.values() {
            for port in ports {
                exposed.push(format!("{port}/tcp"));
                exposed.push(format!("{port}/udp"));
            }
        }

        exposed
    }

    async fn container_config(
        &self,
        config: &crate::config::Config,
        client: &bollard::Docker,
        filesystem: &crate::server::filesystem::Filesystem,
        host_mounts: Option<&host_mounts::HostMountTable>,
    ) -> Result<bollard::plugin::ContainerCreateBody, anyhow::Error> {
        let mut labels = self.labels.clone();
        labels.insert("Service".into(), config.load().app_name.clone());
        labels.insert("ContainerType".into(), "server_process".into());

        let network_mode = if self.allocations.force_outgoing_ip
            && let Some(default) = &self.allocations.default
        {
            let network_name = format!("ip-{}", default.ip.replace('.', "-").replace(':', "--"));

            if client.inspect_network(&network_name, None).await.is_err()
                && let Err(err) = client
                    .create_network(bollard::plugin::NetworkCreateRequest {
                        name: network_name.to_string(),
                        driver: Some("bridge".to_string()),
                        enable_ipv6: Some(false),
                        internal: Some(false),
                        attachable: Some(false),
                        ingress: Some(false),
                        options: Some(HashMap::from([
                            ("encryption".to_string(), "false".to_string()),
                            (
                                "com.docker.network.bridge.default_bridge".to_string(),
                                "false".to_string(),
                            ),
                            (
                                "com.docker.network.host_ipv4".to_string(),
                                default.ip.to_string(),
                            ),
                            (
                                "com.docker.network.driver.mtu".to_string(),
                                config.load().docker.network.network_mtu.to_string(),
                            ),
                        ])),
                        ..Default::default()
                    })
                    .await
            {
                tracing::error!(
                    server = %self.uuid,
                    "failed to create container network {}: {}",
                    network_name,
                    err
                );
            }

            network_name
        } else {
            config.load().docker.network.mode.clone()
        };

        let resources = self.convert_container_resources(config);
        let sysctls = convert_sysctls(config, &network_mode);

        if resources.blkio_weight.is_some() && !cgroup::io_weight_effective() {
            static WARNED_IO_WEIGHT: OnceLock<()> = OnceLock::new();

            if WARNED_IO_WEIGHT.set(()).is_ok() {
                tracing::warn!(
                    server = %self.uuid,
                    "io weights are configured, but no io scheduler on this host enforces them (needs bfq or an iocost model) - they will have no effect"
                );
            }
        }

        let mut security_opt = vec!["no-new-privileges".to_string()];
        if config.load().docker.container_apply_seccomp {
            security_opt.push(
                crate::server::configuration::seccomp::Seccomp::default()
                    .remove_names(
                        &self.container.seccomp.remove_allowed,
                        crate::server::configuration::seccomp::Action::Allow,
                    )
                    .to_string()?,
            );
        }
        if let Some(profile) = string_to_option(&config.load().docker.container_apparmor_profile) {
            security_opt.push(format!("apparmor={profile}"));
        }

        let (mounts, binds) =
            split_selinux_binds(self.convert_mounts(config, filesystem, host_mounts).await);

        Ok(bollard::plugin::ContainerCreateBody {
            exposed_ports: Some(self.convert_allocations_exposed()),
            host_config: Some(bollard::plugin::HostConfig {
                memory: resources.memory,
                memory_reservation: resources.memory_reservation,
                memory_swap: resources.memory_swap,
                cpu_quota: resources.cpu_quota,
                cpu_period: resources.cpu_period,
                cpuset_cpus: resources.cpuset_cpus,
                cpuset_mems: resources.cpuset_mems,
                pids_limit: resources.pids_limit,
                blkio_weight: resources.blkio_weight,
                oom_kill_disable: resources.oom_kill_disable,
                shm_size: match config.load().docker.shm_size.as_bytes() {
                    0 => None,
                    size => Some(size as i64),
                },

                port_bindings: Some(self.convert_allocations_docker_bindings(config)),
                mounts: Some(mounts),
                binds,
                #[cfg(unix)]
                devices: Some(self.convert_devices()),
                network_mode: Some(network_mode),
                dns: Some(config.load().docker.network.dns.clone()),
                dns_options: Some(config.load().docker.network.dns_options.clone()),
                tmpfs: Some(HashMap::from([(
                    "/tmp".to_string(),
                    format!(
                        "rw,exec,nosuid,size={}M",
                        config.load().docker.tmpfs_size.as_mib()
                    ),
                )])),
                log_config: Some(bollard::plugin::HostConfigLogConfig {
                    typ: Some(config.load().docker.log_config.r#type.clone()),
                    config: Some(
                        config
                            .load()
                            .docker
                            .log_config
                            .config
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    ),
                }),
                security_opt: Some(security_opt),
                ulimits: convert_ulimits(config),
                sysctls,
                cap_drop: Some(vec![
                    "setpcap".to_string(),
                    "mknod".to_string(),
                    "audit_write".to_string(),
                    "net_raw".to_string(),
                    "dac_override".to_string(),
                    "fowner".to_string(),
                    "fsetid".to_string(),
                    "net_bind_service".to_string(),
                    "sys_chroot".to_string(),
                    "setfcap".to_string(),
                    "sys_ptrace".to_string(),
                ]),
                userns_mode: string_to_option(&config.load().docker.userns_mode),
                readonly_rootfs: Some(true),
                ..Default::default()
            }),
            hostname: Some(self.uuid.to_string()),
            domainname: string_to_option(&config.load().docker.domainname),
            entrypoint: self.entrypoint.clone(),
            image: Some(self.container.image.trim_end_matches('~').to_string()),
            env: Some(self.environment(config)),
            user: Some(if config.load().system.user.rootless.enabled {
                let config = config.load();

                format!(
                    "{}:{}",
                    config.system.user.rootless.container_uid,
                    config.system.user.rootless.container_gid
                )
            } else {
                let config = config.load();

                format!("{}:{}", config.system.user.uid, config.system.user.gid)
            }),
            labels: Some(labels),
            attach_stdin: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            open_stdin: Some(true),
            tty: Some(true),
            ..Default::default()
        })
    }

    fn container_update_config(
        &self,
        config: &crate::config::Config,
    ) -> bollard::plugin::ContainerUpdateBody {
        let resources = self.convert_container_resources(config);

        bollard::plugin::ContainerUpdateBody {
            memory: resources.memory,
            memory_reservation: resources.memory_reservation,
            memory_swap: resources.memory_swap,
            cpu_quota: resources.cpu_quota,
            cpu_period: resources.cpu_period,
            cpuset_cpus: resources.cpuset_cpus,
            cpuset_mems: resources.cpuset_mems,
            pids_limit: resources.pids_limit,
            blkio_weight: resources.blkio_weight,
            oom_kill_disable: resources.oom_kill_disable,
            ..Default::default()
        }
    }

    fn installer_resources(&self, config: &crate::config::Config) -> bollard::models::Resources {
        let mut resources = self.convert_container_resources(config);

        let config = config.load();
        let installer_limits = &config.docker.installer_limits;

        if resources
            .memory_reservation
            .is_some_and(|m| m > 0 && m < installer_limits.memory.as_bytes() as i64)
        {
            resources.memory = None;
            resources.memory_reservation = Some(installer_limits.memory.as_bytes() as i64);
            resources.memory_swap = None;
        }

        let floor = installer_limits.cpu as i64 * config.docker.cpu_period_us() / 100;
        if resources.cpu_quota.is_some_and(|c| c > 0 && c < floor) {
            resources.cpu_quota = Some(floor);
        }

        resources
    }
}

const TRANSIENT_JSON_ATTEMPTS: u32 = 4;
const TRANSIENT_JSON_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

#[inline]
fn is_transient_json_error(err: &bollard::errors::Error) -> bool {
    matches!(
        err,
        bollard::errors::Error::JsonDataError { .. }
            | bollard::errors::Error::JsonSerdeError { .. }
    )
}

#[async_trait::async_trait]
trait DockerCompatJsonExt {
    async fn list_containers_settled(
        &self,
        options: Option<bollard::query_parameters::ListContainersOptions>,
    ) -> Result<Vec<bollard::models::ContainerSummary>, bollard::errors::Error>;

    async fn inspect_container_settled(
        &self,
        container_id: &str,
        options: Option<bollard::query_parameters::InspectContainerOptions>,
    ) -> Result<bollard::models::ContainerInspectResponse, bollard::errors::Error>;
}

#[async_trait::async_trait]
impl DockerCompatJsonExt for bollard::Docker {
    async fn list_containers_settled(
        &self,
        options: Option<bollard::query_parameters::ListContainersOptions>,
    ) -> Result<Vec<bollard::models::ContainerSummary>, bollard::errors::Error> {
        for attempt in 1..TRANSIENT_JSON_ATTEMPTS {
            match self.list_containers(options.clone()).await {
                Err(err) if is_transient_json_error(&err) => {
                    tracing::debug!(
                        "container list returned an unparseable state, retrying ({}/{}): {}",
                        attempt,
                        TRANSIENT_JSON_ATTEMPTS,
                        err
                    );

                    tokio::time::sleep(TRANSIENT_JSON_BACKOFF * attempt).await;
                }
                result => return result,
            }
        }

        self.list_containers(options).await
    }

    async fn inspect_container_settled(
        &self,
        container_id: &str,
        options: Option<bollard::query_parameters::InspectContainerOptions>,
    ) -> Result<bollard::models::ContainerInspectResponse, bollard::errors::Error> {
        for attempt in 1..TRANSIENT_JSON_ATTEMPTS {
            match self.inspect_container(container_id, options.clone()).await {
                Err(err) if is_transient_json_error(&err) => {
                    tracing::debug!(
                        container = %container_id,
                        "container inspect returned an unparseable state, retrying ({}/{}): {}",
                        attempt,
                        TRANSIENT_JSON_ATTEMPTS,
                        err
                    );

                    tokio::time::sleep(TRANSIENT_JSON_BACKOFF * attempt).await;
                }
                result => return result,
            }
        }

        self.inspect_container(container_id, options).await
    }
}

#[async_trait::async_trait]
trait DockerRemoveExt {
    async fn remove_container_forgiving(
        &self,
        container_id: &str,
    ) -> Result<(), bollard::errors::Error>;
}

#[async_trait::async_trait]
impl DockerRemoveExt for bollard::Docker {
    async fn remove_container_forgiving(
        &self,
        container_id: &str,
    ) -> Result<(), bollard::errors::Error> {
        let result = self
            .remove_container(
                container_id,
                Some(bollard::query_parameters::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(()),
            Err(err) => match self.inspect_container_settled(container_id, None).await {
                Err(DockerResponseServerError {
                    status_code: 404, ..
                }) => {
                    tracing::debug!(
                        container = %container_id,
                        "container removal reported an error but the container is gone, treating as removed: {}",
                        err
                    );

                    Ok(())
                }
                _ => Err(err),
            },
        }
    }
}

#[async_trait::async_trait]
trait DockerCfsBurstExt {
    async fn write_cfs_burst(&self, container_id: &str, multiple: f64);
    async fn apply_cfs_burst(&self, container_id: &str, config: &crate::config::Config);
    async fn clear_cfs_burst(&self, container_id: &str);
}

#[async_trait::async_trait]
impl DockerCfsBurstExt for bollard::Docker {
    async fn write_cfs_burst(&self, container_id: &str, multiple: f64) {
        for attempt in 0..2 {
            let inspect = match self.inspect_container_settled(container_id, None).await {
                Ok(inspect) => inspect,
                Err(err) => {
                    tracing::debug!(
                        container = %container_id,
                        "failed to inspect container for cfs burst: {}",
                        err
                    );

                    return;
                }
            };

            let Some(pid) = inspect
                .state
                .and_then(|state| state.pid)
                .filter(|pid| *pid > 0)
            else {
                return;
            };

            match cgroup::CpuCgroup::write_process_burst(pid, multiple) {
                cgroup::BurstOutcome::CgroupGone if attempt == 0 => continue,
                _ => return,
            }
        }
    }

    async fn apply_cfs_burst(&self, container_id: &str, config: &crate::config::Config) {
        let burst = config.load().docker.cfs_burst;

        if burst.enabled {
            self.write_cfs_burst(container_id, burst.multiple).await;
        }
    }

    async fn clear_cfs_burst(&self, container_id: &str) {
        self.write_cfs_burst(container_id, 0.0).await;
    }
}

pub struct DockerExecutor {
    docker: Arc<bollard::Docker>,
    app_config: Arc<crate::config::Config>,
    stats_sampler: Arc<cgroup::StatsSampler>,
    host_mounts: OnceLock<Option<host_mounts::HostMountTable>>,
    host_gateway: OnceLock<Option<std::net::IpAddr>>,
}

impl DockerExecutor {
    pub fn new(docker: Arc<bollard::Docker>, app_config: Arc<crate::config::Config>) -> Self {
        Self {
            docker,
            app_config,
            stats_sampler: Arc::new(cgroup::StatsSampler::default()),
            host_mounts: OnceLock::new(),
            host_gateway: OnceLock::new(),
        }
    }

    #[inline]
    fn host_mounts(&self) -> Option<&host_mounts::HostMountTable> {
        self.host_mounts.get().and_then(Option::as_ref)
    }

    /// Returns the host gateway address to route through when wings itself is
    /// running inside a container. `None` means wings is running on the host (or
    /// the gateway could not be determined), in which case the game server's
    /// internal docker network IP is reachable directly.
    #[inline]
    fn host_gateway(&self) -> Option<std::net::IpAddr> {
        *self.host_gateway.get_or_init(Self::detect_host_gateway)
    }

    #[cfg(target_os = "linux")]
    fn detect_host_gateway() -> Option<std::net::IpAddr> {
        // Only reroute when wings is running inside a container. On the host the
        // default route points at the LAN router, which must never receive game
        // server traffic.
        if !Path::new("/.dockerenv").exists() {
            return None;
        }

        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in routes.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let _iface = fields.next()?;
            let destination = fields.next()?;
            let gateway = fields.next()?;

            // The default route has a zero destination and a non-zero gateway.
            // Both fields are little-endian hex of the raw IPv4 address.
            if destination == "00000000" && gateway != "00000000" {
                let raw = u32::from_str_radix(gateway, 16).ok()?;
                return Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    raw.to_le_bytes(),
                )));
            }
        }

        None
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_host_gateway() -> Option<std::net::IpAddr> {
        None
    }

    async fn image_exists(&self, image_name: &str) -> bool {
        self.docker
            .list_images(Some(bollard::query_parameters::ListImagesOptions {
                all: true,
                filters: Some(HashMap::from([(
                    "reference".to_string(),
                    vec![image_name.to_string()],
                )])),
                ..Default::default()
            }))
            .await
            .is_ok_and(|images| !images.is_empty())
    }

    async fn pull_image(
        &self,
        image: &str,
        server: &super::super::Server,
        quiet: bool,
    ) -> Result<(), anyhow::Error> {
        if image.ends_with('~') {
            return Ok(());
        }

        let (image_name, tag) = match image.rsplit_once(':') {
            Some((name, tag)) if !tag.is_empty() => {
                let colon_is_tag_sep = image.rfind('/').is_none_or(|slash| slash < name.len());
                if colon_is_tag_sep {
                    (name, tag)
                } else {
                    (image, "latest")
                }
            }
            _ => (image, "latest"),
        };

        let pull_cache = {
            type InnerMap = HashMap<
                compact_str::CompactString,
                Arc<tokio::sync::Mutex<Option<std::time::Instant>>>,
            >;
            static IMAGE_PULL_CACHE: OnceLock<Arc<parking_lot::Mutex<InnerMap>>> = OnceLock::new();

            IMAGE_PULL_CACHE.get_or_init(|| {
                let cache = Arc::new(parking_lot::Mutex::new(HashMap::new()));

                tokio::spawn({
                    let cache = Arc::clone(&cache);
                    let config = Arc::clone(&self.app_config);

                    async move {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_secs(60)).await;

                            let mut cache = cache.lock();
                            let duration = config.load().docker.registry_image_fetch_cache.duration;
                            cache.retain(
                                |_,
                                 timestamp: &mut Arc<
                                    tokio::sync::Mutex<Option<std::time::Instant>>,
                                >| {
                                    match timestamp.try_lock() {
                                        Ok(timestamp) => timestamp
                                            .is_some_and(|t| t.elapsed().as_secs() < duration),
                                        Err(_) => true,
                                    }
                                },
                            );
                        }
                    }
                });

                cache
            })
        };

        let cache_config = self.app_config.load().docker.registry_image_fetch_cache;

        let mut registry_auth = None;
        for (registry, config) in self.app_config.load().docker.registries.iter() {
            if image.starts_with(registry.as_str()) {
                registry_auth = Some(bollard::auth::DockerCredentials {
                    username: Some(config.username.clone()),
                    password: Some(config.password.clone()),
                    serveraddress: Some(registry.clone()),
                    ..Default::default()
                });
                break;
            }
        }

        if cache_config.background_refresh && self.image_exists(image_name).await {
            let entry = {
                let mut cache = pull_cache.lock();
                Arc::clone(cache.entry(image.into()).or_default())
            };

            if let Ok(mut last_pull) = entry.try_lock_owned() {
                let stale = !cache_config.enabled
                    || last_pull.is_none_or(|pulled_at| {
                        pulled_at.elapsed().as_secs() >= cache_config.duration
                    });

                if stale {
                    let docker = Arc::clone(&self.docker);
                    let image_name = image_name.to_string();
                    let tag = tag.to_string();

                    tokio::spawn(async move {
                        let mut stream = docker.create_image(
                            Some(bollard::query_parameters::CreateImageOptions {
                                from_image: Some(image_name.clone()),
                                tag: Some(tag),
                                ..Default::default()
                            }),
                            None,
                            registry_auth,
                        );

                        while let Some(status) = stream.next().await {
                            if let Err(err) = status {
                                tracing::debug!(
                                    image = %image_name,
                                    "background image refresh failed: {}",
                                    err
                                );

                                return;
                            }
                        }

                        *last_pull = Some(std::time::Instant::now());

                        tracing::debug!(image = %image_name, "background image refresh finished");
                    });
                }
            }

            tracing::debug!(
                server = %server.uuid,
                image = %image_name,
                "image exists locally, starting from it and refreshing in the background"
            );

            return Ok(());
        }

        let mut last_pull = if cache_config.enabled {
            let entry = {
                let mut cache = pull_cache.lock();
                Arc::clone(cache.entry(image.into()).or_default())
            };

            Some(entry.lock_owned().await)
        } else {
            None
        };

        if let Some(guard) = &last_pull
            && let Some(pulled_at) = **guard
            && pulled_at.elapsed().as_secs() < cache_config.duration
            && self.image_exists(image_name).await
        {
            tracing::debug!(
                server = %server.uuid,
                image = %image_name,
                "image pull skipped, cached as recently pulled"
            );

            return Ok(());
        }

        if !quiet {
            server.log_daemon_with_prelude(
                "Pulling Docker container image, this could take a few minutes to complete...",
            );
        }

        let mut stream = self.docker.create_image(
            Some(bollard::query_parameters::CreateImageOptions {
                from_image: Some(image_name.to_string()),
                tag: Some(tag.to_string()),
                ..Default::default()
            }),
            None,
            registry_auth,
        );

        while let Some(status) = stream.next().await {
            match status {
                Ok(info) => {
                    if let Some(id) = &info.id {
                        match info.status.as_deref().map(str::to_lowercase).as_deref() {
                            Some("downloading") => {
                                if let Some(ref detail) = info.progress_detail {
                                    server
                                        .websocket
                                        .send(
                                            super::super::websocket::WebsocketMessage::builder(
                                                super::super::websocket::WebsocketEvent::ServerImagePullProgress,
                                            )
                                            .arg(id.clone())
                                            .structured_arg(crate::models::PullProgress {
                                                status: crate::models::PullProgressStatus::Pulling,
                                                bytes_processed: detail.current.unwrap_or_default(),
                                                bytes_total: detail.total.unwrap_or_default(),
                                            })
                                            .build(),
                                        )
                                        .ok();
                                }
                            }
                            Some("extracting") => {
                                if let Some(ref detail) = info.progress_detail {
                                    server
                                        .websocket
                                        .send(
                                            super::super::websocket::WebsocketMessage::builder(
                                                super::super::websocket::WebsocketEvent::ServerImagePullProgress,
                                            )
                                            .arg(id.clone())
                                            .structured_arg(crate::models::PullProgress {
                                                status: crate::models::PullProgressStatus::Extracting,
                                                bytes_processed: detail.current.unwrap_or_default(),
                                                bytes_total: detail.total.unwrap_or_default(),
                                            })
                                            .build(),
                                        )
                                        .ok();
                                }
                            }
                            Some("download complete") | Some("pull complete") => {
                                server
                                    .websocket
                                    .send(
                                        super::super::websocket::WebsocketMessage::builder(
                                            super::super::websocket::WebsocketEvent::ServerImagePullCompleted,
                                        )
                                        .arg(id.clone())
                                        .build(),
                                    )
                                    .ok();
                            }
                            _ => {}
                        }
                    }

                    if !quiet && let Some(status_str) = info.status {
                        if let Some(ref detail) = info.progress_detail {
                            server.log_daemon_install(
                                format!(
                                    "{status_str} {} of {}",
                                    crate::utils::draw_progress_bar(
                                        50usize.saturating_sub(status_str.len()),
                                        detail.current.unwrap_or_default() as f64,
                                        detail.total.unwrap_or_default() as f64,
                                    ),
                                    human_bytes::human_bytes(
                                        detail.total.unwrap_or_default() as f64
                                    ),
                                )
                                .into(),
                            );
                        } else {
                            server.log_daemon_install(status_str.into());
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        image = %image_name,
                        "failed to pull image: {:?}",
                        err
                    );

                    if !quiet {
                        server.log_daemon_error(&format!("failed to pull image: {err}"));
                    }

                    if !self.image_exists(image_name).await {
                        return Err(err.into());
                    }

                    tracing::warn!(
                        server = %server.uuid,
                        image = %image_name,
                        "image already exists locally, ignoring pull error"
                    );
                }
            }
        }

        if let Some(guard) = &mut last_pull {
            **guard = Some(std::time::Instant::now());
        }

        if !quiet {
            server.log_daemon_with_prelude("Finished pulling Docker container image");
        }

        Ok(())
    }
}

struct LogsReader {
    stream: futures::stream::BoxStream<'static, Result<Vec<u8>, std::io::Error>>,
    buffer: Vec<u8>,
    pos: usize,
}

impl tokio::io::AsyncRead for LogsReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.pos < self.buffer.len() {
                let n = buf.remaining().min(self.buffer.len() - self.pos);
                let buffer_slice = match self.buffer.get_slice(self.pos..self.pos + n) {
                    Ok(slice) => slice,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                buf.put_slice(buffer_slice);
                self.pos += n;

                return Poll::Ready(Ok(()));
            }

            self.buffer.clear();
            self.pos = 0;

            match self.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => self.buffer = chunk,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct DockerProcessHandle {
    container_id: String,
    docker: Arc<bollard::Docker>,
    server: Weak<super::super::InnerServer>,
    app_config: Arc<crate::config::Config>,

    resource_usage: tokio::sync::watch::Sender<super::super::resources::ResourceUsage>,
    publish_resource_usage: bool,
    cfs_lock: Arc<tokio::sync::Mutex<()>>,
    boosted_limit_percent: Arc<AtomicU32>,
    stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdout_ratelimited_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
    stdout_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,

    state_task: tokio::task::JoinHandle<()>,
    stats_task: tokio::task::JoinHandle<()>,
    stdin_task: tokio::task::JoinHandle<()>,
}

impl DockerProcessHandle {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        container_id: String,
        docker: Arc<bollard::Docker>,
        server: &super::super::Server,
        app_config: Arc<crate::config::Config>,
        stats_sampler: Arc<cgroup::StatsSampler>,
        status_tx: tokio::sync::mpsc::Sender<super::ProcessStatus>,
        publish_resource_usage: bool,
        attach_stdin: bool,
    ) -> Result<Self, anyhow::Error> {
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(150);
        let (stdout_ratelimited_tx, stdout_ratelimited_rx) =
            tokio::sync::broadcast::channel::<Arc<compact_str::CompactString>>(
                app_config.load().system.websocket_log_count,
            );
        let (stdout_tx, stdout_rx) = tokio::sync::broadcast::channel::<
            Arc<compact_str::CompactString>,
        >(app_config.load().system.websocket_log_count * 2);

        let resource_usage = server.resource_usage.clone();
        if publish_resource_usage {
            let disk_bytes = server.filesystem.limiter_usage().await;
            resource_usage.send_modify(|usage| {
                usage.wipe(server.state.get_state());
                usage.disk_bytes = disk_bytes;
            });
        }

        let mut attach = docker
            .attach_container(
                &container_id,
                Some(bollard::query_parameters::AttachContainerOptions {
                    stdin: attach_stdin,
                    stdout: true,
                    stderr: true,
                    stream: true,
                    ..Default::default()
                }),
            )
            .await?;

        let stdin_task = tokio::spawn(async move {
            if !attach_stdin {
                return;
            }

            while let Some(data) = stdin_rx.recv().await {
                if let Err(err) = attach.input.write_all(&data).await {
                    tracing::error!(error = %err, "failed to write to container stdin");
                }
            }
        });

        // intentionally not aborted on drop so that it can finish writing any remaining logs to the channel
        tokio::spawn({
            let server = server.clone();
            let app_config = Arc::clone(&app_config);

            async move {
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

                while let Some(Ok(data)) = attach.output.next().await {
                    line_buffer.extend(&data.into_bytes());

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
        });

        let stats_docker = Arc::clone(&docker);
        let stats_id = container_id.clone();
        let stats_usage = resource_usage.clone();
        let stats_server = server.clone();

        let boosted_limit_percent = Arc::new(AtomicU32::new(0));

        let stats_task = tokio::spawn(async move {
            if !publish_resource_usage {
                return;
            }

            enum StatsSource {
                Unresolved,
                Cgroup(cgroup::SampleReceiver),
                Api,
            }

            let mut source = StatsSource::Unresolved;
            let mut prev_cpu_total = 0;
            let mut prev_at = None;

            let mut tick = tokio::time::interval_at(
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            );
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                let received = match &mut source {
                    StatsSource::Cgroup(samples) => {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            samples.recv(),
                        )
                        .await
                        {
                            Ok(Some(result)) => Some(result),
                            Ok(None) | Err(_) => {
                                tracing::debug!(
                                    server = %stats_server.uuid,
                                    "cgroup stats sampler stopped delivering, using the stats api"
                                );
                                source = StatsSource::Api;

                                continue;
                            }
                        }
                    }
                    _ => {
                        tick.tick().await;

                        None
                    }
                };

                let disk_bytes = stats_server.filesystem.limiter_usage().await;

                if stats_server.state.get_state() == super::super::state::ServerState::Offline {
                    stats_usage.send_modify(|usage| {
                        usage.disk_bytes = disk_bytes;
                        usage.state = stats_server.state.get_state();
                    });
                    source = StatsSource::Unresolved;
                    prev_at = None;

                    continue;
                }

                if matches!(source, StatsSource::Unresolved) {
                    source = match stats_docker
                        .inspect_container_settled(&stats_id, None)
                        .await
                    {
                        Ok(inspect) => {
                            match inspect
                                .state
                                .and_then(|state| state.pid)
                                .filter(|pid| *pid > 0)
                            {
                                Some(pid) => match cgroup::StatFiles::resolve(pid) {
                                    Some(files) => {
                                        StatsSource::Cgroup(stats_sampler.register(files))
                                    }
                                    None => {
                                        tracing::debug!(
                                            server = %stats_server.uuid,
                                            "container cgroup not resolvable from here, using the stats api"
                                        );

                                        StatsSource::Api
                                    }
                                },
                                None => continue,
                            }
                        }
                        Err(_) => continue,
                    };

                    if matches!(source, StatsSource::Cgroup(_)) {
                        continue;
                    }
                }

                let sample = match received {
                    Some(Ok(sample)) => sample,
                    Some(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                        source = StatsSource::Unresolved;

                        continue;
                    }
                    Some(Err(err)) => {
                        tracing::debug!(
                            server = %stats_server.uuid,
                            "failed to read container cgroup stats, using the stats api: {}",
                            err
                        );
                        source = StatsSource::Api;

                        continue;
                    }
                    None => {
                        let mut stream = stats_docker.stats(
                            &stats_id,
                            Some(bollard::query_parameters::StatsOptions {
                                stream: false,
                                one_shot: true,
                            }),
                        );

                        let stats = match stream.next().await {
                            Some(Ok(stats)) => stats,
                            Some(Err(err)) => {
                                tracing::warn!(
                                    server = %stats_server.uuid,
                                    "failed to get container stats: {:?}",
                                    err
                                );
                                continue;
                            }
                            None => break,
                        };

                        let mut memory_bytes = stats
                            .memory_stats
                            .as_ref()
                            .and_then(|memory| memory.usage)
                            .unwrap_or(0);
                        if let Some(stats) = stats
                            .memory_stats
                            .as_ref()
                            .and_then(|memory| memory.stats.as_ref())
                            && let Some(&inactive_file) = stats
                                .get("total_inactive_file")
                                .or_else(|| stats.get("inactive_file"))
                            && inactive_file < memory_bytes
                        {
                            memory_bytes -= inactive_file;
                        }

                        cgroup::StatSample {
                            memory_bytes,
                            memory_limit_bytes: stats
                                .memory_stats
                                .as_ref()
                                .and_then(|memory| memory.limit)
                                .unwrap_or(0),
                            network: stats.networks.as_ref().and_then(|networks| {
                                networks.values().next().map(|net| {
                                    (
                                        net.rx_bytes.unwrap_or(0),
                                        net.rx_packets.unwrap_or(0),
                                        net.tx_bytes.unwrap_or(0),
                                        net.tx_packets.unwrap_or(0),
                                    )
                                })
                            }),
                            cpu_total_ns: stats
                                .cpu_stats
                                .as_ref()
                                .and_then(|cpu| cpu.cpu_usage.as_ref())
                                .and_then(|cpu| cpu.total_usage)
                                .unwrap_or(0),
                            at: std::time::Instant::now(),
                        }
                    }
                };

                stats_usage.send_modify(|usage| {
                    usage.memory_bytes = sample.memory_bytes;
                    usage.memory_limit_bytes = sample.memory_limit_bytes;
                    usage.disk_bytes = disk_bytes;
                    usage.state = stats_server.state.get_state();

                    if let Some((rx_bytes, rx_packets, tx_bytes, tx_packets)) = sample.network {
                        usage.network.rx_bytes = rx_bytes;
                        usage.network.rx_packets = rx_packets;
                        usage.network.tx_bytes = tx_bytes;
                        usage.network.tx_packets = tx_packets;
                    }

                    usage.cpu_absolute = if let Some(prev) = prev_at {
                        let cpu_delta_ns =
                            sample.cpu_total_ns.saturating_sub(prev_cpu_total) as f64;
                        let wall_delta_ns = sample.at.duration_since(prev).as_nanos() as f64;

                        if wall_delta_ns > 0.0 && cpu_delta_ns > 0.0 {
                            ((cpu_delta_ns / wall_delta_ns) * 100.0 * 1000.0).round() / 1000.0
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    };

                    prev_cpu_total = sample.cpu_total_ns;
                    prev_at = Some(sample.at);
                });
            }
        });

        let state_docker = Arc::clone(&docker);
        let state_id = container_id.clone();
        let state_usage = resource_usage.clone();
        let state_boosted_limit = Arc::clone(&boosted_limit_percent);

        let state_task = tokio::spawn(async move {
            const RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

            struct CachedState {
                status: Option<bollard::plugin::ContainerStateStatusEnum>,
                started_at: Option<chrono::DateTime<chrono::Utc>>,
                exit_code: i32,
                oom_killed: bool,
                cpu_limit: u32,
            }

            let arm_wait = || {
                state_docker.wait_container(
                    &state_id,
                    Some(bollard::query_parameters::WaitContainerOptions {
                        condition: "next-exit".to_string(),
                    }),
                )
            };

            let mut wait_stream = arm_wait();
            let mut wait_armed = true;
            let mut wait_exit_code = None;
            let mut cached: Option<CachedState> = None;
            let mut last_inspect: Option<std::time::Instant> = None;

            let mut tick = tokio::time::interval_at(
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            );
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                let died = tokio::select! {
                    exit = wait_stream.next(), if wait_armed => {
                        wait_armed = false;
                        if let Some(Ok(response)) = exit {
                            wait_exit_code = Some(response.status_code);
                        }

                        true
                    }
                    _ = tick.tick() => false,
                };

                if died
                    || cached.is_none()
                    || last_inspect.is_none_or(|at| at.elapsed() >= RECONCILE_INTERVAL)
                {
                    let inspect = match state_docker
                        .inspect_container_settled(&state_id, None)
                        .await
                    {
                        Ok(inspect) => inspect,
                        Err(DockerResponseServerError {
                            status_code: 404, ..
                        }) => Default::default(),
                        Err(err) => {
                            tracing::warn!(
                                server = %state_id,
                                "failed to inspect container for state: {:?}",
                                err
                            );
                            continue;
                        }
                    };
                    last_inspect = Some(std::time::Instant::now());

                    let state = inspect.state.unwrap_or_default();
                    let host_config = inspect.host_config.unwrap_or_default();

                    cached = Some(CachedState {
                        status: state.status,
                        started_at: state.started_at.as_deref().and_then(|started_at| {
                            chrono::DateTime::parse_from_rfc3339(started_at)
                                .ok()
                                .map(|started_at| started_at.with_timezone(&chrono::Utc))
                        }),
                        exit_code: state.exit_code.or(wait_exit_code).unwrap_or(-1) as i32,
                        oom_killed: state.oom_killed.unwrap_or(false),
                        cpu_limit: cgroup::CpuCgroup::limit_percent(
                            host_config.cpu_quota.unwrap_or(0),
                            host_config.cpu_period.unwrap_or(100000),
                        ),
                    });
                }

                let Some(state) = &cached else {
                    continue;
                };

                let process_status = match state.status {
                    Some(bollard::plugin::ContainerStateStatusEnum::RUNNING) => {
                        if publish_resource_usage && let Some(started_at) = state.started_at {
                            let uptime = chrono::Utc::now()
                                .signed_duration_since(started_at)
                                .num_milliseconds()
                                .max(0) as u64;

                            let limit = match state_boosted_limit.load(Ordering::Relaxed) {
                                0 => state.cpu_limit,
                                boosted => boosted,
                            };

                            state_usage.send_modify(|usage| {
                                usage.uptime = uptime;
                                usage.cpu_limit_absolute = if limit > 0 {
                                    limit
                                } else {
                                    std::thread::available_parallelism()
                                        .map_or(1, |threads| threads.get())
                                        as u32
                                        * 100
                                };
                            });
                        }
                        super::ProcessStatus::Running
                    }
                    Some(bollard::plugin::ContainerStateStatusEnum::PAUSED) => {
                        super::ProcessStatus::Paused
                    }
                    _ => {
                        if publish_resource_usage {
                            state_usage.send_modify(|usage| usage.uptime = 0);
                        }
                        super::ProcessStatus::Stopped {
                            exit_code: state.exit_code,
                            oom_killed: state.oom_killed,
                        }
                    }
                };

                if !wait_armed && matches!(process_status, super::ProcessStatus::Running) {
                    wait_stream = arm_wait();
                    wait_armed = true;
                    wait_exit_code = None;
                }

                if status_tx.send(process_status).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            container_id,
            docker,
            server: Arc::downgrade(&**server),
            app_config,
            resource_usage,
            publish_resource_usage,
            cfs_lock: Arc::new(tokio::sync::Mutex::new(())),
            boosted_limit_percent,
            stdin_tx,
            stdout_ratelimited_rx,
            stdout_rx,
            state_task,
            stats_task,
            stdin_task,
        })
    }

    #[inline]
    fn get_server(&self) -> Result<Arc<super::super::InnerServer>, anyhow::Error> {
        self.server
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("server has been dropped"))
    }

    async fn begin_startup_boost(&self) -> bool {
        static ACTIVE_BOOSTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let boost = self.app_config.load().docker.startup_boost;
        if !boost.enabled {
            return false;
        }

        let Ok(server) = self.get_server() else {
            return false;
        };

        let update_config = server
            .configuration
            .read()
            .await
            .container_update_config(&self.app_config);
        let quota = update_config.cpu_quota.unwrap_or(-1);
        let period = update_config.cpu_period.unwrap_or(100000);
        if quota <= 0 {
            return false;
        }

        let mut active = ACTIVE_BOOSTS.load(Ordering::Relaxed);
        loop {
            if active >= boost.max_concurrent {
                tracing::debug!(
                    server = %server.uuid,
                    "startup boost skipped, {} boosts already active",
                    active
                );

                return false;
            }

            match ACTIVE_BOOSTS.compare_exchange(
                active,
                active + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => active = current,
            }
        }

        {
            let _cfs_guard = self.cfs_lock.lock().await;

            self.docker.clear_cfs_burst(&self.container_id).await;
            if let Err(err) = self
                .docker
                .update_container(
                    &self.container_id,
                    bollard::plugin::ContainerUpdateBody {
                        cpu_quota: Some(-1),
                        cpu_period: Some(period),
                        ..Default::default()
                    },
                )
                .await
            {
                tracing::debug!(
                    container = %self.container_id,
                    "failed to apply startup boost: {}",
                    err
                );
                ACTIVE_BOOSTS.fetch_sub(1, Ordering::Relaxed);

                return false;
            }
        }

        self.boosted_limit_percent.store(
            cgroup::CpuCgroup::limit_percent(quota, period),
            Ordering::Relaxed,
        );

        tracing::debug!(
            server = %server.uuid,
            container = %self.container_id,
            "startup boost active, cpu quota lifted until the server is running"
        );

        tokio::spawn({
            let docker = Arc::clone(&self.docker);
            let app_config = Arc::clone(&self.app_config);
            let container_id = self.container_id.clone();
            let cfs_lock = Arc::clone(&self.cfs_lock);
            let boosted_limit_percent = Arc::clone(&self.boosted_limit_percent);
            let server = Arc::downgrade(&server);

            async move {
                if let Some(server) = server.upgrade() {
                    server
                        .state
                        .wait_while_state(
                            super::super::state::ServerState::Starting,
                            std::time::Duration::from_secs(boost.timeout),
                        )
                        .await;
                }

                if let Some(server) = server.upgrade() {
                    let update_config = server
                        .configuration
                        .read()
                        .await
                        .container_update_config(&app_config);

                    let _cfs_guard = cfs_lock.lock().await;

                    docker.clear_cfs_burst(&container_id).await;
                    if let Err(err) = docker.update_container(&container_id, update_config).await {
                        tracing::debug!(
                            container = %container_id,
                            "failed to restore cpu quota after startup boost: {}",
                            err
                        );
                    }
                    docker.apply_cfs_burst(&container_id, &app_config).await;

                    tracing::debug!(
                        server = %server.uuid,
                        container = %container_id,
                        "startup boost ended, cpu quota restored"
                    );
                }

                boosted_limit_percent.store(0, Ordering::Relaxed);
                ACTIVE_BOOSTS.fetch_sub(1, Ordering::Relaxed);
            }
        });

        true
    }
}

impl Drop for DockerProcessHandle {
    fn drop(&mut self) {
        self.state_task.abort();
        self.stats_task.abort();
        self.stdin_task.abort();

        if self.publish_resource_usage
            && let Some(server) = self.server.upgrade()
        {
            self.resource_usage.wipe(server.state.get_state());
        }
    }
}

#[async_trait::async_trait]
impl super::ProcessHandle for DockerProcessHandle {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, anyhow::Error> {
        let docker = Arc::clone(&self.docker);
        let container_id = self.container_id.clone();
        let tail = lines.map_or_else(|| "all".to_string(), |n| n.to_string());

        let stream = docker
            .logs(
                &container_id,
                Some(bollard::query_parameters::LogsOptions {
                    follow: false,
                    stdout: true,
                    stderr: true,
                    timestamps: false,
                    tail,
                    ..Default::default()
                }),
            )
            .map(|result| {
                result
                    .map(|log| log.into_bytes().to_vec())
                    .map_err(std::io::Error::other)
            });

        Ok(Box::new(LogsReader {
            stream: Box::pin(stream),
            buffer: Vec::new(),
            pos: 0,
        }))
    }

    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.stdin_tx.send(data).await.map_err(Into::into)
    }

    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>
    {
        Ok(self.stdout_ratelimited_rx.resubscribe())
    }
    async fn subscribe_stdout_lines(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>
    {
        Ok(self.stdout_rx.resubscribe())
    }

    async fn sync_configuration(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;

        let update_config = server
            .configuration
            .read()
            .await
            .container_update_config(&self.app_config);

        let _cfs_guard = self.cfs_lock.lock().await;

        self.docker.clear_cfs_burst(&self.container_id).await;
        self.docker
            .update_container(&self.container_id, update_config)
            .await?;
        self.docker
            .apply_cfs_burst(&self.container_id, &self.app_config)
            .await;

        Ok(())
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        self.docker
            .start_container(&self.container_id, None)
            .await?;

        if !self.begin_startup_boost().await {
            let _cfs_guard = self.cfs_lock.lock().await;
            self.docker
                .apply_cfs_burst(&self.container_id, &self.app_config)
                .await;
        }

        Ok(())
    }

    async fn stop(&self) -> Result<(), anyhow::Error> {
        let server = self.get_server()?;

        let process_config = server.process_configuration.read().await;
        let stop_type = process_config.stop.r#type.clone();
        let stop_value = process_config.stop.value.clone();
        drop(process_config);

        match stop_type.as_str() {
            "signal" => {
                let signal = match stop_value.as_deref().map(str::to_uppercase).as_deref() {
                    Some("SIGABRT") => "SIGABRT",
                    Some("SIGINT") | Some("C") => "SIGINT",
                    Some("SIGTERM") => "SIGTERM",
                    Some("SIGQUIT") => "SIGQUIT",
                    _ => "SIGKILL",
                };
                self.docker
                    .kill_container(
                        &self.container_id,
                        Some(bollard::query_parameters::KillContainerOptions {
                            signal: signal.to_string(),
                        }),
                    )
                    .await
                    .map_err(Into::into)
            }
            "command" => {
                let mut command = stop_value
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                command.push(b'\n');
                self.stdin_tx
                    .send(command)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
            _ => self
                .docker
                .stop_container(
                    &self.container_id,
                    Some(bollard::query_parameters::StopContainerOptions {
                        t: Some(-1),
                        ..Default::default()
                    }),
                )
                .await
                .map_err(Into::into),
        }
    }

    async fn kill(&self) -> Result<(), anyhow::Error> {
        self.docker
            .kill_container(
                &self.container_id,
                Some(bollard::query_parameters::KillContainerOptions {
                    signal: "SIGKILL".to_string(),
                }),
            )
            .await
            .map_err(Into::into)
    }
}

type StatusReceiver = tokio::sync::mpsc::Receiver<super::ProcessStatus>;

async fn find_running_container(
    docker: &bollard::Docker,
    name_filter: &str,
    container_type: Option<&str>,
) -> Option<String> {
    let mut filters = HashMap::from([
        ("name".to_string(), vec![name_filter.to_string()]),
        ("status".to_string(), vec!["running".to_string()]),
    ]);
    if let Some(container_type) = container_type {
        filters.insert(
            "label".to_string(),
            vec![format!("ContainerType={container_type}")],
        );
    }

    let containers = docker
        .list_containers_settled(Some(bollard::query_parameters::ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        }))
        .await
        .unwrap_or_default();

    for c in containers {
        if c.state != Some(bollard::plugin::ContainerSummaryStateEnum::RUNNING) {
            continue;
        }

        if let Some(id) = c.id {
            return Some(id);
        }
    }

    None
}

#[async_trait::async_trait]
impl super::ServerExecutor for DockerExecutor {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        self.app_config.ensure_docker_network(&self.docker).await?;

        if std::env::var("OCI_CONTAINER").is_ok() {
            match host_mounts::HostMountTable::discover(&self.docker).await {
                Ok(table) => {
                    table.validate_directories(&self.app_config.load())?;

                    tracing::info!(
                        "running in container {}, translating bind mount sources to host paths",
                        table.container_id().get(..12).unwrap_or_default()
                    );
                    for (destination, source) in table.mounts() {
                        if destination != source {
                            tracing::info!(
                                "translating bind mount sources under {} to {}",
                                destination.display(),
                                source.display()
                            );
                        }
                    }

                    let _ = self.host_mounts.set(Some(table));
                }
                Err(err) => {
                    tracing::warn!(
                        "running in a container, but failed to inspect own container: {err:#}"
                    );
                    tracing::warn!(
                        "bind mount sources will be passed to the container engine untranslated, host paths must match the wings container's paths exactly"
                    );
                    let _ = self.host_mounts.set(None);
                }
            }
        }

        Ok(())
    }

    async fn setup_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let image = server.configuration.read().await.container.image.clone();

        self.pull_image(&image, server, false).await?;

        let container_name = {
            let cfg = server.configuration.read().await;
            if self.app_config.load().docker.server_name_in_container_name {
                let mut filtered = String::new();
                for c in cfg.meta.name.chars() {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        filtered.push(c);
                    }
                }
                filtered.truncate(63 - 1 - 36);
                format!("{}.{}", filtered, cfg.uuid)
            } else {
                cfg.uuid.to_string()
            }
        };

        let bollard_config = server
            .configuration
            .read()
            .await
            .container_config(
                &self.app_config,
                &self.docker,
                &server.filesystem,
                self.host_mounts(),
            )
            .await?;
        server
            .configuration
            .read()
            .await
            .ensure_vmounts(&self.app_config)
            .await?;

        let container = self
            .docker
            .create_container(
                Some(bollard::query_parameters::CreateContainerOptions {
                    name: Some(container_name),
                    ..Default::default()
                }),
                bollard_config,
            )
            .await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            DockerProcessHandle::new(
                container.id,
                Arc::clone(&self.docker),
                server,
                Arc::clone(&self.app_config),
                Arc::clone(&self.stats_sampler),
                status_tx,
                true,
                true,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn attach_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let container_id = find_running_container(
            &self.docker,
            &server.uuid.to_string(),
            Some("server_process"),
        )
        .await
        .ok_or_else(|| anyhow::anyhow!("no running server container found"))?;

        self.docker
            .apply_cfs_burst(&container_id, &self.app_config)
            .await;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            DockerProcessHandle::new(
                container_id,
                Arc::clone(&self.docker),
                server,
                Arc::clone(&self.app_config),
                Arc::clone(&self.stats_sampler),
                status_tx,
                true,
                true,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let containers = self
            .docker
            .list_containers_settled(Some(bollard::query_parameters::ListContainersOptions {
                all: true,
                filters: Some(HashMap::from([(
                    "name".to_string(),
                    vec![server.uuid.to_string()],
                )])),
                ..Default::default()
            }))
            .await?;

        for c in containers {
            let Some(id) = c.id else { continue };
            if let Err(err) = self.docker.remove_container_forgiving(&id).await {
                tracing::error!(
                    server = %server.uuid,
                    container = %id,
                    "failed to remove container: {}",
                    err
                );
            }
        }

        Ok(())
    }

    async fn setup_installation_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        self.pull_image(&script.container_image, server, false)
            .await?;

        let server_config = server.configuration.read().await;
        let resources = server_config.installer_resources(&self.app_config);

        let mut env = server_config.environment(&self.app_config);
        for (k, v) in &script.environment {
            env.push(format!(
                "{k}={}",
                match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                }
            ));
        }

        env.push(format!(
            "INSTALL_STATUS_FILE=/mnt/install/{}",
            super::super::installation::INSTALL_STATUS_FILE_NAME
        ));

        drop(server_config);

        let tmp_dir = self.app_config.tmp_data_path(server.uuid);
        tokio::fs::create_dir_all(&tmp_dir).await?;
        tokio::fs::write(
            tmp_dir.join("install.sh"),
            script.script.replace("\r\n", "\n"),
        )
        .await?;

        let status_path = tmp_dir.join(super::super::installation::INSTALL_STATUS_FILE_NAME);
        tokio::fs::write(&status_path, "").await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o755)).await?;
            tokio::fs::set_permissions(&status_path, std::fs::Permissions::from_mode(0o666))
                .await?;
        }

        let (mounts, binds) = split_selinux_binds(vec![
            bollard::plugin::Mount {
                typ: Some(bollard::plugin::MountType::BIND),
                source: Some(host_mounts::translate_source(
                    self.host_mounts(),
                    &server.filesystem.base(),
                )),
                target: Some("/mnt/server".to_string()),
                ..Default::default()
            },
            bollard::plugin::Mount {
                typ: Some(bollard::plugin::MountType::BIND),
                source: Some(host_mounts::translate_source(
                    self.host_mounts(),
                    &tmp_dir.to_string_lossy(),
                )),
                target: Some("/mnt/install".to_string()),
                ..Default::default()
            },
        ]);

        let bollard_config = bollard::plugin::ContainerCreateBody {
            host_config: Some(bollard::plugin::HostConfig {
                memory: resources.memory,
                memory_reservation: resources.memory_reservation,
                memory_swap: resources.memory_swap,
                cpu_quota: resources.cpu_quota,
                cpu_period: resources.cpu_period,
                cpuset_cpus: resources.cpuset_cpus,
                cpuset_mems: resources.cpuset_mems,
                pids_limit: resources.pids_limit,
                blkio_weight: resources.blkio_weight,
                oom_kill_disable: resources.oom_kill_disable,
                mounts: Some(mounts),
                binds,
                network_mode: Some(self.app_config.load().docker.network.mode.clone()),
                dns: Some(self.app_config.load().docker.network.dns.clone()),
                dns_options: Some(self.app_config.load().docker.network.dns_options.clone()),
                tmpfs: Some(HashMap::from([(
                    "/tmp".to_string(),
                    format!(
                        "rw,exec,nosuid,size={}M",
                        self.app_config.load().docker.tmpfs_size.as_mib()
                    ),
                )])),
                log_config: Some(bollard::plugin::HostConfigLogConfig {
                    typ: Some(self.app_config.load().docker.log_config.r#type.clone()),
                    config: Some(
                        self.app_config
                            .load()
                            .docker
                            .log_config
                            .config
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    ),
                }),
                userns_mode: string_to_option(&self.app_config.load().docker.userns_mode),
                ..Default::default()
            }),
            cmd: Some(vec![
                script.entrypoint.to_string(),
                "/mnt/install/install.sh".to_string(),
            ]),
            hostname: Some("installer".to_string()),
            image: Some(script.container_image.trim_end_matches('~').to_string()),
            env: Some(env),
            labels: Some(HashMap::from([
                (
                    "Service".to_string(),
                    self.app_config.load().app_name.clone(),
                ),
                ("ContainerType".to_string(), "server_installer".to_string()),
            ])),
            attach_stdin: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            open_stdin: Some(true),
            tty: Some(true),
            ..Default::default()
        };

        let container = self
            .docker
            .create_container(
                Some(bollard::query_parameters::CreateContainerOptions {
                    name: Some(format!("{}_installer", server.uuid)),
                    ..Default::default()
                }),
                bollard_config,
            )
            .await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            DockerProcessHandle::new(
                container.id,
                Arc::clone(&self.docker),
                server,
                Arc::clone(&self.app_config),
                Arc::clone(&self.stats_sampler),
                status_tx,
                true,
                true,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn attach_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let container_id = find_running_container(
            &self.docker,
            &format!("{}_installer", server.uuid),
            Some("server_installer"),
        )
        .await
        .ok_or_else(|| anyhow::anyhow!("no running installer container found"))?;

        self.docker
            .apply_cfs_burst(&container_id, &self.app_config)
            .await;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            DockerProcessHandle::new(
                container_id,
                Arc::clone(&self.docker),
                server,
                Arc::clone(&self.app_config),
                Arc::clone(&self.stats_sampler),
                status_tx,
                true,
                true,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let containers = self
            .docker
            .list_containers_settled(Some(bollard::query_parameters::ListContainersOptions {
                all: true,
                filters: Some(HashMap::from([(
                    "name".to_string(),
                    vec![format!("{}_installer", server.uuid)],
                )])),
                ..Default::default()
            }))
            .await?;

        for c in containers {
            let Some(id) = c.id else { continue };
            if let Err(err) = self.docker.remove_container_forgiving(&id).await {
                tracing::error!(
                    server = %server.uuid,
                    container = %id,
                    "failed to remove installation container: {}",
                    err
                );
            }
        }

        Ok(())
    }

    async fn setup_script_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        self.pull_image(&script.container_image, server, true)
            .await?;

        let server_config = server.configuration.read().await;
        let resources = server_config.installer_resources(&self.app_config);

        let mut env = server_config.environment(&self.app_config);
        for (k, v) in &script.environment {
            env.push(format!(
                "{k}={}",
                match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                }
            ));
        }

        drop(server_config);

        let tmp_dir = self.app_config.tmp_data_path(server.uuid);
        tokio::fs::create_dir_all(&tmp_dir).await?;
        tokio::fs::write(
            tmp_dir.join("script.sh"),
            script.script.replace("\r\n", "\n"),
        )
        .await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o755)).await?;
        }

        let (mounts, binds) = split_selinux_binds(vec![
            bollard::plugin::Mount {
                typ: Some(bollard::plugin::MountType::BIND),
                source: Some(host_mounts::translate_source(
                    self.host_mounts(),
                    &server.filesystem.base(),
                )),
                target: Some("/mnt/server".to_string()),
                ..Default::default()
            },
            bollard::plugin::Mount {
                typ: Some(bollard::plugin::MountType::BIND),
                source: Some(host_mounts::translate_source(
                    self.host_mounts(),
                    &tmp_dir.to_string_lossy(),
                )),
                target: Some("/mnt/script".to_string()),
                ..Default::default()
            },
        ]);

        let bollard_config = bollard::plugin::ContainerCreateBody {
            host_config: Some(bollard::plugin::HostConfig {
                memory: resources.memory,
                memory_reservation: resources.memory_reservation,
                memory_swap: resources.memory_swap,
                cpu_quota: resources.cpu_quota,
                cpu_period: resources.cpu_period,
                cpuset_cpus: resources.cpuset_cpus,
                cpuset_mems: resources.cpuset_mems,
                pids_limit: resources.pids_limit,
                blkio_weight: resources.blkio_weight,
                oom_kill_disable: resources.oom_kill_disable,
                mounts: Some(mounts),
                binds,
                network_mode: Some(self.app_config.load().docker.network.mode.clone()),
                dns: Some(self.app_config.load().docker.network.dns.clone()),
                dns_options: Some(self.app_config.load().docker.network.dns_options.clone()),
                tmpfs: Some(HashMap::from([(
                    "/tmp".to_string(),
                    format!(
                        "rw,exec,nosuid,size={}M",
                        self.app_config.load().docker.tmpfs_size.as_mib()
                    ),
                )])),
                log_config: Some(bollard::plugin::HostConfigLogConfig {
                    typ: Some(self.app_config.load().docker.log_config.r#type.clone()),
                    config: Some(
                        self.app_config
                            .load()
                            .docker
                            .log_config
                            .config
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    ),
                }),
                userns_mode: string_to_option(&self.app_config.load().docker.userns_mode),
                ..Default::default()
            }),
            cmd: Some(vec![
                script.entrypoint.to_string(),
                "/mnt/script/script.sh".to_string(),
            ]),
            hostname: Some("script".to_string()),
            image: Some(script.container_image.trim_end_matches('~').to_string()),
            env: Some(env),
            labels: Some(HashMap::from([
                (
                    "Service".to_string(),
                    self.app_config.load().app_name.clone(),
                ),
                ("ContainerType".to_string(), "script_runner".to_string()),
            ])),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            ..Default::default()
        };

        let name = format!(
            "{}_script_runner_{}",
            server.uuid,
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 8)
        );

        let container = self
            .docker
            .create_container(
                Some(bollard::query_parameters::CreateContainerOptions {
                    name: Some(name),
                    ..Default::default()
                }),
                bollard_config,
            )
            .await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            DockerProcessHandle::new(
                container.id.clone(),
                Arc::clone(&self.docker),
                server,
                Arc::clone(&self.app_config),
                Arc::clone(&self.stats_sampler),
                status_tx,
                false,
                false,
            )
            .await?,
        );

        tokio::spawn({
            let docker = Arc::clone(&self.docker);
            let server = server.uuid;

            async move {
                if let Some(Err(err)) = docker
                    .wait_container(
                        &container.id,
                        Some(bollard::query_parameters::WaitContainerOptions {
                            condition: "next-exit".to_string(),
                        }),
                    )
                    .next()
                    .await
                {
                    tracing::error!(
                        server = %server,
                        container = %container.id,
                        "script failed: {}",
                        err
                    );
                }

                if let Err(err) = docker.remove_container_forgiving(&container.id).await {
                    tracing::error!(
                        server = %server,
                        container = %container.id,
                        "failed to remove script container: {}",
                        err
                    );
                }
            }
        });

        Ok((handle, status_rx))
    }

    async fn resolve_internal_target(
        &self,
        server: &super::super::Server,
        port: u16,
    ) -> Result<Option<std::net::SocketAddr>, anyhow::Error> {
        let container_id = match find_running_container(
            &self.docker,
            &server.uuid.to_string(),
            Some("server_process"),
        )
        .await
        {
            Some(id) => id,
            None => return Ok(None),
        };

        if let Some(gateway) = self.host_gateway() {
            let binding = {
                let configuration = server.configuration.read().await;
                configuration
                    .allocations
                    .mappings
                    .iter()
                    .find(|(_, ports)| ports.contains(&port))
                    .and_then(|(ip, _)| ip.parse::<std::net::IpAddr>().ok())
            };

            if let Some(binding_ip) = binding {
                let target_ip = if binding_ip.is_unspecified() || binding_ip.is_loopback() {
                    gateway
                } else {
                    binding_ip
                };

                return Ok(Some(std::net::SocketAddr::new(target_ip, port)));
            }
        }

        let inspect = self
            .docker
            .inspect_container_settled(&container_id, None)
            .await?;

        let network_name = self.app_config.load().docker.network.name.clone();
        match inspect
            .network_settings
            .and_then(|settings| settings.networks)
            .and_then(|mut networks| networks.remove(&network_name))
            .and_then(|endpoint| endpoint.ip_address)
            .filter(|ip| !ip.is_empty())
        {
            Some(ip) => Ok(Some(std::net::SocketAddr::new(ip.parse()?, port))),
            None => Ok(None),
        }
    }

    async fn used_ports(
        &self,
        ips: &[std::net::IpAddr],
    ) -> Result<HashMap<std::net::IpAddr, Vec<super::UsedPort>>, anyhow::Error> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }

        let config = self.app_config.load();
        let bindings: Vec<(std::net::IpAddr, HostBinding)> = ips
            .iter()
            .map(|ip| (*ip, HostBinding::resolve(&config.docker.network, *ip)))
            .collect();
        let mut used: HashMap<std::net::IpAddr, HashMap<u16, Option<uuid::Uuid>>> =
            ips.iter().map(|ip| (*ip, HashMap::new())).collect();

        let containers = self
            .docker
            .list_containers_settled(Some(bollard::query_parameters::ListContainersOptions {
                all: false,
                ..Default::default()
            }))
            .await?;

        for container in containers {
            let server = container_server(container.names.as_deref());

            for port in container.ports.unwrap_or_default() {
                let Some(public_port) = port.public_port else {
                    continue;
                };

                for (ip, binding) in &bindings {
                    if binding.collides_with(port.ip.as_deref())
                        && let Some(ports) = used.get_mut(ip)
                    {
                        ports.entry(public_port).or_insert(server);
                    }
                }
            }
        }

        Ok(used
            .into_iter()
            .map(|(ip, ports)| {
                let mut ports: Vec<super::UsedPort> = ports
                    .into_iter()
                    .map(|(port, server)| super::UsedPort { port, server })
                    .collect();
                ports.sort_unstable_by_key(|port| port.port);

                (ip, ports)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::configuration::ServerConfiguration;

    // cpu period scaling

    #[test]
    fn a_non_default_cpu_period_scales_every_quota_consistently() {
        let config = tokio_test::block_on(async { crate::config::Config::mock() });
        {
            let inner = config.mutate_in_place_for_testing();
            inner.docker.cpu_period = 20000;
            inner.docker.installer_limits.cpu = 100;
        }

        let mut configuration = ServerConfiguration::mock(uuid::Uuid::new_v4());
        configuration.build.cpu_limit = 250;

        let resources = configuration.convert_container_resources(&config);
        assert_eq!(resources.cpu_period, Some(20000));
        assert_eq!(resources.cpu_quota, Some(50000));
        assert_eq!(cgroup::CpuCgroup::limit_percent(50000, 20000), 250);

        // below the installer floor, which is a percentage of the same period
        configuration.build.cpu_limit = 50;
        let installer = configuration.installer_resources(&config);
        assert_eq!(installer.cpu_quota, Some(20000));
        assert_eq!(cgroup::CpuCgroup::limit_percent(20000, 20000), 100);

        // above the floor, the server limit is kept
        configuration.build.cpu_limit = 400;
        let installer = configuration.installer_resources(&config);
        assert_eq!(installer.cpu_quota, Some(80000));
    }

    // selinux relabelling

    fn bind(source: &str, target: &str, read_only: bool) -> bollard::models::Mount {
        bollard::models::Mount {
            typ: Some(bollard::plugin::MountType::BIND),
            source: Some(source.to_string()),
            target: Some(target.to_string()),
            read_only: Some(read_only),
            ..Default::default()
        }
    }

    #[test]
    fn without_selinux_mounts_stay_structured() {
        let (mounts, binds) = split_binds_for_relabel(
            vec![bind("/var/lib/wings/volumes/a", "/home/container", false)],
            false,
        );

        assert_eq!(mounts.len(), 1);
        assert_eq!(binds, None);
    }

    #[test]
    fn with_selinux_binds_carry_the_shared_relabel_option() {
        let (mounts, binds) = split_binds_for_relabel(
            vec![
                bind("/var/lib/wings/volumes/a", "/home/container", false),
                bind("/run/wings/etc/passwd", "/etc/passwd", true),
            ],
            true,
        );

        assert!(mounts.is_empty());
        assert_eq!(
            binds,
            Some(vec![
                "/var/lib/wings/volumes/a:/home/container:rw,z".to_string(),
                "/run/wings/etc/passwd:/etc/passwd:ro,z".to_string(),
            ])
        );
    }

    #[test]
    fn kernel_filesystems_are_never_relabelled() {
        let (mounts, binds) = split_binds_for_relabel(
            vec![
                bind("/dev/hugepages", "/dev/hugepages", false),
                bind("/var/lib/wings/volumes/a", "/home/container", false),
            ],
            true,
        );

        assert_eq!(
            mounts.first().and_then(|mount| mount.source.as_deref()),
            Some("/dev/hugepages")
        );
        assert_eq!(
            binds,
            Some(vec![
                "/var/lib/wings/volumes/a:/home/container:rw,z".to_string()
            ])
        );
    }
}
