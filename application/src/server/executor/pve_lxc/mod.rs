//! Proxmox VE LXC runtime support.
//!
//! This module intentionally sits behind the existing `ServerExecutor` boundary so
//! Docker remains the default runtime and upstream changes to the Docker executor
//! do not have to be carried into the PVE implementation.

pub mod cli;
pub mod firewall;
mod helper_process;
mod server_process;

use super::{ProcessHandle, ProcessStatus, ServerExecutor, StatusReceiver, UsedPort, cgroup};
use crate::io::line_buffer::LineBuffer;
use anyhow::Context;
use compact_str::ToCompactString;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::Cursor,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub use cli::PveCli;
use helper_process::PveHelperProcessHandle;
use server_process::PveProcessHandle;

pub async fn create_firewall(
    app_config: &crate::config::Config,
    cli: &PveCli,
) -> Result<Arc<dyn crate::server::firewall::FirewallBackend>, anyhow::Error> {
    let (backend, limits, tag_prefix, configured_node) = {
        let config = app_config.load();
        let firewall = &config.runtime.pve_lxc.firewall;
        (
            firewall.backend,
            crate::server::firewall::sets::SourceFileLimits {
                max_entries: usize::try_from(firewall.source_file_max_entries)
                    .context("Proxmox firewall source entry limit exceeds usize")?,
                max_bytes: firewall.source_file_max_bytes,
            },
            config.runtime.pve_lxc.tag_prefix.clone(),
            config.runtime.pve_lxc.node.clone(),
        )
    };
    let local_node = cli.local_node().await?;
    let node = PveLxcExecutor::runtime_node(&configured_node, &local_node)?;

    let proxmox_enabled = match cli.cluster_firewall_enabled().await {
        Ok(enabled) => enabled,
        Err(error) if backend == crate::config::PveLxcFirewallBackend::Auto => {
            tracing::warn!(
                "failed to probe the Proxmox datacenter firewall, falling back to host firewalling: {error:#}"
            );
            false
        }
        Err(error) => return Err(error.context("failed to probe the Proxmox datacenter firewall")),
    };

    let firewall: Arc<dyn crate::server::firewall::FirewallBackend> = match backend {
        crate::config::PveLxcFirewallBackend::Auto if proxmox_enabled => Arc::new(
            firewall::ProxmoxFirewall::new(cli.clone(), node.clone(), tag_prefix, limits),
        ),
        crate::config::PveLxcFirewallBackend::Proxmox => Arc::new(firewall::ProxmoxFirewall::new(
            cli.clone(),
            node,
            tag_prefix,
            limits,
        )),
        crate::config::PveLxcFirewallBackend::Auto => {
            tracing::info!(
                "Proxmox datacenter firewall is disabled; using the host-local firewall backend"
            );
            firewall::ProxmoxFirewall::new(cli.clone(), node, tag_prefix, limits)
                    .clear_managed()
                    .await
                    .context("failed to clear stale Proxmox guest firewall rules before selecting the host-local backend")?;
            crate::server::firewall::create_host_local_with(
                crate::server::firewall::FirewallBackendKind::Auto,
                limits,
            )
            .await
        }
        crate::config::PveLxcFirewallBackend::Nftables => {
            crate::server::firewall::create_host_local_with(
                crate::server::firewall::FirewallBackendKind::Nftables,
                limits,
            )
            .await
        }
        crate::config::PveLxcFirewallBackend::Iptables => {
            crate::server::firewall::create_host_local_with(
                crate::server::firewall::FirewallBackendKind::Iptables,
                limits,
            )
            .await
        }
        crate::config::PveLxcFirewallBackend::Disabled => {
            crate::server::firewall::create_host_local_with(
                crate::server::firewall::FirewallBackendKind::Disabled,
                limits,
            )
            .await
        }
    };
    Ok(firewall)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcNetFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundPort {
    family: ProcNetFamily,
    address: Option<IpAddr>,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdgePeer {
    public_ip: Ipv4Addr,
    tunnel_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PveVersion {
    major: u64,
    minor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerContainerPlan {
    Reuse {
        vmid: u32,
        stale_replacement: Option<u32>,
    },
    ReplaceWithStaged {
        old_vmid: u32,
        staged_vmid: u32,
    },
    ReplaceFresh {
        old_vmid: u32,
        stale_replacement: Option<u32>,
    },
    RecoverStaged {
        staged_vmid: u32,
    },
    CreateFresh {
        stale_replacement: Option<u32>,
    },
}

impl PveVersion {
    fn parse(value: &str) -> Result<Self, anyhow::Error> {
        let (_, version_and_rest) = value
            .trim()
            .split_once('/')
            .context("pveversion output did not include a version")?;
        let version = version_and_rest
            .split('/')
            .next()
            .context("pveversion output did not include a version number")?;
        let mut parts = version.split('.');
        let major = parts
            .next()
            .context("pveversion output did not include a major version")?
            .parse()
            .context("failed to parse Proxmox major version")?;
        let minor = parts
            .next()
            .context("pveversion output did not include a minor version")?
            .parse()
            .context("failed to parse Proxmox minor version")?;

        Ok(Self { major, minor })
    }

    fn is_supported(self) -> bool {
        self.major > 9 || (self.major == 9 && self.minor >= 2)
    }
}

pub struct PveLxcExecutor {
    cli: PveCli,
    app_config: Arc<crate::config::Config>,
    firewall: Arc<dyn crate::server::firewall::FirewallBackend>,
    stats_sampler: Arc<super::cgroup::StatsSampler>,
    node: OnceLock<String>,
    template_provisioning: tokio::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl PveLxcExecutor {
    const DATA_MOUNT_TARGET: &'static str = "/home/container";

    pub(super) fn pids_limit(config: &crate::config::Config) -> Option<u64> {
        let config = config.load();
        match config
            .runtime
            .pve_lxc
            .pids_limit
            .unwrap_or(config.docker.container_pid_limit)
        {
            0 => None,
            limit => Some(limit),
        }
    }

    fn image_cache_max_age(config: &crate::config::InnerConfig) -> std::time::Duration {
        let cache = config.docker.registry_image_fetch_cache;
        if cache.enabled {
            std::time::Duration::from_secs(cache.duration)
        } else {
            std::time::Duration::ZERO
        }
    }

    async fn template_provisioning_lock(
        &self,
        node: &str,
        storage: &str,
        image: &str,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let key = format!("{node}\0{storage}\0{image}");
        let mut locks = self.template_provisioning.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    fn network_option(
        bridge: &str,
        vlan_tag: Option<u16>,
        address: Option<(Ipv4Addr, u8, Ipv4Addr)>,
    ) -> Result<String, anyhow::Error> {
        if bridge.is_empty()
            || !bridge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(anyhow::anyhow!("invalid Proxmox LXC bridge: {bridge}"));
        }
        if let Some(tag) = vlan_tag
            && !(1..=4094).contains(&tag)
        {
            return Err(anyhow::anyhow!(
                "Proxmox LXC VLAN tag must be between 1 and 4094, got {tag}"
            ));
        }

        let mut options = vec![
            format!("name=eth0,bridge={bridge}"),
            "firewall=1".to_string(),
        ];
        if let Some(tag) = vlan_tag {
            options.push(format!("tag={tag}"));
        }
        match address {
            Some((ip, prefix, gateway)) => {
                if prefix > 32 {
                    return Err(anyhow::anyhow!(
                        "Proxmox LXC network prefix must be between 0 and 32, got {prefix}"
                    ));
                }
                options.push(format!("ip={ip}/{prefix}"));
                options.push(format!("gw={gateway}"));
            }
            None => options.push("ip=dhcp".to_string()),
        }
        options.push("type=veth".to_string());
        if address.is_none() {
            options.push("host-managed=1".to_string());
        }
        Ok(options.join(","))
    }

    fn dhcp_network(bridge: &str, vlan_tag: Option<u16>) -> Result<String, anyhow::Error> {
        Self::network_option(bridge, vlan_tag, None)
    }

    fn network_for_allocation(
        bridge: &str,
        vlan_tag: Option<u16>,
        network_prefix: Option<u8>,
        gateway: Option<&str>,
        allocation: Option<&str>,
    ) -> Result<String, anyhow::Error> {
        let Some(allocation) = allocation else {
            return Self::dhcp_network(bridge, vlan_tag);
        };
        let allocation = allocation.parse::<Ipv4Addr>().with_context(|| {
            format!("LXC primary allocation {allocation} is not an IPv4 address")
        })?;
        let prefix = network_prefix.context(
            "Proxmox LXC static allocations require runtime.pve_lxc.network_prefix; configure the isolated LXC subnet before assigning panel allocations",
        )?;
        let gateway = gateway
            .filter(|gateway| !gateway.trim().is_empty())
            .context(
                "Proxmox LXC static allocations require runtime.pve_lxc.gateway; configure the isolated LXC subnet before assigning panel allocations",
            )?
            .parse::<Ipv4Addr>()
            .context("Proxmox LXC gateway is not an IPv4 address")?;
        Self::network_option(bridge, vlan_tag, Some((allocation, prefix, gateway)))
    }

    async fn rootfs_storage(
        &self,
        node: &str,
        configured_storage: String,
        rootfs_size_gib: u64,
    ) -> Result<String, anyhow::Error> {
        if !configured_storage.is_empty() && configured_storage != "auto" {
            return Ok(configured_storage);
        }

        let required_bytes = rootfs_size_gib
            .checked_mul(1024 * 1024 * 1024)
            .context("Proxmox LXC rootfs size overflowed u64")?;
        self.cli
            .available_lxc_storages(node)
            .await?
            .into_iter()
            .find(|storage| storage.available_bytes >= required_bytes)
            .map(|storage| storage.name)
            .context(format!(
                "no active Proxmox LXC storage has {} GiB free for the requested rootfs",
                rootfs_size_gib
            ))
    }

    const INSTALLER_HELPER_ROLE: &'static str = "installer";
    const SCRIPT_HELPER_ROLE: &'static str = "script";

    pub fn new(
        app_config: Arc<crate::config::Config>,
        cli: PveCli,
        firewall: Arc<dyn crate::server::firewall::FirewallBackend>,
    ) -> Self {
        Self {
            cli,
            app_config,
            firewall,
            stats_sampler: Arc::new(super::cgroup::StatsSampler::default()),
            node: OnceLock::new(),
            template_provisioning: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn unsupported<T>(operation: &str) -> Result<T, anyhow::Error> {
        Err(anyhow::anyhow!(
            "Proxmox VE LXC runtime does not implement {operation} yet"
        ))
    }

    fn runtime_node(configured_node: &str, local_node: &str) -> Result<String, anyhow::Error> {
        if configured_node.trim().is_empty() {
            return Ok(local_node.to_string());
        }
        if configured_node != local_node {
            return Err(anyhow::anyhow!(
                "Proxmox VE LXC runtime must target the local node ({local_node}); configured node was {configured_node}"
            ));
        }

        Ok(configured_node.to_string())
    }

    fn vmid_conflict(error: &anyhow::Error) -> bool {
        let message = error.to_string().to_ascii_lowercase();
        message.contains("already exists") || message.contains("already in use")
    }

    fn parse_proc_net_address(raw: &str, family: ProcNetFamily) -> Result<IpAddr, anyhow::Error> {
        match family {
            ProcNetFamily::Ipv4 => {
                if raw.len() != 8 {
                    return Err(anyhow::anyhow!(
                        "invalid IPv4 address in Linux socket table: {raw}"
                    ));
                }
                let word = u32::from_str_radix(raw, 16)
                    .context("failed to parse IPv4 address from Linux socket table")?;
                Ok(std::net::Ipv4Addr::from(word.to_le_bytes()).into())
            }
            ProcNetFamily::Ipv6 => {
                if raw.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "invalid IPv6 address in Linux socket table: {raw}"
                    ));
                }

                let mut bytes = [0u8; 16];
                for (index, chunk) in raw.as_bytes().chunks_exact(8).enumerate() {
                    let chunk = std::str::from_utf8(chunk)
                        .context("Linux IPv6 socket table contained non-UTF8 data")?;
                    let word = u32::from_str_radix(chunk, 16)
                        .context("failed to parse IPv6 address from Linux socket table")?;
                    bytes
                        .get_mut(index * 4..index * 4 + 4)
                        .context("IPv6 socket-table word exceeded its destination buffer")?
                        .copy_from_slice(&word.to_le_bytes());
                }
                Ok(std::net::Ipv6Addr::from(bytes).into())
            }
        }
    }

    fn parse_proc_net_ports(
        contents: &str,
        family: ProcNetFamily,
        tcp: bool,
    ) -> Result<Vec<BoundPort>, anyhow::Error> {
        let mut ports = Vec::new();

        for line in contents.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 {
                continue;
            }
            let state = fields
                .get(3)
                .context("Linux socket table row did not include a state")?;
            if tcp && *state != "0A" {
                continue;
            }

            let endpoint = fields
                .get(1)
                .context("Linux socket table row did not include a local endpoint")?;
            let (raw_address, raw_port) = endpoint
                .rsplit_once(':')
                .context("Linux socket table local address did not include a port")?;
            let port = u16::from_str_radix(raw_port, 16)
                .context("failed to parse port from Linux socket table")?;
            if port == 0 {
                continue;
            }

            let address = Self::parse_proc_net_address(raw_address, family)?;
            ports.push(BoundPort {
                family,
                address: (!address.is_unspecified()).then_some(address),
                port,
            });
        }

        Ok(ports)
    }

    async fn container_bound_ports(pid: i64) -> Result<Vec<BoundPort>, anyhow::Error> {
        if pid <= 0 {
            return Err(anyhow::anyhow!(
                "Proxmox LXC runtime returned invalid PID {pid}"
            ));
        }

        let tables = [
            ("tcp", ProcNetFamily::Ipv4, true),
            ("tcp6", ProcNetFamily::Ipv6, true),
            ("udp", ProcNetFamily::Ipv4, false),
            ("udp6", ProcNetFamily::Ipv6, false),
        ];
        let mut ports = Vec::new();
        let mut tables_read = 0usize;

        for (table, family, tcp) in tables {
            let path = format!("/proc/{pid}/net/{table}");
            match tokio::fs::read_to_string(&path).await {
                Ok(contents) => {
                    tables_read += 1;
                    ports.extend(
                        Self::parse_proc_net_ports(&contents, family, tcp).with_context(|| {
                            format!("failed to parse Proxmox LXC socket table {path}")
                        })?,
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to read Proxmox LXC socket table {path}")
                    });
                }
            }
        }

        if tables_read == 0 {
            return Err(anyhow::anyhow!(
                "Proxmox LXC process {pid} disappeared before its socket tables could be read"
            ));
        }

        Ok(ports)
    }

    fn bound_port_matches_address(bound: BoundPort, address: IpAddr) -> bool {
        match bound.address {
            None => matches!(
                (bound.family, address),
                (ProcNetFamily::Ipv4, IpAddr::V4(_)) | (ProcNetFamily::Ipv6, IpAddr::V6(_))
            ),
            Some(IpAddr::V6(bound_v6)) => {
                bound_v6
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .is_some_and(|mapped| mapped == address)
                    || IpAddr::V6(bound_v6) == address
            }
            Some(bound_address) => bound_address == address,
        }
    }

    fn server_tag(prefix: &str, uuid: uuid::Uuid) -> String {
        format!("{prefix}-server-{uuid}")
    }

    fn replacement_tag(prefix: &str, uuid: uuid::Uuid) -> String {
        format!("{prefix}-repl-{uuid}")
    }

    fn helper_tag(prefix: &str, role: &str, uuid: uuid::Uuid) -> String {
        format!("{prefix}-helper-{role}-{uuid}")
    }

    fn server_from_tags(prefix: &str, tags: &[String]) -> Option<uuid::Uuid> {
        if !tags.iter().any(|tag| tag == prefix) {
            return None;
        }

        let server_tag_prefix = format!("{prefix}-server-");
        tags.iter().find_map(|tag| {
            tag.strip_prefix(&server_tag_prefix)
                .and_then(|uuid| uuid::Uuid::parse_str(uuid).ok())
        })
    }

    fn replacement_from_tags(prefix: &str, tags: &[String]) -> Option<uuid::Uuid> {
        if !tags.iter().any(|tag| tag == prefix) {
            return None;
        }

        let replacement_tag_prefix = format!("{prefix}-repl-");
        tags.iter().find_map(|tag| {
            tag.strip_prefix(&replacement_tag_prefix)
                .and_then(|uuid| uuid::Uuid::parse_str(uuid).ok())
        })
    }

    fn has_image_tag(container: &cli::ClusterContainer, image_tag: &str) -> bool {
        container.tags.iter().any(|tag| tag == image_tag)
    }

    fn plan_server_container(
        existing: Option<&cli::ClusterContainer>,
        replacement: Option<&cli::ClusterContainer>,
        image_tag: &str,
    ) -> ServerContainerPlan {
        match (existing, replacement) {
            (Some(existing), replacement) if Self::has_image_tag(existing, image_tag) => {
                ServerContainerPlan::Reuse {
                    vmid: existing.vmid,
                    stale_replacement: replacement.map(|container| container.vmid),
                }
            }
            (Some(existing), Some(replacement)) if Self::has_image_tag(replacement, image_tag) => {
                ServerContainerPlan::ReplaceWithStaged {
                    old_vmid: existing.vmid,
                    staged_vmid: replacement.vmid,
                }
            }
            (Some(existing), replacement) => ServerContainerPlan::ReplaceFresh {
                old_vmid: existing.vmid,
                stale_replacement: replacement.map(|container| container.vmid),
            },
            (None, Some(replacement)) if Self::has_image_tag(replacement, image_tag) => {
                ServerContainerPlan::RecoverStaged {
                    staged_vmid: replacement.vmid,
                }
            }
            (None, replacement) => ServerContainerPlan::CreateFresh {
                stale_replacement: replacement.map(|container| container.vmid),
            },
        }
    }

    fn helper_from_tags(prefix: &str, role: &str, tags: &[String]) -> Option<uuid::Uuid> {
        if !tags.iter().any(|tag| tag == prefix) {
            return None;
        }

        let helper_tag_prefix = format!("{prefix}-helper-{role}-");
        tags.iter().find_map(|tag| {
            tag.strip_prefix(&helper_tag_prefix)
                .and_then(|uuid| uuid::Uuid::parse_str(uuid).ok())
        })
    }

    fn owned_server_container(
        containers: &[cli::ClusterContainer],
        node: &str,
        prefix: &str,
        server_uuid: uuid::Uuid,
    ) -> Result<Option<cli::ClusterContainer>, anyhow::Error> {
        let mut owned = containers
            .iter()
            .filter(|container| container.node == node)
            .filter(|container| {
                Self::server_from_tags(prefix, &container.tags) == Some(server_uuid)
            })
            .cloned()
            .collect::<Vec<_>>();

        match owned.len() {
            0 => Ok(None),
            1 => Ok(owned.pop()),
            _ => {
                let mut vmids = owned
                    .iter()
                    .map(|container| container.vmid)
                    .collect::<Vec<_>>();
                vmids.sort_unstable();
                Err(anyhow::anyhow!(
                    "multiple Proxmox LXC containers claim server {server_uuid}: VMIDs {}",
                    vmids
                        .into_iter()
                        .map(|vmid| vmid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        }
    }

    fn owned_replacement_container(
        containers: &[cli::ClusterContainer],
        node: &str,
        prefix: &str,
        server_uuid: uuid::Uuid,
    ) -> Result<Option<cli::ClusterContainer>, anyhow::Error> {
        let mut owned = containers
            .iter()
            .filter(|container| container.node == node)
            .filter(|container| {
                Self::replacement_from_tags(prefix, &container.tags) == Some(server_uuid)
            })
            .cloned()
            .collect::<Vec<_>>();

        match owned.len() {
            0 => Ok(None),
            1 => Ok(owned.pop()),
            _ => {
                let mut vmids = owned
                    .iter()
                    .map(|container| container.vmid)
                    .collect::<Vec<_>>();
                vmids.sort_unstable();
                Err(anyhow::anyhow!(
                    "multiple staged Proxmox LXC replacements claim server {server_uuid}: VMIDs {}",
                    vmids
                        .into_iter()
                        .map(|vmid| vmid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        }
    }

    async fn ensure_container_stopped(
        &self,
        container: &cli::ClusterContainer,
        purpose: &str,
    ) -> Result<(), anyhow::Error> {
        let status = match container.status {
            Some(status) => status,
            None => self.cli.status(container.vmid).await?,
        };
        if status == cli::ContainerStatus::Running {
            return Err(anyhow::anyhow!(
                "Proxmox LXC container {} must be stopped before {purpose}",
                container.vmid
            ));
        }
        Ok(())
    }

    async fn remove_staged_replacement(
        &self,
        replacement: &cli::ClusterContainer,
        server_uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        self.ensure_container_stopped(replacement, "discarding a staged image replacement")
            .await?;
        self.cli.destroy(replacement.vmid).await.with_context(|| {
            format!(
                "failed to remove stale staged Proxmox LXC replacement {} for server {server_uuid}",
                replacement.vmid
            )
        })
    }

    fn owned_helper_container(
        containers: &[cli::ClusterContainer],
        node: &str,
        prefix: &str,
        role: &str,
        server_uuid: uuid::Uuid,
    ) -> Result<Option<cli::ClusterContainer>, anyhow::Error> {
        let mut owned = containers
            .iter()
            .filter(|container| container.node == node)
            .filter(|container| {
                Self::helper_from_tags(prefix, role, &container.tags) == Some(server_uuid)
            })
            .cloned()
            .collect::<Vec<_>>();

        match owned.len() {
            0 => Ok(None),
            1 => Ok(owned.pop()),
            _ => {
                let mut vmids = owned
                    .iter()
                    .map(|container| container.vmid)
                    .collect::<Vec<_>>();
                vmids.sort_unstable();
                Err(anyhow::anyhow!(
                    "multiple Proxmox LXC {role} helpers claim server {server_uuid}: VMIDs {}",
                    vmids
                        .into_iter()
                        .map(|vmid| vmid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        }
    }

    async fn server_container(
        &self,
        server_uuid: uuid::Uuid,
    ) -> Result<Option<cli::ClusterContainer>, anyhow::Error> {
        let node = self
            .node
            .get()
            .context("Proxmox VE LXC runtime has not been booted")?;
        let tag_prefix = self.app_config.load().runtime.pve_lxc.tag_prefix.clone();
        Self::owned_server_container(
            &self.cli.list_containers().await?,
            node,
            &tag_prefix,
            server_uuid,
        )
    }

    async fn helper_container(
        &self,
        server_uuid: uuid::Uuid,
        role: &str,
    ) -> Result<Option<cli::ClusterContainer>, anyhow::Error> {
        let node = self
            .node
            .get()
            .context("Proxmox VE LXC runtime has not been booted")?;
        let tag_prefix = self.app_config.load().runtime.pve_lxc.tag_prefix.clone();
        Self::owned_helper_container(
            &self.cli.list_containers().await?,
            node,
            &tag_prefix,
            role,
            server_uuid,
        )
    }

    async fn server_address(
        &self,
        server_uuid: uuid::Uuid,
    ) -> Result<Option<IpAddr>, anyhow::Error> {
        let Some(container) = self.server_container(server_uuid).await? else {
            return Ok(None);
        };
        if container.status != Some(cli::ContainerStatus::Running) {
            return Ok(None);
        }

        let interfaces = self.cli.interfaces(&container.node, container.vmid).await?;
        Ok(PveCli::primary_container_address(&interfaces))
    }

    async fn server_addresses(
        &self,
        server_uuid: uuid::Uuid,
    ) -> Result<Vec<IpAddr>, anyhow::Error> {
        let Some(container) = self.server_container(server_uuid).await? else {
            return Ok(Vec::new());
        };
        if container.status != Some(cli::ContainerStatus::Running) {
            return Ok(Vec::new());
        }

        let interfaces = self.cli.interfaces(&container.node, container.vmid).await?;
        Ok(PveCli::container_addresses(&interfaces))
    }

    fn direct_bridge_firewall_spec(
        server: uuid::Uuid,
        mappings: &HashMap<compact_str::CompactString, Vec<u16>>,
        rules: &[crate::server::firewall::FirewallRule],
        mut container_ips: Vec<IpAddr>,
        vmid: Option<u32>,
    ) -> crate::server::firewall::FirewallServerSpec {
        let mut ports = BTreeSet::new();
        for allocation_ports in mappings.values() {
            ports.extend(allocation_ports.iter().copied());
        }
        container_ips.sort_unstable();
        container_ips.dedup();

        crate::server::firewall::FirewallServerSpec {
            server,
            target: vmid.map(|vmid| crate::server::firewall::FirewallTarget::ProxmoxLxc {
                vmid,
                interface: "net0".to_string(),
            }),
            // Bridged PVE containers do not publish Docker-style host bindings.
            bindings: Vec::new(),
            container_ports: ports.into_iter().collect(),
            container_ips,
            rules: rules.to_vec(),
            files: None,
        }
    }

    fn firewall_spec(
        configuration: &crate::server::configuration::ServerConfiguration,
        container_ips: Vec<IpAddr>,
        vmid: Option<u32>,
    ) -> crate::server::firewall::FirewallServerSpec {
        Self::direct_bridge_firewall_spec(
            configuration.uuid,
            &configuration.allocations.mappings,
            &configuration.firewall,
            container_ips,
            vmid,
        )
    }

    fn edge_forward_payload(
        configuration: &crate::server::configuration::ServerConfiguration,
        destination: Ipv4Addr,
    ) -> Result<Option<(Ipv4Addr, serde_json::Value)>, anyhow::Error> {
        let Some(allocation) = configuration.allocations.default.as_ref() else {
            return Ok(None);
        };
        let public_ip = allocation
            .ip
            .to_string()
            .parse::<Ipv4Addr>()
            .with_context(|| {
                format!(
                    "Proxmox edge forwarding requires an IPv4 primary allocation, got {}",
                    allocation.ip
                )
            })?;
        let ports = configuration
            .allocations
            .mappings
            .get(&allocation.ip.to_compact_string())
            .cloned()
            .unwrap_or_default();
        Ok(Some((
            public_ip,
            serde_json::json!({
                "ip": destination.to_string(),
                // Panel allocations are protocol-neutral. Publish both transports so
                // TCP games and UDP games preserve the same allocation contract.
                "tcp": ports,
                "udp": ports,
            }),
        )))
    }

    fn edge_forwarding_config(
        app_config: &crate::config::Config,
    ) -> Result<Option<(String, String, String, String)>, anyhow::Error> {
        let config = app_config.load();
        let pve = &config.runtime.pve_lxc;
        let interface = pve.edge_wireguard_interface.trim().to_string();
        let user = pve.edge_ssh_user.trim().to_string();
        let identity_path = pve.edge_ssh_identity_path.trim().to_string();
        let known_hosts_path = pve.edge_known_hosts_path.trim().to_string();
        if identity_path.is_empty() && known_hosts_path.is_empty() {
            return Ok(None);
        }
        if interface.is_empty()
            || user.is_empty()
            || identity_path.is_empty()
            || known_hosts_path.is_empty()
        {
            return Err(anyhow::anyhow!(
                "Proxmox edge forwarding requires edge_wireguard_interface, edge_ssh_user, edge_ssh_identity_path, and edge_known_hosts_path"
            ));
        }
        if !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            anyhow::bail!("Proxmox edge SSH user contains unsupported characters: {user}");
        }
        Ok(Some((interface, user, identity_path, known_hosts_path)))
    }

    async fn validate_edge_forwarding_config(
        app_config: &crate::config::Config,
    ) -> Result<(), anyhow::Error> {
        let Some((_, _, identity_path, _)) = Self::edge_forwarding_config(app_config)? else {
            return Ok(());
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let metadata = tokio::fs::metadata(&identity_path).await.with_context(|| {
                format!("failed to inspect Proxmox edge SSH identity {identity_path}")
            })?;
            if !metadata.is_file() {
                anyhow::bail!("Proxmox edge SSH identity is not a regular file: {identity_path}");
            }
            if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
                anyhow::bail!(
                    "Proxmox edge SSH identity must be owned by root and inaccessible to group and other users: {identity_path}"
                );
            }
        }
        Ok(())
    }

    async fn edge_peers(interface: &str) -> Result<Vec<EdgePeer>, anyhow::Error> {
        let mut command = tokio::process::Command::new("/usr/bin/wg");
        command.args(["show", interface, "dump"]).kill_on_drop(true);
        let output = tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
            .await
            .context("timed out inspecting WireGuard peers for Proxmox edge forwarding")?
            .context("failed to inspect WireGuard peers for Proxmox edge forwarding")?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to inspect WireGuard interface {interface}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let dump = String::from_utf8(output.stdout)
            .context("WireGuard peer output was not valid UTF-8")?;
        let mut peers = Vec::new();
        for line in dump.lines().skip(1) {
            let fields = line.split('\t').collect::<Vec<_>>();
            let Some([_, _, endpoint, allowed_ips, ..]) = fields.get(..) else {
                continue;
            };
            if *endpoint == "(none)" {
                continue;
            }
            let endpoint = endpoint
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("WireGuard peer endpoint was invalid: {endpoint}"))?;
            let IpAddr::V4(public_ip) = endpoint.ip() else {
                tracing::warn!(endpoint = %endpoint, "ignoring IPv6 WireGuard edge endpoint because panel allocations require IPv4");
                continue;
            };
            let Some(tunnel_ip) = allowed_ips
                .split(',')
                .filter_map(|cidr| cidr.split_once('/'))
                .find_map(|(ip, prefix)| {
                    (prefix == "32")
                        .then(|| ip.parse::<Ipv4Addr>().ok())
                        .flatten()
                })
            else {
                continue;
            };
            peers.push(EdgePeer {
                public_ip,
                tunnel_ip,
            });
        }
        peers.sort_unstable_by_key(|peer| (peer.public_ip, peer.tunnel_ip));
        peers.dedup();
        Ok(peers)
    }

    async fn edge_ssh(
        host: Ipv4Addr,
        user: &str,
        identity_path: &str,
        known_hosts_path: &str,
        server: uuid::Uuid,
        payload: Option<serde_json::Value>,
    ) -> Result<(), anyhow::Error> {
        let action = if payload.is_some() { "sync" } else { "clear" };
        let mut command = tokio::process::Command::new("/usr/bin/ssh");
        command
            .args([
                "-i",
                identity_path,
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                &format!("UserKnownHostsFile={known_hosts_path}"),
                &format!("{user}@{host}"),
                action,
                &server.to_string(),
            ])
            .stdin(if payload.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .context("failed to start Proxmox edge forwarding SSH command")?;
        if let Some(payload) = payload {
            let bytes = serde_json::to_vec(&payload)
                .context("failed to serialize Proxmox edge forwarding payload")?;
            child
                .stdin
                .as_mut()
                .context("Proxmox edge forwarding SSH stdin was unavailable")?
                .write_all(&bytes)
                .await?;
        }
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(15), child.wait_with_output())
                .await
                .context("timed out synchronizing Proxmox edge forwarding")?
                .context("failed while synchronizing Proxmox edge forwarding")?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Proxmox edge forwarding {action} for {server} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    async fn sync_edge_forwarding(
        app_config: &crate::config::Config,
        server: uuid::Uuid,
        public_ip: Option<Ipv4Addr>,
        payload: Option<serde_json::Value>,
    ) -> Result<(), anyhow::Error> {
        let Some((interface, user, identity_path, known_hosts_path)) =
            Self::edge_forwarding_config(app_config)?
        else {
            return Ok(());
        };
        let peers = Self::edge_peers(&interface).await?;
        for peer in &peers {
            Self::edge_ssh(
                peer.tunnel_ip,
                &user,
                &identity_path,
                &known_hosts_path,
                server,
                None,
            )
            .await?;
        }
        if let Some(payload) = payload {
            let public_ip = public_ip.context(
                "Proxmox edge forwarding payload did not include a public allocation IP",
            )?;
            let peer = peers
                .iter()
                .find(|peer| peer.public_ip == public_ip)
                .with_context(|| {
                    format!("no WireGuard peer on {interface} has endpoint address {public_ip}")
                })?;
            Self::edge_ssh(
                peer.tunnel_ip,
                &user,
                &identity_path,
                &known_hosts_path,
                server,
                Some(payload),
            )
            .await?;
        }
        Ok(())
    }

    fn firewall_file_access(
        server: &Arc<crate::server::InnerServer>,
    ) -> crate::server::firewall::sets::FirewallFileAccess {
        crate::server::firewall::sets::FirewallFileAccess {
            filesystem: (*server.filesystem).clone(),
            notifier: Some(server.filesystem.server_notifier().clone()),
            server: Some(Arc::downgrade(server)),
        }
    }

    async fn sync_server_firewall(
        &self,
        server: &crate::server::Server,
    ) -> Result<(), anyhow::Error> {
        let container = self.server_container(server.uuid).await?;
        let addresses = self.server_addresses(server.uuid).await?;
        let (has_rules, mut spec) = {
            let configuration = server.configuration.read().await;
            (
                !configuration.firewall.is_empty(),
                Self::firewall_spec(
                    &configuration,
                    addresses,
                    container.as_ref().map(|container| container.vmid),
                ),
            )
        };
        if has_rules && spec.container_ips.is_empty() {
            let running = self
                .server_container(server.uuid)
                .await?
                .is_some_and(|container| container.status == Some(cli::ContainerStatus::Running));
            if running {
                return Err(anyhow::anyhow!(
                    "running Proxmox LXC server {} has no usable bridged address; refusing to leave configured firewall rules unapplied",
                    server.uuid
                ));
            }
        }
        spec.files = Some(Self::firewall_file_access(server));
        self.firewall.sync(&spec).await
    }

    fn helper_resources(
        configuration: &crate::server::configuration::ServerConfiguration,
        app_config: &crate::config::Config,
    ) -> Result<cli::ContainerResources, anyhow::Error> {
        let mut resources = PveCli::panel_resources(
            configuration.build.memory_limit,
            configuration.build.overhead_memory,
            configuration.build.swap,
            configuration.build.cpu_limit,
            configuration.build.threads.as_deref(),
        )?;
        let config = app_config.load();
        let limits = &config.docker.installer_limits;

        resources.memory_mib = resources.memory_mib.max(limits.memory.as_mib());
        if let Some(cpu_limit_percent) = resources.cpu_limit_percent
            && cpu_limit_percent < limits.cpu
        {
            resources.cpu_limit_percent = Some(limits.cpu);
        }

        Ok(resources)
    }

    async fn server_mount_specs(
        &self,
        server: &crate::server::Server,
    ) -> Result<Vec<cli::HostBindMountSpec>, anyhow::Error> {
        #[cfg(not(unix))]
        {
            let _ = server;
            return Self::unsupported("bind mounts on this host platform");
        }

        #[cfg(unix)]
        {
            let (server_uuid, hugepages_passthrough_enabled, configured_mounts) = {
                let configuration = server.configuration.read().await;
                (
                    configuration.uuid,
                    configuration.container.hugepages_passthrough_enabled,
                    configuration.mounts.clone(),
                )
            };
            let (host_data_uid, host_data_gid) = {
                let config = self.app_config.load();
                (config.system.user.uid, config.system.user.gid)
            };

            let mut mounts = Vec::with_capacity(configured_mounts.len() + 2);
            mounts.push((
                server.filesystem.get_base_fs_mount_path().await,
                Self::DATA_MOUNT_TARGET.to_string(),
                false,
            ));

            if hugepages_passthrough_enabled {
                mounts.push((
                    PathBuf::from("/dev/hugepages"),
                    "/dev/hugepages".to_string(),
                    false,
                ));
            }

            if !configured_mounts.is_empty() {
                let allowed =
                    crate::server::configuration::AllowedMounts::load(&self.app_config).await;
                for mount in configured_mounts {
                    let source = match mount.resolve_allowed_source(&allowed).await {
                        Ok(source) => source,
                        Err(error) => {
                            tracing::warn!(
                                server = %server_uuid,
                                "not mounting {} -> {} in Proxmox LXC: {error:#}",
                                mount.source,
                                mount.target,
                            );
                            continue;
                        }
                    };
                    mounts.push((source, mount.target.to_string(), mount.read_only));
                }
            }

            let mut specs = Vec::with_capacity(mounts.len());
            for (slot, (source, target, read_only)) in mounts.into_iter().enumerate() {
                let slot = u8::try_from(slot).map_err(|_| {
                    anyhow::anyhow!("Proxmox LXC supports at most 256 bind mount slots")
                })?;
                let source = tokio::fs::canonicalize(&source).await.with_context(|| {
                    format!(
                        "failed to resolve Proxmox bind mount source {}",
                        source.display()
                    )
                })?;
                let metadata = tokio::fs::metadata(&source).await.with_context(|| {
                    format!(
                        "failed to inspect Proxmox bind mount source {}",
                        source.display()
                    )
                })?;
                if !metadata.is_dir() {
                    return Err(anyhow::anyhow!(
                        "Proxmox LXC native mpN bind mounts require a directory source; {} -> {target} is not a directory",
                        source.display()
                    ));
                }
                let source_path = source
                    .into_os_string()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("Proxmox bind mount source is not valid UTF-8"))?;

                specs.push(cli::HostBindMountSpec {
                    slot,
                    source_path,
                    target_path: target,
                    read_only,
                    host_uid: host_data_uid,
                    host_gid: host_data_gid,
                });
            }

            Ok(specs)
        }
    }

    fn device_deny_write(permissions: &str, path: &std::path::Path) -> Result<bool, anyhow::Error> {
        let readable = permissions.contains('r');
        let writable = permissions.contains('w');
        let invalid = permissions
            .chars()
            .any(|permission| !matches!(permission, 'r' | 'w' | 'm'));

        if !readable || invalid {
            return Err(anyhow::anyhow!(
                "Proxmox LXC devN passthrough for {} requires read access and accepts r, w, and m permission flags; requested {permissions}",
                path.display()
            ));
        }

        Ok(!writable)
    }

    async fn server_device_specs(
        &self,
        server: &crate::server::Server,
    ) -> Result<Vec<cli::HostDevicePassthroughSpec>, anyhow::Error> {
        #[cfg(not(unix))]
        {
            let _ = server;
            return Self::unsupported("device passthrough on this host platform");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};

            let (server_uuid, kvm_passthrough_enabled, configured_devices) = {
                let configuration = server.configuration.read().await;
                (
                    configuration.uuid,
                    configuration.container.kvm_passthrough_enabled,
                    configuration.devices.clone(),
                )
            };

            let mut devices = Vec::<(PathBuf, String)>::with_capacity(
                configured_devices.len() + usize::from(kvm_passthrough_enabled),
            );
            if kvm_passthrough_enabled {
                devices.push((PathBuf::from("/dev/kvm"), "rw".to_string()));
            }

            if !configured_devices.is_empty() {
                let allowed =
                    crate::server::configuration::AllowedDevices::load(&self.app_config).await;
                for device in configured_devices {
                    let source = match device.resolve_allowed_source(&allowed).await {
                        Ok(source) => source,
                        Err(error) => {
                            tracing::warn!(
                                server = %server_uuid,
                                "not passing device {} -> {} into Proxmox LXC: {error:#}",
                                device.source,
                                device.target,
                            );
                            continue;
                        }
                    };
                    let source_string = source.to_string_lossy();
                    if device.target.as_str() != source_string.as_ref() {
                        return Err(anyhow::anyhow!(
                            "Proxmox LXC devN passthrough cannot remap device {} to {}; source and target must be identical",
                            source.display(),
                            device.target
                        ));
                    }
                    devices.push((source, device.permissions.to_string()));
                }
            }

            let mut specs = Vec::with_capacity(devices.len());
            for (slot, (path, permissions)) in devices.into_iter().enumerate() {
                let slot = u8::try_from(slot).map_err(|_| {
                    anyhow::anyhow!("Proxmox LXC supports at most 256 device passthrough slots")
                })?;
                let deny_write = Self::device_deny_write(&permissions, &path)?;

                let metadata = tokio::fs::metadata(&path).await.with_context(|| {
                    format!(
                        "failed to inspect Proxmox device passthrough source {}",
                        path.display()
                    )
                })?;
                let file_type = metadata.file_type();
                if !file_type.is_char_device() && !file_type.is_block_device() {
                    return Err(anyhow::anyhow!(
                        "Proxmox device passthrough source {} is not a character or block device",
                        path.display()
                    ));
                }
                let path = path
                    .into_os_string()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("Proxmox device path is not valid UTF-8"))?;

                specs.push(cli::HostDevicePassthroughSpec {
                    slot,
                    path,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    mode: metadata.mode() & 0o777,
                    deny_write,
                });
            }

            Ok(specs)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_helper_container(
        &self,
        server: &crate::server::Server,
        script: &crate::server::installation::InstallationScript,
        role: &str,
        vmid: u32,
        resources: cli::ContainerResources,
        environment: Vec<String>,
        staging_path: &std::path::Path,
        staging_target: &str,
        script_target: &str,
        log_path: &std::path::Path,
    ) -> Result<(), anyhow::Error> {
        let node = self
            .node
            .get()
            .cloned()
            .context("Proxmox VE LXC runtime has not been booted")?;
        let image = PveCli::normalize_oci_reference(script.container_image.trim_end_matches('~'))?;
        let (
            template_storage,
            rootfs_storage,
            bridge,
            vlan_tag,
            rootfs_size_gib,
            tag_prefix,
            unprivileged,
            host_data_uid,
            host_data_gid,
            image_cache_max_age,
        ) = {
            let config = self.app_config.load();
            let pve = &config.runtime.pve_lxc;
            (
                pve.template_storage.clone(),
                pve.rootfs_storage.clone(),
                pve.bridge.clone(),
                pve.vlan_tag,
                pve.rootfs_size_gib,
                pve.tag_prefix.clone(),
                pve.unprivileged,
                config.system.user.uid,
                config.system.user.gid,
                Self::image_cache_max_age(&config),
            )
        };

        let template = {
            let template_lock = self
                .template_provisioning_lock(&node, &template_storage, &image)
                .await;
            let _template = template_lock.lock().await;
            self.cli
                .ensure_oci_template(&node, &template_storage, &image, image_cache_max_age)
                .await?
        };
        let image_tag = PveCli::oci_revision_tag(&template.revision)?;
        let rootfs_storage = self
            .rootfs_storage(&node, rootfs_storage, rootfs_size_gib)
            .await?;
        let network = Self::dhcp_network(&bridge, vlan_tag)?;
        let staging_path_utf8 = staging_path
            .to_str()
            .context("Proxmox helper staging path is not valid UTF-8")?;
        let log_path = log_path
            .to_str()
            .context("Proxmox helper log path is not valid UTF-8")?;
        let create = cli::CreateContainerSpec {
            vmid,
            template: template.volid,
            hostname: format!("{role}-{vmid}"),
            rootfs_storage,
            rootfs_size_gib,
            memory_mib: resources.memory_mib,
            swap_mib: resources.swap_mib,
            cpu_limit_percent: resources.cpu_limit_percent,
            cores: resources.cores,
            network,
            tags: vec![
                tag_prefix.clone(),
                Self::helper_tag(&tag_prefix, role, server.uuid),
                image_tag,
            ],
            unprivileged,
        };
        let mounts = [
            cli::HostBindMountSpec {
                slot: 0,
                source_path: server.filesystem.base().to_string(),
                target_path: "/mnt/server".to_string(),
                read_only: false,
                host_uid: host_data_uid,
                host_gid: host_data_gid,
            },
            cli::HostBindMountSpec {
                slot: 1,
                source_path: staging_path_utf8.to_string(),
                target_path: staging_target.to_string(),
                read_only: false,
                host_uid: host_data_uid,
                host_gid: host_data_gid,
            },
        ];

        let helper_wrapper_name = "calagopus-helper-entrypoint";
        let helper_wrapper_path = staging_path.join(helper_wrapper_name);
        tokio::fs::write(
            &helper_wrapper_path,
            r#"#!/bin/sh
attempt=0
while [ "$attempt" -lt 120 ]; do
    if grep -q '^eth0[[:space:]]*00000000[[:space:]]' /proc/net/route; then
        "$@"
        status=$?
        if [ -n "${INSTALL_STATUS_FILE:-}" ]; then
            if [ "$status" -eq 0 ]; then
                : > "$INSTALL_STATUS_FILE"
            else
                printf 'installer exited with status %s\n' "$status" > "$INSTALL_STATUS_FILE"
            fi
        fi
        exit "$status"
    fi
    attempt=$((attempt + 1))
    sleep 0.25
done
echo 'timed out waiting for Proxmox DHCP' >&2
if [ -n "${INSTALL_STATUS_FILE:-}" ]; then
    printf '%s\n' 'timed out waiting for Proxmox DHCP' > "$INSTALL_STATUS_FILE"
fi
exit 1
"#,
        )
        .await
        .context("failed to write Proxmox helper entrypoint wrapper")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(
                &helper_wrapper_path,
                std::fs::Permissions::from_mode(0o755),
            )
            .await
            .context("failed to make Proxmox helper entrypoint wrapper executable")?;
        }

        self.cli.create_with_bind_mounts(&create, &mounts).await?;
        // PVE applies a host-managed DHCP lease immediately after CT init starts.
        // Keep PID 1 alive until that lease installs a default route; otherwise a
        // fast installer can attempt its first download and exit before `pct`
        // has a chance to run its DHCP hook.
        let init_command = PveCli::encode_init_command(&[
            format!("{staging_target}/{helper_wrapper_name}"),
            script.entrypoint.to_string(),
            script_target.to_string(),
        ])?;
        let (pids_limit, io_weight) = {
            let configuration = server.configuration.read().await;
            (
                Self::pids_limit(&self.app_config),
                PveCli::cgroup2_io_weight(configuration.build.io_weight)?,
            )
        };
        let runtime_config = cli::RuntimeConfigSpec {
            vmid,
            environment,
            halt_signal: None,
            init_command: Some(init_command),
            console_logfile: Some(log_path.to_string()),
            cpuset_cpus: resources.cpuset_cpus.clone(),
            pids_limit,
            io_weight,
            memory_unlimited: resources.memory_unlimited,
            swap_unlimited: resources.swap_unlimited,
            managed_file_mounts: None,
        };

        if let Err(error) = self.cli.apply_runtime_config(&runtime_config).await {
            if let Err(cleanup_error) = self.cli.destroy(vmid).await {
                tracing::warn!(
                    server = %server.uuid,
                    vmid,
                    "failed to remove newly created Proxmox helper after runtime configuration failed: {cleanup_error:#}"
                );
            }
            return Err(error.context("failed to configure Proxmox helper LXC"));
        }

        Ok(())
    }

    async fn prepare_server_container(
        &self,
        server: &crate::server::Server,
    ) -> Result<(u32, cli::ContainerOciUser, bool), anyhow::Error> {
        let node = self
            .node
            .get()
            .cloned()
            .context("Proxmox VE LXC runtime has not been booted")?;

        let (server_uuid, image, resources, primary_allocation) = {
            let configuration = server.configuration.read().await;
            let resources = PveCli::panel_resources(
                configuration.build.memory_limit,
                configuration.build.overhead_memory,
                configuration.build.swap,
                configuration.build.cpu_limit,
                configuration.build.threads.as_deref(),
            )?;

            (
                configuration.uuid,
                configuration
                    .container
                    .image
                    .trim_end_matches('~')
                    .to_string(),
                resources,
                configuration
                    .allocations
                    .default
                    .as_ref()
                    .map(|allocation| allocation.ip.to_string()),
            )
        };
        let image = PveCli::normalize_oci_reference(&image)?;
        let mounts = self.server_mount_specs(server).await?;
        let devices = self.server_device_specs(server).await?;

        let (
            template_storage,
            rootfs_storage,
            bridge,
            vlan_tag,
            network_prefix,
            gateway,
            rootfs_size_gib,
            tag_prefix,
            unprivileged,
            edge_forwarding,
            image_cache_max_age,
        ) = {
            let config = self.app_config.load();
            let pve = &config.runtime.pve_lxc;
            (
                pve.template_storage.clone(),
                pve.rootfs_storage.clone(),
                pve.bridge.clone(),
                pve.vlan_tag,
                pve.network_prefix,
                pve.gateway.clone(),
                pve.rootfs_size_gib,
                pve.tag_prefix.clone(),
                pve.unprivileged,
                Self::edge_forwarding_config(&self.app_config)?.is_some(),
                Self::image_cache_max_age(&config),
            )
        };
        let network = if edge_forwarding {
            Self::dhcp_network(&bridge, vlan_tag)?
        } else {
            Self::network_for_allocation(
                &bridge,
                vlan_tag,
                network_prefix,
                gateway.as_deref(),
                primary_allocation.as_deref(),
            )?
        };

        let template = {
            let template_lock = self
                .template_provisioning_lock(&node, &template_storage, &image)
                .await;
            let _template = template_lock.lock().await;
            self.cli
                .ensure_oci_template(&node, &template_storage, &image, image_cache_max_age)
                .await?
        };
        let image_tag = PveCli::oci_revision_tag(&template.revision)?;
        let containers = self.cli.list_containers().await?;
        let existing = Self::owned_server_container(&containers, &node, &tag_prefix, server_uuid)?;
        let replacement =
            Self::owned_replacement_container(&containers, &node, &tag_prefix, server_uuid)?;
        let plan = Self::plan_server_container(existing.as_ref(), replacement.as_ref(), &image_tag);

        let final_tags = vec![
            tag_prefix.clone(),
            Self::server_tag(&tag_prefix, server_uuid),
            image_tag.clone(),
        ];

        match plan {
            ServerContainerPlan::Reuse {
                vmid,
                stale_replacement,
            } => {
                if let Some(stale_vmid) = stale_replacement {
                    let stale = replacement
                        .as_ref()
                        .filter(|container| container.vmid == stale_vmid)
                        .context(
                            "staged Proxmox replacement disappeared from the inventory plan",
                        )?;
                    self.remove_staged_replacement(stale, server_uuid).await?;
                }

                self.cli.set_resources(vmid, &resources).await?;
                self.cli.set_network(vmid, &network).await?;
                let user = self.cli.oci_user(vmid).await?;
                self.cli
                    .configure_mounts_and_devices(vmid, user, &mounts, &devices)
                    .await?;
                return Ok((vmid, user, false));
            }
            ServerContainerPlan::RecoverStaged { staged_vmid } => {
                let staged = replacement
                    .as_ref()
                    .filter(|container| container.vmid == staged_vmid)
                    .context("staged Proxmox replacement disappeared from the inventory plan")?;
                self.ensure_container_stopped(staged, "recovering a staged image replacement")
                    .await?;
                self.cli.set_resources(staged_vmid, &resources).await?;
                self.cli.set_network(staged_vmid, &network).await?;
                let user = self.cli.oci_user(staged_vmid).await?;
                self.cli
                    .configure_mounts_and_devices(staged_vmid, user, &mounts, &devices)
                    .await?;
                self.cli
                    .set_tags(staged_vmid, &final_tags)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to promote staged Proxmox LXC replacement {staged_vmid} for server {server_uuid}"
                        )
                    })?;
                return Ok((staged_vmid, user, true));
            }
            ServerContainerPlan::CreateFresh { stale_replacement } => {
                if let Some(stale_vmid) = stale_replacement {
                    let stale = replacement
                        .as_ref()
                        .filter(|container| container.vmid == stale_vmid)
                        .context(
                            "staged Proxmox replacement disappeared from the inventory plan",
                        )?;
                    self.remove_staged_replacement(stale, server_uuid).await?;
                }
            }
            ServerContainerPlan::ReplaceFresh {
                old_vmid,
                stale_replacement,
            } => {
                let old = existing
                    .as_ref()
                    .filter(|container| container.vmid == old_vmid)
                    .context("owned Proxmox container disappeared from the inventory plan")?;
                self.ensure_container_stopped(old, "replacing its OCI image")
                    .await?;
                if let Some(stale_vmid) = stale_replacement {
                    let stale = replacement
                        .as_ref()
                        .filter(|container| container.vmid == stale_vmid)
                        .context(
                            "staged Proxmox replacement disappeared from the inventory plan",
                        )?;
                    self.remove_staged_replacement(stale, server_uuid).await?;
                }
            }
            ServerContainerPlan::ReplaceWithStaged {
                old_vmid,
                staged_vmid,
            } => {
                let old = existing
                    .as_ref()
                    .filter(|container| container.vmid == old_vmid)
                    .context("owned Proxmox container disappeared from the inventory plan")?;
                let staged = replacement
                    .as_ref()
                    .filter(|container| container.vmid == staged_vmid)
                    .context("staged Proxmox replacement disappeared from the inventory plan")?;
                self.ensure_container_stopped(old, "replacing its OCI image")
                    .await?;
                self.ensure_container_stopped(staged, "promoting a staged image replacement")
                    .await?;

                self.cli.set_resources(staged_vmid, &resources).await?;
                self.cli.set_network(staged_vmid, &network).await?;
                let user = self.cli.oci_user(staged_vmid).await?;
                self.cli
                    .configure_mounts_and_devices(staged_vmid, user, &mounts, &devices)
                    .await?;

                if let Err(error) = self.cli.destroy(old_vmid).await {
                    return Err(error.context(format!(
                        "failed to remove old Proxmox LXC container {old_vmid} while staged replacement {staged_vmid} remains recoverable"
                    )));
                }
                self.cli
                    .set_tags(staged_vmid, &final_tags)
                    .await
                    .with_context(|| {
                        format!(
                            "old Proxmox LXC container {old_vmid} was removed, but failed to promote staged replacement {staged_vmid}; the staged replacement remains recoverable on the next setup"
                        )
                    })?;
                return Ok((staged_vmid, user, true));
            }
        }

        let rootfs_storage = self
            .rootfs_storage(&node, rootfs_storage, rootfs_size_gib)
            .await?;
        let replacing = matches!(plan, ServerContainerPlan::ReplaceFresh { .. });
        let create_tags = if replacing {
            vec![
                tag_prefix.clone(),
                Self::replacement_tag(&tag_prefix, server_uuid),
                image_tag,
            ]
        } else {
            final_tags.clone()
        };
        let mut created = None;
        let min_vmid = self.app_config.load().runtime.pve_lxc.min_vmid;
        for _ in 0..3 {
            let _vmid_lock = self.cli.lock_vmid_allocation().await?;
            let vmid = self.cli.next_vmid(min_vmid).await?;
            let create = cli::CreateContainerSpec {
                vmid,
                template: template.volid.clone(),
                hostname: server_uuid.to_string(),
                rootfs_storage: rootfs_storage.clone(),
                rootfs_size_gib,
                memory_mib: resources.memory_mib,
                swap_mib: resources.swap_mib,
                cpu_limit_percent: resources.cpu_limit_percent,
                cores: resources.cores,
                network: network.clone(),
                tags: create_tags.clone(),
                unprivileged,
            };
            match self
                .cli
                .create_with_bind_mounts_and_devices(&create, &mounts, &devices)
                .await
            {
                Ok(user) => {
                    created = Some((vmid, user));
                    break;
                }
                Err(error) if Self::vmid_conflict(&error) => {
                    tracing::warn!(vmid, "retrying Proxmox LXC create after VMID collision");
                }
                Err(error) => return Err(error),
            }
        }
        let (vmid, user) = created
            .context("failed to create Proxmox LXC after three VMID allocation collisions")?;

        if let ServerContainerPlan::ReplaceFresh { old_vmid, .. } = plan {
            if let Err(error) = self.cli.destroy(old_vmid).await {
                return match self.cli.destroy(vmid).await {
                    Ok(()) => Err(error.context(format!(
                        "failed to remove old Proxmox LXC container {old_vmid}; discarded prepared replacement {vmid}"
                    ))),
                    Err(cleanup_error) => Err(anyhow::anyhow!(
                        "failed to remove old Proxmox LXC container {old_vmid}: {error:#}; additionally failed to discard staged replacement {vmid}: {cleanup_error:#}"
                    )),
                };
            }

            self.cli.set_tags(vmid, &final_tags).await.with_context(|| {
                format!(
                    "old Proxmox LXC container {old_vmid} was removed, but failed to promote staged replacement {vmid}; the staged replacement remains recoverable on the next setup"
                )
            })?;
        }

        Ok((vmid, user, true))
    }
}

#[async_trait::async_trait]
impl ServerExecutor for PveLxcExecutor {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        if !cfg!(target_os = "linux") {
            return Err(anyhow::anyhow!(
                "Proxmox VE LXC runtime requires a Linux host running Proxmox VE"
            ));
        }
        if !self.app_config.load().runtime.pve_lxc.unprivileged {
            return Err(anyhow::anyhow!(
                "Proxmox VE LXC runtime currently requires unprivileged containers because per-mount idmap is required for Wings-owned server data"
            ));
        }
        Self::validate_edge_forwarding_config(&self.app_config).await?;

        let raw_version = self.cli.version().await?;
        let version = PveVersion::parse(&raw_version)?;
        if !version.is_supported() {
            return Err(anyhow::anyhow!(
                "Proxmox VE LXC runtime requires Proxmox VE 9.2 or newer, found {raw_version}"
            ));
        }

        let configured_node = self.app_config.load().runtime.pve_lxc.node.clone();
        let local_node = self.cli.local_node().await?;
        let node = Self::runtime_node(&configured_node, &local_node)?;
        self.node
            .set(node.clone())
            .map_err(|_| anyhow::anyhow!("Proxmox VE LXC runtime was booted more than once"))?;

        self.firewall
            .boot()
            .await
            .context("failed to initialize Proxmox LXC host firewall")?;

        let min_vmid = self.app_config.load().runtime.pve_lxc.min_vmid;
        let next_vmid = self.cli.next_vmid(min_vmid).await?;
        tracing::info!(
            pve_version = %raw_version,
            node = %node,
            next_vmid,
            min_vmid,
            "Proxmox VE LXC runtime is available"
        );

        Ok(())
    }

    async fn reconcile_firewall(
        &self,
        servers: &[crate::remote::servers::RawServer],
    ) -> Result<(), anyhow::Error> {
        let node = self
            .node
            .get()
            .context("Proxmox VE LXC runtime has not been booted")?;
        let tag_prefix = self.app_config.load().runtime.pve_lxc.tag_prefix.clone();
        let containers = self.cli.list_containers().await?;
        let mut specs = Vec::with_capacity(servers.len());
        for server in servers {
            let container =
                Self::owned_server_container(&containers, node, &tag_prefix, server.settings.uuid)?;
            let running = container
                .as_ref()
                .is_some_and(|container| container.status == Some(cli::ContainerStatus::Running));
            let addresses = if let Some(container) = container.as_ref().filter(|_| running) {
                PveCli::container_addresses(
                    &self
                        .cli
                        .interfaces(&container.node, container.vmid)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to resolve Proxmox LXC addresses while reconciling firewall for {}",
                                server.settings.uuid
                            )
                        })?,
                )
            } else {
                Vec::new()
            };
            let mut spec = Self::firewall_spec(
                &server.settings,
                addresses,
                container.as_ref().map(|container| container.vmid),
            );

            if !server.settings.firewall.is_empty() && spec.container_ips.is_empty() && running {
                return Err(anyhow::anyhow!(
                    "running Proxmox LXC server {} has no usable bridged address; refusing to reconcile configured firewall rules without a destination",
                    server.settings.uuid
                ));
            }

            if spec.references_files() {
                match crate::server::filesystem::cap::CapFilesystem::new(
                    &self.app_config.data_path(spec.server),
                )
                .await
                {
                    Ok(filesystem) => {
                        spec.files = Some(crate::server::firewall::sets::FirewallFileAccess {
                            filesystem,
                            notifier: None,
                            server: None,
                        });
                    }
                    Err(error) => {
                        tracing::warn!(
                            server = %spec.server,
                            "failed to open the server directory for its firewall source files: {error}"
                        );
                    }
                }
            }

            specs.push(spec);
        }

        self.firewall.reconcile(&specs).await
    }

    async fn setup_server_process(
        &self,
        server: &crate::server::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        let (vmid, _oci_user, created) = self.prepare_server_container(server).await?;
        let runtime_config = match PveProcessHandle::runtime_config(
            server,
            &self.app_config,
            &self.cli,
            vmid,
        )
        .await
        {
            Ok(runtime_config) => runtime_config,
            Err(error) => {
                if created && let Err(cleanup_error) = self.cli.destroy(vmid).await {
                    tracing::warn!(
                        server = %server.uuid,
                        vmid,
                        "failed to remove newly created Proxmox LXC container after managed file preparation failed: {cleanup_error:#}"
                    );
                }
                return Err(error.context("failed to prepare managed Proxmox container files"));
            }
        };

        if let Err(error) = self.cli.apply_runtime_config(&runtime_config).await {
            if created && let Err(cleanup_error) = self.cli.destroy(vmid).await {
                tracing::warn!(
                    server = %server.uuid,
                    vmid,
                    "failed to remove newly created Proxmox LXC container after runtime configuration failed: {cleanup_error:#}"
                );
            }
            return Err(error.context("failed to apply Proxmox LXC runtime configuration"));
        }

        if let Err(error) = self.sync_server_firewall(server).await {
            let has_rules = !server.configuration.read().await.firewall.is_empty();
            if has_rules {
                if created && let Err(cleanup_error) = self.cli.destroy(vmid).await {
                    tracing::warn!(
                        server = %server.uuid,
                        vmid,
                        "failed to remove newly created Proxmox LXC container after firewall setup failed: {cleanup_error:#}"
                    );
                }
                return Err(error.context("failed to prepare Proxmox LXC server firewall"));
            }

            tracing::warn!(
                server = %server.uuid,
                "failed to clear Proxmox LXC firewall state for a server without rules: {error:#}"
            );
        }

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let node = self
            .node
            .get()
            .cloned()
            .context("Proxmox VE LXC runtime has not been booted")?;
        let handle = match PveProcessHandle::new(
            vmid,
            node,
            self.cli.clone(),
            Arc::clone(&self.stats_sampler),
            server,
            Arc::clone(&self.app_config),
            Arc::clone(&self.firewall),
            status_tx,
            true,
            true,
        )
        .await
        {
            Ok(handle) => Arc::new(handle),
            Err(error) => {
                if created && let Err(cleanup_error) = self.cli.destroy(vmid).await {
                    tracing::warn!(
                        server = %server.uuid,
                        vmid,
                        "failed to remove newly created Proxmox LXC container after process setup failed: {cleanup_error:#}"
                    );
                }
                return Err(error.context("failed to create Proxmox LXC process handle"));
            }
        };

        Ok((handle, status_rx))
    }

    async fn attach_server_process(
        &self,
        server: &crate::server::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        let container = self
            .server_container(server.uuid)
            .await?
            .context("no Proxmox LXC container found for server")?;
        if container.status != Some(cli::ContainerStatus::Running) {
            return Err(anyhow::anyhow!(
                "Proxmox LXC container {} for server {} is not running",
                container.vmid,
                server.uuid
            ));
        }

        // Reconcile runtime-owned files and mount entries when Wings adopts an
        // already-running container. This covers features enabled after the
        // container was created, including Tundra's managed /etc/hosts file.
        // LXC applies a newly-added mount entry on the container's next start,
        // while creating the backing file immediately lets Tundra reconcile
        // its state without racing a missing host path.
        self.cli
            .apply_runtime_config(
                &PveProcessHandle::runtime_config(
                    server,
                    &self.app_config,
                    &self.cli,
                    container.vmid,
                )
                .await?,
            )
            .await
            .context("failed to reconcile an adopted Proxmox LXC runtime configuration")?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            PveProcessHandle::new(
                container.vmid,
                container.node.clone(),
                self.cli.clone(),
                Arc::clone(&self.stats_sampler),
                server,
                Arc::clone(&self.app_config),
                Arc::clone(&self.firewall),
                status_tx,
                false,
                false,
            )
            .await?,
        );

        if let Err(error) = handle.sync_firewall(true).await {
            let configuration = server.configuration.read().await;
            let requires_network_policy = !configuration.firewall.is_empty()
                || (configuration.allocations.default.is_some()
                    && Self::edge_forwarding_config(&self.app_config)?.is_some());
            drop(configuration);
            if requires_network_policy {
                return Err(handle
                    .stop_after_firewall_failure(
                        error,
                        "failed to attach Proxmox LXC network policy",
                    )
                    .await);
            }
            tracing::warn!(
                server = %server.uuid,
                "failed to clear Proxmox LXC firewall state for a server without rules: {error:#}"
            );
        }

        Ok((handle, status_rx))
    }

    async fn cleanup_server_process(
        &self,
        server: &crate::server::Server,
    ) -> Result<(), anyhow::Error> {
        if let Err(error) = self.firewall.clear(server.uuid).await {
            tracing::warn!(
                server = %server.uuid,
                "failed to clear Proxmox LXC firewall rules during cleanup: {error:#}"
            );
        }
        Self::sync_edge_forwarding(&self.app_config, server.uuid, None, None).await?;

        let Some(container) = self.server_container(server.uuid).await? else {
            PveProcessHandle::cleanup_managed_file_staging(&self.app_config, server.uuid).await?;
            return Ok(());
        };

        let status = match container.status {
            Some(status) => status,
            None => self.cli.status(container.vmid).await?,
        };
        if status == cli::ContainerStatus::Running {
            self.cli.stop(container.vmid).await?;
        }
        self.cli.destroy(container.vmid).await?;
        PveProcessHandle::cleanup_managed_file_staging(&self.app_config, server.uuid).await?;

        Ok(())
    }

    async fn setup_installation_process(
        &self,
        server: &crate::server::Server,
        script: &crate::server::installation::InstallationScript,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        if let Some(container) = self
            .helper_container(server.uuid, Self::INSTALLER_HELPER_ROLE)
            .await?
        {
            return Err(anyhow::anyhow!(
                "Proxmox installer helper already exists for server {} as VMID {}",
                server.uuid,
                container.vmid
            ));
        }

        let (resources, mut environment, host_data_uid, host_data_gid) = {
            let configuration = server.configuration.read().await;
            let config = self.app_config.load();
            (
                Self::helper_resources(&configuration, &self.app_config)?,
                configuration.environment(&self.app_config),
                config.system.user.uid,
                config.system.user.gid,
            )
        };
        for (key, value) in &script.environment {
            environment.push(format!(
                "{key}={}",
                match value {
                    serde_json::Value::String(value) => value.clone(),
                    other => other.to_string(),
                }
            ));
        }
        environment.push(format!(
            "INSTALL_STATUS_FILE=/mnt/install/{}",
            crate::server::installation::INSTALL_STATUS_FILE_NAME
        ));
        environment.push(format!(
            "INSTALL_PROGRESS_FILE=/mnt/install/{}",
            crate::server::installation::INSTALL_PROGRESS_FILE_NAME
        ));

        let staging_path = self.app_config.tmp_data_path(server.uuid);
        let status_path = staging_path.join(crate::server::installation::INSTALL_STATUS_FILE_NAME);
        let progress_path =
            staging_path.join(crate::server::installation::INSTALL_PROGRESS_FILE_NAME);
        let log_path = staging_path.join("pve-installer-console.log");
        async {
            tokio::fs::create_dir_all(&staging_path).await?;
            tokio::fs::write(
                staging_path.join("install.sh"),
                script.script.replace("\r\n", "\n"),
            )
            .await?;
            // The helper clears this marker only after the installer exits
            // successfully. A killed helper therefore cannot be mistaken for a
            // completed installation.
            tokio::fs::write(&status_path, "installation process did not complete\n").await?;
            tokio::fs::write(&progress_path, "").await?;
            tokio::fs::File::create(&log_path).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&staging_path, std::fs::Permissions::from_mode(0o755))
                    .await?;
                tokio::fs::set_permissions(&status_path, std::fs::Permissions::from_mode(0o644))
                    .await?;
                tokio::fs::set_permissions(&progress_path, std::fs::Permissions::from_mode(0o644))
                    .await?;
                let status_path = status_path.clone();
                let progress_path = progress_path.clone();
                tokio::task::spawn_blocking(move || {
                    std::os::unix::fs::chown(
                        &status_path,
                        Some(host_data_uid),
                        Some(host_data_gid),
                    )?;
                    std::os::unix::fs::chown(
                        &progress_path,
                        Some(host_data_uid),
                        Some(host_data_gid),
                    )
                })
                .await
                .map_err(std::io::Error::other)??;
            }

            Ok::<(), std::io::Error>(())
        }
        .await
        .with_context(|| {
            format!(
                "failed to prepare Proxmox installer staging directory {}",
                staging_path.display()
            )
        })?;

        let mut created_vmid = None;
        let min_vmid = self.app_config.load().runtime.pve_lxc.min_vmid;
        for _ in 0..3 {
            let _vmid_lock = self.cli.lock_vmid_allocation().await?;
            let vmid = self.cli.next_vmid(min_vmid).await?;
            match self
                .create_helper_container(
                    server,
                    script,
                    Self::INSTALLER_HELPER_ROLE,
                    vmid,
                    resources.clone(),
                    environment.clone(),
                    &staging_path,
                    "/mnt/install",
                    "/mnt/install/install.sh",
                    &log_path,
                )
                .await
            {
                Ok(()) => {
                    created_vmid = Some(vmid);
                    break;
                }
                Err(error) if Self::vmid_conflict(&error) => {
                    tracing::warn!(
                        vmid,
                        "retrying Proxmox installer create after VMID collision"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        let vmid = created_vmid
            .context("failed to create Proxmox installer after three VMID allocation collisions")?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = match PveHelperProcessHandle::new(
            vmid,
            self.cli.clone(),
            server,
            Arc::clone(&self.app_config),
            log_path,
            status_tx,
            false,
            false,
            false,
            None,
        )
        .await
        {
            Ok(handle) => Arc::new(handle),
            Err(error) => {
                if let Err(cleanup_error) = self.cli.destroy(vmid).await {
                    tracing::warn!(
                        server = %server.uuid,
                        vmid,
                        "failed to remove Proxmox installer helper after handle setup failed: {cleanup_error:#}"
                    );
                }
                return Err(error.context("failed to create Proxmox installer process handle"));
            }
        };

        Ok((handle, status_rx))
    }

    async fn attach_installation_process(
        &self,
        server: &crate::server::Server,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        let container = self
            .helper_container(server.uuid, Self::INSTALLER_HELPER_ROLE)
            .await?
            .context("no Proxmox installer helper found")?;
        let status = match container.status {
            Some(status) => status,
            None => self.cli.status(container.vmid).await?,
        };
        if status != cli::ContainerStatus::Running {
            return Err(anyhow::anyhow!(
                "Proxmox installer helper {} for server {} is not running",
                container.vmid,
                server.uuid
            ));
        }

        let log_path = self
            .app_config
            .tmp_data_path(server.uuid)
            .join("pve-installer-console.log");
        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            PveHelperProcessHandle::new(
                container.vmid,
                self.cli.clone(),
                server,
                Arc::clone(&self.app_config),
                log_path,
                status_tx,
                true,
                true,
                false,
                None,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_installation_process(
        &self,
        server: &crate::server::Server,
    ) -> Result<(), anyhow::Error> {
        let Some(container) = self
            .helper_container(server.uuid, Self::INSTALLER_HELPER_ROLE)
            .await?
        else {
            return Ok(());
        };
        let status = match container.status {
            Some(status) => status,
            None => self.cli.status(container.vmid).await?,
        };
        if status == cli::ContainerStatus::Running {
            self.cli.stop(container.vmid).await?;
        }
        self.cli.destroy(container.vmid).await?;
        Ok(())
    }

    async fn setup_script_process(
        &self,
        server: &crate::server::Server,
        script: &crate::server::installation::InstallationScript,
    ) -> Result<(Arc<dyn ProcessHandle>, StatusReceiver), anyhow::Error> {
        let (resources, mut environment) = {
            let configuration = server.configuration.read().await;
            (
                Self::helper_resources(&configuration, &self.app_config)?,
                configuration.environment(&self.app_config),
            )
        };
        for (key, value) in &script.environment {
            environment.push(format!(
                "{key}={}",
                match value {
                    serde_json::Value::String(value) => value.clone(),
                    other => other.to_string(),
                }
            ));
        }

        let staging_path = self
            .app_config
            .tmp_data_path(server.uuid)
            .join(format!("pve-script-{}", uuid::Uuid::new_v4()));
        let log_path = staging_path.join("console.log");
        tokio::fs::create_dir_all(&staging_path).await?;
        tokio::fs::write(
            staging_path.join("script.sh"),
            script.script.replace("\r\n", "\n"),
        )
        .await?;
        tokio::fs::File::create(&log_path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&staging_path, std::fs::Permissions::from_mode(0o755))
                .await?;
        }

        let mut created_vmid = None;
        let min_vmid = self.app_config.load().runtime.pve_lxc.min_vmid;
        for _ in 0..3 {
            let _vmid_lock = self.cli.lock_vmid_allocation().await?;
            let vmid = self.cli.next_vmid(min_vmid).await?;
            match self
                .create_helper_container(
                    server,
                    script,
                    Self::SCRIPT_HELPER_ROLE,
                    vmid,
                    resources.clone(),
                    environment.clone(),
                    &staging_path,
                    "/mnt/script",
                    "/mnt/script/script.sh",
                    &log_path,
                )
                .await
            {
                Ok(()) => {
                    created_vmid = Some(vmid);
                    break;
                }
                Err(error) if Self::vmid_conflict(&error) => {
                    tracing::warn!(vmid, "retrying Proxmox script create after VMID collision");
                }
                Err(error) => {
                    tokio::fs::remove_dir_all(&staging_path).await.ok();
                    return Err(error);
                }
            }
        }
        let Some(vmid) = created_vmid else {
            tokio::fs::remove_dir_all(&staging_path).await.ok();
            return Err(anyhow::anyhow!(
                "failed to create Proxmox script helper after three VMID allocation collisions"
            ));
        };

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = match PveHelperProcessHandle::new(
            vmid,
            self.cli.clone(),
            server,
            Arc::clone(&self.app_config),
            log_path,
            status_tx,
            false,
            false,
            true,
            Some(staging_path.clone()),
        )
        .await
        {
            Ok(handle) => Arc::new(handle),
            Err(error) => {
                self.cli.destroy(vmid).await.ok();
                tokio::fs::remove_dir_all(&staging_path).await.ok();
                return Err(error.context("failed to create Proxmox script process handle"));
            }
        };

        Ok((handle, status_rx))
    }

    async fn resolve_internal_target(
        &self,
        server: &crate::server::Server,
        port: u16,
    ) -> Result<Option<std::net::SocketAddr>, anyhow::Error> {
        Ok(self
            .server_address(server.uuid)
            .await?
            .map(|address| std::net::SocketAddr::new(address, port)))
    }

    async fn resolve_published_address(&self, server: &crate::server::Server) -> Option<IpAddr> {
        match self.server_address(server.uuid).await {
            Ok(address) => address,
            Err(error) => {
                tracing::error!(
                    server = %server.uuid,
                    "failed to resolve Proxmox LXC address: {error:#}"
                );
                None
            }
        }
    }

    async fn container_refs(
        &self,
        servers: &[crate::server::Server],
    ) -> HashMap<uuid::Uuid, String> {
        let Some(node) = self.node.get() else {
            tracing::error!("cannot inventory Proxmox containers before runtime boot");
            return HashMap::new();
        };
        let containers = match self.cli.list_containers().await {
            Ok(containers) => containers,
            Err(err) => {
                tracing::error!("failed to list Proxmox LXC containers: {err:#}");
                return HashMap::new();
            }
        };
        let tag_prefix = self.app_config.load().runtime.pve_lxc.tag_prefix.clone();
        let requested_servers: HashSet<_> = servers.iter().map(|server| server.uuid).collect();

        let owned = containers
            .into_iter()
            .filter(|container| container.node == *node)
            .filter_map(|container| {
                let server_uuid = Self::server_from_tags(&tag_prefix, &container.tags)?;
                requested_servers
                    .contains(&server_uuid)
                    .then_some((server_uuid, container))
            })
            .collect::<Vec<_>>();

        let runtime_statuses = match self.cli.node_runtime_statuses(node).await {
            Ok(statuses) => statuses
                .into_iter()
                .map(|status| (status.vmid, status))
                .collect::<HashMap<_, _>>(),
            Err(error) => {
                tracing::error!("failed to list Proxmox LXC runtime status: {error:#}");
                return HashMap::new();
            }
        };

        let mut references = HashMap::new();
        for (server_uuid, container) in owned {
            if container.status != Some(cli::ContainerStatus::Running) {
                continue;
            }
            match runtime_statuses.get(&container.vmid) {
                Some(status) if status.status == cli::ContainerStatus::Running => {
                    if let Some(pid) = status.pid.filter(|pid| *pid > 0) {
                        references.insert(server_uuid, format!("pid:{pid}"));
                    } else {
                        tracing::warn!(
                            server = %server_uuid,
                            vmid = container.vmid,
                            "running Proxmox LXC did not expose an init PID for private networking"
                        );
                    }
                }
                Some(_) => {}
                None => tracing::warn!(
                    server = %server_uuid,
                    vmid = container.vmid,
                    "Proxmox node inventory omitted an LXC needed for private networking"
                ),
            }
        }

        references
    }

    async fn used_ports(
        &self,
        ips: &[IpAddr],
    ) -> Result<HashMap<IpAddr, Vec<UsedPort>>, anyhow::Error> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }

        let node = self
            .node
            .get()
            .context("Proxmox VE LXC runtime has not been booted")?;
        let requested = ips.iter().copied().collect::<HashSet<_>>();
        let tag_prefix = self.app_config.load().runtime.pve_lxc.tag_prefix.clone();
        let mut used = ips
            .iter()
            .copied()
            .map(|ip| (ip, HashMap::<u16, Option<uuid::Uuid>>::new()))
            .collect::<HashMap<_, _>>();

        let mut containers = self.cli.list_containers().await?;
        containers.sort_unstable_by_key(|container| container.vmid);
        let runtime_statuses = self
            .cli
            .node_runtime_statuses(node)
            .await?
            .into_iter()
            .map(|status| (status.vmid, status))
            .collect::<HashMap<_, _>>();

        for container in containers.into_iter().filter(|container| {
            container.node == *node && container.status == Some(cli::ContainerStatus::Running)
        }) {
            let interfaces = match self.cli.interfaces(&container.node, container.vmid).await {
                Ok(interfaces) => interfaces,
                Err(error) => {
                    tracing::warn!(
                        vmid = container.vmid,
                        "skipping Proxmox LXC during used-port discovery after interface lookup failed: {error:#}"
                    );
                    continue;
                }
            };
            let matching_addresses = PveCli::container_addresses(&interfaces)
                .into_iter()
                .filter(|address| requested.contains(address))
                .collect::<Vec<_>>();
            if matching_addresses.is_empty() {
                continue;
            }

            let runtime = match runtime_statuses.get(&container.vmid) {
                Some(runtime) => runtime,
                None => {
                    tracing::warn!(
                        vmid = container.vmid,
                        "skipping Proxmox LXC omitted from the node runtime inventory"
                    );
                    continue;
                }
            };
            if runtime.status != cli::ContainerStatus::Running {
                continue;
            }
            let Some(pid) = runtime.pid.filter(|pid| *pid > 0) else {
                tracing::warn!(
                    vmid = container.vmid,
                    "skipping running Proxmox LXC without an init PID during used-port discovery"
                );
                continue;
            };
            let bound_ports = match Self::container_bound_ports(pid).await {
                Ok(bound_ports) => bound_ports,
                Err(error) => {
                    tracing::warn!(
                        vmid = container.vmid,
                        "skipping Proxmox LXC during used-port discovery after namespace inspection failed: {error:#}"
                    );
                    continue;
                }
            };
            let server = Self::server_from_tags(&tag_prefix, &container.tags);

            for address in matching_addresses {
                let Some(address_ports) = used.get_mut(&address) else {
                    continue;
                };
                for bound in bound_ports
                    .iter()
                    .copied()
                    .filter(|bound| Self::bound_port_matches_address(*bound, address))
                {
                    address_ports
                        .entry(bound.port)
                        .and_modify(|owner| {
                            if *owner != server {
                                *owner = None;
                            }
                        })
                        .or_insert(server);
                }
            }
        }

        Ok(used
            .into_iter()
            .map(|(ip, ports)| {
                let mut ports = ports
                    .into_iter()
                    .map(|(port, server)| UsedPort { port, server })
                    .collect::<Vec<_>>();
                ports.sort_unstable_by_key(|port| port.port);
                (ip, ports)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
