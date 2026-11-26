//! The managed bridge, private addresses, published allocations and outgoing addresses.

use super::super::UsedPort;
use super::{
    Instance,
    client::{Client, segment},
    instance::Devices,
};
use crate::config::Config;
use crate::server::{
    bandwidth::{BandwidthBackendKind, limits::BandwidthLimits},
    configuration::ServerConfiguration,
};
use anyhow::{Context, bail, ensure};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Stdio,
    sync::Arc,
};
use tokio::io::AsyncWriteExt;

/// What an instance publishes: host addresses and their ports.
pub(super) type Published = BTreeMap<IpAddr, BTreeSet<u16>>;

pub(super) const JOURNAL: &str = "user.wings.allocations";
pub(super) const SOURCE_NAT: &str = "user.wings.source-nat";
const ADDRESS_V4: &str = "user.wings.ip";
const ADDRESS_V6: &str = "user.wings.ip6";
const PROXY_PREFIX: &str = "wings-port-";

pub(super) fn published(instance: &Instance) -> anyhow::Result<Published> {
    serde_json::from_str(
        instance
            .config
            .get(JOURNAL)
            .context("instance allocation journal missing")?,
    )
    .context("invalid instance allocation journal")
}

/// The private addresses of an instance, IPv4 first.
pub(super) fn addresses(instance: &Instance) -> anyhow::Result<Vec<IpAddr>> {
    let mut result = vec![
        instance
            .config
            .get(ADDRESS_V4)
            .context("instance address missing")?
            .parse()?,
    ];
    if let Some(address) = instance.config.get(ADDRESS_V6) {
        result.push(address.parse()?);
    }
    Ok(result)
}

/// The address a server's outgoing connections must come from.
pub(super) fn forced_source(config: &ServerConfiguration) -> anyhow::Result<Option<Ipv4Addr>> {
    if !config.allocations.force_outgoing_ip {
        return Ok(None);
    }
    let Some(default) = &config.allocations.default else {
        return Ok(None);
    };
    let address: IpAddr = default.ip.parse().context("invalid panel allocation IP")?;
    match address {
        IpAddr::V4(address) if !address.is_unspecified() && !address.is_loopback() => {
            Ok(Some(address))
        }
        IpAddr::V4(_) => Ok(None),
        IpAddr::V6(_) => bail!("a forced outgoing IP must be IPv4 with the Incus runtime"),
    }
}

pub(super) fn ipv4_pool(value: &str) -> anyhow::Result<(u32, u32, u32)> {
    let (address, prefix) = value
        .split_once('/')
        .context("Incus bridge requires IPv4 CIDR")?;
    let gateway = u32::from(address.parse::<Ipv4Addr>()?);
    let prefix: u32 = prefix.parse()?;
    ensure!(
        (16..=30).contains(&prefix),
        "Incus bridge IPv4 prefix must be /16 through /30"
    );
    let mask = u32::MAX << (32 - prefix);
    let network = gateway & mask;
    let broadcast = network | !mask;
    ensure!(
        gateway > network && gateway < broadcast,
        "bridge address must be a usable host address"
    );
    Ok((network, broadcast, gateway))
}

/// The network part of the bridge's IPv6 prefix.
fn ipv6_network(value: &str) -> anyhow::Result<u128> {
    let (address, prefix) = value
        .split_once('/')
        .context("Incus bridge requires IPv6 CIDR")?;
    let address = u128::from(address.parse::<Ipv6Addr>()?);
    let prefix: u32 = prefix.parse()?;
    ensure!(
        (48..=112).contains(&prefix),
        "Incus bridge IPv6 prefix must be /48 through /112"
    );
    Ok(address & (u128::MAX << (128 - prefix)))
}

fn unspecified(like: IpAddr) -> IpAddr {
    match like {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}

/// Where a panel allocation listens on the host, following the docker runtime: `127.0.0.1` means
/// the bridge gateway, which other servers can reach.
fn listen_address(
    network: &crate::config::DockerNetwork,
    gateway: Ipv4Addr,
    ip: IpAddr,
) -> Option<IpAddr> {
    if network.disable_interface_binding {
        return Some(unspecified(ip));
    }
    if ip == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return (!network.ispn).then_some(IpAddr::V4(gateway));
    }
    Some(ip)
}

fn proxy_devices(
    v4: Ipv4Addr,
    v6: Option<Ipv6Addr>,
    desired: &Published,
) -> anyhow::Result<Devices> {
    let mut devices = Devices::new();
    for (ip, ports) in desired {
        if ports.is_empty() {
            continue;
        }
        let target = match ip {
            IpAddr::V4(_) => IpAddr::V4(v4),
            IpAddr::V6(_) => {
                IpAddr::V6(v6.context("IPv6 allocations need IPv6 enabled on the Incus bridge")?)
            }
        };
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        for protocol in ["tcp", "udp"] {
            let endpoint = |address: IpAddr| match address {
                IpAddr::V4(address) => format!("{protocol}:{address}:{ports}"),
                IpAddr::V6(address) => format!("{protocol}:[{address}]:{ports}"),
            };
            devices.insert(
                format!(
                    "{PROXY_PREFIX}{}-{protocol}",
                    ip.to_string().replace(['.', ':'], "-")
                ),
                BTreeMap::from([
                    ("type".into(), "proxy".into()),
                    ("bind".into(), "host".into()),
                    ("nat".into(), "true".into()),
                    ("listen".into(), endpoint(*ip)),
                    ("connect".into(), endpoint(target)),
                ]),
            );
        }
    }
    Ok(devices)
}

fn port_set(value: &str) -> anyhow::Result<BTreeSet<u16>> {
    let mut result = BTreeSet::new();
    for part in value.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.parse()?;
            let end: u16 = end.parse()?;
            ensure!(start > 0 && start <= end, "invalid port range");
            result.extend(start..=end);
        } else {
            let port: u16 = part.parse()?;
            ensure!(port > 0, "invalid port");
            result.insert(port);
        }
    }
    Ok(result)
}

/// The host ports a device holds, if it is a TCP or UDP proxy listening on the host.
fn proxy_binding(device: &BTreeMap<String, String>) -> Option<(IpAddr, BTreeSet<u16>)> {
    if device.get("type").map(String::as_str) != Some("proxy")
        || device.get("bind").map(String::as_str) == Some("instance")
    {
        return None;
    }
    let (protocol, rest) = device.get("listen")?.split_once(':')?;
    if !matches!(protocol, "tcp" | "udp") {
        return None;
    }
    let (address, ports) = rest.rsplit_once(':')?;
    let address = address
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()?;
    Some((address, port_set(ports).ok()?))
}

fn overlaps(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4() && (a == b || a.is_unspecified() || b.is_unspecified())
}

/// Docker refuses to publish a port something on the host already listens on. A NAT rule would
/// silently take such traffic away instead, so check first.
fn check_host_ports(desired: &Published) -> anyhow::Result<()> {
    for (ip, ports) in desired {
        for port in ports {
            let address = SocketAddr::new(*ip, *port);
            let tcp = std::net::TcpListener::bind(address).map(drop);
            let udp = std::net::UdpSocket::bind(address).map(drop);
            for result in [tcp, udp] {
                match result {
                    Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                        bail!(
                            "failed to publish {address}: the address is already in use on this host"
                        )
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                        bail!("failed to publish {address}: that IP is not assigned to this host")
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn add_port(entries: &mut Vec<UsedPort>, port: u16, server: Option<uuid::Uuid>) {
    if !entries.iter().any(|item| item.port == port) {
        entries.push(UsedPort { port, server });
    }
}

#[derive(Deserialize)]
struct Forward {
    listen_address: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    config: BTreeMap<String, String>,
    #[serde(default)]
    ports: Vec<ForwardPort>,
}

#[derive(Deserialize)]
struct ForwardPort {
    listen_port: String,
    #[serde(default)]
    target_address: String,
    #[serde(default)]
    description: String,
}

type Reserved = Arc<parking_lot::Mutex<BTreeSet<u32>>>;

/// Private addresses held for an instance that is being created.
pub(super) struct Address {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
    reserved: Reserved,
}

impl Address {
    pub(super) fn instance_config(&self) -> BTreeMap<String, String> {
        let mut result = BTreeMap::from([(ADDRESS_V4.into(), self.v4.to_string())]);
        if let Some(v6) = self.v6 {
            result.insert(ADDRESS_V6.into(), v6.to_string());
        }
        result
    }
}

impl Drop for Address {
    fn drop(&mut self) {
        self.reserved.lock().remove(&u32::from(self.v4));
    }
}

type Starting = Arc<parking_lot::Mutex<Vec<(String, Published)>>>;

/// Ports claimed by an instance that is in the middle of starting.
pub(super) struct Claim {
    name: String,
    starting: Starting,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.starting.lock().retain(|(name, _)| *name != self.name);
    }
}

/// The first port two publications would both take.
fn shared_port(held: &Published, desired: &Published) -> Option<(IpAddr, u16)> {
    desired.iter().find_map(|(wanted, wanted_ports)| {
        held.iter()
            .filter(|(address, _)| overlaps(**address, *wanted))
            .find_map(|(_, ports)| wanted_ports.intersection(ports).next())
            .map(|port| (*wanted, *port))
    })
}

pub(super) struct Network {
    client: Client,
    config: Arc<Config>,
    reserved: Reserved,
    allocating: tokio::sync::Mutex<()>,
    starting: Starting,
    /// Serializes rewrites of the NAT table.
    nat: tokio::sync::Mutex<()>,
}

impl Network {
    pub(super) fn new(client: Client, config: Arc<Config>) -> Self {
        Self {
            client,
            config,
            reserved: Reserved::default(),
            allocating: tokio::sync::Mutex::new(()),
            starting: Starting::default(),
            nat: tokio::sync::Mutex::new(()),
        }
    }

    fn name(&self) -> String {
        self.config.load().runtime.incus.network.clone()
    }

    fn owner(&self) -> String {
        format!("wings:{}", self.config.load().uuid)
    }

    fn path(&self) -> String {
        format!("/1.0/networks/{}", segment(&self.name()))
    }

    fn ipv6(&self) -> Option<String> {
        let config = self.config.load();
        let address = &config.runtime.incus.ipv6_address;
        (config.docker.network.interfaces.v6.enabled && !address.is_empty())
            .then(|| address.clone())
    }

    fn global(&self) -> Client {
        let mut client = self.client.clone();
        client.project = "default".into();
        client
    }

    pub(super) fn bandwidth_enabled(&self) -> bool {
        self.config.load().docker.bandwidth.backend != BandwidthBackendKind::Disabled
    }

    /// The traffic shaping keys of a network device. Incus measures from the instance's side.
    pub(super) fn bandwidth_config(&self, limits: BandwidthLimits) -> BTreeMap<String, String> {
        let mut result = BTreeMap::new();
        if !self.bandwidth_enabled() {
            return result;
        }
        if limits.download > 0 {
            result.insert("limits.ingress".into(), format!("{}bit", limits.download));
        }
        if limits.upload > 0 {
            result.insert("limits.egress".into(), format!("{}bit", limits.upload));
        }
        result
    }

    pub(super) fn nic(
        &self,
        address: &Address,
        bandwidth: Option<BandwidthLimits>,
    ) -> BTreeMap<String, String> {
        let isolated = !self.config.load().docker.network.enable_icc;
        let mut device = BTreeMap::from([
            ("type".into(), "nic".into()),
            ("network".into(), self.name()),
            ("name".into(), "eth0".into()),
            ("ipv4.address".into(), address.v4.to_string()),
            ("security.mac_filtering".into(), "true".into()),
            ("security.ipv4_filtering".into(), "true".into()),
            ("security.port_isolation".into(), isolated.to_string()),
        ]);
        if let Some(v6) = address.v6 {
            device.insert("ipv6.address".into(), v6.to_string());
            device.insert("security.ipv6_filtering".into(), "true".into());
        }
        if let Some(limits) = bandwidth {
            device.extend(self.bandwidth_config(limits));
        }
        device
    }

    /// The host addresses and ports a server's allocations publish.
    pub(super) fn publish_map(&self, config: &ServerConfiguration) -> anyhow::Result<Published> {
        let node = self.config.load();
        let (_, _, gateway) = ipv4_pool(&node.runtime.incus.ipv4_address)?;
        let mut result = Published::new();
        for (address, ports) in &config.allocations.mappings {
            let ip: IpAddr = address.parse().context("invalid panel allocation IP")?;
            ensure!(
                ports.iter().all(|port| *port > 0),
                "allocation port zero is invalid"
            );
            if let Some(listen) = listen_address(&node.docker.network, Ipv4Addr::from(gateway), ip)
            {
                result
                    .entry(listen)
                    .or_default()
                    .extend(ports.iter().copied());
            }
        }
        // Incus rejects a wildcard listener beside a specific one on the same port, and the
        // wildcard already covers it.
        for wildcard in [
            IpAddr::from(Ipv4Addr::UNSPECIFIED),
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
        ] {
            let Some(covered) = result.get(&wildcard).cloned() else {
                continue;
            };
            for (ip, ports) in &mut result {
                if *ip != wildcard && ip.is_ipv4() == wildcard.is_ipv4() {
                    ports.retain(|port| !covered.contains(port));
                }
            }
        }
        result.retain(|_, ports| !ports.is_empty());
        Ok(result)
    }

    pub(super) fn proxy_devices(
        &self,
        address: &Address,
        published: &Published,
    ) -> anyhow::Result<Devices> {
        proxy_devices(address.v4, address.v6, published)
    }

    async fn all_instances(&self) -> anyhow::Result<Vec<Instance>> {
        let (value, _) = self
            .client
            .request(
                Method::GET,
                "/1.0/instances?recursion=1&all-projects=true",
                None,
                None,
                false,
            )
            .await?;
        serde_json::from_value(value).context("decoding all-project Incus instances")
    }

    async fn forwards(&self) -> anyhow::Result<Vec<Forward>> {
        self.global()
            .get(&format!("{}/forwards?recursion=1", self.path()))
            .await
    }

    /// Claims `desired` for an instance about to start, failing if a running or starting
    /// instance, or a host service, already holds one of the ports. Keep the claim until the
    /// instance has started.
    pub(super) async fn claim(&self, name: &str, desired: &Published) -> anyhow::Result<Claim> {
        let claim = {
            let mut starting = self.starting.lock();
            for (other, held) in starting.iter() {
                if other != name
                    && let Some((ip, port)) = shared_port(held, desired)
                {
                    bail!(
                        "failed to publish {ip}:{port}: port is already allocated to Incus instance {other}"
                    );
                }
            }
            starting.push((name.into(), desired.clone()));
            Claim {
                name: name.into(),
                starting: Arc::clone(&self.starting),
            }
        };
        for instance in self.all_instances().await? {
            if (instance.name == name && instance.project == self.client.project)
                || !matches!(instance.status.as_str(), "Running" | "Frozen")
            {
                continue;
            }
            for (address, ports) in instance
                .effective_devices()
                .values()
                .filter_map(proxy_binding)
            {
                if let Some((ip, port)) = shared_port(&Published::from([(address, ports)]), desired)
                {
                    bail!(
                        "failed to publish {ip}:{port}: port is already allocated to Incus instance {}",
                        instance.name
                    );
                }
            }
        }
        check_host_ports(desired)?;
        Ok(claim)
    }

    pub(super) async fn boot(&self) -> anyhow::Result<()> {
        let (cidr, mtu, internal) = {
            let config = self.config.load();
            (
                config.runtime.incus.ipv4_address.clone(),
                config.docker.network.network_mtu,
                config.docker.network.is_internal,
            )
        };
        ipv4_pool(&cidr)?;
        let v6 = self.ipv6();
        if let Some(v6) = &v6 {
            ipv6_network(v6)?;
        }
        let nat = (!internal).to_string();
        let mut wanted = BTreeMap::from([
            ("ipv4.address", cidr.clone()),
            ("ipv4.nat", nat.clone()),
            ("ipv4.dhcp", "true".into()),
            ("ipv6.address", v6.clone().unwrap_or_else(|| "none".into())),
            ("bridge.mtu", mtu.to_string()),
        ]);
        if v6.is_some() {
            wanted.insert("ipv6.nat", nat);
            wanted.insert("ipv6.dhcp.stateful", "true".into());
        }
        let global = self.global();
        if let Some(network) = global.optional::<Value>(&self.path()).await? {
            ensure!(
                network.get("type").and_then(Value::as_str) == Some("bridge"),
                "Incus network is not a bridge"
            );
            let current = |key: &str| {
                network
                    .get("config")
                    .and_then(|config| config.get(key))
                    .and_then(Value::as_str)
            };
            ensure!(
                current("user.wings.owner") == Some(&self.owner()),
                "Incus network {} belongs to something else, set runtime.incus.network",
                self.name()
            );
            ensure!(
                current("ipv4.address") == Some(&cidr),
                "existing Incus network subnet differs from configuration"
            );
            let changes: BTreeMap<&str, String> = wanted
                .into_iter()
                .filter(|(key, value)| current(key) != Some(value))
                .collect();
            if !changes.is_empty() {
                tracing::info!("updating Incus bridge settings: {changes:?}");
                global
                    .mutate(Method::PATCH, &self.path(), json!({"config": changes}))
                    .await
                    .context("updating the Incus bridge")?;
            }
        } else {
            let mut config: BTreeMap<&str, String> = wanted;
            config.insert("user.wings.owner", self.owner());
            global
                .mutate(
                    Method::POST,
                    "/1.0/networks",
                    json!({"name": self.name(), "type": "bridge", "config": config}),
                )
                .await
                .context("creating the Incus bridge")?;
        }
        if let Err(err) = self.migrate_forwards().await {
            tracing::warn!("could not remove earlier Wings network forwards: {err:#}");
        }
        self.refresh_nat().await
    }

    /// Removes the network forwards earlier versions of this runtime published ports with.
    async fn migrate_forwards(&self) -> anyhow::Result<()> {
        let owner = self.owner();
        let prefix = format!("{owner}:");
        for forward in self.forwards().await? {
            let owned = forward.description == owner
                && forward
                    .ports
                    .iter()
                    .all(|port| port.description.starts_with(&prefix))
                && !forward.config.contains_key("target_address");
            if !owned {
                continue;
            }
            self.global()
                .mutate(
                    Method::DELETE,
                    &format!(
                        "{}/forwards/{}",
                        self.path(),
                        segment(&forward.listen_address)
                    ),
                    json!({}),
                )
                .await?;
        }
        Ok(())
    }

    /// Picks an unused pair of private addresses and holds them until the result is dropped.
    pub(super) async fn reserve(&self) -> anyhow::Result<Address> {
        let _guard = self.allocating.lock().await;
        let cidr = self.config.load().runtime.incus.ipv4_address.clone();
        let (network, broadcast, gateway) = ipv4_pool(&cidr)?;
        let mut used = BTreeSet::new();
        let mut take = |address: &str| {
            if let Ok(address) = address.parse::<Ipv4Addr>() {
                used.insert(u32::from(address));
            }
        };
        // The bridge is shared, so instances of every project count.
        for instance in self.all_instances().await? {
            if let Some(address) = instance.config.get(ADDRESS_V4) {
                take(address);
            }
            for device in instance.effective_devices().values() {
                if let Some(address) = device.get("ipv4.address") {
                    take(address);
                }
            }
        }
        let leases: Vec<Value> = self
            .global()
            .get(&format!("{}/leases", self.path()))
            .await?;
        for lease in &leases {
            if let Some(address) = lease.get("address").and_then(Value::as_str) {
                take(address);
            }
        }
        for forward in self.forwards().await.unwrap_or_default() {
            for port in &forward.ports {
                take(&port.target_address);
            }
        }
        let mut reserved = self.reserved.lock();
        let v4 = (network + 1..broadcast)
            .find(|address| {
                *address != gateway && !used.contains(address) && !reserved.contains(address)
            })
            .context("Incus bridge has no free private IPv4 addresses")?;
        reserved.insert(v4);
        drop(reserved);
        let v6 = self
            .ipv6()
            .map(|cidr| ipv6_network(&cidr))
            .transpose()?
            .map(|prefix| {
                // The same host number as the IPv4 address, offset past the gateway's `::1`.
                Ipv6Addr::from(prefix + 0x1_0000 + u128::from(v4 - network))
            });
        Ok(Address {
            v4: Ipv4Addr::from(v4),
            v6,
            reserved: Arc::clone(&self.reserved),
        })
    }

    /// Rewrites the NAT rules Incus does not add itself: servers reaching each other through a
    /// published allocation, and servers with a forced outgoing address.
    pub(super) async fn refresh_nat(&self) -> anyhow::Result<()> {
        let _guard = self.nat.lock().await;
        let owner = self.owner();
        let bridge = self.name();
        let cidr = self.config.load().runtime.incus.ipv4_address.clone();
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let sources = instances
            .iter()
            .filter(|instance| instance.config.get("user.wings.owner") == Some(&owner))
            .filter_map(|instance| {
                let address = |key: &str| {
                    instance
                        .config
                        .get(key)
                        .and_then(|value| value.parse::<Ipv4Addr>().ok())
                };
                Some((address(ADDRESS_V4)?, address(SOURCE_NAT)?))
            })
            .collect::<Vec<_>>();
        nft(&nat_script(
            &bridge,
            &cidr,
            self.ipv6().as_deref(),
            &sources,
        )?)
        .await
        .context("applying Incus NAT rules")
    }

    pub(super) async fn used_ports(
        &self,
        ips: &[IpAddr],
    ) -> anyhow::Result<HashMap<IpAddr, Vec<UsedPort>>> {
        let owner = self.owner();
        let mut result: HashMap<IpAddr, Vec<UsedPort>> =
            ips.iter().map(|ip| (*ip, Vec::new())).collect();
        for instance in self.all_instances().await? {
            let server: Option<uuid::Uuid> =
                if instance.config.get("user.wings.owner") == Some(&owner) {
                    instance
                        .config
                        .get("user.wings.server")
                        .and_then(|s| s.parse().ok())
                } else {
                    None
                };
            for (address, ports) in instance
                .effective_devices()
                .values()
                .filter_map(proxy_binding)
            {
                for (ip, entries) in &mut result {
                    if overlaps(*ip, address) {
                        for &port in &ports {
                            add_port(entries, port, server);
                        }
                    }
                }
            }
        }
        for forward in self.forwards().await.unwrap_or_default() {
            let Ok(address) = forward.listen_address.parse::<IpAddr>() else {
                continue;
            };
            if let Some(entries) = result.get_mut(&address) {
                for entry in &forward.ports {
                    for port in port_set(&entry.listen_port).unwrap_or_default() {
                        add_port(entries, port, None);
                    }
                }
            }
        }
        Ok(result)
    }
}

fn nat_script(
    bridge: &str,
    ipv4: &str,
    ipv6: Option<&str>,
    sources: &[(Ipv4Addr, Ipv4Addr)],
) -> anyhow::Result<String> {
    let table = format!("wings_incus_{}", bridge.replace('-', "_"));
    let (network, broadcast, _) = ipv4_pool(ipv4)?;
    let prefix = (broadcast ^ network).count_zeros();
    let mut rules = vec![format!(
        "ip saddr {0}/{prefix} ip daddr {0}/{prefix} oifname \"{bridge}\" ct status dnat masquerade",
        Ipv4Addr::from(network)
    )];
    if let Some(ipv6) = ipv6 {
        let (_, prefix) = ipv6
            .split_once('/')
            .context("Incus bridge requires IPv6 CIDR")?;
        let network = Ipv6Addr::from(ipv6_network(ipv6)?);
        rules.push(format!(
            "ip6 saddr {network}/{prefix} ip6 daddr {network}/{prefix} oifname \"{bridge}\" ct status dnat masquerade"
        ));
    }
    for (private, source) in sources {
        rules.push(format!(
            "ip saddr {private} oifname != \"{bridge}\" snat ip to {source}"
        ));
    }
    // Declaring the table first makes deleting it safe whether or not it exists. Priority 90
    // runs before the masquerade rules Incus installs at `srcnat`.
    let mut script = format!(
        "add table inet {table}\ndelete table inet {table}\nadd table inet {table}\nadd chain inet {table} postrouting {{ type nat hook postrouting priority 90; policy accept; }}\n"
    );
    for rule in rules {
        script.push_str(&format!("add rule inet {table} postrouting {rule}\n"));
    }
    Ok(script)
}

async fn nft(script: &str) -> anyhow::Result<()> {
    let mut child = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("starting nft")?;
    child
        .stdin
        .take()
        .context("nft stdin missing")?
        .write_all(script.as_bytes())
        .await?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
        .await
        .context("nft timed out")??;
    ensure!(
        output.status.success(),
        "nft failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(entries: &[(&str, &[u16])]) -> Published {
        entries
            .iter()
            .map(|(ip, ports)| (ip.parse().expect("ip"), ports.iter().copied().collect()))
            .collect()
    }

    #[test]
    fn proxies_round_trip_for_both_families() {
        let desired = published(&[("0.0.0.0", &[25565, 25566]), ("::", &[25565])]);
        let devices = proxy_devices(
            Ipv4Addr::new(10, 0, 0, 2),
            Some("fd00::2".parse().expect("ip")),
            &desired,
        )
        .expect("devices");
        assert_eq!(devices.len(), 4);
        assert!(devices.keys().all(|name| {
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        }));
        for device in devices.values() {
            let (address, ports) = proxy_binding(device).expect("binding");
            assert_eq!(desired.get(&address), Some(&ports));
        }
        assert!(proxy_devices(Ipv4Addr::LOCALHOST, None, &desired).is_err());
    }

    #[test]
    fn loopback_allocations_listen_on_the_gateway() {
        let mut network = crate::config::DockerNetwork::default();
        let gateway = Ipv4Addr::new(10, 76, 0, 1);
        let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            listen_address(&network, gateway, localhost),
            Some(gateway.into())
        );
        network.ispn = true;
        assert_eq!(listen_address(&network, gateway, localhost), None);
        network.disable_interface_binding = true;
        assert_eq!(
            listen_address(&network, gateway, "192.0.2.1".parse().expect("ip")),
            Some(Ipv4Addr::UNSPECIFIED.into())
        );
    }

    #[test]
    fn nat_rules_cover_hairpins_and_forced_sources() {
        let script = nat_script(
            "wings-br0",
            "10.76.0.1/16",
            Some("fd00:1::1/64"),
            &[(Ipv4Addr::new(10, 76, 0, 2), Ipv4Addr::new(192, 0, 2, 1))],
        )
        .expect("script");
        assert!(script.contains("add table inet wings_incus_wings_br0"));
        assert!(script.contains(
            "ip saddr 10.76.0.0/16 ip daddr 10.76.0.0/16 oifname \"wings-br0\" ct status dnat masquerade"
        ));
        assert!(script.contains("ip6 saddr fd00:1::/64 ip6 daddr fd00:1::/64"));
        assert!(
            script.contains("ip saddr 10.76.0.2 oifname != \"wings-br0\" snat ip to 192.0.2.1")
        );
    }

    #[test]
    fn shared_ports_respect_addresses() {
        let held = published(&[("192.0.2.1", &[80, 81])]);
        assert_eq!(
            shared_port(&held, &published(&[("0.0.0.0", &[81])])),
            Some((Ipv4Addr::UNSPECIFIED.into(), 81))
        );
        assert_eq!(
            shared_port(&held, &published(&[("192.0.2.2", &[80])])),
            None
        );
    }

    #[test]
    fn overlap_is_per_family() {
        let any4: IpAddr = Ipv4Addr::UNSPECIFIED.into();
        assert!(overlaps(any4, "192.0.2.1".parse().expect("ip")));
        assert!(!overlaps(any4, "::1".parse().expect("ip")));
    }

    #[test]
    fn host_listeners_are_not_taken_over() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        assert!(check_host_ports(&published(&[("127.0.0.1", &[port])])).is_err());
        drop(listener);
        // A test running in parallel may briefly hold a copy of the socket while spawning.
        let freed = (0..100).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            check_host_ports(&published(&[("127.0.0.1", &[port])])).is_ok()
        });
        assert!(freed);
    }
}
