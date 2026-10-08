use super::{
    Instance,
    client::{Client, is_status, segment},
    instance::Devices,
};
use anyhow::{Context, ensure};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(super) struct ForwardPort {
    pub protocol: String,
    pub listen_port: String,
    pub target_address: String,
    #[serde(default)]
    pub target_port: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Forward {
    pub listen_address: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<ForwardPort>,
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

pub(super) fn allocations(
    config: &crate::server::configuration::ServerConfiguration,
) -> anyhow::Result<BTreeMap<IpAddr, BTreeSet<u16>>> {
    let mut result = BTreeMap::<IpAddr, BTreeSet<u16>>::new();
    for (address, ports) in &config.allocations.mappings {
        let ip: IpAddr = address.parse().context("invalid panel allocation IP")?;
        ensure!(
            ports.iter().all(|p| *p > 0),
            "allocation port zero is invalid"
        );
        result.entry(ip).or_default().extend(ports.iter().copied());
    }
    if let Some(wildcard) = result.get(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
        ensure!(
            result
                .iter()
                .filter(|(ip, _)| !ip.is_unspecified())
                .all(|(_, ports)| ports.is_disjoint(wildcard)),
            "wildcard and concrete allocations overlap on the same port"
        );
    }
    ensure!(
        result.keys().all(IpAddr::is_ipv4),
        "IPv6 allocations require an IPv6-enabled Incus network (not implemented yet)"
    );
    Ok(result)
}

fn port_set(value: &str) -> anyhow::Result<BTreeSet<u16>> {
    let mut result = BTreeSet::new();
    for part in value.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.parse()?;
            let end: u16 = end.parse()?;
            ensure!(start > 0 && start <= end, "invalid forward port range");
            result.extend(start..=end);
        } else {
            let port: u16 = part.parse()?;
            ensure!(port > 0, "invalid forward port");
            result.insert(port);
        }
    }
    Ok(result)
}

const PROXY_PREFIX: &str = "wings-port-";

fn proxy_devices(target: &str, desired: &BTreeMap<IpAddr, BTreeSet<u16>>) -> Devices {
    let mut devices = Devices::new();
    for (ip, ports) in desired {
        if ports.is_empty() {
            continue;
        }
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        for protocol in ["tcp", "udp"] {
            devices.insert(
                format!(
                    "{PROXY_PREFIX}{}-{protocol}",
                    ip.to_string().replace('.', "-")
                ),
                BTreeMap::from([
                    ("type".into(), "proxy".into()),
                    ("bind".into(), "host".into()),
                    ("nat".into(), "true".into()),
                    ("listen".into(), format!("{protocol}:{ip}:{ports}")),
                    ("connect".into(), format!("{protocol}:{target}:{ports}")),
                ]),
            );
        }
    }
    devices
}

fn proxy_binding(
    device: &BTreeMap<String, String>,
) -> anyhow::Result<Option<(IpAddr, BTreeSet<u16>)>> {
    if device.get("type").map(String::as_str) != Some("proxy")
        || device.get("bind").map(String::as_str) == Some("instance")
    {
        return Ok(None);
    }
    let Some(listen) = device.get("listen") else {
        return Ok(None);
    };
    let mut parts = listen.splitn(3, ':');
    if !matches!(parts.next(), Some("tcp" | "udp")) {
        return Ok(None);
    }
    let Some(address) = parts.next().and_then(|s| s.parse::<IpAddr>().ok()) else {
        return Ok(None);
    };
    Ok(Some((
        address,
        port_set(parts.next().context("proxy listen ports missing")?)?,
    )))
}

fn overlaps(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4() && (a == b || a.is_unspecified() || b.is_unspecified())
}

fn check_proxy_conflicts(
    devices: &Devices,
    desired: &BTreeMap<IpAddr, BTreeSet<u16>>,
) -> anyhow::Result<()> {
    for device in devices.values() {
        if let Some((address, ports)) = proxy_binding(device)? {
            for (wanted_ip, wanted_ports) in desired {
                ensure!(
                    !overlaps(address, *wanted_ip) || ports.is_disjoint(wanted_ports),
                    "allocation conflicts with an existing Incus proxy on {address}"
                );
            }
        }
    }
    Ok(())
}

pub(super) struct Network {
    client: Client,
    name: String,
    owner: String,
    cidr: String,
    timeout: Duration,
    lock: tokio::sync::Mutex<()>,
}
impl Network {
    pub(super) fn new(client: Client, cfg: &crate::config::IncusRuntime, node: uuid::Uuid) -> Self {
        Self {
            client,
            name: cfg.network.clone(),
            owner: format!("wings:{node}"),
            cidr: cfg.ipv4_address.clone(),
            timeout: Duration::from_secs(cfg.operation_timeout_seconds),
            lock: tokio::sync::Mutex::new(()),
        }
    }
    fn path(&self) -> String {
        format!("/1.0/networks/{}", segment(&self.name))
    }
    pub(super) async fn boot(&self) -> anyhow::Result<()> {
        ipv4_pool(&self.cidr)?;
        let mut global = self.client.clone();
        global.project = "default".into();
        if let Some(network) = global.optional::<Value>(&self.path()).await? {
            ensure!(
                network.get("type").and_then(Value::as_str) == Some("bridge"),
                "Incus network is not a bridge"
            );
            ensure!(
                network
                    .pointer("/config/user.wings.owner")
                    .and_then(Value::as_str)
                    == Some(&self.owner),
                "refusing unmanaged Incus network"
            );
            ensure!(
                network
                    .pointer("/config/ipv4.address")
                    .and_then(Value::as_str)
                    == Some(&self.cidr),
                "existing Incus network subnet differs from configuration"
            );
        } else {
            global.mutate(Method::POST, "/1.0/networks", json!({"name": self.name, "type": "bridge", "config": {
                "ipv4.address": self.cidr, "ipv4.nat": "true", "ipv4.dhcp": "true", "ipv6.address": "none", "user.wings.owner": self.owner
            }})).await?;
        }
        self.migrate_forwards().await?;
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        for instance in instances {
            if instance.name.starts_with("wgs-")
                && instance.config.get("user.wings.owner") == Some(&self.owner)
                && matches!(instance.status.as_str(), "Running" | "Frozen")
            {
                let server = instance
                    .config
                    .get("user.wings.server")
                    .context("instance server missing")?
                    .parse()?;
                let target = instance
                    .config
                    .get("user.wings.ip")
                    .context("instance IP missing")?;
                let desired = serde_json::from_str(
                    instance
                        .config
                        .get("user.wings.allocations")
                        .context("allocation journal missing")?,
                )?;
                self.sync(server, target, &desired).await?;
            }
        }
        Ok(())
    }
    pub(super) async fn allocate(&self, instances: &[Instance]) -> anyhow::Result<Ipv4Addr> {
        let (network, broadcast, gateway) = ipv4_pool(&self.cidr)?;
        let mut used: BTreeSet<u32> = instances
            .iter()
            .filter_map(|i| i.config.get("user.wings.ip"))
            .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
            .map(u32::from)
            .collect();
        let mut global = self.client.clone();
        global.project = "default".into();
        let leases: Vec<Value> = global.get(&format!("{}/leases", self.path())).await?;
        for lease in leases {
            if let Some(address) = lease
                .get("address")
                .and_then(Value::as_str)
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            {
                used.insert(u32::from(address));
            }
        }
        for forward in self.forwards().await? {
            for entry in forward.ports {
                if let Ok(address) = entry.target_address.parse::<Ipv4Addr>() {
                    used.insert(u32::from(address));
                }
            }
        }
        for address in network + 1..broadcast {
            if address != gateway && !used.contains(&address) {
                return Ok(address.into());
            }
        }
        anyhow::bail!("Incus bridge has no free private IPv4 addresses")
    }
    async fn forwards(&self) -> anyhow::Result<Vec<Forward>> {
        let mut global = self.client.clone();
        global.project = "default".into();
        global
            .get(&format!("{}/forwards?recursion=1", self.path()))
            .await
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
    async fn migrate_forwards(&self) -> anyhow::Result<()> {
        let prefix = format!("{}:", self.owner);
        let forwards = self.forwards().await?;
        for forward in &forwards {
            if forward
                .ports
                .iter()
                .any(|p| p.description.starts_with(&prefix))
            {
                ensure!(
                    forward.description == self.owner
                        && forward
                            .ports
                            .iter()
                            .all(|p| p.description.starts_with(&prefix))
                        && !forward.config.contains_key("target_address"),
                    "cannot migrate shared/unmanaged Incus forward {}; move its unrelated rules first",
                    forward.listen_address
                );
            }
        }
        let mut global = self.client.clone();
        global.project = "default".into();
        for forward in forwards {
            if forward.description == self.owner
                && forward
                    .ports
                    .iter()
                    .all(|p| p.description.starts_with(&prefix))
                && !forward.config.contains_key("target_address")
            {
                global
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
        }
        Ok(())
    }
    pub(super) async fn sync(
        &self,
        server: uuid::Uuid,
        target: &str,
        desired: &BTreeMap<IpAddr, BTreeSet<u16>>,
    ) -> anyhow::Result<()> {
        let _guard = self.lock.lock().await;
        let name = format!("wgs-{server}");
        let path = format!("/1.0/instances/{}", segment(&name));
        let instances = self.all_instances().await?;
        for instance in &instances {
            if instance.name == name
                && instance.project == self.client.project
                && instance.config.get("user.wings.owner") == Some(&self.owner)
                && instance.config.get("user.wings.server") == Some(&server.to_string())
            {
                let unmanaged: Devices = instance
                    .effective_devices()
                    .iter()
                    .filter(|(name, _)| !name.starts_with(PROXY_PREFIX))
                    .map(|(name, device)| (name.clone(), device.clone()))
                    .collect();
                check_proxy_conflicts(&unmanaged, desired)?;
            } else {
                check_proxy_conflicts(instance.effective_devices(), desired)?;
            }
        }
        for forward in self.forwards().await? {
            let address: IpAddr = forward.listen_address.parse()?;
            ensure!(
                !desired.keys().any(|ip| overlaps(*ip, address)),
                "allocation overlaps existing Incus network forward {address}; remove or migrate that forward first"
            );
        }
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut precondition_failures = 0;
        loop {
            let (mut instance, etag) = match self.client.get_with_etag::<Instance>(&path).await {
                Ok(result) => result,
                Err(err) if is_status(&err, StatusCode::NOT_FOUND) && desired.is_empty() => {
                    return Ok(());
                }
                Err(err) => return Err(err),
            };
            ensure!(
                instance.config.get("user.wings.owner") == Some(&self.owner)
                    && instance.config.get("user.wings.server") == Some(&server.to_string()),
                "refusing unmanaged Incus instance {name}"
            );
            let mut devices = instance.devices.clone();
            devices.retain(|name, _| !name.starts_with(PROXY_PREFIX));
            devices.extend(proxy_devices(target, desired));
            let journal = serde_json::to_string(desired)?;
            if instance.devices == devices
                && instance.config.get("user.wings.allocations") == Some(&journal)
            {
                return Ok(());
            }
            instance.devices = devices;
            instance
                .config
                .insert("user.wings.allocations".into(), journal);
            match self
                .client
                .request(
                    Method::PUT,
                    &path,
                    Some(&instance.update_body()),
                    etag.as_deref(),
                    true,
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(err) if is_status(&err, StatusCode::PRECONDITION_FAILED) => {
                    precondition_failures += 1;
                    ensure!(
                        precondition_failures < 5,
                        "Incus instance changed repeatedly while updating allocation proxies"
                    );
                }
                Err(err)
                    if err.chain().any(|cause| {
                        cause
                            .to_string()
                            .contains("Instance is busy running a \"stop\" operation")
                    }) && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }
    pub(super) async fn used_ports(
        &self,
        ips: &[IpAddr],
    ) -> anyhow::Result<HashMap<IpAddr, Vec<super::super::UsedPort>>> {
        let mut result: HashMap<IpAddr, Vec<super::super::UsedPort>> =
            ips.iter().map(|ip| (*ip, Vec::new())).collect();
        let instances = self.all_instances().await?;
        for instance in instances {
            let server = if instance.config.get("user.wings.owner") == Some(&self.owner) {
                instance
                    .config
                    .get("user.wings.server")
                    .and_then(|s| s.parse().ok())
            } else {
                None
            };
            for device in instance.effective_devices().values() {
                if let Some((address, ports)) = proxy_binding(device)? {
                    for (ip, entries) in &mut result {
                        if overlaps(*ip, address) {
                            for port in &ports {
                                if !entries.iter().any(|item| item.port == *port) {
                                    entries.push(super::super::UsedPort {
                                        port: *port,
                                        server,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        for forward in self.forwards().await? {
            let address: IpAddr = forward.listen_address.parse()?;
            for (ip, entries) in &mut result {
                if *ip != address {
                    continue;
                }
                for entry in &forward.ports {
                    let server = entry
                        .description
                        .strip_prefix(&format!("{}:", self.owner))
                        .and_then(|uuid| uuid.parse().ok());
                    for port in port_set(&entry.listen_port)? {
                        if !entries.iter().any(|item| item.port == port) {
                            entries.push(super::super::UsedPort { port, server });
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}
