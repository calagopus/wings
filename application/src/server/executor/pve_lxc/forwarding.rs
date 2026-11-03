use anyhow::Context;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    process::Stdio,
    sync::OnceLock,
};
use tokio::io::AsyncWriteExt;

const NFT_PATH: &str = "/usr/sbin/nft";
const TABLE: &str = "wings_pve_forward";
const CHAINS: [&str; 5] = [
    "pve_conntrack_zone",
    "prerouting",
    "output",
    "forward",
    "postrouting",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkContext {
    bridge: String,
    guest_network: Ipv4Addr,
    prefix: u8,
}

impl NetworkContext {
    pub(super) fn new(
        bridge: &str,
        prefix: Option<u8>,
        gateway: Option<&str>,
    ) -> Result<Self, anyhow::Error> {
        if bridge.is_empty()
            || !bridge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            anyhow::bail!("invalid Proxmox LXC bridge: {bridge}");
        }
        let prefix = prefix
            .filter(|prefix| (1..=32).contains(prefix))
            .context("Proxmox allocation forwarding requires network_prefix between 1 and 32")?;
        let gateway = gateway
            .filter(|gateway| !gateway.trim().is_empty())
            .context("Proxmox allocation forwarding requires an IPv4 gateway")?
            .parse::<Ipv4Addr>()
            .context("Proxmox LXC gateway is not an IPv4 address")?;
        let mask = u32::MAX << (32 - u32::from(prefix));
        let guest_network = Ipv4Addr::from(u32::from(gateway) & mask);
        Ok(Self {
            bridge: bridge.to_string(),
            guest_network,
            prefix,
        })
    }

    pub(super) fn bridge(&self) -> &str {
        &self.bridge
    }

    pub(super) fn guest_cidr(&self) -> String {
        format!("{}/{}", self.guest_network, self.prefix)
    }

    pub(super) fn guest_destination(
        &self,
        addresses: &[std::net::IpAddr],
    ) -> Result<Ipv4Addr, anyhow::Error> {
        let mask = u32::MAX << (32 - u32::from(self.prefix));
        let network = u32::from(self.guest_network);
        let broadcast = network | !mask;
        addresses
            .iter()
            .filter_map(|address| match address {
                std::net::IpAddr::V4(address) => Some(*address),
                std::net::IpAddr::V6(_) => None,
            })
            .find(|address| {
                let value = u32::from(*address);
                value & mask == network
                    && value != network
                    && value != broadcast
                    && !address.is_loopback()
                    && !address.is_link_local()
                    && !address.is_unspecified()
            })
            .with_context(|| {
                format!(
                    "running Proxmox LXC has no usable IPv4 address in the configured guest subnet {}",
                    self.guest_cidr()
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ForwardingBinding {
    allocation_ip: Ipv4Addr,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ForwardingSpec {
    destination: Ipv4Addr,
    bindings: BTreeSet<ForwardingBinding>,
}

impl ForwardingSpec {
    pub(super) fn from_configuration(
        configuration: &crate::server::configuration::ServerConfiguration,
        destination: Ipv4Addr,
    ) -> Result<Option<Self>, anyhow::Error> {
        let mut bindings = BTreeSet::new();
        for (allocation_ip, ports) in &configuration.allocations.mappings {
            let allocation_ip = allocation_ip.parse::<Ipv4Addr>().with_context(|| {
                format!(
                    "Proxmox allocation forwarding requires IPv4 allocation addresses, got {allocation_ip}"
                )
            })?;
            for &port in ports {
                bindings.insert(ForwardingBinding {
                    allocation_ip,
                    port,
                });
            }
        }

        if bindings.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            destination,
            bindings,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ManagedRule {
    pub(super) server: uuid::Uuid,
    chain: String,
    handle: u64,
    binding: Option<ForwardingBinding>,
}

impl ManagedRule {
    #[cfg(test)]
    pub(super) fn new(server: uuid::Uuid, chain: impl Into<String>, handle: u64) -> Self {
        Self {
            server,
            chain: chain.into(),
            handle,
            binding: None,
        }
    }

    #[cfg(test)]
    pub(super) fn new_binding(
        server: uuid::Uuid,
        chain: impl Into<String>,
        handle: u64,
        allocation_ip: Ipv4Addr,
        port: u16,
    ) -> Self {
        Self {
            server,
            chain: chain.into(),
            handle,
            binding: Some(ForwardingBinding {
                allocation_ip,
                port,
            }),
        }
    }
}

fn marker(server: uuid::Uuid) -> String {
    format!("wings-pve:{server}")
}

pub(super) fn reconcile_script(
    server: uuid::Uuid,
    existing: &[ManagedRule],
    spec: Option<&ForwardingSpec>,
) -> String {
    let mut script = String::new();
    for rule in existing.iter().filter(|rule| rule.server == server) {
        script.push_str(&format!(
            "delete rule ip {TABLE} {} handle {}\n",
            rule.chain, rule.handle
        ));
    }
    if let Some(spec) = spec {
        append_spec(&mut script, server, spec);
    }
    script
}

fn append_spec(script: &mut String, server: uuid::Uuid, spec: &ForwardingSpec) {
    let marker = marker(server);
    for binding in &spec.bindings {
        for protocol in ["tcp", "udp"] {
            for chain in ["prerouting", "output"] {
                script.push_str(&format!(
                    "add rule ip {TABLE} {chain} ip daddr {} {protocol} dport {} dnat to {}:{} comment \"{marker}\"\n",
                    binding.allocation_ip,
                    binding.port,
                    spec.destination,
                    binding.port,
                ));
            }
            script.push_str(&format!(
                "add rule ip {TABLE} forward ip daddr {} {protocol} dport {} ct status dnat accept comment \"{marker}\"\n",
                spec.destination, binding.port,
            ));
            script.push_str(&format!(
                "add rule ip {TABLE} postrouting ip daddr {} {protocol} dport {} ct status dnat masquerade comment \"{marker}\"\n",
                spec.destination, binding.port,
            ));
        }
    }
}

fn append_base_rules(script: &mut String, network: &NetworkContext) {
    // Proxmox firewall bridges traverse IPv4 netfilter once before routing and
    // again after routing. Zone every fwbr direction so both halves use the
    // same bridge-side conntrack entry. Defer masquerading until the routed
    // pass by excluding the firewall bridge itself.
    script.push_str(&format!(
        "add rule ip {TABLE} pve_conntrack_zone iifname \"fwbr*\" ct zone set 1 comment \"wings-pve-base\"\n"
    ));
    script.push_str(&format!(
        "add rule ip {TABLE} postrouting ip saddr {} oifname != \"{}\" oifname != \"fwbr*\" masquerade comment \"wings-pve-base\"\n",
        network.guest_cidr(),
        network.bridge()
    ));
}

pub(super) fn managed_rules(listing: &str) -> Result<Vec<ManagedRule>, anyhow::Error> {
    let mut chain = None;
    let mut rules = Vec::new();

    for line in listing.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("chain ")
            && let Some(name) = rest.split_whitespace().next()
        {
            if !CHAINS.contains(&name) {
                anyhow::bail!("unexpected managed nftables chain {name}");
            }
            chain = Some(name.to_string());
            continue;
        }
        if trimmed == "}" {
            chain = None;
            continue;
        }
        let Some(marker_start) = trimmed.find("comment \"wings-pve:") else {
            continue;
        };
        let server_start = marker_start + "comment \"wings-pve:".len();
        let server_end = trimmed[server_start..]
            .find('"')
            .map(|offset| server_start + offset)
            .context("managed nftables rule had an unterminated server marker")?;
        let server = trimmed[server_start..server_end]
            .parse::<uuid::Uuid>()
            .context("managed nftables rule had an invalid server UUID")?;
        let chain = chain
            .as_ref()
            .context("managed nftables rule appeared outside a chain")?;
        let handle = trimmed
            .rsplit_once("# handle ")
            .context("managed nftables rule did not include a handle")?
            .1
            .trim()
            .parse::<u64>()
            .context("managed nftables rule had an invalid handle")?;
        let binding = if chain == "prerouting" {
            let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
            let allocation_ip = tokens
                .windows(2)
                .find_map(|tokens| (tokens[0] == "daddr").then_some(tokens[1]))
                .context("managed prerouting rule did not include a destination address")?
                .parse::<Ipv4Addr>()
                .context("managed prerouting rule had an invalid destination address")?;
            let port = tokens
                .windows(2)
                .find_map(|tokens| (tokens[0] == "dport").then_some(tokens[1]))
                .context("managed prerouting rule did not include a destination port")?
                .parse::<u16>()
                .context("managed prerouting rule had an invalid destination port")?;
            Some(ForwardingBinding {
                allocation_ip,
                port,
            })
        } else {
            None
        };
        rules.push(ManagedRule {
            server,
            chain: chain.clone(),
            handle,
            binding,
        });
    }

    Ok(rules)
}

pub(super) fn validate_binding_owners(
    desired: &BTreeMap<uuid::Uuid, ForwardingSpec>,
) -> Result<(), anyhow::Error> {
    let (_, mut errors) = without_binding_conflicts(desired.clone());
    if let Some(error) = errors.pop() {
        return Err(error);
    }
    Ok(())
}

pub(super) fn without_binding_conflicts(
    mut desired: BTreeMap<uuid::Uuid, ForwardingSpec>,
) -> (BTreeMap<uuid::Uuid, ForwardingSpec>, Vec<anyhow::Error>) {
    let mut owners = BTreeMap::<ForwardingBinding, BTreeSet<uuid::Uuid>>::new();
    for (&server, spec) in &desired {
        for &binding in &spec.bindings {
            owners.entry(binding).or_default().insert(server);
        }
    }

    let mut conflicted = BTreeSet::new();
    let mut errors = Vec::new();
    for (binding, owners) in owners {
        if owners.len() < 2 {
            continue;
        }
        conflicted.extend(owners.iter().copied());
        let owners = owners
            .into_iter()
            .map(|owner| owner.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(anyhow::anyhow!(
            "Proxmox allocation binding {}:{} is configured for multiple servers: {owners}",
            binding.allocation_ip,
            binding.port
        ));
    }
    desired.retain(|server, _| !conflicted.contains(server));
    (desired, errors)
}

pub(super) fn validate_runtime_binding_owners(
    server: uuid::Uuid,
    spec: &ForwardingSpec,
    existing: &[ManagedRule],
) -> Result<(), anyhow::Error> {
    for rule in existing {
        if rule.server != server
            && let Some(binding) = rule.binding
            && spec.bindings.contains(&binding)
        {
            anyhow::bail!(
                "Proxmox allocation binding {}:{} is already owned by server {}",
                binding.allocation_ip,
                binding.port,
                rule.server
            );
        }
    }
    Ok(())
}

pub(super) fn runtime_reconcile_plan(
    server: uuid::Uuid,
    spec: Option<&ForwardingSpec>,
    existing: &[ManagedRule],
) -> (String, Option<anyhow::Error>) {
    let conflict =
        spec.and_then(|spec| validate_runtime_binding_owners(server, spec, existing).err());
    let desired = if conflict.is_some() { None } else { spec };
    (reconcile_script(server, existing, desired), conflict)
}

pub(super) fn replace_table_script(
    network: &NetworkContext,
    desired: &BTreeMap<uuid::Uuid, ForwardingSpec>,
    table_exists: bool,
) -> String {
    let mut script = String::new();
    if table_exists {
        script.push_str(&format!("delete table ip {TABLE}\n"));
    }
    script.push_str(&format!(
        "add table ip {TABLE}\n\
         add chain ip {TABLE} pve_conntrack_zone {{ type filter hook prerouting priority raw; policy accept; }}\n\
         add chain ip {TABLE} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n\
         add chain ip {TABLE} output {{ type nat hook output priority dstnat; policy accept; }}\n\
         add chain ip {TABLE} forward {{ type filter hook forward priority filter; policy accept; }}\n\
         add chain ip {TABLE} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n"
    ));
    append_base_rules(&mut script, network);
    for (&server, spec) in desired {
        append_spec(&mut script, server, spec);
    }
    script
}

pub(super) fn parse_ipv4_forwarding(value: &str) -> Result<(), anyhow::Error> {
    if value.trim() == "1" {
        return Ok(());
    }
    anyhow::bail!(
        "IPv4 forwarding is disabled in /proc/sys/net/ipv4/ip_forward; set net.ipv4.ip_forward=1 before enabling the Proxmox LXC runtime"
    )
}

async fn nft_output(arguments: &[&str]) -> Result<std::process::Output, anyhow::Error> {
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(NFT_PATH)
            .args(arguments)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("timed out running nftables for Proxmox allocation forwarding")?
    .context("failed to run nftables for Proxmox allocation forwarding")
}

pub(super) async fn run_script_with(
    program: &std::path::Path,
    arguments: &[&str],
    script: &[u8],
    timeout: std::time::Duration,
) -> Result<std::process::Output, anyhow::Error> {
    let mut child = tokio::process::Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start nftables for Proxmox allocation forwarding")?;

    tokio::time::timeout(timeout, async move {
        let mut stdin = child
            .stdin
            .take()
            .context("nftables stdin was unavailable")?;
        stdin
            .write_all(script)
            .await
            .context("failed to write Proxmox allocation forwarding rules to nftables")?;
        stdin.shutdown().await.context(
            "failed to close nftables stdin after writing Proxmox allocation forwarding rules",
        )?;
        drop(stdin);
        child
            .wait_with_output()
            .await
            .context("failed while applying Proxmox allocation forwarding rules")
    })
    .await
    .context("timed out applying Proxmox allocation forwarding rules")?
}

async fn run_script(script: &str) -> Result<(), anyhow::Error> {
    if script.is_empty() {
        return Ok(());
    }

    let output = run_script_with(
        std::path::Path::new(NFT_PATH),
        &["-f", "-"],
        script.as_bytes(),
        std::time::Duration::from_secs(15),
    )
    .await?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to apply Proxmox allocation forwarding rules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn reconciliation_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(super) async fn initialize(_network: &NetworkContext) -> Result<(), anyhow::Error> {
    let ip_forward = tokio::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .await
        .context("failed to read /proc/sys/net/ipv4/ip_forward while initializing Proxmox allocation forwarding")?;
    parse_ipv4_forwarding(&ip_forward)?;

    let output = nft_output(&["--version"]).await?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to validate nftables for Proxmox allocation forwarding: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub(super) async fn sync(
    server: uuid::Uuid,
    spec: Option<&ForwardingSpec>,
) -> Result<(), anyhow::Error> {
    let _guard = reconciliation_lock().lock().await;
    let output = nft_output(&["-a", "list", "table", "ip", TABLE]).await?;
    if !output.status.success() {
        anyhow::bail!(
            "Proxmox allocation forwarding table {TABLE} is unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let listing = String::from_utf8(output.stdout)
        .context("nftables listing for Proxmox allocation forwarding was not UTF-8")?;
    let existing = managed_rules(&listing)?;
    let (script, conflict) = runtime_reconcile_plan(server, spec, &existing);
    let applied = run_script(&script).await;
    match (conflict, applied) {
        (None, result) => result,
        (Some(conflict), Ok(())) => Err(conflict),
        (Some(conflict), Err(clear_error)) => Err(anyhow::anyhow!(
            "{conflict:#}; failed to clear the server's previous forwarding rules: {clear_error:#}"
        )),
    }
}

pub(super) async fn sync_all(
    network: &NetworkContext,
    desired: &BTreeMap<uuid::Uuid, ForwardingSpec>,
) -> Result<(), anyhow::Error> {
    validate_binding_owners(desired)?;
    let _guard = reconciliation_lock().lock().await;
    let listing = nft_output(&["list", "table", "ip", TABLE]).await?;
    run_script(&replace_table_script(
        network,
        desired,
        listing.status.success(),
    ))
    .await
}
