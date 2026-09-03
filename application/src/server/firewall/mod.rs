use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
    sync::{Arc, OnceLock},
};
use utoipa::ToSchema;

pub mod iptables;
pub mod nftables;
pub mod noop;
pub mod runner;
pub mod sets;

use runner::CommandRunner;

#[derive(ToSchema, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackendKind {
    #[default]
    Auto,
    Nftables,
    Iptables,
    Container,
    Disabled,
}

#[derive(ToSchema, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleAction {
    Allow,
    Deny,
}

#[derive(
    ToSchema, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleProtocol {
    Tcp,
    Udp,
}

impl FirewallRuleProtocol {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(ToSchema, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub action: FirewallRuleAction,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub protocols: HashSet<FirewallRuleProtocol>,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    #[schema(value_type = Vec<String>)]
    pub sources: Vec<cidr::IpCidr>,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    #[serde(default)]
    pub source_file: Option<compact_str::CompactString>,
}

impl FirewallRule {
    fn expand_sources(
        &self,
        server: uuid::Uuid,
        concrete: &mut Vec<ConcreteRule>,
        protocol: FirewallRuleProtocol,
        dst: RuleDst,
    ) {
        if self.sources.is_empty() && self.source_file.is_none() {
            concrete.push(ConcreteRule {
                protocol,
                dst,
                source: RuleSource::Any,
                action: self.action,
            });

            return;
        }

        for source in &self.sources {
            let source_is_v4 = matches!(source, cidr::IpCidr::V4(_));
            if let Some(ip) = dst.ip()
                && ip.is_ipv4() != source_is_v4
            {
                continue;
            }

            concrete.push(ConcreteRule {
                protocol,
                dst,
                source: RuleSource::Cidr(*source),
                action: self.action,
            });
        }

        if let Some(file) = &self.source_file {
            let set = sets::set_base_name(server, &sets::source_file_path(file));

            for family in [AddressFamily::V4, AddressFamily::V6] {
                if dst
                    .ip()
                    .is_some_and(|ip| ip.is_ipv4() != (family == AddressFamily::V4))
                {
                    continue;
                }

                concrete.push(ConcreteRule {
                    protocol,
                    dst,
                    source: RuleSource::Set {
                        name: set.clone(),
                        family,
                    },
                    action: self.action,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirewallBinding {
    pub ip: Option<IpAddr>,
    pub port: u16,
}

pub struct FirewallServerSpec {
    pub server: uuid::Uuid,
    pub bindings: Vec<FirewallBinding>,
    pub container_ports: Vec<u16>,
    pub container_ips: Vec<IpAddr>,
    pub rules: Vec<FirewallRule>,
    pub files: Option<sets::FirewallFileAccess>,
}

impl FirewallServerSpec {
    #[inline]
    pub fn references_files(&self) -> bool {
        self.rules.iter().any(|rule| rule.source_file.is_some())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDst {
    Published { ip: Option<IpAddr>, port: u16 },
    Container { ip: IpAddr, port: u16 },
}

impl RuleDst {
    #[inline]
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Published { ip, .. } => *ip,
            Self::Container { ip, .. } => Some(*ip),
        }
    }

    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::Published { port, .. } | Self::Container { port, .. } => *port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    #[inline]
    pub fn set_suffix(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    Any,
    Cidr(cidr::IpCidr),
    Set { name: String, family: AddressFamily },
}

impl RuleSource {
    #[inline]
    pub fn applies_to_v4(&self) -> bool {
        match self {
            Self::Any => true,
            Self::Cidr(cidr) => matches!(cidr, cidr::IpCidr::V4(_)),
            Self::Set { family, .. } => *family == AddressFamily::V4,
        }
    }

    #[inline]
    pub fn applies_to_v6(&self) -> bool {
        match self {
            Self::Any => true,
            Self::Cidr(cidr) => matches!(cidr, cidr::IpCidr::V6(_)),
            Self::Set { family, .. } => *family == AddressFamily::V6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcreteRule {
    pub protocol: FirewallRuleProtocol,
    pub dst: RuleDst,
    pub source: RuleSource,
    pub action: FirewallRuleAction,
}

impl ConcreteRule {
    #[inline]
    pub fn applies_to_v4(&self) -> bool {
        self.dst.ip().is_none_or(|ip| ip.is_ipv4()) && self.source.applies_to_v4()
    }

    #[inline]
    pub fn applies_to_v6(&self) -> bool {
        self.dst.ip().is_none_or(|ip| ip.is_ipv6()) && self.source.applies_to_v6()
    }
}

pub fn expand_rules(spec: &FirewallServerSpec) -> Vec<ConcreteRule> {
    let mut concrete = Vec::new();

    for rule in &spec.rules {
        // a set has no order of its own, expanding through a fixed list keeps the emitted
        // rules in a stable order no matter how the rule was written
        let protocols: Vec<FirewallRuleProtocol> =
            [FirewallRuleProtocol::Tcp, FirewallRuleProtocol::Udp]
                .into_iter()
                .filter(|protocol| rule.protocols.is_empty() || rule.protocols.contains(protocol))
                .collect();

        for binding in &spec.bindings {
            if let Some(ports) = &rule.ports
                && !ports.contains(&binding.port)
            {
                continue;
            }

            for protocol in &protocols {
                rule.expand_sources(
                    spec.server,
                    &mut concrete,
                    *protocol,
                    RuleDst::Published {
                        ip: binding.ip,
                        port: binding.port,
                    },
                );
            }
        }

        for port in &spec.container_ports {
            if let Some(ports) = &rule.ports
                && !ports.contains(port)
            {
                continue;
            }

            for ip in &spec.container_ips {
                for protocol in &protocols {
                    rule.expand_sources(
                        spec.server,
                        &mut concrete,
                        *protocol,
                        RuleDst::Container {
                            ip: *ip,
                            port: *port,
                        },
                    );
                }
            }
        }
    }

    concrete
}

#[async_trait::async_trait]
pub trait FirewallBackend: Send + Sync {
    async fn boot(&self) -> Result<(), anyhow::Error>;

    async fn sync(&self, spec: &FirewallServerSpec) -> Result<(), anyhow::Error>;
    async fn clear(&self, server: uuid::Uuid) -> Result<(), anyhow::Error>;

    async fn reconcile(&self, specs: &[FirewallServerSpec]) -> Result<(), anyhow::Error>;
}

pub async fn create(
    config: &crate::config::Config,
    docker: &Arc<bollard::Docker>,
    own_container: Option<&(String, bollard::models::ContainerInspectResponse)>,
) -> Arc<dyn FirewallBackend> {
    let backend = config.load().docker.firewall.backend;
    let limits = sets::SourceFileLimits::from_config(config);

    if backend == FirewallBackendKind::Disabled {
        return Arc::new(noop::NoopFirewall::new(false));
    }

    if !cfg!(target_os = "linux") {
        if backend != FirewallBackendKind::Auto {
            tracing::warn!(
                "docker.firewall.backend is set to {:?}, but server firewalls are only supported on linux",
                backend
            );
        }

        return Arc::new(noop::NoopFirewall::new(true));
    }

    if config.load().system.user.rootless.enabled {
        tracing::warn!(
            "server firewalls are not supported with rootless container engines, published port traffic does not traverse the host netfilter forward path - servers with firewall rules will fail to start (set docker.firewall.backend to disabled to run them unprotected)"
        );

        return Arc::new(noop::NoopFirewall::new(true));
    }

    let containerized =
        std::path::Path::new("/.dockerenv").exists() || std::env::var("OCI_CONTAINER").is_ok();
    let host_netns = match own_container {
        Some((_, inspect)) => shares_host_netns(docker, inspect).await,
        None => {
            if containerized {
                tracing::warn!(
                    "running in a container whose own inspect failed, assuming the host network namespace - server firewall rules may be applied where server traffic never passes"
                );
            }

            true
        }
    };

    let exempt_sources = if containerized && host_netns && own_container.is_some() {
        Vec::new()
    } else {
        let own_container_ips = own_container
            .map(|(_, inspect)| {
                crate::server::executor::docker::DockerExecutor::endpoint_ips(inspect)
            })
            .unwrap_or_default();

        exempt_sources(config, &own_container_ips)
    };

    match backend {
        FirewallBackendKind::Nftables | FirewallBackendKind::Iptables
            if containerized && !host_netns =>
        {
            tracing::warn!(
                "docker.firewall.backend is set to {:?}, but wings runs inside a container with its own network namespace where server traffic never passes (container:* network modes are treated as foreign) - use the container backend, or give the wings container host networking",
                backend
            );

            Arc::new(noop::NoopFirewall::new(true))
        }
        FirewallBackendKind::Nftables => {
            let runner = CommandRunner::Local;
            warn_bridge_nf(&runner).await;

            Arc::new(nftables::NftablesFirewall::new(
                exempt_sources,
                runner,
                limits,
            ))
        }
        FirewallBackendKind::Iptables => {
            let runner = CommandRunner::Local;
            warn_bridge_nf(&runner).await;

            Arc::new(iptables::IptablesFirewall::new(exempt_sources, runner, limits).await)
        }
        FirewallBackendKind::Container => {
            match container_helper(config, docker, own_container).await {
                Ok(runner) => {
                    tracing::info!(
                        "using nftables server firewall backend through a helper container"
                    );
                    warn_bridge_nf(&runner).await;

                    Arc::new(nftables::NftablesFirewall::new(
                        exempt_sources,
                        runner,
                        limits,
                    ))
                }
                Err(err) => {
                    tracing::warn!(
                        "failed to set up the firewall helper container, server firewall rules will not be applied: {err:#}"
                    );

                    Arc::new(noop::NoopFirewall::new(true))
                }
            }
        }
        FirewallBackendKind::Auto => {
            if containerized && !host_netns {
                match container_helper(config, docker, own_container).await {
                    Ok(runner) => {
                        tracing::info!(
                            "using nftables server firewall backend through a helper container"
                        );
                        warn_bridge_nf(&runner).await;

                        return Arc::new(nftables::NftablesFirewall::new(
                            exempt_sources,
                            runner,
                            limits,
                        ));
                    }
                    Err(err) => {
                        tracing::warn!(
                            "wings runs inside a container without host networking and the firewall helper container is unusable, server firewall rules will not be applied: {err:#}"
                        );

                        return Arc::new(noop::NoopFirewall::new(true));
                    }
                }
            }

            let runner = CommandRunner::Local;
            if runner
                .run(
                    "nft",
                    &["--check", "-f", "-"],
                    Some(b"add table inet wings\n"),
                )
                .await
                .is_ok()
            {
                tracing::info!("using nftables server firewall backend");
                warn_bridge_nf(&runner).await;

                Arc::new(nftables::NftablesFirewall::new(
                    exempt_sources,
                    runner,
                    limits,
                ))
            } else if runner
                .run("iptables", &["-w", "-S", "FORWARD"], None)
                .await
                .is_ok()
            {
                tracing::info!("using iptables server firewall backend");
                warn_bridge_nf(&runner).await;

                Arc::new(iptables::IptablesFirewall::new(exempt_sources, runner, limits).await)
            } else {
                tracing::warn!(
                    "neither nftables nor iptables are usable on this host, server firewall rules will not be applied"
                );

                Arc::new(noop::NoopFirewall::new(true))
            }
        }
        FirewallBackendKind::Disabled => Arc::new(noop::NoopFirewall::new(false)),
    }
}

async fn container_helper(
    config: &crate::config::Config,
    docker: &Arc<bollard::Docker>,
    own_container: Option<&(String, bollard::models::ContainerInspectResponse)>,
) -> Result<CommandRunner, anyhow::Error> {
    let Some((_, inspect)) = own_container else {
        return Err(anyhow::anyhow!(
            "the container firewall backend needs wings to run as a container of the connected container engine"
        ));
    };
    let image = inspect
        .image
        .clone()
        .ok_or_else(|| anyhow::anyhow!("own container inspect carries no image id"))?;

    let helper =
        runner::DockerHelper::new(Arc::clone(docker), image, config.load().app_name.clone());
    helper.ensure().await?;

    let runner = CommandRunner::Docker(helper);
    if let Err(err) = runner
        .run(
            "nft",
            &["--check", "-f", "-"],
            Some(b"add table inet wings\n"),
        )
        .await
    {
        return Err(err.context("nftables is not usable inside the firewall helper container"));
    }

    Ok(runner)
}

async fn shares_host_netns(
    docker: &bollard::Docker,
    inspect: &bollard::models::ContainerInspectResponse,
) -> bool {
    let mut mode = inspect
        .host_config
        .as_ref()
        .and_then(|host_config| host_config.network_mode.clone());

    for _ in 0..4 {
        let Some(current) = mode else {
            return false;
        };
        if current == "host" {
            return true;
        }

        let Some(id) = current.strip_prefix("container:") else {
            return false;
        };
        mode = match docker.inspect_container(id, None).await {
            Ok(inspect) => inspect
                .host_config
                .and_then(|host_config| host_config.network_mode),
            Err(err) => {
                tracing::warn!(
                    "failed to inspect container {id} referenced by wings's own network mode: {err}"
                );

                return false;
            }
        };
    }

    false
}

async fn warn_bridge_nf(runner: &CommandRunner) {
    for sysctl in ["bridge-nf-call-iptables", "bridge-nf-call-ip6tables"] {
        let path = format!("/proc/sys/net/bridge/{sysctl}");
        // read in the namespace the rules will live in, br_netfilter state
        // is per network namespace
        let value = match runner {
            CommandRunner::Local => std::fs::read_to_string(&path).ok(),
            CommandRunner::Docker(_) => runner.run("cat", &[path.as_str()], None).await.ok(),
        };

        if value.is_some_and(|value| value.trim() == "0") {
            tracing::warn!(
                "net.bridge.{sysctl} is disabled, traffic between containers on the same network will bypass server firewall rules"
            );
        }
    }
}

fn exempt_sources(
    config: &crate::config::Config,
    own_container_ips: &[IpAddr],
) -> Vec<cidr::IpCidr> {
    if !std::path::Path::new("/.dockerenv").exists() && std::env::var("OCI_CONTAINER").is_err() {
        return Vec::new();
    }

    if !own_container_ips.is_empty() {
        return own_container_ips
            .iter()
            .map(|ip| cidr::IpCidr::new_host(*ip))
            .collect();
    }

    tracing::warn!(
        "running in a container with unknown own addresses, exempting the whole container networks from server firewalls - rules will not apply to traffic from other containers"
    );

    let config = config.load();
    let mut sources = Vec::new();

    if config.docker.network.interfaces.v4.enabled
        && let Ok(subnet) = config.docker.network.interfaces.v4.subnet.parse()
    {
        sources.push(subnet);
    }
    if config.docker.network.interfaces.v6.enabled
        && let Ok(subnet) = config.docker.network.interfaces.v6.subnet.parse()
    {
        sources.push(subnet);
    }

    sources
}

#[inline]
pub(crate) fn server_chain_name(server: uuid::Uuid) -> String {
    let mut name = server.simple().to_string();
    name.truncate(12);

    format!("wings-{name}")
}

pub(crate) async fn flush_denied_conntrack(runner: &CommandRunner, rules: &[ConcreteRule]) {
    static CONNTRACK_MISSING_WARNED: OnceLock<()> = OnceLock::new();

    let mut tuples = BTreeSet::new();
    for rule in rules {
        if rule.action == FirewallRuleAction::Deny {
            tuples.insert((rule.protocol, rule.dst.port(), rule.dst.ip()));
        }
    }

    for (protocol, port, orig_dst) in tuples {
        let port = port.to_string();
        let families: &[Option<&str>] = match orig_dst {
            Some(IpAddr::V4(_)) => &[None],
            Some(IpAddr::V6(_)) => &[Some("ipv6")],
            None => &[None, Some("ipv6")],
        };

        for family in families {
            let mut args = vec!["-D", "-p", protocol.as_str(), "--orig-port-dst", &port];
            let orig_dst = orig_dst.map(|ip| ip.to_string());
            if let Some(orig_dst) = &orig_dst {
                args.extend(["--orig-dst", orig_dst]);
            }
            if let Some(family) = family {
                args.extend(["-f", family]);
            }

            match runner.run("conntrack", &args, None).await {
                Ok(_) => {}
                Err(err) => {
                    let message = err.to_string();
                    if (message.contains("No such file or directory")
                        || message.contains("executable file not found"))
                        && CONNTRACK_MISSING_WARNED.set(()).is_ok()
                    {
                        tracing::warn!(
                            "the conntrack tool is not installed, denied sources with active connections keep their flows until they expire"
                        );
                    } else {
                        tracing::debug!("conntrack flush: {message}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn spec(bindings: Vec<FirewallBinding>, rules: Vec<FirewallRule>) -> FirewallServerSpec {
        FirewallServerSpec {
            server: uuid::Uuid::new_v4(),
            bindings,
            container_ports: Vec::new(),
            container_ips: Vec::new(),
            rules,
            files: None,
        }
    }

    fn binding(ip: Option<&str>, port: u16) -> FirewallBinding {
        FirewallBinding {
            ip: ip.map(|ip| ip.parse().unwrap()),
            port,
        }
    }

    // expand_rules

    #[test]
    fn expand_rules_returns_nothing_for_an_empty_rule_list() {
        assert!(expand_rules(&spec(vec![binding(None, 25565)], Vec::new())).is_empty());
    }

    #[test]
    fn expand_rules_expands_a_deny_all_to_every_binding_and_protocol() {
        let concrete = expand_rules(&spec(
            vec![binding(Some("192.168.1.5"), 25565), binding(None, 25566)],
            vec![FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::new(),
                sources: Vec::new(),
                ports: None,
                source_file: None,
            }],
        ));

        assert_eq!(concrete.len(), 4);
        assert!(
            concrete
                .iter()
                .all(|r| r.action == FirewallRuleAction::Deny)
        );
        assert!(concrete.iter().all(|r| r.source == RuleSource::Any));
    }

    #[test]
    fn expand_rules_filters_ports_to_the_servers_allocations() {
        let concrete = expand_rules(&spec(
            vec![binding(None, 25565)],
            vec![FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: Vec::new(),
                ports: Some(vec![25565, 9999]),
                source_file: None,
            }],
        ));

        assert_eq!(concrete.len(), 1);
        assert_eq!(concrete.first().unwrap().dst.port(), 25565);
    }

    #[test]
    fn expand_rules_emits_container_dst_rules_for_every_container_address() {
        let mut spec = spec(
            vec![binding(Some("192.168.1.5"), 25565)],
            vec![FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: Vec::new(),
                ports: None,
                source_file: None,
            }],
        );
        spec.container_ports = vec![25565];
        spec.container_ips = vec![
            "172.18.0.5".parse().unwrap(),
            "fdba:17c8:6c94::5".parse().unwrap(),
        ];

        let concrete = expand_rules(&spec);

        assert_eq!(concrete.len(), 3);
        assert_eq!(
            concrete
                .iter()
                .filter(|r| matches!(r.dst, RuleDst::Container { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn expand_rules_covers_container_ports_without_a_host_binding() {
        let mut spec = spec(
            Vec::new(),
            vec![FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::from([FirewallRuleProtocol::Udp]),
                sources: Vec::new(),
                ports: None,
                source_file: None,
            }],
        );
        spec.container_ports = vec![25565];
        spec.container_ips = vec!["172.18.0.5".parse().unwrap()];

        let concrete = expand_rules(&spec);

        assert_eq!(concrete.len(), 1);
        assert_eq!(
            concrete.first().unwrap().dst,
            RuleDst::Container {
                ip: "172.18.0.5".parse().unwrap(),
                port: 25565,
            }
        );
    }

    #[test]
    fn expand_rules_skips_container_sources_of_a_mismatched_address_family() {
        let mut spec = spec(
            Vec::new(),
            vec![FirewallRule {
                action: FirewallRuleAction::Allow,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: vec![
                    cidr::IpCidr::from_str("10.0.0.0/8").unwrap(),
                    cidr::IpCidr::from_str("2001:db8::/32").unwrap(),
                ],
                ports: None,
                source_file: None,
            }],
        );
        spec.container_ports = vec![25565];
        spec.container_ips = vec!["172.18.0.5".parse().unwrap()];

        let concrete = expand_rules(&spec);

        assert_eq!(concrete.len(), 1);
        assert_eq!(
            concrete.first().unwrap().source,
            RuleSource::Cidr(cidr::IpCidr::from_str("10.0.0.0/8").unwrap())
        );
    }

    #[test]
    fn expand_rules_skips_sources_of_a_mismatched_address_family() {
        let concrete = expand_rules(&spec(
            vec![binding(Some("192.168.1.5"), 25565)],
            vec![FirewallRule {
                action: FirewallRuleAction::Allow,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: vec![
                    cidr::IpCidr::from_str("10.0.0.0/8").unwrap(),
                    cidr::IpCidr::from_str("2001:db8::/32").unwrap(),
                ],
                ports: None,
                source_file: None,
            }],
        ));

        assert_eq!(concrete.len(), 1);
        assert_eq!(
            concrete.first().unwrap().source,
            RuleSource::Cidr(cidr::IpCidr::from_str("10.0.0.0/8").unwrap())
        );
    }

    #[test]
    fn expand_rules_keeps_both_families_for_wildcard_bindings() {
        let concrete = expand_rules(&spec(
            vec![binding(None, 25565)],
            vec![FirewallRule {
                action: FirewallRuleAction::Allow,
                protocols: HashSet::from([FirewallRuleProtocol::Udp]),
                sources: vec![
                    cidr::IpCidr::from_str("10.0.0.0/8").unwrap(),
                    cidr::IpCidr::from_str("2001:db8::/32").unwrap(),
                ],
                ports: None,
                source_file: None,
            }],
        ));

        assert_eq!(concrete.len(), 2);
    }

    #[test]
    fn expand_rules_preserves_rule_order() {
        let concrete = expand_rules(&spec(
            vec![binding(None, 25565)],
            vec![
                FirewallRule {
                    action: FirewallRuleAction::Allow,
                    protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                    sources: vec![cidr::IpCidr::from_str("10.0.0.0/8").unwrap()],
                    ports: None,
                    source_file: None,
                },
                FirewallRule {
                    action: FirewallRuleAction::Deny,
                    protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                    sources: Vec::new(),
                    ports: None,
                    source_file: None,
                },
            ],
        ));

        assert_eq!(
            concrete.iter().map(|r| r.action).collect::<Vec<_>>(),
            vec![FirewallRuleAction::Allow, FirewallRuleAction::Deny]
        );
    }

    #[test]
    fn expand_rules_emits_set_rules_per_family_for_a_source_file() {
        let server = uuid::Uuid::new_v4();
        let mut spec = spec(
            vec![binding(Some("192.168.1.5"), 25565), binding(None, 25566)],
            vec![FirewallRule {
                action: FirewallRuleAction::Allow,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: Vec::new(),
                ports: None,
                source_file: Some("lists/allow.txt".into()),
            }],
        );
        spec.server = server;

        let concrete = expand_rules(&spec);
        let set = sets::set_base_name(server, std::path::Path::new("lists/allow.txt"));

        assert!(concrete.iter().all(|r| r.source != RuleSource::Any));
        assert_eq!(
            concrete
                .iter()
                .map(|r| (r.dst.port(), r.source.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    25565,
                    RuleSource::Set {
                        name: set.clone(),
                        family: AddressFamily::V4
                    }
                ),
                (
                    25566,
                    RuleSource::Set {
                        name: set.clone(),
                        family: AddressFamily::V4
                    }
                ),
                (
                    25566,
                    RuleSource::Set {
                        name: set,
                        family: AddressFamily::V6
                    }
                ),
            ]
        );
    }

    #[test]
    fn expand_rules_unions_inline_sources_with_a_source_file() {
        let concrete = expand_rules(&spec(
            vec![binding(None, 25565)],
            vec![FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::from([FirewallRuleProtocol::Udp]),
                sources: vec![cidr::IpCidr::from_str("10.0.0.0/8").unwrap()],
                ports: None,
                source_file: Some("deny.txt".into()),
            }],
        ));

        assert_eq!(concrete.len(), 3);
        assert!(matches!(
            concrete.first().unwrap().source,
            RuleSource::Cidr(_)
        ));
        assert!(
            concrete
                .iter()
                .skip(1)
                .all(|rule| matches!(rule.source, RuleSource::Set { .. }))
        );
    }

    // serde

    #[test]
    fn firewall_rules_deserialize_null_fields_as_defaults() {
        let rule: FirewallRule = serde_json::from_str(
            r#"{"action":"deny","protocols":null,"sources":null,"ports":null}"#,
        )
        .unwrap();

        assert_eq!(rule.action, FirewallRuleAction::Deny);
        assert!(rule.protocols.is_empty());
        assert!(rule.sources.is_empty());
        assert_eq!(rule.ports, None);
        assert_eq!(rule.source_file, None);
    }

    #[test]
    fn firewall_rules_reject_malformed_sources_instead_of_dropping_them() {
        assert!(
            serde_json::from_str::<FirewallRule>(r#"{"action":"allow","sources":["not-a-cidr"]}"#)
                .is_err()
        );
    }

    // family application

    #[test]
    fn concrete_rules_without_addresses_apply_to_both_families() {
        let rule = ConcreteRule {
            protocol: FirewallRuleProtocol::Tcp,
            dst: RuleDst::Published {
                ip: None,
                port: 25565,
            },
            source: RuleSource::Any,
            action: FirewallRuleAction::Deny,
        };

        assert!(rule.applies_to_v4());
        assert!(rule.applies_to_v6());
    }

    #[test]
    fn concrete_rules_follow_the_family_of_their_addresses() {
        let rule = ConcreteRule {
            protocol: FirewallRuleProtocol::Tcp,
            dst: RuleDst::Published {
                ip: Some("2001:db8::1".parse().unwrap()),
                port: 25565,
            },
            source: RuleSource::Any,
            action: FirewallRuleAction::Deny,
        };

        assert!(!rule.applies_to_v4());
        assert!(rule.applies_to_v6());

        let rule = ConcreteRule {
            protocol: FirewallRuleProtocol::Tcp,
            dst: RuleDst::Container {
                ip: "172.18.0.5".parse().unwrap(),
                port: 25565,
            },
            source: RuleSource::Any,
            action: FirewallRuleAction::Deny,
        };

        assert!(rule.applies_to_v4());
        assert!(!rule.applies_to_v6());
    }
}
