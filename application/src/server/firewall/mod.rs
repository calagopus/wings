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

#[derive(ToSchema, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackendKind {
    #[default]
    Auto,
    Nftables,
    Iptables,
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
}

impl FirewallRule {
    fn expand_sources(
        &self,
        concrete: &mut Vec<ConcreteRule>,
        protocol: FirewallRuleProtocol,
        dst: RuleDst,
    ) {
        if self.sources.is_empty() {
            concrete.push(ConcreteRule {
                protocol,
                dst,
                source: None,
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
                source: Some(*source),
                action: self.action,
            });
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcreteRule {
    pub protocol: FirewallRuleProtocol,
    pub dst: RuleDst,
    pub source: Option<cidr::IpCidr>,
    pub action: FirewallRuleAction,
}

impl ConcreteRule {
    #[inline]
    pub fn applies_to_v4(&self) -> bool {
        self.dst.ip().is_none_or(|ip| ip.is_ipv4())
            && self.source.is_none_or(|s| matches!(s, cidr::IpCidr::V4(_)))
    }

    #[inline]
    pub fn applies_to_v6(&self) -> bool {
        self.dst.ip().is_none_or(|ip| ip.is_ipv6())
            && self.source.is_none_or(|s| matches!(s, cidr::IpCidr::V6(_)))
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
    own_container_ips: &[IpAddr],
) -> Arc<dyn FirewallBackend> {
    let backend = config.load().docker.firewall.backend;

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
            "server firewalls are not supported with rootless container engines, published port traffic does not traverse the host netfilter forward path - firewall rules will not be applied"
        );

        return Arc::new(noop::NoopFirewall::new(true));
    }

    for sysctl in ["bridge-nf-call-iptables", "bridge-nf-call-ip6tables"] {
        if std::fs::read_to_string(format!("/proc/sys/net/bridge/{sysctl}"))
            .is_ok_and(|value| value.trim() == "0")
        {
            tracing::warn!(
                "net.bridge.{sysctl} is disabled, traffic between containers on the same network will bypass server firewall rules"
            );
        }
    }

    let exempt_sources = exempt_sources(config, own_container_ips);

    match backend {
        FirewallBackendKind::Nftables => Arc::new(nftables::NftablesFirewall::new(exempt_sources)),
        FirewallBackendKind::Iptables => Arc::new(iptables::IptablesFirewall::new(exempt_sources)),
        FirewallBackendKind::Auto => {
            if run_command(
                "nft",
                &["--check", "-f", "-"],
                Some(b"add table inet wings\n"),
            )
            .await
            .is_ok()
            {
                tracing::info!("using nftables server firewall backend");

                Arc::new(nftables::NftablesFirewall::new(exempt_sources))
            } else if run_command("iptables", &["-w", "-S", "FORWARD"], None)
                .await
                .is_ok()
            {
                tracing::info!("using iptables server firewall backend");

                Arc::new(iptables::IptablesFirewall::new(exempt_sources))
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

pub(crate) async fn run_command(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
) -> Result<String, anyhow::Error> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(if input.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command.spawn()?;

    if let Some(input) = input {
        use tokio::io::AsyncWriteExt;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stdin of {program}"))?;
        stdin.write_all(input).await?;
        drop(stdin);
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(crate) async fn flush_denied_conntrack(rules: &[ConcreteRule]) {
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

            match run_command("conntrack", &args, None).await {
                Ok(_) => {}
                Err(err) => {
                    let message = err.to_string();
                    if message.contains("No such file or directory")
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
            }],
        ));

        assert_eq!(concrete.len(), 4);
        assert!(
            concrete
                .iter()
                .all(|r| r.action == FirewallRuleAction::Deny)
        );
        assert!(concrete.iter().all(|r| r.source.is_none()));
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
            }],
        );
        spec.container_ports = vec![25565];
        spec.container_ips = vec!["172.18.0.5".parse().unwrap()];

        let concrete = expand_rules(&spec);

        assert_eq!(concrete.len(), 1);
        assert_eq!(
            concrete.first().unwrap().source,
            Some(cidr::IpCidr::from_str("10.0.0.0/8").unwrap())
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
            }],
        ));

        assert_eq!(concrete.len(), 1);
        assert_eq!(
            concrete.first().unwrap().source,
            Some(cidr::IpCidr::from_str("10.0.0.0/8").unwrap())
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
                },
                FirewallRule {
                    action: FirewallRuleAction::Deny,
                    protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                    sources: Vec::new(),
                    ports: None,
                },
            ],
        ));

        assert_eq!(
            concrete.iter().map(|r| r.action).collect::<Vec<_>>(),
            vec![FirewallRuleAction::Allow, FirewallRuleAction::Deny]
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
            source: None,
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
            source: None,
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
            source: None,
            action: FirewallRuleAction::Deny,
        };

        assert!(rule.applies_to_v4());
        assert!(!rule.applies_to_v6());
    }
}
