use super::{
    ConcreteRule, FirewallBackend, FirewallRuleAction, FirewallServerSpec, RuleDst, expand_rules,
    flush_denied_conntrack, runner::CommandRunner, server_chain_name,
};
use std::{collections::BTreeMap, fmt::Write, sync::Arc};

const DISPATCH_CHAIN: &str = "WINGS-FIREWALL";
const SERVER_CHAIN_PREFIX: &str = "wings-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    #[inline]
    fn tool(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    #[inline]
    fn save_tool(self) -> &'static str {
        match self {
            Self::V4 => "iptables-save",
            Self::V6 => "ip6tables-save",
        }
    }

    #[inline]
    fn restore_tool(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }

    #[inline]
    fn applies(self, rule: &ConcreteRule) -> bool {
        match self {
            Self::V4 => rule.applies_to_v4(),
            Self::V6 => rule.applies_to_v6(),
        }
    }

    #[inline]
    fn applies_source(self, source: &cidr::IpCidr) -> bool {
        matches!(
            (self, source),
            (Self::V4, cidr::IpCidr::V4(_)) | (Self::V6, cidr::IpCidr::V6(_))
        )
    }
}

/// Firewalls servers through per-server chains dispatched from a
/// `WINGS-FIREWALL` chain that is jumped to from `DOCKER-USER` (the container
/// engine's documented user-filtering hook), or directly from `FORWARD` when
/// no `DOCKER-USER` chain exists. Allowed traffic uses RETURN rather than
/// ACCEPT so it falls through to the engine's own filtering instead of
/// bypassing it.
pub struct IptablesFirewall {
    inner: Arc<Inner>,
}

struct Inner {
    exempt_sources: Vec<cidr::IpCidr>,
    runner: CommandRunner,
    state: tokio::sync::Mutex<BTreeMap<uuid::Uuid, Vec<ConcreteRule>>>,
}

impl IptablesFirewall {
    pub fn new(exempt_sources: Vec<cidr::IpCidr>, runner: CommandRunner) -> Self {
        Self {
            inner: Arc::new(Inner {
                exempt_sources,
                runner,
                state: tokio::sync::Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

fn render_rule(chain: &str, rule: &ConcreteRule) -> String {
    let mut out = format!("-A {chain} -p {}", rule.protocol.as_str());

    match rule.dst {
        RuleDst::Published { ip, port } => {
            let _ = write!(out, " -m conntrack --ctstate DNAT");
            if let Some(ip) = ip {
                let _ = write!(out, " --ctorigdst {ip}");
            }
            let _ = write!(out, " --ctorigdstport {port}");
        }
        RuleDst::Container { ip, port } => {
            let _ = write!(out, " -m conntrack ! --ctstate DNAT -d {ip} --dport {port}");
        }
    }
    if let Some(source) = rule.source {
        let _ = write!(out, " -s {source:#}");
    }
    let _ = write!(
        out,
        " -j {}",
        match rule.action {
            FirewallRuleAction::Allow => "RETURN",
            FirewallRuleAction::Deny => "DROP",
        }
    );

    out
}

fn render_restore_file(
    servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    exempt_sources: &[cidr::IpCidr],
    stale_chains: &[String],
    family: Family,
) -> String {
    let live: Vec<(String, Vec<&ConcreteRule>)> = servers
        .iter()
        .filter_map(|(server, rules)| {
            let rules: Vec<&ConcreteRule> =
                rules.iter().filter(|rule| family.applies(rule)).collect();

            if rules.is_empty() {
                None
            } else {
                Some((server_chain_name(*server), rules))
            }
        })
        .collect();

    let mut out = String::from("*filter\n");

    let _ = writeln!(out, ":{DISPATCH_CHAIN} - [0:0]");
    for (chain, _) in &live {
        let _ = writeln!(out, ":{chain} - [0:0]");
    }
    for chain in stale_chains {
        if !live.iter().any(|(live, _)| live == chain) {
            let _ = writeln!(out, ":{chain} - [0:0]");
        }
    }

    let _ = writeln!(out, "-F {DISPATCH_CHAIN}");
    if !live.is_empty() {
        for source in exempt_sources {
            if family.applies_source(source) {
                let _ = writeln!(out, "-A {DISPATCH_CHAIN} -s {source:#} -j RETURN");
            }
        }
    }
    for (chain, _) in &live {
        let _ = writeln!(out, "-A {DISPATCH_CHAIN} -j {chain}");
    }

    for (chain, rules) in &live {
        let _ = writeln!(out, "-F {chain}");
        let _ = writeln!(
            out,
            "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
        );
        for rule in rules {
            let _ = writeln!(out, "{}", render_rule(chain, rule));
        }
    }

    for chain in stale_chains {
        if !live.iter().any(|(live, _)| live == chain) {
            let _ = writeln!(out, "-F {chain}");
            let _ = writeln!(out, "-X {chain}");
        }
    }

    out.push_str("COMMIT\n");

    out
}

/// Parses `iptables-save -t filter` output into (dispatch chain exists,
/// existing per-server chain names).
fn parse_existing_chains(save_output: &str) -> (bool, Vec<String>) {
    let mut has_dispatch = false;
    let mut chains = Vec::new();

    for line in save_output.lines() {
        let Some(name) = line
            .strip_prefix(':')
            .and_then(|line| line.split_whitespace().next())
        else {
            continue;
        };

        if name == DISPATCH_CHAIN {
            has_dispatch = true;
        } else if name.starts_with(SERVER_CHAIN_PREFIX) {
            chains.push(name.to_string());
        }
    }

    (has_dispatch, chains)
}

impl Inner {
    fn family_needed(
        &self,
        servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
        family: Family,
    ) -> bool {
        servers.values().flatten().any(|rule| family.applies(rule))
    }

    async fn apply_family(
        &self,
        servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
        family: Family,
    ) -> Result<(), anyhow::Error> {
        let save_output = match self
            .runner
            .run(family.save_tool(), &["-t", "filter"], None)
            .await
        {
            Ok(output) => output,
            Err(err) => {
                if self.family_needed(servers, family) {
                    return Err(err.context(format!(
                        "failed to read the current {} ruleset",
                        family.tool()
                    )));
                }

                return Ok(());
            }
        };

        let (has_dispatch, stale_chains) = parse_existing_chains(&save_output);
        let needed = self.family_needed(servers, family);
        if !needed && !has_dispatch && stale_chains.is_empty() {
            return Ok(());
        }

        let restore_file =
            render_restore_file(servers, &self.exempt_sources, &stale_chains, family);
        self.runner
            .run(
                family.restore_tool(),
                &["-w", "-n"],
                Some(restore_file.as_bytes()),
            )
            .await?;

        if needed {
            ensure_jump(&self.runner, family).await?;
        }

        Ok(())
    }

    async fn apply(
        &self,
        servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    ) -> Result<(), anyhow::Error> {
        self.apply_family(servers, Family::V4).await?;
        self.apply_family(servers, Family::V6).await?;

        Ok(())
    }

    async fn reassert(&self, force: bool) {
        let servers = self.state.lock().await;
        if servers.is_empty() && !force {
            return;
        }

        let mut intact = true;
        for family in [Family::V4, Family::V6] {
            if !self.family_needed(&servers, family) {
                continue;
            }

            if !has_jump(&self.runner, family).await {
                intact = false;
            }
        }
        if intact && !force {
            return;
        }

        if !intact {
            tracing::warn!(
                "the wings iptables chains were flushed externally, reapplying server firewall rules"
            );
        }

        if let Err(err) = self.apply(&servers).await {
            tracing::error!("failed to reapply server firewall rules: {err:#}");
            return;
        }

        let denied: Vec<Vec<ConcreteRule>> = if intact {
            Vec::new()
        } else {
            servers.values().cloned().collect()
        };
        drop(servers);

        for rules in denied {
            flush_denied_conntrack(&self.runner, &rules).await;
        }
    }
}

async fn has_jump(runner: &CommandRunner, family: Family) -> bool {
    for parent in ["DOCKER-USER", "FORWARD"] {
        if runner
            .run(
                family.tool(),
                &["-w", "-C", parent, "-j", DISPATCH_CHAIN],
                None,
            )
            .await
            .is_ok()
        {
            return true;
        }
    }

    false
}

async fn ensure_jump(runner: &CommandRunner, family: Family) -> Result<(), anyhow::Error> {
    if has_jump(runner, family).await {
        return Ok(());
    }

    let parent = if runner
        .run(family.tool(), &["-w", "-S", "DOCKER-USER"], None)
        .await
        .is_ok()
    {
        "DOCKER-USER"
    } else {
        "FORWARD"
    };

    runner
        .run(
            family.tool(),
            &["-w", "-I", parent, "1", "-j", DISPATCH_CHAIN],
            None,
        )
        .await?;

    Ok(())
}

#[async_trait::async_trait]
impl FirewallBackend for IptablesFirewall {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        tokio::spawn({
            let inner = Arc::clone(&self.inner);

            async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                let mut tick: u64 = 0;
                loop {
                    interval.tick().await;
                    tick = tick.wrapping_add(1);
                    inner.reassert(tick.is_multiple_of(10)).await;
                }
            }
        });

        Ok(())
    }

    async fn sync(&self, spec: &FirewallServerSpec) -> Result<(), anyhow::Error> {
        let rules = expand_rules(spec);
        let mut state = self.inner.state.lock().await;

        let unchanged = match state.get(&spec.server) {
            Some(applied) => *applied == rules,
            None => rules.is_empty(),
        };
        if unchanged {
            return Ok(());
        }

        let mut servers = state.clone();
        if rules.is_empty() {
            servers.remove(&spec.server);
        } else {
            servers.insert(spec.server, rules.clone());
        }

        self.inner.apply(&servers).await?;
        *state = servers;
        drop(state);

        flush_denied_conntrack(&self.inner.runner, &rules).await;

        Ok(())
    }

    async fn clear(&self, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        let mut state = self.inner.state.lock().await;
        if state.remove(&server).is_none() {
            return Ok(());
        }

        self.inner.apply(&state).await?;

        Ok(())
    }

    async fn reconcile(&self, specs: &[FirewallServerSpec]) -> Result<(), anyhow::Error> {
        let mut servers = BTreeMap::new();
        for spec in specs {
            let rules = expand_rules(spec);
            if !rules.is_empty() {
                servers.insert(spec.server, rules);
            }
        }

        let mut state = self.inner.state.lock().await;

        self.inner.apply(&servers).await?;
        let changed: Vec<Vec<ConcreteRule>> = servers
            .iter()
            .filter(|(server, rules)| state.get(server) != Some(rules))
            .map(|(_, rules)| rules.clone())
            .collect();
        *state = servers;
        drop(state);

        for rules in changed {
            flush_denied_conntrack(&self.inner.runner, &rules).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::firewall::{FirewallBinding, FirewallRule, FirewallRuleProtocol};
    use std::{collections::HashSet, str::FromStr};

    fn rules() -> BTreeMap<uuid::Uuid, Vec<ConcreteRule>> {
        let spec = FirewallServerSpec {
            server: uuid::Uuid::from_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap(),
            bindings: vec![
                FirewallBinding {
                    ip: Some("192.168.1.5".parse().unwrap()),
                    port: 25565,
                },
                FirewallBinding {
                    ip: None,
                    port: 25566,
                },
            ],
            container_ports: Vec::new(),
            container_ips: Vec::new(),
            rules: vec![
                FirewallRule {
                    action: FirewallRuleAction::Allow,
                    protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                    sources: vec![cidr::IpCidr::from_str("10.0.0.0/8").unwrap()],
                    ports: Some(vec![25565]),
                },
                FirewallRule {
                    action: FirewallRuleAction::Deny,
                    protocols: HashSet::new(),
                    sources: Vec::new(),
                    ports: None,
                },
            ],
        };

        BTreeMap::from([(spec.server, expand_rules(&spec))])
    }

    #[test]
    fn render_rule_matches_container_addresses_outside_dnat() {
        let rendered = render_rule(
            "wings-abcdef123456",
            &ConcreteRule {
                protocol: FirewallRuleProtocol::Tcp,
                dst: RuleDst::Container {
                    ip: "172.18.0.5".parse().unwrap(),
                    port: 25565,
                },
                source: Some(cidr::IpCidr::from_str("172.18.0.0/16").unwrap()),
                action: FirewallRuleAction::Deny,
            },
        );

        assert_eq!(
            rendered,
            "-A wings-abcdef123456 -p tcp -m conntrack ! --ctstate DNAT -d 172.18.0.5 --dport 25565 -s 172.18.0.0/16 -j DROP"
        );
    }

    #[test]
    fn render_restore_file_builds_the_expected_v4_ruleset() {
        let restore_file = render_restore_file(
            &rules(),
            &[cidr::IpCidr::from_str("172.18.0.0/16").unwrap()],
            &["wings-deadbeef0000".to_string()],
            Family::V4,
        );

        assert_eq!(
            restore_file,
            concat!(
                "*filter\n",
                ":WINGS-FIREWALL - [0:0]\n",
                ":wings-abcdef123456 - [0:0]\n",
                ":wings-deadbeef0000 - [0:0]\n",
                "-F WINGS-FIREWALL\n",
                "-A WINGS-FIREWALL -s 172.18.0.0/16 -j RETURN\n",
                "-A WINGS-FIREWALL -j wings-abcdef123456\n",
                "-F wings-abcdef123456\n",
                "-A wings-abcdef123456 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n",
                "-A wings-abcdef123456 -p tcp -m conntrack --ctstate DNAT --ctorigdst 192.168.1.5 --ctorigdstport 25565 -s 10.0.0.0/8 -j RETURN\n",
                "-A wings-abcdef123456 -p tcp -m conntrack --ctstate DNAT --ctorigdst 192.168.1.5 --ctorigdstport 25565 -j DROP\n",
                "-A wings-abcdef123456 -p udp -m conntrack --ctstate DNAT --ctorigdst 192.168.1.5 --ctorigdstport 25565 -j DROP\n",
                "-A wings-abcdef123456 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 25566 -j DROP\n",
                "-A wings-abcdef123456 -p udp -m conntrack --ctstate DNAT --ctorigdstport 25566 -j DROP\n",
                "-F wings-deadbeef0000\n",
                "-X wings-deadbeef0000\n",
                "COMMIT\n",
            )
        );
    }

    #[test]
    fn render_restore_file_only_keeps_wildcard_rules_for_v6() {
        let restore_file = render_restore_file(&rules(), &[], &[], Family::V6);

        assert_eq!(
            restore_file,
            concat!(
                "*filter\n",
                ":WINGS-FIREWALL - [0:0]\n",
                ":wings-abcdef123456 - [0:0]\n",
                "-F WINGS-FIREWALL\n",
                "-A WINGS-FIREWALL -j wings-abcdef123456\n",
                "-F wings-abcdef123456\n",
                "-A wings-abcdef123456 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n",
                "-A wings-abcdef123456 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 25566 -j DROP\n",
                "-A wings-abcdef123456 -p udp -m conntrack --ctstate DNAT --ctorigdstport 25566 -j DROP\n",
                "COMMIT\n",
            )
        );
    }

    #[test]
    fn parse_existing_chains_finds_the_dispatch_and_server_chains() {
        let (has_dispatch, chains) = parse_existing_chains(concat!(
            "*filter\n",
            ":INPUT ACCEPT [0:0]\n",
            ":DOCKER-USER - [0:0]\n",
            ":WINGS-FIREWALL - [0:0]\n",
            ":wings-abcdef123456 - [0:0]\n",
            "-A WINGS-FIREWALL -j wings-abcdef123456\n",
            "COMMIT\n",
        ));

        assert!(has_dispatch);
        assert_eq!(chains, vec!["wings-abcdef123456".to_string()]);
    }
}
