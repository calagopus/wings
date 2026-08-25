use super::{
    ConcreteRule, FirewallBackend, FirewallRuleAction, FirewallServerSpec, RuleDst, expand_rules,
    flush_denied_conntrack, run_command, server_chain_name,
};
use std::{collections::BTreeMap, fmt::Write, sync::Arc};

/// Firewalls servers through an own `inet wings` table with a forward hook
/// chain. The table never touches the container engine's own ruleset: drops
/// are final across all netfilter tables no matter which backend the engine
/// uses, while allowed traffic simply falls through to the engine's normal
/// filtering.
pub struct NftablesFirewall {
    inner: Arc<Inner>,
}

struct Inner {
    exempt_sources: Vec<cidr::IpCidr>,
    state: tokio::sync::Mutex<BTreeMap<uuid::Uuid, Vec<ConcreteRule>>>,
}

impl NftablesFirewall {
    pub fn new(exempt_sources: Vec<cidr::IpCidr>) -> Self {
        Self {
            inner: Arc::new(Inner {
                exempt_sources,
                state: tokio::sync::Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

impl Inner {
    async fn apply(
        &self,
        servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    ) -> Result<(), anyhow::Error> {
        let ruleset = render_ruleset(servers, &self.exempt_sources);

        run_command("nft", &["-f", "-"], Some(ruleset.as_bytes())).await?;

        Ok(())
    }

    async fn reassert(&self, force: bool) {
        let servers = self.state.lock().await;
        if servers.is_empty() && !force {
            return;
        }

        let intact = servers.is_empty()
            || matches!(
                run_command("nft", &["list", "chain", "inet", "wings", "forward"], None).await,
                Ok(output) if output.contains("jump")
            );
        if intact && !force {
            return;
        }

        if !intact {
            tracing::warn!(
                "the wings nftables table was flushed externally, reapplying server firewall rules"
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
            flush_denied_conntrack(&rules).await;
        }
    }
}

fn render_ruleset(
    servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    exempt_sources: &[cidr::IpCidr],
) -> String {
    let mut out = String::new();

    out.push_str("add table inet wings\n");
    out.push_str("delete table inet wings\n");

    if servers.is_empty() {
        return out;
    }

    out.push_str("add table inet wings\n");
    out.push_str(
        "add chain inet wings forward { type filter hook forward priority filter - 1 ; policy accept ; }\n",
    );

    for (server, rules) in servers {
        let chain = server_chain_name(*server);

        let _ = writeln!(out, "add chain inet wings {chain}");
        let _ = writeln!(
            out,
            "add rule inet wings {chain} ct state established,related return"
        );
        for rule in rules {
            match rule.dst {
                RuleDst::Published { ip, port } => {
                    let _ = write!(
                        out,
                        "add rule inet wings {chain} ct status dnat meta l4proto {}",
                        rule.protocol.as_str()
                    );
                    match ip {
                        Some(std::net::IpAddr::V4(ip)) => {
                            let _ = write!(out, " ct original ip daddr {ip}");
                        }
                        Some(std::net::IpAddr::V6(ip)) => {
                            let _ = write!(out, " ct original ip6 daddr {ip}");
                        }
                        None => {}
                    }
                    let _ = write!(out, " ct original proto-dst {port}");
                }
                RuleDst::Container { ip, port } => {
                    let _ = write!(
                        out,
                        "add rule inet wings {chain} ct status & dnat == 0 meta l4proto {}",
                        rule.protocol.as_str()
                    );
                    match ip {
                        std::net::IpAddr::V4(ip) => {
                            let _ = write!(out, " ip daddr {ip}");
                        }
                        std::net::IpAddr::V6(ip) => {
                            let _ = write!(out, " ip6 daddr {ip}");
                        }
                    }
                    let _ = write!(out, " th dport {port}");
                }
            }
            match rule.source {
                Some(cidr::IpCidr::V4(source)) => {
                    let _ = write!(out, " ip saddr {source:#}");
                }
                Some(cidr::IpCidr::V6(source)) => {
                    let _ = write!(out, " ip6 saddr {source:#}");
                }
                None => {}
            }
            let _ = writeln!(
                out,
                " {}",
                match rule.action {
                    FirewallRuleAction::Allow => "return",
                    FirewallRuleAction::Deny => "drop",
                }
            );
        }
    }

    for source in exempt_sources {
        match source {
            cidr::IpCidr::V4(source) => {
                let _ = writeln!(
                    out,
                    "add rule inet wings forward ip saddr {source:#} return"
                );
            }
            cidr::IpCidr::V6(source) => {
                let _ = writeln!(
                    out,
                    "add rule inet wings forward ip6 saddr {source:#} return"
                );
            }
        }
    }
    for server in servers.keys() {
        let _ = writeln!(
            out,
            "add rule inet wings forward jump {}",
            server_chain_name(*server)
        );
    }

    out
}

#[async_trait::async_trait]
impl FirewallBackend for NftablesFirewall {
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

        flush_denied_conntrack(&rules).await;

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
            flush_denied_conntrack(&rules).await;
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
            container_ports: vec![25565, 25566],
            container_ips: vec!["172.18.0.5".parse().unwrap()],
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
    fn render_ruleset_removes_the_table_when_no_servers_have_rules() {
        assert_eq!(
            render_ruleset(&BTreeMap::new(), &[]),
            "add table inet wings\ndelete table inet wings\n"
        );
    }

    #[test]
    fn render_ruleset_builds_the_expected_transaction() {
        let ruleset = render_ruleset(
            &rules(),
            &[cidr::IpCidr::from_str("172.18.0.0/16").unwrap()],
        );

        assert_eq!(
            ruleset,
            concat!(
                "add table inet wings\n",
                "delete table inet wings\n",
                "add table inet wings\n",
                "add chain inet wings forward { type filter hook forward priority filter - 1 ; policy accept ; }\n",
                "add chain inet wings wings-abcdef123456\n",
                "add rule inet wings wings-abcdef123456 ct state established,related return\n",
                "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto tcp ct original ip daddr 192.168.1.5 ct original proto-dst 25565 ip saddr 10.0.0.0/8 return\n",
                "add rule inet wings wings-abcdef123456 ct status & dnat == 0 meta l4proto tcp ip daddr 172.18.0.5 th dport 25565 ip saddr 10.0.0.0/8 return\n",
                "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto tcp ct original ip daddr 192.168.1.5 ct original proto-dst 25565 drop\n",
                "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto udp ct original ip daddr 192.168.1.5 ct original proto-dst 25565 drop\n",
                "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto tcp ct original proto-dst 25566 drop\n",
                "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto udp ct original proto-dst 25566 drop\n",
                "add rule inet wings wings-abcdef123456 ct status & dnat == 0 meta l4proto tcp ip daddr 172.18.0.5 th dport 25565 drop\n",
                "add rule inet wings wings-abcdef123456 ct status & dnat == 0 meta l4proto udp ip daddr 172.18.0.5 th dport 25565 drop\n",
                "add rule inet wings wings-abcdef123456 ct status & dnat == 0 meta l4proto tcp ip daddr 172.18.0.5 th dport 25566 drop\n",
                "add rule inet wings wings-abcdef123456 ct status & dnat == 0 meta l4proto udp ip daddr 172.18.0.5 th dport 25566 drop\n",
                "add rule inet wings forward ip saddr 172.18.0.0/16 return\n",
                "add rule inet wings forward jump wings-abcdef123456\n",
            )
        );
    }
}
