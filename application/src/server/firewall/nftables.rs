use super::{
    AddressFamily, ConcreteRule, FirewallBackend, FirewallRuleAction, FirewallServerSpec, RuleDst,
    RuleSource, expand_rules, flush_denied_conntrack, runner::CommandRunner, server_chain_name,
    sets,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    path::Path,
    sync::Arc,
};

/// Firewalls servers through an own `inet wings` table with a forward hook
/// chain. The table never touches the container engine's own ruleset: drops
/// are final across all netfilter tables no matter which backend the engine
/// uses, while allowed traffic simply falls through to the engine's normal
/// filtering.
///
/// The table is persistent: chains are rebuilt in place and source files
/// live in named sets that survive both rule changes and wings restarts, so
/// their contents never have to be held by wings.
pub struct NftablesFirewall {
    inner: Arc<Inner>,
}

struct Inner {
    exempt_sources: Vec<cidr::IpCidr>,
    runner: CommandRunner,
    limits: sets::SourceFileLimits,
    state: tokio::sync::Mutex<State>,
}

#[derive(Default)]
struct State {
    rules: BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    files: BTreeMap<uuid::Uuid, sets::ServerSourceFiles>,
}

impl NftablesFirewall {
    pub fn new(
        exempt_sources: Vec<cidr::IpCidr>,
        runner: CommandRunner,
        limits: sets::SourceFileLimits,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                exempt_sources,
                runner,
                limits,
                state: tokio::sync::Mutex::new(State::default()),
            }),
        }
    }
}

fn set_name(base: &str, family: AddressFamily) -> String {
    format!("{base}{}", family.set_suffix())
}

fn flush_sets(base: &str) -> String {
    format!(
        "flush set inet wings {}\nflush set inet wings {}\n",
        set_name(base, AddressFamily::V4),
        set_name(base, AddressFamily::V6)
    )
}

/// Whether nft refused the elements because they overlap an interval the set
/// already holds. Both the userspace overlap check and the kernel report this,
/// each with their own wording.
fn is_interval_conflict(err: &anyhow::Error) -> bool {
    let err = err.to_string();

    err.contains("conflicting intervals") || err.contains("interval overlaps")
}

fn write_set_declaration(out: &mut String, base: &str) {
    let _ = writeln!(
        out,
        "add set inet wings {} {{ type ipv4_addr; flags interval; auto-merge; }}",
        set_name(base, AddressFamily::V4)
    );
    let _ = writeln!(
        out,
        "add set inet wings {} {{ type ipv6_addr; flags interval; auto-merge; }}",
        set_name(base, AddressFamily::V6)
    );
}

fn write_elements(out: &mut Vec<u8>, base: &str, entries: &[cidr::IpCidr]) {
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let mut first = true;
        for entry in entries {
            let matches = match entry {
                cidr::IpCidr::V4(_) => family == AddressFamily::V4,
                cidr::IpCidr::V6(_) => family == AddressFamily::V6,
            };
            if !matches {
                continue;
            }

            if first {
                out.extend_from_slice(
                    format!("add element inet wings {} {{ ", set_name(base, family)).as_bytes(),
                );
                first = false;
            } else {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(format!("{entry:#}").as_bytes());
        }

        if !first {
            out.extend_from_slice(b" }\n");
        }
    }
}

fn parse_table_listing(json: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut chains = BTreeSet::new();
    let mut sets = BTreeSet::new();

    let Ok(listing) = serde_json::from_str::<serde_json::Value>(json) else {
        return (chains, sets);
    };
    let Some(objects) = listing.get("nftables").and_then(|value| value.as_array()) else {
        return (chains, sets);
    };

    for object in objects {
        if let Some(name) = object
            .get("chain")
            .and_then(|chain| chain.get("name"))
            .and_then(|name| name.as_str())
        {
            chains.insert(name.to_string());
        } else if let Some(name) = object
            .get("set")
            .and_then(|set| set.get("name"))
            .and_then(|name| name.as_str())
        {
            sets.insert(name.to_string());
        }
    }

    (chains, sets)
}

impl Inner {
    async fn list_table(&self) -> (BTreeSet<String>, BTreeSet<String>) {
        match self
            .runner
            .run("nft", &["-j", "list", "table", "inet", "wings"], None)
            .await
        {
            Ok(output) => parse_table_listing(&output),
            Err(_) => (BTreeSet::new(), BTreeSet::new()),
        }
    }

    async fn declare_sets(&self, bases: &BTreeSet<String>) -> Result<(), anyhow::Error> {
        if bases.is_empty() {
            return Ok(());
        }

        let mut out = String::from("add table inet wings\n");
        for base in bases {
            write_set_declaration(&mut out, base);
        }

        self.runner
            .run("nft", &["-f", "-"], Some(out.as_bytes()))
            .await?;

        Ok(())
    }

    async fn apply(
        &self,
        servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    ) -> Result<(), anyhow::Error> {
        let (existing_chains, existing_sets) = self.list_table().await;

        let stale_chains: Vec<String> = existing_chains
            .into_iter()
            .filter(|chain| chain != "forward")
            .filter(|chain| {
                !servers
                    .keys()
                    .any(|server| server_chain_name(*server) == *chain)
            })
            .collect();

        let ruleset = render_ruleset(servers, &self.exempt_sources, &stale_chains);
        self.runner
            .run("nft", &["-f", "-"], Some(ruleset.as_bytes()))
            .await?;

        if servers.is_empty() {
            return Ok(());
        }

        let needed = sets::needed_sets(servers);
        let mut orphans = String::new();
        for set in existing_sets {
            let referenced = needed.iter().any(|base| {
                set == set_name(base, AddressFamily::V4) || set == set_name(base, AddressFamily::V6)
            });
            if set.starts_with(sets::SET_PREFIX) && !referenced {
                let _ = writeln!(orphans, "delete set inet wings {set}");
            }
        }
        if !orphans.is_empty()
            && let Err(err) = self
                .runner
                .run("nft", &["-f", "-"], Some(orphans.as_bytes()))
                .await
        {
            tracing::debug!("failed to delete unreferenced firewall sets: {err:#}");
        }

        Ok(())
    }

    async fn stream_file(
        &self,
        base: &str,
        filesystem: &crate::server::filesystem::cap::CapFilesystem,
        path: &Path,
        flush_inline: bool,
    ) -> Result<sets::LoadStats, sets::LoadError> {
        let mut command = self
            .runner
            .spawn("nft", &["-f", "-"])
            .await
            .map_err(sets::LoadError::Command)?;

        if flush_inline {
            let flush = flush_sets(base);
            if let Err(err) = command.write(flush.as_bytes()).await {
                command.abort().await;
                return Err(sets::LoadError::Command(err));
            }
        }

        let stats = match sets::stream_source_file(
            filesystem,
            path,
            self.limits,
            &mut command,
            |out, entries| write_elements(out, base, entries),
        )
        .await
        {
            Ok(stats) => stats,
            Err(err) => {
                // nft parses everything before committing
                command.write(b"\nwings-abort\n").await.ok();
                command.abort().await;

                return Err(err);
            }
        };

        command.finish().await.map_err(sets::LoadError::Command)?;

        Ok(stats)
    }

    async fn load_file(
        &self,
        base: &str,
        filesystem: &crate::server::filesystem::cap::CapFilesystem,
        path: &Path,
    ) -> Result<sets::LoadStats, sets::LoadError> {
        match self.stream_file(base, filesystem, path, true).await {
            Err(sets::LoadError::Command(err)) if is_interval_conflict(&err) => {
                // the overlap is checked against what the set held before the
                // transaction, so the flush only helps once it has committed on
                // its own, which leaves the set empty until the entries land
                tracing::debug!("reloading firewall set {base} through a separate flush: {err:#}");

                let flush = flush_sets(base);
                self.runner
                    .run("nft", &["-f", "-"], Some(flush.as_bytes()))
                    .await
                    .map_err(sets::LoadError::Command)?;

                self.stream_file(base, filesystem, path, false)
                    .await
                    .map_err(sets::LoadError::cleared)
            }
            result => result,
        }
    }

    async fn sync_files(self: &Arc<Self>, state: &mut State, spec: &FirewallServerSpec) {
        let wanted = sets::referenced_files(spec);
        if wanted.is_empty() {
            state.files.remove(&spec.server);
            return;
        }

        let files = match (state.files.get_mut(&spec.server), &spec.files) {
            (Some(files), Some(access)) => {
                files.access = access.clone();
                files
            }
            (Some(files), None) => files,
            (None, Some(access)) => state
                .files
                .entry(spec.server)
                .or_insert_with(|| sets::ServerSourceFiles::new(access.clone())),
            (None, None) => return,
        };

        files.update(wanted);
        self.load_changed(files, false).await;

        let inner = Arc::clone(self);
        let server = spec.server;
        files.ensure_watching(move || {
            let inner = Arc::clone(&inner);

            Box::pin(async move { inner.reload_files(server).await })
        });
    }

    async fn load_changed(&self, files: &mut sets::ServerSourceFiles, force: bool) {
        let filesystem = files.access.filesystem.clone();

        for pending in files.pending(force).await {
            let result = self
                .load_file(&pending.set, &filesystem, &pending.path)
                .await;
            files.record(pending, result);
        }
    }

    async fn reload_files(&self, server: uuid::Uuid) {
        let mut state = self.state.lock().await;
        if let Some(files) = state.files.get_mut(&server) {
            self.load_changed(files, false).await;
        }
    }

    async fn reassert(&self, force: bool) {
        let mut state = self.state.lock().await;
        if state.rules.is_empty() && !force {
            return;
        }

        let intact = state.rules.is_empty()
            || matches!(
                self.runner
                    .run("nft", &["list", "chain", "inet", "wings", "forward"], None)
                    .await,
                Ok(output) if output.contains("jump")
            );

        if intact && !force {
            let State { files, .. } = &mut *state;
            for files in files.values_mut() {
                self.load_changed(files, false).await;
            }

            return;
        }

        if !intact {
            tracing::warn!(
                "the wings nftables table was flushed externally, reapplying server firewall rules"
            );
        }

        if let Err(err) = self.apply(&state.rules).await {
            tracing::error!("failed to reapply server firewall rules: {err:#}");
            return;
        }

        let State { rules, files } = &mut *state;
        for files in files.values_mut() {
            self.load_changed(files, !intact).await;
        }

        let denied: Vec<Vec<ConcreteRule>> = if intact {
            Vec::new()
        } else {
            rules.values().cloned().collect()
        };
        drop(state);

        for rules in denied {
            flush_denied_conntrack(&self.runner, &rules).await;
        }
    }
}

fn render_ruleset(
    servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    exempt_sources: &[cidr::IpCidr],
    stale_chains: &[String],
) -> String {
    let mut out = String::new();

    out.push_str("add table inet wings\n");

    if servers.is_empty() {
        out.push_str("delete table inet wings\n");
        return out;
    }

    out.push_str(
        "add chain inet wings forward { type filter hook forward priority filter - 1 ; policy accept ; }\n",
    );
    out.push_str("flush chain inet wings forward\n");

    for base in sets::needed_sets(servers) {
        write_set_declaration(&mut out, &base);
    }

    for (server, rules) in servers {
        let chain = server_chain_name(*server);

        let _ = writeln!(out, "add chain inet wings {chain}");
        let _ = writeln!(out, "flush chain inet wings {chain}");
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
            match &rule.source {
                RuleSource::Cidr(cidr::IpCidr::V4(source)) => {
                    let _ = write!(out, " ip saddr {source:#}");
                }
                RuleSource::Cidr(cidr::IpCidr::V6(source)) => {
                    let _ = write!(out, " ip6 saddr {source:#}");
                }
                RuleSource::Set {
                    name,
                    family: AddressFamily::V4,
                } => {
                    let _ = write!(out, " ip saddr @{}", set_name(name, AddressFamily::V4));
                }
                RuleSource::Set {
                    name,
                    family: AddressFamily::V6,
                } => {
                    let _ = write!(out, " ip6 saddr @{}", set_name(name, AddressFamily::V6));
                }
                RuleSource::Any => {}
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

    for chain in stale_chains {
        let _ = writeln!(out, "delete chain inet wings {chain}");
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

        let unchanged = match state.rules.get(&spec.server) {
            Some(applied) => *applied == rules,
            None => rules.is_empty(),
        };

        let mut servers = state.rules.clone();
        if rules.is_empty() {
            servers.remove(&spec.server);
        } else {
            servers.insert(spec.server, rules.clone());
        }

        if !unchanged {
            self.inner
                .declare_sets(&sets::needed_sets(&servers))
                .await?;
        }

        self.inner.sync_files(&mut state, spec).await;

        if unchanged {
            return Ok(());
        }

        self.inner.apply(&servers).await?;
        state.rules = servers;
        drop(state);

        flush_denied_conntrack(&self.inner.runner, &rules).await;

        Ok(())
    }

    async fn clear(&self, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        let mut state = self.inner.state.lock().await;
        state.files.remove(&server);
        if state.rules.remove(&server).is_none() {
            return Ok(());
        }

        self.inner.apply(&state.rules).await?;

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

        self.inner
            .declare_sets(&sets::needed_sets(&servers))
            .await?;

        state.files.retain(|server, _| servers.contains_key(server));
        for spec in specs {
            if servers.contains_key(&spec.server) {
                self.inner.sync_files(&mut state, spec).await;
            }
        }

        self.inner.apply(&servers).await?;
        let changed: Vec<Vec<ConcreteRule>> = servers
            .iter()
            .filter(|(server, rules)| state.rules.get(server) != Some(rules))
            .map(|(_, rules)| rules.clone())
            .collect();
        state.rules = servers;
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

    fn server() -> uuid::Uuid {
        uuid::Uuid::from_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap()
    }

    fn rules() -> BTreeMap<uuid::Uuid, Vec<ConcreteRule>> {
        let spec = FirewallServerSpec {
            server: server(),
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
                    source_file: None,
                },
                FirewallRule {
                    action: FirewallRuleAction::Deny,
                    protocols: HashSet::new(),
                    sources: Vec::new(),
                    ports: None,
                    source_file: None,
                },
            ],
            files: None,
        };

        BTreeMap::from([(spec.server, expand_rules(&spec))])
    }

    #[test]
    fn render_ruleset_removes_the_table_when_no_servers_have_rules() {
        assert_eq!(
            render_ruleset(&BTreeMap::new(), &[], &[]),
            "add table inet wings\ndelete table inet wings\n"
        );
    }

    #[test]
    fn render_ruleset_builds_the_expected_transaction() {
        let ruleset = render_ruleset(
            &rules(),
            &[cidr::IpCidr::from_str("172.18.0.0/16").unwrap()],
            &["wings-deadbeef0000".to_string()],
        );

        assert_eq!(
            ruleset,
            concat!(
                "add table inet wings\n",
                "add chain inet wings forward { type filter hook forward priority filter - 1 ; policy accept ; }\n",
                "flush chain inet wings forward\n",
                "add chain inet wings wings-abcdef123456\n",
                "flush chain inet wings wings-abcdef123456\n",
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
                "delete chain inet wings wings-deadbeef0000\n",
            )
        );
    }

    #[test]
    fn render_ruleset_declares_sets_and_matches_them_per_family() {
        let spec = FirewallServerSpec {
            server: server(),
            bindings: vec![FirewallBinding {
                ip: None,
                port: 25565,
            }],
            container_ports: Vec::new(),
            container_ips: Vec::new(),
            rules: vec![FirewallRule {
                action: FirewallRuleAction::Allow,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: Vec::new(),
                ports: None,
                source_file: Some("allow.txt".into()),
            }],
            files: None,
        };
        let set = sets::set_base_name(server(), Path::new("allow.txt"));
        let servers = BTreeMap::from([(spec.server, expand_rules(&spec))]);

        assert_eq!(
            render_ruleset(&servers, &[], &[]),
            format!(
                concat!(
                    "add table inet wings\n",
                    "add chain inet wings forward {{ type filter hook forward priority filter - 1 ; policy accept ; }}\n",
                    "flush chain inet wings forward\n",
                    "add set inet wings {set}-4 {{ type ipv4_addr; flags interval; auto-merge; }}\n",
                    "add set inet wings {set}-6 {{ type ipv6_addr; flags interval; auto-merge; }}\n",
                    "add chain inet wings wings-abcdef123456\n",
                    "flush chain inet wings wings-abcdef123456\n",
                    "add rule inet wings wings-abcdef123456 ct state established,related return\n",
                    "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto tcp ct original proto-dst 25565 ip saddr @{set}-4 return\n",
                    "add rule inet wings wings-abcdef123456 ct status dnat meta l4proto tcp ct original proto-dst 25565 ip6 saddr @{set}-6 return\n",
                    "add rule inet wings forward jump wings-abcdef123456\n",
                ),
                set = set
            )
        );
    }

    #[test]
    fn write_elements_groups_entries_by_family() {
        let mut out = Vec::new();
        write_elements(
            &mut out,
            "wf-abcdef123456-01234567",
            &[
                cidr::IpCidr::from_str("10.0.0.0/8").unwrap(),
                cidr::IpCidr::from_str("2001:db8::/32").unwrap(),
                cidr::IpCidr::from_str("192.0.2.1/32").unwrap(),
            ],
        );

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "add element inet wings wf-abcdef123456-01234567-4 { 10.0.0.0/8, 192.0.2.1/32 }\n",
                "add element inet wings wf-abcdef123456-01234567-6 { 2001:db8::/32 }\n",
            )
        );
    }

    #[test]
    fn parse_table_listing_finds_chains_and_sets() {
        let (chains, sets) = parse_table_listing(
            r#"{"nftables":[{"metainfo":{"version":"1.1.6"}},{"table":{"family":"inet","name":"wings"}},{"chain":{"family":"inet","table":"wings","name":"forward"}},{"chain":{"family":"inet","table":"wings","name":"wings-abcdef123456"}},{"set":{"family":"inet","name":"wf-abcdef123456-01234567-4","table":"wings","type":"ipv4_addr"}},{"rule":{"family":"inet","table":"wings","chain":"forward","expr":[]}}]}"#,
        );

        assert_eq!(
            chains,
            BTreeSet::from(["forward".to_string(), "wings-abcdef123456".to_string()])
        );
        assert_eq!(
            sets,
            BTreeSet::from(["wf-abcdef123456-01234567-4".to_string()])
        );
    }
}
