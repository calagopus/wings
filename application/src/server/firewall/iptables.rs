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

const DISPATCH_CHAIN: &str = "WINGS-FIREWALL";
const SERVER_CHAIN_PREFIX: &str = "wings-";
const IPSET_MAX_ELEMENTS: u64 = 1_048_576;

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

    #[inline]
    fn address_family(self) -> AddressFamily {
        match self {
            Self::V4 => AddressFamily::V4,
            Self::V6 => AddressFamily::V6,
        }
    }

    #[inline]
    fn ipset_family(self) -> &'static str {
        match self {
            Self::V4 => "inet",
            Self::V6 => "inet6",
        }
    }
}

impl From<AddressFamily> for Family {
    #[inline]
    fn from(family: AddressFamily) -> Self {
        match family {
            AddressFamily::V4 => Self::V4,
            AddressFamily::V6 => Self::V6,
        }
    }
}

fn set_name(base: &str, family: Family) -> String {
    format!("{base}{}", family.address_family().set_suffix())
}

fn write_ipset_create(out: &mut String, name: &str, family: Family) {
    let _ = writeln!(
        out,
        "create {name} hash:net family {} maxelem {IPSET_MAX_ELEMENTS}",
        family.ipset_family()
    );
}

fn write_ipset_entries(out: &mut Vec<u8>, base: &str, entries: &[cidr::IpCidr]) {
    for entry in entries {
        let family = match entry {
            cidr::IpCidr::V4(_) => Family::V4,
            cidr::IpCidr::V6(_) => Family::V6,
        };

        out.extend_from_slice(format!("add {}-tmp {entry:#}\n", set_name(base, family)).as_bytes());
    }
}

/// Firewalls servers through per-server chains dispatched from a
/// `WINGS-FIREWALL` chain that is jumped to from `DOCKER-USER` (the container
/// engine's documented user-filtering hook), or directly from `FORWARD` when
/// no `DOCKER-USER` chain exists. Allowed traffic uses RETURN rather than
/// ACCEPT so it falls through to the engine's own filtering instead of
/// bypassing it.
///
/// Source files live in ipset `hash:net` sets that are refilled through a
/// shadow set and an atomic swap, so a rule never sees a half loaded list.
pub struct IptablesFirewall {
    inner: Arc<Inner>,
}

struct Inner {
    exempt_sources: Vec<cidr::IpCidr>,
    runner: CommandRunner,
    limits: sets::SourceFileLimits,
    ipset_available: bool,
    state: tokio::sync::Mutex<State>,
}

#[derive(Default)]
struct State {
    rules: BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    files: BTreeMap<uuid::Uuid, sets::ServerSourceFiles>,
}

impl IptablesFirewall {
    pub async fn new(
        exempt_sources: Vec<cidr::IpCidr>,
        runner: CommandRunner,
        limits: sets::SourceFileLimits,
    ) -> Self {
        let ipset_available = runner.run("ipset", &["version"], None).await.is_ok();
        if !ipset_available {
            tracing::warn!(
                "ipset is not installed, firewall rules with a source file will not match anything"
            );
        }

        Self {
            inner: Arc::new(Inner {
                exempt_sources,
                runner,
                limits,
                ipset_available,
                state: tokio::sync::Mutex::new(State::default()),
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
    match &rule.source {
        RuleSource::Cidr(source) => {
            let _ = write!(out, " -s {source:#}");
        }
        RuleSource::Set { name, family } => {
            let _ = write!(
                out,
                " -m set --match-set {} src",
                set_name(name, Family::from(*family))
            );
        }
        RuleSource::Any => {}
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
    ipset_available: bool,
) -> String {
    let live: Vec<(String, Vec<&ConcreteRule>)> = servers
        .iter()
        .filter_map(|(server, rules)| {
            let rules: Vec<&ConcreteRule> = rules
                .iter()
                .filter(|rule| family.applies(rule))
                .filter(|rule| ipset_available || !matches!(rule.source, RuleSource::Set { .. }))
                .collect();

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

    async fn list_sets(&self) -> BTreeSet<String> {
        match self.runner.run("ipset", &["list", "-n"], None).await {
            Ok(output) => output
                .lines()
                .map(str::trim)
                .filter(|name| name.starts_with(sets::SET_PREFIX))
                .map(ToString::to_string)
                .collect(),
            Err(_) => BTreeSet::new(),
        }
    }

    async fn declare_sets(&self, bases: &BTreeSet<String>) -> Result<(), anyhow::Error> {
        if bases.is_empty() || !self.ipset_available {
            return Ok(());
        }

        let mut out = String::new();
        for base in bases {
            for family in [Family::V4, Family::V6] {
                write_ipset_create(&mut out, &set_name(base, family), family);
            }
        }

        self.runner
            .run("ipset", &["-exist", "restore"], Some(out.as_bytes()))
            .await?;

        Ok(())
    }

    async fn destroy_orphan_sets(&self, servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>) {
        if !self.ipset_available {
            return;
        }

        // shadow sets are never matched by a rule and only outlive the load that
        // filled them when it was aborted, and no load can be running here since
        // both paths hold the state lock, so an existing one is always residue
        let needed = sets::needed_sets(servers);
        for set in self.list_sets().await {
            let referenced = needed
                .iter()
                .any(|base| set == set_name(base, Family::V4) || set == set_name(base, Family::V6));
            if referenced {
                continue;
            }

            if let Err(err) = self.runner.run("ipset", &["destroy", &set], None).await {
                tracing::debug!("failed to destroy unreferenced firewall set {set}: {err:#}");
            }
        }
    }

    async fn load_file(
        &self,
        base: &str,
        filesystem: &crate::server::filesystem::cap::CapFilesystem,
        path: &Path,
    ) -> Result<sets::LoadStats, sets::LoadError> {
        if !self.ipset_available {
            return Err(sets::LoadError::Command(anyhow::anyhow!(
                "ipset is not installed on this node"
            )));
        }

        let mut command = self
            .runner
            .spawn("ipset", &["-exist", "restore"])
            .await
            .map_err(sets::LoadError::Command)?;

        let mut prelude = String::new();
        for family in [Family::V4, Family::V6] {
            let live = set_name(base, family);
            write_ipset_create(&mut prelude, &live, family);
            write_ipset_create(&mut prelude, &format!("{live}-tmp"), family);
            let _ = writeln!(prelude, "flush {live}-tmp");
        }
        if let Err(err) = command.write(prelude.as_bytes()).await {
            command.abort().await;
            return Err(sets::LoadError::Command(err));
        }

        let stats = match sets::stream_source_file(
            filesystem,
            path,
            self.limits,
            &mut command,
            |out, entries| write_ipset_entries(out, base, entries),
        )
        .await
        {
            Ok(stats) => stats,
            Err(err) => {
                command.abort().await;
                return Err(err);
            }
        };

        let mut epilogue = String::new();
        for family in [Family::V4, Family::V6] {
            let live = set_name(base, family);
            let _ = writeln!(epilogue, "swap {live}-tmp {live}");
            let _ = writeln!(epilogue, "destroy {live}-tmp");
        }
        if let Err(err) = command.write(epilogue.as_bytes()).await {
            command.abort().await;
            return Err(sets::LoadError::Command(err));
        }

        command.finish().await.map_err(sets::LoadError::Command)?;

        Ok(stats)
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
        if !self.ipset_available {
            files.access.log_error(
                "This node has no ipset installed, firewall rules with a source file match nothing.",
            );
            return;
        }

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

        let restore_file = render_restore_file(
            servers,
            &self.exempt_sources,
            &stale_chains,
            family,
            self.ipset_available,
        );
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
        self.destroy_orphan_sets(servers).await;

        Ok(())
    }

    async fn reassert(&self, force: bool) {
        let mut state = self.state.lock().await;
        if state.rules.is_empty() && !force {
            return;
        }

        let mut intact = true;
        for family in [Family::V4, Family::V6] {
            if !self.family_needed(&state.rules, family) {
                continue;
            }

            if !has_jump(&self.runner, family).await {
                intact = false;
            }
        }

        if intact && self.ipset_available {
            let existing = self.list_sets().await;
            for base in sets::needed_sets(&state.rules) {
                if !existing.contains(&set_name(base.as_str(), Family::V4))
                    || !existing.contains(&set_name(base.as_str(), Family::V6))
                {
                    intact = false;
                }
            }
        }

        if intact && !force {
            let State { files, .. } = &mut *state;
            for files in files.values_mut() {
                self.load_changed(files, false).await;
            }

            return;
        }

        if !intact {
            tracing::warn!(
                "the wings iptables chains were flushed externally, reapplying server firewall rules"
            );
        }

        if let Err(err) = self.declare_sets(&sets::needed_sets(&state.rules)).await {
            tracing::error!("failed to recreate server firewall sets: {err:#}");
            return;
        }
        let State { rules, files } = &mut *state;
        for files in files.values_mut() {
            self.load_changed(files, !intact).await;
        }

        if let Err(err) = self.apply(rules).await {
            tracing::error!("failed to reapply server firewall rules: {err:#}");
            return;
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
    fn render_rule_matches_container_addresses_outside_dnat() {
        let rendered = render_rule(
            "wings-abcdef123456",
            &ConcreteRule {
                protocol: FirewallRuleProtocol::Tcp,
                dst: RuleDst::Container {
                    ip: "172.18.0.5".parse().unwrap(),
                    port: 25565,
                },
                source: RuleSource::Cidr(cidr::IpCidr::from_str("172.18.0.0/16").unwrap()),
                action: FirewallRuleAction::Deny,
            },
        );

        assert_eq!(
            rendered,
            "-A wings-abcdef123456 -p tcp -m conntrack ! --ctstate DNAT -d 172.18.0.5 --dport 25565 -s 172.18.0.0/16 -j DROP"
        );
    }

    #[test]
    fn render_rule_matches_source_file_sets() {
        let rendered = render_rule(
            "wings-abcdef123456",
            &ConcreteRule {
                protocol: FirewallRuleProtocol::Udp,
                dst: RuleDst::Published {
                    ip: None,
                    port: 25565,
                },
                source: RuleSource::Set {
                    name: "wf-abcdef123456-01234567".to_string(),
                    family: AddressFamily::V6,
                },
                action: FirewallRuleAction::Allow,
            },
        );

        assert_eq!(
            rendered,
            "-A wings-abcdef123456 -p udp -m conntrack --ctstate DNAT --ctorigdstport 25565 -m set --match-set wf-abcdef123456-01234567-6 src -j RETURN"
        );
    }

    #[test]
    fn write_ipset_entries_targets_the_shadow_set_of_each_family() {
        let mut out = Vec::new();
        write_ipset_entries(
            &mut out,
            "wf-abcdef123456-01234567",
            &[
                cidr::IpCidr::from_str("10.0.0.0/8").unwrap(),
                cidr::IpCidr::from_str("2001:db8::/32").unwrap(),
            ],
        );

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "add wf-abcdef123456-01234567-4-tmp 10.0.0.0/8\n",
                "add wf-abcdef123456-01234567-6-tmp 2001:db8::/32\n",
            )
        );
    }

    #[test]
    fn render_restore_file_builds_the_expected_v4_ruleset() {
        let restore_file = render_restore_file(
            &rules(),
            &[cidr::IpCidr::from_str("172.18.0.0/16").unwrap()],
            &["wings-deadbeef0000".to_string()],
            Family::V4,
            true,
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
        let restore_file = render_restore_file(&rules(), &[], &[], Family::V6, true);

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
