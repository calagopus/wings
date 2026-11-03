use super::cli::{FirewallPolicySpec, FirewallRuleSpec, PveCli};
use crate::server::firewall::{
    FirewallBackend, FirewallRuleAction, FirewallRuleProtocol, FirewallServerSpec, FirewallTarget,
    sets,
};
use anyhow::Context;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

const MANAGED_COMMENT_PREFIX: &str = "calagopus-wings:";

#[derive(Clone)]
struct StoredPolicy {
    vmid: u32,
    server: uuid::Uuid,
    ports: Vec<u16>,
    rules: Vec<crate::server::firewall::FirewallRule>,
    files: Option<sets::FirewallFileAccess>,
    ipsets: BTreeMap<String, Vec<String>>,
}

struct Watch {
    changed: Arc<tokio::sync::Notify>,
    task: tokio::task::AbortHandle,
    notifier: crate::server::filesystem::inotify::InotifyServerNotifier,
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.task.abort();
        self.notifier
            .watch_firewall_files(Vec::new(), Arc::clone(&self.changed));
    }
}

#[derive(Default)]
struct State {
    policies: BTreeMap<uuid::Uuid, StoredPolicy>,
    watches: BTreeMap<uuid::Uuid, Watch>,
}

struct Inner {
    cli: PveCli,
    node: String,
    tag_prefix: String,
    limits: sets::SourceFileLimits,
    state: tokio::sync::Mutex<State>,
    operation: tokio::sync::Mutex<()>,
}

pub struct ProxmoxFirewall {
    inner: Arc<Inner>,
}

impl ProxmoxFirewall {
    pub fn new(
        cli: PveCli,
        node: String,
        tag_prefix: String,
        limits: sets::SourceFileLimits,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                cli,
                node,
                tag_prefix,
                limits,
                state: tokio::sync::Mutex::new(State::default()),
                operation: tokio::sync::Mutex::new(()),
            }),
        }
    }

    fn stored(spec: &FirewallServerSpec) -> Result<StoredPolicy, anyhow::Error> {
        let FirewallTarget::ProxmoxLxc { vmid, interface } = spec
            .target
            .as_ref()
            .context("Proxmox firewall requires an LXC target")?;
        if interface != "net0" {
            anyhow::bail!("unsupported Proxmox firewall interface {interface}");
        }

        let mut ports = spec.container_ports.clone();
        ports.sort_unstable();
        ports.dedup();
        Ok(StoredPolicy {
            vmid: *vmid,
            server: spec.server,
            ports,
            rules: spec.rules.clone(),
            files: spec.files.clone(),
            ipsets: BTreeMap::new(),
        })
    }

    fn managed_prefix(server: uuid::Uuid) -> String {
        format!("{MANAGED_COMMENT_PREFIX}{server}:")
    }

    fn rule_sources(
        server: uuid::Uuid,
        rule: &crate::server::firewall::FirewallRule,
    ) -> Vec<Option<String>> {
        let mut sources: Vec<Option<String>> = rule
            .sources
            .iter()
            .map(|source| Some(format!("{source:#}")))
            .collect();
        sources.sort();
        if let Some(file) = &rule.source_file {
            let path = sets::source_file_path(file);
            sources.push(Some(format!("+{}", sets::set_base_name(server, &path))));
        }
        if sources.is_empty() {
            sources.push(None);
        }
        sources
    }

    fn translate(policy: &StoredPolicy) -> Vec<FirewallRuleSpec> {
        let mut translated = Vec::new();
        let prefix = Self::managed_prefix(policy.server);

        for (rule_index, rule) in policy.rules.iter().enumerate() {
            if rule.action == FirewallRuleAction::Deny
                && rule.protocols.is_empty()
                && rule.sources.is_empty()
                && rule.ports.is_none()
                && rule.source_file.is_none()
            {
                let sequence = translated.len();
                translated.push(FirewallRuleSpec {
                    r#type: "in".to_string(),
                    action: "DROP".to_string(),
                    iface: "net0".to_string(),
                    proto: None,
                    dport: None,
                    source: None,
                    comment: format!("{prefix}{rule_index}:{sequence} managed by Wings"),
                });
                continue;
            }

            let allowed_ports: BTreeSet<u16> = match &rule.ports {
                Some(restricted) => policy
                    .ports
                    .iter()
                    .copied()
                    .filter(|port| restricted.contains(port))
                    .collect(),
                None => policy.ports.iter().copied().collect(),
            };
            if allowed_ports.is_empty() {
                continue;
            }
            let dport = allowed_ports
                .into_iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let protocols: Vec<FirewallRuleProtocol> =
                [FirewallRuleProtocol::Tcp, FirewallRuleProtocol::Udp]
                    .into_iter()
                    .filter(|protocol| {
                        rule.protocols.is_empty() || rule.protocols.contains(protocol)
                    })
                    .collect();

            for protocol in protocols {
                for source in Self::rule_sources(policy.server, rule) {
                    let sequence = translated.len();
                    translated.push(FirewallRuleSpec {
                        r#type: "in".to_string(),
                        action: match rule.action {
                            FirewallRuleAction::Allow => "ACCEPT",
                            FirewallRuleAction::Deny => "DROP",
                        }
                        .to_string(),
                        iface: "net0".to_string(),
                        proto: Some(protocol.as_str().to_string()),
                        dport: Some(dport.clone()),
                        source,
                        comment: format!("{prefix}{rule_index}:{sequence} managed by Wings"),
                    });
                }
            }
        }

        translated
    }

    async fn load_ipsets(&self, policy: &mut StoredPolicy) {
        let Some(access) = &policy.files else {
            policy.ipsets.clear();
            return;
        };

        let referenced = policy.rules.iter().filter_map(|rule| {
            rule.source_file.as_ref().map(|file| {
                let path = sets::source_file_path(file);
                (sets::set_base_name(policy.server, &path), path)
            })
        });
        let mut wanted = BTreeSet::new();
        for (name, path) in referenced {
            wanted.insert(name.clone());
            policy.ipsets.entry(name.clone()).or_default();
            match sets::read_source_file(&access.filesystem, &path, self.inner.limits).await {
                Ok((entries, stats)) => {
                    policy
                        .ipsets
                        .insert(name, entries.into_iter().map(|entry| format!("{entry:#}")).collect());
                    let message = format!(
                        "Firewall source file {} loaded with {} entries{}.",
                        path.display(),
                        stats.entries,
                        if stats.invalid == 0 {
                            String::new()
                        } else {
                            format!(", {} invalid lines skipped", stats.invalid)
                        }
                    );
                    if stats.entries == 0 || stats.invalid > 0 {
                        access.log_error(&message);
                    } else {
                        access.log(&message);
                    }
                }
                Err(error) => access.log_error(&format!(
                    "Firewall source file {} could not be loaded, the previous entries are retained: {error}",
                    path.display()
                )),
            }
        }
        policy.ipsets.retain(|name, _| wanted.contains(name));
    }

    async fn apply_policy(&self, policy: &mut StoredPolicy) -> Result<(), anyhow::Error> {
        self.load_ipsets(policy).await;
        // Enable filtering first. Applying the managed rules is then the
        // committing operation, so a crash cannot leave new rules ineffective.
        self.inner.cli.enable_network_firewall(policy.vmid).await?;
        self.inner
            .cli
            .apply_firewall_config(&FirewallPolicySpec {
                vmid: policy.vmid,
                managed_prefix: Self::managed_prefix(policy.server),
                rules: Self::translate(policy),
                ipsets: policy.ipsets.clone(),
            })
            .await
    }

    async fn apply_empty(&self, vmid: u32, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        self.inner
            .cli
            .apply_firewall_config(&FirewallPolicySpec {
                vmid,
                managed_prefix: Self::managed_prefix(server),
                rules: Vec::new(),
                ipsets: BTreeMap::new(),
            })
            .await
    }

    async fn reload(inner: Arc<Inner>, server: uuid::Uuid) {
        let firewall = Self { inner };
        let _operation = firewall.inner.operation.lock().await;
        let policy = firewall
            .inner
            .state
            .lock()
            .await
            .policies
            .get(&server)
            .cloned();
        let Some(mut policy) = policy else {
            return;
        };
        if let Err(error) = firewall.apply_policy(&mut policy).await {
            tracing::error!(server = %server, "failed to reload Proxmox firewall source files: {error:#}");
            return;
        }
        firewall
            .inner
            .state
            .lock()
            .await
            .policies
            .insert(server, policy);
    }

    async fn update_watch(&self, policy: &StoredPolicy) {
        let mut state = self.inner.state.lock().await;
        state.watches.remove(&policy.server);
        let Some(access) = &policy.files else {
            return;
        };
        let paths: Vec<_> = policy
            .rules
            .iter()
            .filter_map(|rule| rule.source_file.as_ref())
            .map(|file| {
                access
                    .filesystem
                    .base_path
                    .join(sets::source_file_path(file))
            })
            .collect();
        if paths.is_empty() {
            return;
        }

        let changed = Arc::new(tokio::sync::Notify::new());
        let Some(notifier) = access.notifier.clone() else {
            return;
        };
        notifier.watch_firewall_files(paths, Arc::clone(&changed));
        let inner = Arc::clone(&self.inner);
        let server = policy.server;
        let task = tokio::spawn({
            let changed = Arc::clone(&changed);
            async move {
                loop {
                    changed.notified().await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    Self::reload(Arc::clone(&inner), server).await;
                }
            }
        })
        .abort_handle();
        state.watches.insert(
            policy.server,
            Watch {
                changed,
                task,
                notifier,
            },
        );
    }

    async fn owned_vmids(&self, server: uuid::Uuid) -> Result<Vec<u32>, anyhow::Error> {
        let server_tag = format!("{}-server-{server}", self.inner.tag_prefix);
        let replacement_tag = format!("{}-repl-{server}", self.inner.tag_prefix);
        Ok(self
            .inner
            .cli
            .list_containers()
            .await?
            .into_iter()
            .filter(|container| {
                container.node == self.inner.node
                    && container
                        .tags
                        .iter()
                        .any(|tag| tag == &server_tag || tag == &replacement_tag)
            })
            .map(|container| container.vmid)
            .collect())
    }

    fn managed_vmids_for(
        containers: Vec<super::cli::ClusterContainer>,
        node: &str,
        tag_prefix: &str,
    ) -> BTreeMap<uuid::Uuid, Vec<u32>> {
        let server_prefix = format!("{tag_prefix}-server-");
        let replacement_prefix = format!("{tag_prefix}-repl-");
        let mut managed = BTreeMap::<uuid::Uuid, Vec<u32>>::new();
        for container in containers {
            if container.node != node {
                continue;
            }
            for tag in &container.tags {
                let value = tag
                    .strip_prefix(&server_prefix)
                    .or_else(|| tag.strip_prefix(&replacement_prefix));
                let Some(server) = value.and_then(|value| uuid::Uuid::parse_str(value).ok()) else {
                    continue;
                };
                managed.entry(server).or_default().push(container.vmid);
                break;
            }
        }
        managed
    }

    async fn managed_vmids(&self) -> Result<BTreeMap<uuid::Uuid, Vec<u32>>, anyhow::Error> {
        Ok(Self::managed_vmids_for(
            self.inner.cli.list_containers().await?,
            &self.inner.node,
            &self.inner.tag_prefix,
        ))
    }

    /// Removes Wings-owned guest rules before switching to a host-local
    /// backend. Administrator rules and containers on other cluster nodes are
    /// left untouched.
    pub async fn clear_managed(&self) -> Result<(), anyhow::Error> {
        let _operation = self.inner.operation.lock().await;
        for (server, vmids) in self.managed_vmids().await? {
            for vmid in vmids {
                self.apply_empty(vmid, server).await?;
            }
        }
        self.inner.state.lock().await.policies.clear();
        self.inner.state.lock().await.watches.clear();
        Ok(())
    }
}

#[async_trait::async_trait]
impl FirewallBackend for ProxmoxFirewall {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        if !self.inner.cli.cluster_firewall_enabled().await? {
            anyhow::bail!(
                "the Proxmox datacenter firewall is disabled; enable it before using the Proxmox LXC firewall backend"
            );
        }
        tracing::info!("using Proxmox guest firewall backend");
        Ok(())
    }

    async fn sync(&self, spec: &FirewallServerSpec) -> Result<(), anyhow::Error> {
        let _operation = self.inner.operation.lock().await;
        let mut policy = Self::stored(spec)?;
        if let Some(previous) = self.inner.state.lock().await.policies.get(&spec.server) {
            policy.ipsets = previous.ipsets.clone();
        }
        self.apply_policy(&mut policy).await?;
        self.inner
            .state
            .lock()
            .await
            .policies
            .insert(spec.server, policy.clone());
        drop(_operation);
        self.update_watch(&policy).await;
        Ok(())
    }

    async fn clear(&self, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        let _operation = self.inner.operation.lock().await;
        let remembered = self
            .inner
            .state
            .lock()
            .await
            .policies
            .remove(&server)
            .map(|policy| policy.vmid);
        self.inner.state.lock().await.watches.remove(&server);
        let mut vmids: HashSet<u32> = self.owned_vmids(server).await?.into_iter().collect();
        if let Some(vmid) = remembered {
            vmids.insert(vmid);
        }
        for vmid in vmids {
            self.apply_empty(vmid, server).await?;
        }
        Ok(())
    }

    async fn reconcile(&self, specs: &[FirewallServerSpec]) -> Result<(), anyhow::Error> {
        let wanted: HashSet<uuid::Uuid> = specs.iter().map(|spec| spec.server).collect();
        let mut stale: HashSet<uuid::Uuid> = self
            .inner
            .state
            .lock()
            .await
            .policies
            .keys()
            .filter(|server| !wanted.contains(server))
            .copied()
            .collect();
        let discovered = self.managed_vmids().await?;
        stale.extend(
            discovered
                .keys()
                .filter(|server| !wanted.contains(server))
                .copied(),
        );
        for server in stale {
            let _operation = self.inner.operation.lock().await;
            let remembered = self
                .inner
                .state
                .lock()
                .await
                .policies
                .remove(&server)
                .map(|policy| policy.vmid);
            self.inner.state.lock().await.watches.remove(&server);
            let mut vmids: HashSet<u32> = discovered
                .get(&server)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            if let Some(vmid) = remembered {
                vmids.insert(vmid);
            }
            for vmid in vmids {
                self.apply_empty(vmid, server).await?;
            }
        }
        for spec in specs {
            self.sync(spec).await?;
        }
        crate::server::firewall::clear_host_local(self.inner.limits).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_inventory_excludes_other_cluster_nodes() {
        let local = uuid::Uuid::parse_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap();
        let remote = uuid::Uuid::parse_str("12345678-3456-7890-abcd-ef1234567890").unwrap();
        let containers = vec![
            super::super::cli::ClusterContainer {
                vmid: 100,
                node: "pve-a".to_string(),
                status: None,
                tags: vec![format!("calagopus-server-{local}")],
            },
            super::super::cli::ClusterContainer {
                vmid: 200,
                node: "pve-b".to_string(),
                status: None,
                tags: vec![format!("calagopus-server-{remote}")],
            },
        ];

        let managed = ProxmoxFirewall::managed_vmids_for(containers, "pve-a", "calagopus");
        assert_eq!(managed.get(&local), Some(&vec![100]));
        assert!(!managed.contains_key(&remote));
    }

    #[test]
    fn translates_panel_rules_to_vm_scoped_proxmox_rules() {
        let server = uuid::Uuid::parse_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap();
        let policy = StoredPolicy {
            vmid: 100,
            server,
            ports: vec![25565, 25566],
            rules: vec![crate::server::firewall::FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: vec!["10.0.0.0/8".parse().unwrap()],
                ports: Some(vec![25565]),
                source_file: None,
            }],
            files: None,
            ipsets: BTreeMap::new(),
        };

        let rules = ProxmoxFirewall::translate(&policy);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "DROP");
        assert_eq!(rules[0].iface, "net0");
        assert_eq!(rules[0].proto.as_deref(), Some("tcp"));
        assert_eq!(rules[0].dport.as_deref(), Some("25565"));
        assert_eq!(rules[0].source.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn translates_empty_protocols_and_source_files() {
        let server = uuid::Uuid::parse_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap();
        let source_file = "blocked.txt".to_string();
        let policy = StoredPolicy {
            vmid: 100,
            server,
            ports: vec![25565],
            rules: vec![crate::server::firewall::FirewallRule {
                action: FirewallRuleAction::Allow,
                protocols: HashSet::new(),
                sources: Vec::new(),
                ports: None,
                source_file: Some(source_file.clone().into()),
            }],
            files: None,
            ipsets: BTreeMap::new(),
        };

        let rules = ProxmoxFirewall::translate(&policy);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].proto.as_deref(), Some("tcp"));
        assert_eq!(rules[1].proto.as_deref(), Some("udp"));
        let path = sets::source_file_path(&source_file);
        let expected = format!("+{}", sets::set_base_name(server, &path));
        assert_eq!(rules[0].source.as_deref(), Some(expected.as_str()));
        assert_eq!(rules[1].source.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn does_not_emit_synthetic_fallback_rules() {
        let server = uuid::Uuid::parse_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap();
        let policy = StoredPolicy {
            vmid: 100,
            server,
            ports: vec![25565, 25566],
            rules: vec![crate::server::firewall::FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::from([FirewallRuleProtocol::Tcp]),
                sources: Vec::new(),
                ports: Some(vec![25565]),
                source_file: None,
            }],
            files: None,
            ipsets: BTreeMap::new(),
        };

        let rules = ProxmoxFirewall::translate(&policy);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "DROP");
        assert_eq!(rules[0].proto.as_deref(), Some("tcp"));
        assert_eq!(rules[0].dport.as_deref(), Some("25565"));
    }

    #[test]
    fn translates_terminal_deny_everything_as_an_unrestricted_drop() {
        let server = uuid::Uuid::parse_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap();
        let policy = StoredPolicy {
            vmid: 100,
            server,
            ports: vec![25565],
            rules: vec![crate::server::firewall::FirewallRule {
                action: FirewallRuleAction::Deny,
                protocols: HashSet::new(),
                sources: Vec::new(),
                ports: None,
                source_file: None,
            }],
            files: None,
            ipsets: BTreeMap::new(),
        };

        let rules = ProxmoxFirewall::translate(&policy);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "DROP");
        assert_eq!(rules[0].iface, "net0");
        assert_eq!(rules[0].proto, None);
        assert_eq!(rules[0].dport, None);
        assert_eq!(rules[0].source, None);
    }
}
