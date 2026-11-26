use super::{
    ConcreteRule, FirewallBackend, FirewallServerSpec, expand_rules, flush_denied_conntrack,
    runner::CommandRunner, sets,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

#[async_trait::async_trait]
pub trait FirewallDriver: Send + Sync + 'static {
    const FLUSHED_WARNING: &'static str;

    fn runner(&self) -> &CommandRunner;

    fn source_files_unsupported(&self) -> Option<&'static str> {
        None
    }

    async fn declare_sets(&self, bases: &BTreeSet<String>) -> Result<(), anyhow::Error>;
    async fn apply(
        &self,
        servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    ) -> Result<(), anyhow::Error>;
    async fn load_file(
        &self,
        base: &str,
        filesystem: &crate::server::filesystem::cap::CapFilesystem,
        path: &Path,
    ) -> Result<sets::LoadStats, sets::LoadError>;

    /// Whether the applied `rules` are still hooked into netfilter.
    async fn intact(&self, rules: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>) -> bool;
}

pub struct FirewallController<D: FirewallDriver> {
    inner: Arc<Inner<D>>,
}

struct Inner<D: FirewallDriver> {
    driver: D,
    state: tokio::sync::Mutex<State>,
}

#[derive(Default)]
struct State {
    rules: BTreeMap<uuid::Uuid, Vec<ConcreteRule>>,
    files: BTreeMap<uuid::Uuid, sets::ServerSourceFiles>,
}

impl<D: FirewallDriver> FirewallController<D> {
    pub fn with_driver(driver: D) -> Self {
        Self {
            inner: Arc::new(Inner {
                driver,
                state: tokio::sync::Mutex::new(State::default()),
            }),
        }
    }
}

impl<D: FirewallDriver> Inner<D> {
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
        if let Some(message) = self.driver.source_files_unsupported() {
            files.access.log_error(message);
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
                .driver
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

        let intact = self.driver.intact(&state.rules).await;

        if intact && !force {
            let State { files, .. } = &mut *state;
            for files in files.values_mut() {
                self.load_changed(files, false).await;
            }

            return;
        }

        if !intact {
            tracing::warn!("{}", D::FLUSHED_WARNING);
        }

        if let Err(err) = self
            .driver
            .declare_sets(&sets::needed_sets(&state.rules))
            .await
        {
            tracing::error!("failed to recreate server firewall sets: {err:#}");
            return;
        }
        let State { rules, files } = &mut *state;
        for files in files.values_mut() {
            self.load_changed(files, !intact).await;
        }

        if let Err(err) = self.driver.apply(rules).await {
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
            flush_denied_conntrack(self.driver.runner(), &rules).await;
        }
    }
}

#[async_trait::async_trait]
impl<D: FirewallDriver> FirewallBackend for FirewallController<D> {
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
                .driver
                .declare_sets(&sets::needed_sets(&servers))
                .await?;
        }

        self.inner.sync_files(&mut state, spec).await;

        if unchanged {
            return Ok(());
        }

        self.inner.driver.apply(&servers).await?;
        state.rules = servers;
        drop(state);

        flush_denied_conntrack(self.inner.driver.runner(), &rules).await;

        Ok(())
    }

    async fn clear(&self, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        let mut state = self.inner.state.lock().await;
        state.files.remove(&server);
        if state.rules.remove(&server).is_none() {
            return Ok(());
        }

        self.inner.driver.apply(&state.rules).await?;

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
            .driver
            .declare_sets(&sets::needed_sets(&servers))
            .await?;

        state.files.retain(|server, _| servers.contains_key(server));
        for spec in specs {
            if servers.contains_key(&spec.server) {
                self.inner.sync_files(&mut state, spec).await;
            }
        }

        self.inner.driver.apply(&servers).await?;
        let changed: Vec<Vec<ConcreteRule>> = servers
            .iter()
            .filter(|(server, rules)| state.rules.get(server) != Some(rules))
            .map(|(_, rules)| rules.clone())
            .collect();
        state.rules = servers;
        drop(state);

        for rules in changed {
            flush_denied_conntrack(self.inner.driver.runner(), &rules).await;
        }

        Ok(())
    }
}
