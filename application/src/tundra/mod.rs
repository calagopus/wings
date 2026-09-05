use crate::routes::State;
use anyhow::Context;
use std::{
    collections::HashSet,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use tundra_common::state::Snapshot;

pub mod ca;
pub mod daemon;
pub mod hub;
pub mod shim;

const SOCKET_DIRECTORY: &str = "run";
const SOCKET_NAME: &str = "wings.sock";
const TOKEN_NAME: &str = "token";

const POLL_INTERVAL: Duration = Duration::from_secs(60);
const PANEL_GRACE: Duration = Duration::from_secs(180);
/// A boot storm queues one of these per server, and rebuilding a snapshot costs a container
/// listing, so the requests are left to pile up into a single rebuild.
const REBROADCAST_DEBOUNCE: Duration = Duration::from_secs(2);

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), anyhow::Error> {
    let parent = path.parent().context("private file has no parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    staged.write_all(bytes)?;
    staged.persist(path)?;

    Ok(())
}

struct ControlState {
    cached: Option<Arc<Snapshot>>,
    enriched: Option<Arc<Snapshot>>,
    revoked: Option<Arc<Snapshot>>,
    last_panel_contact: Instant,
    disabled: bool,
}

impl ControlState {
    fn serving(&self) -> bool {
        !self.disabled && self.cached.is_some() && self.last_panel_contact.elapsed() < PANEL_GRACE
    }

    fn publish(&mut self, source: &Arc<Snapshot>, snapshot: Snapshot) -> Option<Arc<Snapshot>> {
        if !self.serving()
            || !self
                .cached
                .as_ref()
                .is_some_and(|cached| Arc::ptr_eq(cached, source))
            || self.enriched.as_deref() == Some(&snapshot)
        {
            return None;
        }

        let snapshot = Arc::new(snapshot);
        self.enriched = Some(Arc::clone(&snapshot));
        Some(snapshot)
    }
}

pub struct TundraManager {
    pub data_dir: PathBuf,
    pub hub: hub::Hub,
    ca: ca::LocalCa,
    docker: Arc<bollard::Docker>,
    token: parking_lot::RwLock<String>,

    control: parking_lot::Mutex<ControlState>,
    refresh: tokio::sync::Notify,
    rebroadcast: tokio::sync::Notify,

    reconcile: tokio::sync::Notify,
    disable: tokio::sync::Notify,
    last_restart: parking_lot::Mutex<Option<Instant>>,
    images_refreshed: AtomicBool,
    filesystem: Arc<tokio::sync::Mutex<()>>,
}

impl TundraManager {
    pub fn create(
        config: &crate::config::Config,
        docker: Arc<bollard::Docker>,
    ) -> Result<Arc<Self>, anyhow::Error> {
        let cfg = config.load();
        let data_dir = cfg.tundra.data_directory.as_path(&cfg);

        let socket_dir = data_dir.join(SOCKET_DIRECTORY);
        std::fs::create_dir_all(&socket_dir)
            .context(format!("failed to create {}", socket_dir.display()))?;

        let ca = ca::LocalCa::load_or_create(&data_dir)?;
        let token = load_or_create_token(&data_dir)?;

        Ok(Arc::new(Self {
            data_dir,
            hub: hub::Hub::default(),
            ca,
            docker,
            token: parking_lot::RwLock::new(token),
            control: parking_lot::Mutex::new(ControlState {
                cached: None,
                enriched: None,
                revoked: None,
                last_panel_contact: Instant::now(),
                disabled: false,
            }),
            refresh: tokio::sync::Notify::new(),
            rebroadcast: tokio::sync::Notify::new(),
            reconcile: tokio::sync::Notify::new(),
            disable: tokio::sync::Notify::new(),
            last_restart: parking_lot::Mutex::new(None),
            images_refreshed: AtomicBool::new(false),
            filesystem: Arc::new(tokio::sync::Mutex::new(())),
        }))
    }

    #[inline]
    pub fn socket_path(&self) -> PathBuf {
        self.data_dir.join(SOCKET_DIRECTORY).join(SOCKET_NAME)
    }

    #[inline]
    pub fn ca(&self) -> &ca::LocalCa {
        &self.ca
    }

    #[inline]
    pub fn docker(&self) -> Arc<bollard::Docker> {
        Arc::clone(&self.docker)
    }

    #[inline]
    pub fn daemon_token(&self) -> String {
        self.token.read().clone()
    }

    #[inline]
    pub fn authenticate(&self, token: &str) -> bool {
        constant_time_eq::constant_time_eq(token.as_bytes(), self.token.read().as_bytes())
    }

    pub fn rotate_token(&self) -> Result<(), anyhow::Error> {
        let token = hex::encode(rand::random::<[u8; 32]>());
        write_private(
            &self.data_dir.join(TOKEN_NAME),
            format!("{token}\n").as_bytes(),
        )?;

        *self.token.write() = token;
        self.hub.disconnect();
        self.poke();

        tracing::info!("rotated the tundra daemon token");

        Ok(())
    }

    pub fn restart_due(&self) -> bool {
        let mut last = self.last_restart.lock();
        if last.is_some_and(|last| last.elapsed() < POLL_INTERVAL) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }

    #[inline]
    pub fn cached(&self) -> Option<Arc<Snapshot>> {
        self.control.lock().cached.clone()
    }

    #[inline]
    pub fn serving(&self) -> bool {
        self.control.lock().serving()
    }

    #[inline]
    pub fn disabled(&self) -> bool {
        self.control.lock().disabled
    }

    #[inline]
    pub fn poke(&self) {
        self.refresh.notify_one();
    }

    /// Rebuilds and resends the snapshot without asking the panel for a new one.
    #[inline]
    pub fn rebroadcast(&self) {
        self.rebroadcast.notify_one();
    }

    pub async fn snapshot(&self, _state: &State) -> Option<Snapshot> {
        self.control.lock().enriched.as_deref().cloned()
    }

    async fn rebuild(&self, state: &State) {
        let Some(cached) = self.cached() else {
            return;
        };
        let mut snapshot = Snapshot::clone(&cached);
        let cfg = state.config.load();

        let owned: HashSet<uuid::Uuid> = snapshot
            .servers
            .iter()
            .filter(|entry| entry.node_uuid == cfg.uuid)
            .map(|entry| entry.uuid)
            .collect();
        let servers: Vec<crate::server::Server> = state
            .server_manager
            .get_servers()
            .await
            .iter()
            .filter(|server| owned.contains(&server.uuid))
            .cloned()
            .collect();
        let container_refs = state.executor.container_refs(&servers).await;

        for entry in snapshot
            .servers
            .iter_mut()
            .filter(|entry| entry.node_uuid == cfg.uuid)
        {
            if let Some(container) = container_refs.get(&entry.uuid) {
                entry.container_ref = container.clone();
            }

            if entry.dial_addr.is_none()
                && let Some(server) = servers.iter().find(|server| server.uuid == entry.uuid)
            {
                entry.dial_addr = state
                    .executor
                    .resolve_published_address(server)
                    .await
                    .map(|address| address.to_string());
            }
        }

        let mut control = self.control.lock();
        if let Some(snapshot) = control.publish(&cached, snapshot) {
            self.hub.broadcast(&snapshot);
        }
    }

    pub async fn sync(&self, state: &State) -> Result<(), anyhow::Error> {
        let response = state.config.client.tundra_state().await?;
        self.apply_state(response);
        Ok(())
    }

    fn apply_state(&self, response: crate::remote::tundra::TunnelState) {
        let mut control = self.control.lock();
        control.last_panel_contact = Instant::now();

        match response {
            crate::remote::tundra::TunnelState::Enabled(mut snapshot) => {
                snapshot.nodes.sort_unstable_by_key(|node| node.uuid);
                snapshot.servers.sort_unstable_by_key(|server| server.uuid);
                snapshot.acls.sort_unstable();
                let regressed = control
                    .cached
                    .as_ref()
                    .is_some_and(|cached| snapshot.epoch < cached.epoch);
                if control.cached.as_deref() != Some(&snapshot) {
                    control.cached = Some(Arc::new(snapshot));
                }
                let was_disabled = control.disabled;
                control.disabled = false;
                control.revoked = None;
                if regressed || was_disabled {
                    control.enriched = None;
                    self.hub.disconnect();
                }
                self.rebroadcast();
            }
            crate::remote::tundra::TunnelState::Disabled { disabled } => {
                let crate::remote::tundra::Disabled = disabled;
                let revoked = match &control.revoked {
                    Some(revoked) => Arc::clone(revoked),
                    None => {
                        let mut revoked = Snapshot::empty();
                        if let Some(cached) = &control.cached {
                            revoked.epoch = cached.epoch;
                        }
                        Arc::new(revoked)
                    }
                };
                control.revoked = Some(Arc::clone(&revoked));
                control.cached = None;
                control.enriched = None;
                control.disabled = true;
                self.hub.broadcast(&revoked);
                self.disable.notify_one();
            }
        }
        self.reconcile.notify_one();
    }
}

fn load_or_create_token(dir: &Path) -> Result<String, anyhow::Error> {
    let path = dir.join(TOKEN_NAME);
    if let Ok(token) = std::fs::read_to_string(&path) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    let token = hex::encode(rand::random::<[u8; 32]>());
    write_private(&path, format!("{token}\n").as_bytes())?;

    Ok(token)
}

pub async fn run(state: State) {
    let Some(manager) = state.tundra.clone() else {
        return;
    };

    let policy = async {
        loop {
            if let Err(err) = manager.sync(&state).await {
                tracing::warn!("failed to fetch tundra state from the panel: {:#}", err);
            }
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {},
                _ = manager.refresh.notified() => {},
            }
        }
    };
    let snapshots = async {
        loop {
            manager.rebuild(&state).await;
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {},
                _ = manager.rebroadcast.notified() => {
                    tokio::time::sleep(REBROADCAST_DEBOUNCE).await;
                },
            }
        }
    };
    let daemon = async {
        loop {
            tokio::select! {
                biased;
                _ = manager.disable.notified() => {},
                result = daemon::ensure(&state, &manager) => {
                    if let Err(err) = result {
                        tracing::error!("failed to reconcile the tundra daemon: {:#}", err);
                    }
                },
            }
            if manager.disabled()
                && let Err(err) = daemon::stop(&manager).await
            {
                tracing::error!("failed to stop the disabled tundra daemon: {:#}", err);
            }
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {},
                _ = manager.reconcile.notified() => {},
            }
        }
    };
    let freshness = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let control = manager.control.lock();
            if !control.disabled && !control.serving() && manager.hub.connected() {
                tracing::warn!("dropping the tundra websocket while the panel is unreachable");
                manager.hub.disconnect();
            }
        }
    };

    tokio::join!(policy, snapshots, daemon, freshness);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::tundra::{Disabled, TunnelState};

    fn manager(dir: &Path) -> TundraManager {
        TundraManager {
            data_dir: dir.to_path_buf(),
            hub: hub::Hub::default(),
            ca: ca::LocalCa::load_or_create(dir).unwrap(),
            docker: Arc::new(bollard::Docker::connect_with_local_defaults().unwrap()),
            token: parking_lot::RwLock::new(String::new()),
            control: parking_lot::Mutex::new(ControlState {
                cached: None,
                enriched: None,
                revoked: None,
                last_panel_contact: Instant::now(),
                disabled: false,
            }),
            refresh: tokio::sync::Notify::new(),
            rebroadcast: tokio::sync::Notify::new(),
            reconcile: tokio::sync::Notify::new(),
            disable: tokio::sync::Notify::new(),
            last_restart: parking_lot::Mutex::new(None),
            images_refreshed: AtomicBool::new(false),
            filesystem: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[test]
    #[ignore = "requires a local docker socket"]
    fn disable_revokes_the_connected_daemon_and_rejects_inflight_enrichment() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        let mut snapshot = Snapshot::empty();
        snapshot.epoch = 42;
        manager.apply_state(TunnelState::Enabled(snapshot.clone()));
        let source = manager.cached().unwrap();
        manager
            .control
            .lock()
            .publish(&source, snapshot.clone())
            .unwrap();
        let mut registration = manager.hub.register();

        manager.apply_state(TunnelState::Disabled { disabled: Disabled });
        manager.apply_state(TunnelState::Disabled { disabled: Disabled });

        assert!(manager.disabled());
        assert!(!manager.serving());
        assert!(manager.cached().is_none());
        let revoked = registration.snapshots.borrow_and_update().clone().unwrap();
        assert_eq!(revoked.epoch, 42);
        assert!(revoked.servers.is_empty());
        assert!(revoked.acls.is_empty());
        assert!(manager.hub.connected());
        let mut control = manager.control.lock();
        assert!(control.enriched.is_none());
        assert!(control.publish(&source, snapshot.clone()).is_none());
        drop(control);

        manager.apply_state(TunnelState::Enabled(snapshot.clone()));
        assert!(manager.control.lock().publish(&source, snapshot).is_none());
    }

    #[test]
    fn identical_snapshots_are_coalesced_but_same_epoch_local_changes_are_published() {
        let source = Arc::new(Snapshot::empty());
        let mut control = ControlState {
            cached: Some(Arc::clone(&source)),
            enriched: None,
            revoked: None,
            last_panel_contact: Instant::now(),
            disabled: false,
        };
        let initial = control.publish(&source, Snapshot::clone(&source)).unwrap();
        assert!(control.publish(&source, Snapshot::clone(&source)).is_none());
        let mut local = Snapshot::clone(&source);
        local.servers.push(tundra_common::state::ServerEntry {
            uuid: uuid::Uuid::nil(),
            idx: 0,
            node_uuid: uuid::Uuid::nil(),
            name: String::new(),
            aliases: Vec::new(),
            container_ref: "new-container".into(),
            dial_addr: None,
            ports: Vec::new(),
        });
        let updated = control.publish(&source, local).unwrap();
        assert_eq!(initial.epoch, updated.epoch);
        assert_ne!(initial.servers, updated.servers);
        control.last_panel_contact = Instant::now() - PANEL_GRACE;
        assert!(!control.serving());
        assert!(control.publish(&source, Snapshot::clone(&source)).is_none());
    }

    #[test]
    #[ignore = "requires a local docker socket"]
    fn restart_requests_do_not_acknowledge_updates_and_are_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path());
        assert!(manager.restart_due());
        assert!(!manager.restart_due());
        *manager.last_restart.lock() = Some(Instant::now() - POLL_INTERVAL);
        assert!(manager.restart_due());
    }
}
