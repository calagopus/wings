use crate::routes::State;
use anyhow::Context;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

pub struct TundraManager {
    pub data_dir: PathBuf,
    pub hub: hub::Hub,
    ca: ca::LocalCa,
    docker: Arc<bollard::Docker>,
    token: parking_lot::RwLock<String>,

    cached: parking_lot::Mutex<Option<Arc<Snapshot>>>,
    last_panel_contact: parking_lot::Mutex<Instant>,
    refresh: tokio::sync::Notify,
    rebroadcast: tokio::sync::Notify,

    pending_restart: AtomicBool,
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
            cached: parking_lot::Mutex::new(None),
            last_panel_contact: parking_lot::Mutex::new(Instant::now()),
            refresh: tokio::sync::Notify::new(),
            rebroadcast: tokio::sync::Notify::new(),
            pending_restart: AtomicBool::new(false),
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

    #[inline]
    pub fn set_restart_pending(&self, pending: bool) {
        self.pending_restart.store(pending, Ordering::Relaxed);
    }

    #[inline]
    pub fn restart_pending(&self) -> bool {
        self.pending_restart.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn cached(&self) -> Option<Arc<Snapshot>> {
        self.cached.lock().clone()
    }

    #[inline]
    pub fn serving(&self) -> bool {
        self.cached.lock().is_some() && self.last_panel_contact.lock().elapsed() < PANEL_GRACE
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

    pub async fn snapshot(&self, state: &State) -> Option<Snapshot> {
        let cached = self.cached()?;
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

        Some(snapshot)
    }

    pub async fn broadcast(&self, state: &State) {
        if let Some(snapshot) = self.snapshot(state).await {
            self.hub.broadcast(&Arc::new(snapshot));
        }
    }

    pub async fn sync(&self, state: &State) -> Result<(), anyhow::Error> {
        let snapshot = state.config.client.tundra_state().await?;
        *self.last_panel_contact.lock() = Instant::now();

        let regressed = {
            let mut cached = self.cached.lock();
            let regressed = cached
                .as_ref()
                .is_some_and(|cached| snapshot.epoch < cached.epoch);
            *cached = Some(Arc::new(snapshot));

            regressed
        };

        if regressed {
            tracing::warn!("tundra state epoch went backwards, reconnecting the daemon");
            self.hub.disconnect();

            return Ok(());
        }

        self.broadcast(state).await;

        Ok(())
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

    loop {
        match manager.sync(&state).await {
            Ok(()) => {
                if let Err(err) = daemon::ensure(&state, &manager).await {
                    tracing::error!("failed to reconcile the tundra daemon: {:#}", err);
                }
            }
            Err(err) => {
                tracing::warn!("failed to fetch tundra state from the panel: {:#}", err);

                if !manager.serving() && manager.hub.connected() {
                    tracing::warn!("dropping the tundra websocket while the panel is unreachable");
                    manager.hub.disconnect();
                }
            }
        }

        let deadline = tokio::time::Instant::now() + POLL_INTERVAL;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                _ = manager.refresh.notified() => break,
                _ = manager.rebroadcast.notified() => {
                    tokio::time::sleep(REBROADCAST_DEBOUNCE).await;
                    manager.broadcast(&state).await;
                }
            }
        }
    }
}
