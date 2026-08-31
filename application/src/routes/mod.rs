use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

pub mod api;
mod download;
mod upload;

#[derive(Debug, ToSchema, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum AppContainerType {
    Official,
    Unknown,
    None,
}

#[derive(Clone, Copy)]
pub struct MimeCacheValue {
    pub mime: &'static str,
    pub valid_utf8: bool,
    pub valid_inner_utf8: bool,
}

impl Default for MimeCacheValue {
    fn default() -> Self {
        MimeCacheValue {
            mime: "application/octet-stream",
            valid_utf8: false,
            valid_inner_utf8: false,
        }
    }
}

impl MimeCacheValue {
    #[inline]
    pub fn directory() -> Self {
        MimeCacheValue {
            mime: "inode/directory",
            valid_utf8: false,
            valid_inner_utf8: false,
        }
    }

    #[inline]
    pub fn symlink() -> Self {
        MimeCacheValue {
            mime: "inode/symlink",
            valid_utf8: false,
            valid_inner_utf8: false,
        }
    }

    #[inline]
    pub fn text() -> Self {
        MimeCacheValue {
            mime: "text/plain",
            valid_utf8: true,
            valid_inner_utf8: false,
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct MimeCacheKey {
    pub ino: u64,
    pub dev: u64,
    pub modified: u64,
}

#[cfg(unix)]
impl From<&std::fs::Metadata> for MimeCacheKey {
    fn from(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            ino: metadata.ino(),
            dev: metadata.dev(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs()),
        }
    }
}

#[cfg(unix)]
impl From<&cap_std::fs::Metadata> for MimeCacheKey {
    fn from(metadata: &cap_std::fs::Metadata) -> Self {
        use cap_std::fs::MetadataExt;

        Self {
            ino: metadata.ino(),
            dev: metadata.dev(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.into_std().duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs()),
        }
    }
}

#[cfg(windows)]
impl From<&std::fs::Metadata> for MimeCacheKey {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            ino: 0,
            dev: 0,
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs()),
        }
    }
}

#[cfg(windows)]
impl From<&cap_std::fs::Metadata> for MimeCacheKey {
    fn from(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            ino: 0,
            dev: 0,
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.into_std().duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs()),
        }
    }
}

pub struct AppState {
    pub start_time: Instant,
    pub container_type: AppContainerType,
    pub version: String,

    pub config: Arc<crate::config::Config>,
    pub executor: Arc<dyn crate::server::executor::ServerExecutor>,
    pub stats_manager: Arc<crate::stats::StatsManager>,
    pub server_manager: Arc<crate::server::manager::ServerManager>,
    pub backup_manager: Arc<crate::server::backup::manager::BackupManager>,
    pub inotify_manager: Arc<crate::server::filesystem::inotify::InotifyManager>,
    pub websocket_limiter: Arc<crate::server::websocket::limiter::WebsocketLimiter>,
    pub mime_cache: moka::future::Cache<MimeCacheKey, MimeCacheValue>,

    #[cfg(unix)]
    pub tundra: Option<Arc<crate::tundra::TundraManager>>,
}

impl AppState {
    #[cfg(test)]
    pub fn mock() -> State {
        Arc::new(Self {
            start_time: Instant::now(),
            container_type: AppContainerType::None,
            version: "0.0.0".to_string(),
            config: Arc::new(crate::config::Config::mock()),
            executor: Arc::new(crate::server::executor::noop::NoopExecutor),
            stats_manager: Arc::new(crate::stats::StatsManager::default()),
            server_manager: Arc::new(crate::server::manager::ServerManager::new(&[])),
            backup_manager: Arc::new(crate::server::backup::manager::BackupManager::default()),
            inotify_manager: Arc::new(
                crate::server::filesystem::inotify::InotifyManager::new()
                    .expect("Creating inotify manager failed"),
            ),
            websocket_limiter: Arc::new(crate::server::websocket::limiter::WebsocketLimiter::new(
                Arc::new(crate::config::Config::mock()),
            )),
            mime_cache: moka::future::Cache::builder().build(),
            #[cfg(unix)]
            tundra: None,
        })
    }
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct ApiError<'a> {
    pub error: &'a str,
}

impl<'a> ApiError<'a> {
    #[inline]
    pub fn new(error: &'a str) -> Self {
        Self { error }
    }
}

pub type State = Arc<AppState>;
pub type GetState = axum::extract::State<State>;

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/download", download::router(state))
        .nest("/upload", upload::router(state))
        .nest("/api", api::router(state))
        .with_state(state.clone())
}
