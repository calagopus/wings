use serde::{Deserialize, Serialize};
use std::{ops::Deref, sync::Arc, time::Instant};
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
    pub modified: u128,
    pub size: u64,
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
                .map_or(0, |duration| duration.as_nanos()),
            size: metadata.size(),
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
                .map_or(0, |duration| duration.as_nanos()),
            size: metadata.size(),
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
                .map_or(0, |duration| duration.as_nanos()),
            size: metadata.len(),
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
                .map_or(0, |duration| duration.as_nanos()),
            size: metadata.len(),
        }
    }
}

const MIME_CACHE_SHARDS: usize = 64;

#[derive(Clone)]
pub struct MimeCache {
    shards: Arc<[parking_lot::RwLock<std::collections::HashMap<MimeCacheKey, MimeCacheValue>>]>,
    shard_capacity: usize,
}

impl MimeCache {
    pub fn new(capacity: u64) -> Self {
        Self {
            shards: (0..MIME_CACHE_SHARDS)
                .map(|_| parking_lot::RwLock::new(std::collections::HashMap::new()))
                .collect(),
            shard_capacity: (capacity as usize).div_ceil(MIME_CACHE_SHARDS).max(16),
        }
    }

    #[inline]
    fn shard(
        &self,
        key: &MimeCacheKey,
    ) -> Option<&parking_lot::RwLock<std::collections::HashMap<MimeCacheKey, MimeCacheValue>>> {
        let mixed = (key.ino ^ key.dev.rotate_left(32)).wrapping_mul(0x9E37_79B9_7F4A_7C15);

        self.shards.get((mixed >> 32) as usize % self.shards.len())
    }

    pub fn get(&self, key: &MimeCacheKey) -> Option<MimeCacheValue> {
        self.shard(key)?.read().get(key).copied()
    }

    pub fn get_with_by_ref(
        &self,
        key: &MimeCacheKey,
        init: impl FnOnce() -> MimeCacheValue,
    ) -> MimeCacheValue {
        let Some(shard) = self.shard(key) else {
            return init();
        };

        if let Some(value) = shard.read().get(key) {
            return *value;
        }

        let mut shard = shard.write();
        if let Some(value) = shard.get(key) {
            return *value;
        }

        let value = init();
        if shard.len() >= self.shard_capacity {
            shard.clear();
        }
        shard.insert(*key, value);

        value
    }

    #[cfg(test)]
    pub fn invalidate_all(&self) {
        for shard in self.shards.iter() {
            shard.write().clear();
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct FingerprintCacheKey {
    pub ino: u64,
    pub dev: u64,
    pub modified: u128,
    pub changed: i128,
    pub size: u64,
    pub algorithm: u8,
}

#[cfg(unix)]
impl FingerprintCacheKey {
    pub fn new(metadata: &cap_std::fs::Metadata, algorithm: u8) -> Self {
        use cap_std::fs::MetadataExt;

        Self {
            ino: metadata.ino(),
            dev: metadata.dev(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.into_std().duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos()),
            changed: (metadata.ctime() as i128)
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.ctime_nsec() as i128),
            size: metadata.size(),
            algorithm,
        }
    }
}

#[cfg(windows)]
impl FingerprintCacheKey {
    pub fn new(metadata: &cap_std::fs::Metadata, algorithm: u8) -> Self {
        Self {
            ino: 0,
            dev: 0,
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.into_std().duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos()),
            changed: 0,
            size: metadata.len(),
            algorithm,
        }
    }
}

#[derive(Clone)]
pub struct FingerprintCache(moka::future::Cache<FingerprintCacheKey, compact_str::CompactString>);

impl Default for FingerprintCache {
    fn default() -> Self {
        Self(
            moka::future::CacheBuilder::new(32 * 1024)
                .time_to_live(std::time::Duration::from_mins(10))
                .build(),
        )
    }
}

impl Deref for FingerprintCache {
    type Target = moka::future::Cache<FingerprintCacheKey, compact_str::CompactString>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn mime_cache_capacity(directory_entry_limit: usize) -> u64 {
    const MIN: u64 = 32 * 1024;
    const MAX: u64 = 256 * 1024;

    (directory_entry_limit as u64)
        .saturating_mul(2)
        .clamp(MIN, MAX)
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
    pub mime_cache: MimeCache,
    pub fingerprint_cache: FingerprintCache,
    pub listing_work: Arc<crate::server::filesystem::listing::ListingWork>,

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
            inotify_manager: Arc::new(crate::server::filesystem::inotify::InotifyManager::new()),
            websocket_limiter: Arc::new(crate::server::websocket::limiter::WebsocketLimiter::new(
                Arc::new(crate::config::Config::mock()),
            )),
            mime_cache: MimeCache::new(mime_cache_capacity(0)),
            fingerprint_cache: FingerprintCache::default(),
            listing_work: Arc::new(crate::server::filesystem::listing::ListingWork::default()),
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
