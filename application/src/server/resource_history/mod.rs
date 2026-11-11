use crate::{
    config::ResourceHistoryTier,
    server::{
        resource_history::{
            accumulator::{Limits, ServerTrack, Span},
            storage::{Batch, Entry, Storage},
        },
        state::ServerState,
    },
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;
use utoipa::ToSchema;

mod accumulator;
mod storage;

pub const MAX_TIERS: usize = 8;
pub const MAX_POINTS: usize = 2000;

const PRUNE_INTERVAL: i64 = 60 * 60;

/// Seconds spent in each state, what is missing from the point's width is unknown.
#[derive(ToSchema, Serialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HistoryStates {
    pub offline: u64,
    pub starting: u64,
    pub stopping: u64,
    pub running: u64,
}

impl HistoryStates {
    fn add(&mut self, state: ServerState, seconds: u64) {
        match state {
            ServerState::Offline => self.offline += seconds,
            ServerState::Starting => self.starting += seconds,
            ServerState::Stopping => self.stopping += seconds,
            ServerState::Running => self.running += seconds,
        }
    }
}

#[derive(ToSchema, Serialize, Debug, PartialEq)]
pub struct HistoryPoint {
    pub start: chrono::DateTime<chrono::Utc>,
    pub states: Option<HistoryStates>,
    /// Seconds with container stats within this point.
    pub sampled_seconds: Option<u64>,
    /// Average cpu usage in percent while running.
    pub cpu_average: Option<f64>,
    pub cpu_max: Option<f64>,
    /// Average memory usage while running.
    pub memory_average_bytes: Option<u64>,
    pub memory_max_bytes: Option<u64>,
    /// Disk usage at the end of this point.
    pub disk_bytes: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
}

/// Configured limits, excluding memory overhead and CPU boosts, `0` is unlimited.
#[derive(ToSchema, Serialize, Debug, PartialEq)]
pub struct HistoryLimits {
    pub since: chrono::DateTime<chrono::Utc>,
    pub memory_limit_bytes: u64,
    pub cpu_limit: u64,
}

#[derive(ToSchema, Serialize, Debug, PartialEq)]
pub struct History {
    /// Bucket width in seconds of the tier the points were aggregated from.
    pub resolution: u64,
    pub points: Vec<HistoryPoint>,
    /// Limits in effect over the requested range, the first entry may start before it.
    pub limits: Vec<HistoryLimits>,
}

impl History {
    fn timestamp(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default()
    }

    /// Bounds `[start, end)` of point `i` when the range is split into `points` equal slices.
    fn point_bounds(start: i64, end: i64, points: usize, i: usize) -> (i64, i64) {
        let width = (end - start) as i128;

        (
            start + (width * i as i128 / points as i128) as i64,
            start + (width * (i as i128 + 1) / points as i128) as i64,
        )
    }

    /// Seconds per state of every point, `None` for points no span overlaps.
    fn point_states(
        spans: &[Span],
        start: i64,
        end: i64,
        points: usize,
    ) -> Vec<Option<HistoryStates>> {
        let width = (end - start) as i128;
        let index =
            |t: i64| (((t - start) as i128 * points as i128 / width) as usize).min(points - 1);

        let mut states = vec![None::<HistoryStates>; points];
        for span in spans {
            let (since, until) = (span.since.max(start), span.until.min(end));
            if since >= until {
                continue;
            }

            let first = index(since).saturating_sub(1);
            let last = (index(until - 1) + 1).min(points - 1);
            for (i, point) in states.iter_mut().enumerate().take(last + 1).skip(first) {
                let (point_start, point_end) = Self::point_bounds(start, end, points, i);
                let overlap = until.min(point_end) - since.max(point_start);
                if overlap > 0 {
                    point
                        .get_or_insert_default()
                        .add(span.state, overlap as u64);
                }
            }
        }

        states
    }

    fn assemble(raw: storage::RawHistory, start: i64, end: i64, points: usize) -> Self {
        let mut disk = raw.disk_before;
        let mut states = Self::point_states(&raw.spans, start, end, points).into_iter();

        let points = (0..points)
            .map(|i| {
                let (point_start, point_end) = Self::point_bounds(start, end, points, i);
                let states = states.next().flatten();

                if raw.covered_from.is_none_or(|from| from >= point_end) {
                    return HistoryPoint {
                        start: Self::timestamp(point_start),
                        states,
                        sampled_seconds: None,
                        cpu_average: None,
                        cpu_max: None,
                        memory_average_bytes: None,
                        memory_max_bytes: None,
                        disk_bytes: None,
                        network_rx_bytes: None,
                        network_tx_bytes: None,
                    };
                }

                if let Some(&d) = raw.disks.get(&i) {
                    disk = Some(d);
                }
                let row = raw.rows.get(&i).copied().unwrap_or_default();
                let running = row.n > 0.0;

                HistoryPoint {
                    start: Self::timestamp(point_start),
                    states,
                    sampled_seconds: Some(row.n.max(0.0).round() as u64),
                    cpu_average: running.then(|| row.cpu_sum / row.n / 100.0),
                    cpu_max: running.then(|| row.cpu_max / 100.0),
                    memory_average_bytes: running
                        .then(|| (row.mem_sum / row.n).max(0.0) as u64 * 1024),
                    memory_max_bytes: running.then(|| row.mem_max.max(0.0) as u64 * 1024),
                    disk_bytes: disk.map(|d| d.max(0) as u64 * 1024),
                    network_rx_bytes: Some(row.rx.max(0.0).round() as u64),
                    network_tx_bytes: Some(row.tx.max(0.0).round() as u64),
                }
            })
            .collect();

        Self {
            resolution: raw.step,
            points,
            limits: raw
                .limits
                .into_iter()
                .map(|(at, limits)| HistoryLimits {
                    since: Self::timestamp(at),
                    memory_limit_bytes: limits.memory.max(0) as u64 * 1024,
                    cpu_limit: limits.cpu.max(0) as u64,
                })
                .collect(),
        }
    }

    pub fn empty(start: i64, end: i64, points: usize) -> Self {
        Self::assemble(storage::RawHistory::default(), start, end, points)
    }
}

struct Tracks {
    steps: Vec<u64>,
    servers: HashMap<uuid::Uuid, ServerTrack>,
}

pub struct ResourceHistory {
    config: Arc<crate::config::Config>,
    db_path: PathBuf,
    storage: Arc<Mutex<Option<Storage>>>,
    tracks: parking_lot::Mutex<Tracks>,
}

impl ResourceHistory {
    pub fn new(config: &Arc<crate::config::Config>) -> Self {
        Self {
            db_path: config
                .resolve_as_path(|cfg| &cfg.system.root_directory)
                .join("resource_history.db"),
            config: Arc::clone(config),
            storage: Arc::new(Mutex::new(None)),
            tracks: parking_lot::Mutex::new(Tracks {
                steps: Vec::new(),
                servers: HashMap::new(),
            }),
        }
    }

    fn configured_tiers(&self) -> Vec<ResourceHistoryTier> {
        let config = self.config.load();
        if !config.system.resource_history.enabled {
            return Vec::new();
        }

        let mut tiers = config.system.resource_history.tiers.clone();
        tiers.sort_unstable_by_key(|t| t.step);

        tiers
    }

    async fn with_storage<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Storage) -> Result<T, anyhow::Error> + Send + 'static,
    ) -> Result<Option<T>, anyhow::Error> {
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || {
            let mut guard = storage.blocking_lock();
            guard.as_mut().map(f).transpose()
        })
        .await?
    }

    async fn apply_tiers(&self, tiers: Vec<ResourceHistoryTier>) -> Result<(), anyhow::Error> {
        let db_path = self.db_path.clone();
        let storage = Arc::clone(&self.storage);
        let steps: Vec<u64> = tiers.iter().map(|t| t.step).collect();

        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut guard = storage.blocking_lock();
            let storage = match guard.as_mut() {
                Some(storage) => storage,
                None => guard.insert(Storage::open(&db_path)?),
            };

            storage.reconcile(&tiers)
        })
        .await??;

        let mut tracks = self.tracks.lock();
        tracks.steps = steps;
        tracks.servers.clear();

        Ok(())
    }

    fn drain(&self, only: Option<uuid::Uuid>) -> Batch {
        let mut tracks = self.tracks.lock();

        tracks
            .servers
            .iter_mut()
            .filter(|(uuid, _)| only.is_none_or(|only| only == **uuid))
            .filter_map(|(uuid, track)| {
                let (rows, limits) = track.drain();
                let spans = track.drain_spans();

                (!rows.is_empty() || limits.is_some() || !spans.is_empty()).then_some(Entry {
                    uuid: *uuid,
                    rows,
                    limits,
                    spans,
                })
            })
            .collect()
    }

    async fn write(&self, batch: Batch) -> Result<(), anyhow::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        self.with_storage(move |storage| storage.write(batch))
            .await
            .map(|_| ())
    }

    async fn flush(&self) {
        if let Err(err) = self.write(self.drain(None)).await {
            tracing::warn!("failed to write resource history: {err:#}");
        }
    }

    async fn sample(&self, server_manager: &crate::server::manager::ServerManager, ts: i64) {
        let servers = server_manager.get_servers().await;
        let mut samples = Vec::with_capacity(servers.len());
        let mut seen = HashSet::with_capacity(servers.len());

        for server in servers.iter() {
            seen.insert(server.uuid);

            if server.is_transferring() {
                continue;
            }

            let limits = {
                let configuration = server.configuration.read().await;
                Limits {
                    memory: configuration.build.memory_limit.max(0) * 1024,
                    cpu: configuration.build.cpu_limit.max(0),
                }
            };

            samples.push((
                server.uuid,
                server.resource_usage(),
                server.state.get_state(),
                limits,
            ));
        }
        drop(servers);

        let mut new = Vec::new();
        {
            let mut tracks = self.tracks.lock();

            for (uuid, usage, state, limits) in samples {
                match tracks.servers.get_mut(&uuid) {
                    Some(track) => {
                        track.push(ts, &usage, limits);
                        track.push_state(ts, state);
                    }
                    None => new.push((uuid, usage, state, limits)),
                }
            }

            tracks.servers.retain(|uuid, _| seen.contains(uuid));
        }

        if new.is_empty() {
            return;
        }

        let uuids: Vec<uuid::Uuid> = new.iter().map(|(uuid, ..)| *uuid).collect();
        let resumed = self
            .with_storage(move |storage| {
                uuids
                    .into_iter()
                    .map(|uuid| {
                        Ok((
                            uuid,
                            (storage.latest_limits(uuid)?, storage.last_span(uuid)?),
                        ))
                    })
                    .collect::<Result<HashMap<_, _>, anyhow::Error>>()
            })
            .await
            .unwrap_or_else(|err| {
                tracing::warn!("failed to read resource history state: {err:#}");
                None
            })
            .unwrap_or_default();

        let mut tracks = self.tracks.lock();
        let steps = tracks.steps.clone();
        for (uuid, usage, state, limits) in new {
            let (stored, span) = resumed.get(&uuid).copied().unwrap_or_default();
            let mut track = ServerTrack::new(&steps, stored, span);
            track.push(ts, &usage, limits);
            track.push_state(ts, state);
            tracks.servers.insert(uuid, track);
        }
    }

    async fn prune(&self, known: Option<HashSet<uuid::Uuid>>) {
        let now = chrono::Utc::now().timestamp();
        if let Err(err) = self
            .with_storage(move |storage| storage.prune(now, known.as_ref()))
            .await
        {
            tracing::warn!("failed to prune resource history: {err:#}");
        }
    }

    pub async fn run(self: Arc<Self>, server_manager: Arc<crate::server::manager::ServerManager>) {
        let mut applied: Option<Vec<ResourceHistoryTier>> = None;
        let mut last_flush = 0;
        let mut last_prune = 0;
        let mut retry_setup_at = 0;

        let period = std::time::Duration::from_secs(1);
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::from_std(crate::utils::next_aligned_instant(period) + period / 2),
            period,
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tick.tick().await;
            let now = chrono::Utc::now().timestamp();

            let tiers = self.configured_tiers();
            if applied.as_ref() != Some(&tiers) {
                if applied.is_some() {
                    self.flush().await;
                }

                if tiers.is_empty() {
                    self.storage.lock().await.take();
                    self.tracks.lock().servers.clear();
                    applied = Some(tiers);
                    continue;
                }

                if now < retry_setup_at {
                    continue;
                }
                if let Err(err) = self.apply_tiers(tiers.clone()).await {
                    tracing::error!("failed to set up resource history: {err:#}");
                    retry_setup_at = now + 60;
                    continue;
                }
                applied = Some(tiers);
            }
            if applied.as_ref().is_none_or(|t| t.is_empty()) {
                continue;
            }

            self.sample(&server_manager, now).await;

            let flush_interval = self
                .config
                .load()
                .system
                .resource_history
                .flush_interval
                .max(1) as i64;
            if now - last_flush >= flush_interval {
                last_flush = now;
                self.flush().await;
            }

            if server_manager.booted() && now - last_prune >= PRUNE_INTERVAL {
                last_prune = now;
                let known = server_manager
                    .get_servers()
                    .await
                    .iter()
                    .map(|s| s.uuid)
                    .collect();
                self.prune(Some(known)).await;
            }
        }
    }

    pub async fn query(
        &self,
        server: uuid::Uuid,
        start: i64,
        end: i64,
        points: usize,
    ) -> Result<Option<History>, anyhow::Error> {
        if let Err(err) = self.write(self.drain(Some(server))).await {
            tracing::warn!(server = %server, "failed to write resource history: {err:#}");
        }

        let raw = self
            .with_storage(move |storage| storage.query(server, start, end, points))
            .await?
            .flatten();

        Ok(raw.map(|raw| History::assemble(raw, start, end, points)))
    }

    pub async fn delete_server(&self, server: uuid::Uuid) {
        self.tracks.lock().servers.remove(&server);

        if let Err(err) = self
            .with_storage(move |storage| storage.delete_server(server))
            .await
        {
            tracing::warn!(server = %server, "failed to delete resource history: {err:#}");
        }
    }

    pub async fn export(
        &self,
        server: uuid::Uuid,
    ) -> Result<Option<tokio::fs::File>, anyhow::Error> {
        self.write(self.drain(Some(server))).await?;

        let mut temp = self.db_path.clone().into_os_string();
        temp.push(format!(".{server}.transfer"));
        let temp = PathBuf::from(temp);

        let exported = self
            .with_storage({
                let temp = temp.clone();

                move |storage| {
                    std::fs::remove_file(&temp).ok();
                    storage.export(server, &temp)
                }
            })
            .await?
            .unwrap_or(false);
        if !exported {
            return Ok(None);
        }

        let file = tokio::fs::File::open(&temp).await;
        tokio::fs::remove_file(&temp).await.ok();

        Ok(Some(file?))
    }

    pub fn import_path(&self, server: uuid::Uuid) -> PathBuf {
        let mut path = self.db_path.clone().into_os_string();
        path.push(format!(".{server}.import"));

        PathBuf::from(path)
    }

    pub async fn import(&self, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        let path = self.import_path(server);

        let result = self
            .with_storage({
                let path = path.clone();
                move |storage| storage.import(server, &path)
            })
            .await
            .map(|_| ());
        tokio::fs::remove_file(&path).await.ok();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::{
        accumulator::Limits,
        storage::{PointRow, RawHistory},
        *,
    };

    fn spans_only(covered_from: Option<i64>, spans: Vec<Span>) -> RawHistory {
        RawHistory {
            step: 10,
            covered_from,
            spans,
            ..Default::default()
        }
    }

    // History
    #[test]
    fn assemble_converts_units_carries_disk_and_marks_uncovered_points() {
        let limits = Limits {
            memory: 1024,
            cpu: 200,
        };
        let raw = RawHistory {
            step: 10,
            covered_from: Some(10),
            rows: HashMap::from([
                (
                    1,
                    PointRow {
                        n: 2.0,
                        cpu_sum: 300.0,
                        cpu_max: 200.0,
                        mem_sum: 2048.0,
                        mem_max: 1536.0,
                        rx: 5.0,
                        tx: 6.0,
                    },
                ),
                (
                    3,
                    PointRow {
                        rx: 7.0,
                        ..Default::default()
                    },
                ),
            ]),
            disks: HashMap::from([(1, 100), (3, 50)]),
            disk_before: Some(77),
            limits: vec![(5, limits)],
            spans: Vec::new(),
        };

        let history = History::assemble(raw, 0, 40, 4);
        let unknown = |start| HistoryPoint {
            start: History::timestamp(start),
            states: None,
            sampled_seconds: None,
            cpu_average: None,
            cpu_max: None,
            memory_average_bytes: None,
            memory_max_bytes: None,
            disk_bytes: None,
            network_rx_bytes: None,
            network_tx_bytes: None,
        };

        assert_eq!(history.resolution, 10);
        assert_eq!(
            history.limits,
            vec![HistoryLimits {
                since: History::timestamp(5),
                memory_limit_bytes: 1024 * 1024,
                cpu_limit: 200,
            }]
        );
        assert_eq!(
            history.points,
            vec![
                unknown(0),
                HistoryPoint {
                    start: History::timestamp(10),
                    states: None,
                    sampled_seconds: Some(2),
                    cpu_average: Some(1.5),
                    cpu_max: Some(2.0),
                    memory_average_bytes: Some(1024 * 1024),
                    memory_max_bytes: Some(1536 * 1024),
                    disk_bytes: Some(100 * 1024),
                    network_rx_bytes: Some(5),
                    network_tx_bytes: Some(6),
                },
                HistoryPoint {
                    sampled_seconds: Some(0),
                    disk_bytes: Some(100 * 1024),
                    network_rx_bytes: Some(0),
                    network_tx_bytes: Some(0),
                    ..unknown(20)
                },
                HistoryPoint {
                    sampled_seconds: Some(0),
                    disk_bytes: Some(50 * 1024),
                    network_rx_bytes: Some(7),
                    network_tx_bytes: Some(0),
                    ..unknown(30)
                },
            ]
        );
    }

    #[test]
    fn assemble_starts_disk_from_disk_before_and_unknown_without_coverage() {
        let raw = |covered_from| RawHistory {
            step: 60,
            covered_from,
            disk_before: Some(3),
            ..Default::default()
        };

        let history = History::assemble(raw(Some(0)), 0, 120, 2);
        assert_eq!(history.points.len(), 2);
        assert!(
            history
                .points
                .iter()
                .all(|p| p.disk_bytes == Some(3 * 1024))
        );

        let history = History::assemble(raw(None), 0, 120, 2);
        assert!(
            history
                .points
                .iter()
                .all(|p| p.disk_bytes.is_none() && p.sampled_seconds.is_none())
        );
    }

    #[test]
    fn assemble_splits_spans_exactly_across_uneven_points() {
        let raw = spans_only(
            Some(100),
            vec![
                Span {
                    since: 95,
                    until: 115,
                    state: ServerState::Running,
                },
                Span {
                    since: 115,
                    until: 127,
                    state: ServerState::Offline,
                },
                Span {
                    since: 127,
                    until: 129,
                    state: ServerState::Stopping,
                },
            ],
        );

        let history = History::assemble(raw, 100, 150, 4);
        let states: Vec<_> = history.points.iter().map(|p| p.states).collect();
        assert_eq!(
            states,
            vec![
                Some(HistoryStates {
                    running: 12,
                    ..Default::default()
                }),
                Some(HistoryStates {
                    running: 3,
                    offline: 10,
                    ..Default::default()
                }),
                Some(HistoryStates {
                    offline: 2,
                    stopping: 2,
                    ..Default::default()
                }),
                None,
            ]
        );
    }

    #[test]
    fn assemble_sets_states_on_points_without_tier_coverage() {
        let span = Span {
            since: 0,
            until: 1000,
            state: ServerState::Starting,
        };
        let starting = Some(HistoryStates {
            starting: 10,
            ..Default::default()
        });

        let history = History::assemble(spans_only(Some(20), vec![span]), 0, 40, 4);
        assert!(history.points.iter().all(|p| p.states == starting));
        assert_eq!(history.points[0].sampled_seconds, None);
        assert_eq!(history.points[1].cpu_average, None);
        assert_eq!(history.points[2].sampled_seconds, Some(0));

        let history = History::assemble(spans_only(None, vec![span]), 0, 40, 4);
        assert!(
            history
                .points
                .iter()
                .all(|p| p.states == starting && p.sampled_seconds.is_none())
        );
    }
}
