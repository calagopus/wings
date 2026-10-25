use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use sysinfo::{Disks, Networks, System};
use utoipa::ToSchema;

const PVE_STORAGE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const WORKER_LIVENESS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

fn wait_while_alive(owner: &std::sync::Weak<()>, duration: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    loop {
        if owner.upgrade().is_none() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        std::thread::sleep(remaining.min(WORKER_LIVENESS_POLL_INTERVAL));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiskCapacity {
    total: u64,
    available: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PveCapacityRequest {
    configured_node: String,
    configured_storage: String,
    rootfs_size_gib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PveCapacityCache {
    request: PveCapacityRequest,
    resolved_node: String,
    selected_storage: String,
    capacity: DiskCapacity,
}

fn capacity_for_request(
    cached: Option<&PveCapacityCache>,
    request: &PveCapacityRequest,
) -> Option<DiskCapacity> {
    cached
        .filter(|cached| cached.request == *request)
        .map(|cached| cached.capacity)
}

fn invalidate_capacity_for_request(
    cached: &mut Option<PveCapacityCache>,
    current_request: &PveCapacityRequest,
) {
    if capacity_for_request(cached.as_ref(), current_request).is_none() {
        *cached = None;
    }
}

fn publish_capacity_if_current(
    cached: &mut Option<PveCapacityCache>,
    refreshed: PveCapacityCache,
    current_request: &PveCapacityRequest,
) {
    if refreshed.request == *current_request {
        *cached = Some(refreshed);
    } else {
        *cached = None;
    }
}

impl DiskCapacity {
    fn used(self) -> u64 {
        self.total.saturating_sub(self.available)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskCapacitySource {
    Filesystem,
    PveLxc,
}

fn authoritative_disk_capacity(
    source: DiskCapacitySource,
    filesystem: DiskCapacity,
    pve_lxc: Option<DiskCapacity>,
) -> Option<DiskCapacity> {
    match source {
        DiskCapacitySource::Filesystem => Some(filesystem),
        DiskCapacitySource::PveLxc => pve_lxc,
    }
}

fn pve_capacity_request(config: &crate::config::Config) -> PveCapacityRequest {
    let config = config.load();
    let pve = &config.runtime.pve_lxc;
    PveCapacityRequest {
        configured_node: pve.node.clone(),
        configured_storage: pve.rootfs_storage.clone(),
        rootfs_size_gib: pve.rootfs_size_gib,
    }
}

async fn refresh_pve_disk_capacity(
    config: &crate::config::Config,
) -> Result<PveCapacityCache, anyhow::Error> {
    use anyhow::Context;

    let (cli, request) = {
        let config = config.load();
        let pve = &config.runtime.pve_lxc;
        (
            crate::server::executor::pve_lxc::PveCli::from_config(pve),
            PveCapacityRequest {
                configured_node: pve.node.clone(),
                configured_storage: pve.rootfs_storage.clone(),
                rootfs_size_gib: pve.rootfs_size_gib,
            },
        )
    };
    let node = if request.configured_node.trim().is_empty() {
        cli.local_node().await?
    } else {
        request.configured_node.clone()
    };
    let storages = cli.available_lxc_storages(&node).await?;
    let required_bytes =
        if request.configured_storage.is_empty() || request.configured_storage == "auto" {
            request
                .rootfs_size_gib
                .checked_mul(1024 * 1024 * 1024)
                .context("Proxmox LXC rootfs size overflowed u64")?
        } else {
            0
        };
    let selected = crate::server::executor::pve_lxc::PveLxcExecutor::select_rootfs_storage(
        &request.configured_storage,
        required_bytes,
        &storages,
    )?;
    let storage = storages
        .iter()
        .find(|storage| storage.name == selected)
        .with_context(|| {
            format!("configured Proxmox LXC rootfs storage {selected} is not active and enabled")
        })?;
    Ok(PveCapacityCache {
        request,
        resolved_node: node,
        selected_storage: selected,
        capacity: DiskCapacity {
            total: storage.total_bytes,
            available: storage.available_bytes,
        },
    })
}

fn spawn_pve_capacity_refresher(
    owner: std::sync::Weak<()>,
    config: std::sync::Weak<crate::config::Config>,
    capacity: std::sync::Weak<std::sync::Mutex<Option<PveCapacityCache>>>,
) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!("failed to start Proxmox storage stats refresher: {error}");
                return;
            }
        };

        loop {
            let Some(config) = config.upgrade() else {
                return;
            };
            let Some(capacity) = capacity.upgrade() else {
                return;
            };
            let request = pve_capacity_request(&config);
            if let Ok(mut current) = capacity.lock() {
                invalidate_capacity_for_request(&mut current, &request);
            }
            let refreshed = runtime.block_on(refresh_pve_disk_capacity(&config));
            let current_request = pve_capacity_request(&config);
            if let Ok(mut current) = capacity.lock() {
                invalidate_capacity_for_request(&mut current, &current_request);
            }
            match refreshed {
                Ok(refreshed) => {
                    if let Ok(mut current) = capacity.lock() {
                        publish_capacity_if_current(&mut current, refreshed, &current_request);
                    }
                }
                Err(error) => tracing::warn!(
                    "failed to refresh Proxmox LXC storage capacity; retaining the last successful value: {error:#}"
                ),
            }
            drop(capacity);
            drop(config);
            if !wait_while_alive(&owner, PVE_STORAGE_REFRESH_INTERVAL) {
                return;
            }
        }
    });
}

#[derive(ToSchema, Serialize, Default)]
struct SystemCpuStats {
    used: f32,
    threads: usize,
    model: String,
}

#[derive(ToSchema, Serialize, Default)]
struct SystemNetworkStats {
    received: u64,
    received_packets: u64,
    receiving_rate: f64,
    received_packets_rate: f64,
    sent: u64,
    sent_packets: u64,
    sending_rate: f64,
    sending_packets_rate: f64,
}

#[derive(ToSchema, Serialize, Default)]
struct SystemMemoryStats {
    used: u64,
    used_process: u64,
    total: u64,
}

#[derive(ToSchema, Serialize, Default)]
struct SystemDiskStats {
    used: u64,
    total: u64,
    read: u64,
    reading_rate: f64,
    written: u64,
    writing_rate: f64,
}

#[derive(ToSchema, Serialize, Default)]
pub struct SystemStats {
    #[schema(inline)]
    cpu: SystemCpuStats,
    #[schema(inline)]
    network: SystemNetworkStats,
    #[schema(inline)]
    memory: SystemMemoryStats,
    #[schema(inline)]
    disk: SystemDiskStats,
}

const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);
const IDLE_AFTER: Duration = Duration::from_secs(30);

pub struct StatsManager {
    stats: tokio::sync::watch::Receiver<(Instant, Arc<SystemStats>)>,
    last_read: Arc<parking_lot::Mutex<Instant>>,
    sampler: std::thread::Thread,
    _pve_capacity: Arc<std::sync::Mutex<Option<PveCapacityCache>>>,
    _worker_owner: Arc<()>,
}

impl StatsManager {
    pub async fn get_stats(&self) -> Arc<SystemStats> {
        *self.last_read.lock() = Instant::now();
        self.sampler.unpark();

        let mut stats = self.stats.clone();
        if stats.borrow_and_update().0.elapsed() > 2 * SAMPLE_INTERVAL {
            tokio::time::timeout(4 * SAMPLE_INTERVAL, stats.changed())
                .await
                .ok();
        }

        Arc::clone(&stats.borrow().1)
    }
}

impl StatsManager {
    pub fn new(config: Arc<crate::config::Config>) -> Self {
        Self::new_with_config(Some(config))
    }

    fn new_with_config(config: Option<Arc<crate::config::Config>>) -> Self {
        let (stats_tx, stats) =
            tokio::sync::watch::channel((Instant::now(), Arc::new(SystemStats::default())));
        let last_read = Arc::new(parking_lot::Mutex::new(Instant::now()));
        let worker_owner = Arc::new(());
        let capacity_source = config
            .as_ref()
            .map_or(DiskCapacitySource::Filesystem, |config| {
                match config.active_runtime_backend() {
                    crate::config::RuntimeBackend::PveLxc => DiskCapacitySource::PveLxc,
                    crate::config::RuntimeBackend::Auto | crate::config::RuntimeBackend::Docker => {
                        DiskCapacitySource::Filesystem
                    }
                }
            });
        let pve_capacity = Arc::new(std::sync::Mutex::new(None));
        if capacity_source == DiskCapacitySource::PveLxc
            && let Some(config) = config.as_ref()
        {
            spawn_pve_capacity_refresher(
                Arc::downgrade(&worker_owner),
                Arc::downgrade(config),
                Arc::downgrade(&pve_capacity),
            );
        }

        let sampler = std::thread::spawn({
            let owner = Arc::downgrade(&worker_owner);
            let last_read = Arc::clone(&last_read);
            let pve_capacity = Arc::downgrade(&pve_capacity);

            move || {
                let refresh_kind = sysinfo::RefreshKind::nothing()
                    .with_cpu(sysinfo::CpuRefreshKind::nothing().with_usage())
                    .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram());

                let (mut sys, mut disks, mut networks) = match (
                    System::new_with_specifics(refresh_kind),
                    Disks::new_with_refreshed_list(),
                    Networks::new_with_refreshed_list(),
                ) {
                    (Ok(sys), Ok(disks), Ok(networks)) => (sys, disks, networks),
                    (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => {
                        tracing::error!("failed to initialize system stats sampler: {:?}", err);
                        return;
                    }
                };
                let data_directory = config.as_ref().map_or_else(
                    || std::path::PathBuf::from("/"),
                    |config| config.resolve_as_path(|inner| &inner.system.data_directory),
                );

                let cpu_model = sys
                    .cpus()
                    .first()
                    .map_or_else(|| "unknown".to_string(), |cpu| cpu.brand().to_string());

                let refresh = |sys: &mut System, disks: &mut Disks, networks: &mut Networks| {
                    sys.refresh_specifics(refresh_kind);
                    networks.refresh(true);
                    for disk in disks.iter_mut() {
                        if data_directory.starts_with(disk.mount_point()) {
                            disk.refresh();
                        }
                    }
                };

                loop {
                    if !wait_while_alive(&owner, SAMPLE_INTERVAL) {
                        return;
                    }

                    if last_read.lock().elapsed() > IDLE_AFTER {
                        std::thread::park();

                        if owner.upgrade().is_none() {
                            return;
                        }

                        refresh(&mut sys, &mut disks, &mut networks);
                        continue;
                    }

                    let Some(pve_capacity) = pve_capacity.upgrade() else {
                        return;
                    };

                    refresh(&mut sys, &mut disks, &mut networks);

                    let used_memory_process = match crate::utils::process_memory_usage() {
                        Some(used_memory_process) => used_memory_process,
                        None => {
                            let mut used_memory_process = 0;
                            if let Ok(current_pid) = sysinfo::get_current_pid() {
                                sys.refresh_processes_specifics(
                                    sysinfo::ProcessesToUpdate::Some(&[current_pid]),
                                    false,
                                    sysinfo::ProcessRefreshKind::nothing().with_memory(),
                                );

                                if let Some(process) = sys.process(current_pid) {
                                    used_memory_process = process.memory();
                                }
                            }

                            used_memory_process
                        }
                    };

                    let total_memory = sys.total_memory();
                    let used_memory = sys.used_memory();

                    let disk = match disks
                        .iter()
                        .filter(|disk| data_directory.starts_with(disk.mount_point()))
                        .max_by_key(|disk| disk.mount_point().as_os_str().len())
                    {
                        Some(d) => d,
                        None => match disks.first() {
                            Some(d) => d,
                            None => continue,
                        },
                    };
                    let filesystem_capacity = DiskCapacity {
                        total: disk.total_space(),
                        available: disk.available_space(),
                    };
                    let cached_pve_capacity = config.as_ref().and_then(|config| {
                        let request = pve_capacity_request(config);
                        pve_capacity
                            .lock()
                            .ok()
                            .and_then(|capacity| capacity_for_request(capacity.as_ref(), &request))
                    });
                    let disk_capacity = authoritative_disk_capacity(
                        capacity_source,
                        filesystem_capacity,
                        cached_pve_capacity,
                    );
                    let total_disk_space = disk_capacity.map_or(0, |capacity| capacity.total);
                    let used_disk_space = disk_capacity.map_or(0, DiskCapacity::used);
                    let total_disk_read = disk.usage().total_read_bytes;
                    let disk_read_rate = disk.usage().read_bytes as f64;
                    let total_disk_write = disk.usage().total_written_bytes;
                    let disk_write_rate = disk.usage().written_bytes as f64;

                    let mut network = SystemNetworkStats {
                        received: 0,
                        receiving_rate: 0.0,
                        received_packets: 0,
                        received_packets_rate: 0.0,
                        sent: 0,
                        sending_rate: 0.0,
                        sent_packets: 0,
                        sending_packets_rate: 0.0,
                    };
                    for net in networks.values() {
                        network.received += net.total_received();
                        network.received_packets += net.total_packets_received();
                        network.receiving_rate += net.received() as f64;
                        network.received_packets_rate += net.packets_received() as f64;
                        network.sent += net.total_transmitted();
                        network.sent_packets += net.total_packets_transmitted();
                        network.sending_rate += net.transmitted() as f64;
                        network.sending_packets_rate += net.packets_transmitted() as f64;
                    }

                    let cpu_usage = sys.global_cpu_usage();
                    let cpu_threads = sys.cpus().len();

                    stats_tx.send_replace((
                        Instant::now(),
                        Arc::new(SystemStats {
                            cpu: SystemCpuStats {
                                used: cpu_usage,
                                threads: cpu_threads,
                                model: cpu_model.clone(),
                            },
                            network,
                            memory: SystemMemoryStats {
                                used: used_memory,
                                used_process: used_memory_process,
                                total: total_memory,
                            },
                            disk: SystemDiskStats {
                                used: used_disk_space,
                                total: total_disk_space,
                                read: total_disk_read,
                                reading_rate: disk_read_rate,
                                written: total_disk_write,
                                writing_rate: disk_write_rate,
                            },
                        }),
                    ));
                }
            }
        })
        .thread()
        .clone();

        Self {
            stats,
            last_read,
            sampler,
            _pve_capacity: pve_capacity,
            _worker_owner: worker_owner,
        }
    }
}

impl Drop for StatsManager {
    fn drop(&mut self) {
        self.sampler.unpark();
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new_with_config(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_capacity_remains_filesystem_derived() {
        let local = DiskCapacity {
            total: 1_000,
            available: 250,
        };
        let pve = DiskCapacity {
            total: 9_000,
            available: 8_000,
        };

        assert_eq!(
            authoritative_disk_capacity(DiskCapacitySource::Filesystem, local, Some(pve)),
            Some(local)
        );
    }

    #[test]
    fn pve_capacity_uses_selected_storage_and_reports_total_minus_available() {
        let local = DiskCapacity {
            total: 1_000,
            available: 250,
        };
        let pve = DiskCapacity {
            total: 9_000,
            available: 8_000,
        };

        let selected = authoritative_disk_capacity(DiskCapacitySource::PveLxc, local, Some(pve))
            .expect("PVE capacity should be authoritative");
        assert_eq!(selected.total, 9_000);
        assert_eq!(selected.used(), 1_000);
    }

    #[test]
    fn failed_pve_refresh_retains_last_capacity_without_filesystem_fallback() {
        let local = DiskCapacity {
            total: 1_000,
            available: 250,
        };
        let cached = DiskCapacity {
            total: 9_000,
            available: 8_000,
        };

        assert_eq!(
            authoritative_disk_capacity(DiskCapacitySource::PveLxc, local, Some(cached)),
            Some(cached)
        );
        assert_eq!(
            authoritative_disk_capacity(DiskCapacitySource::PveLxc, local, None),
            None
        );
    }

    fn request(node: &str, storage: &str, rootfs_size_gib: u64) -> PveCapacityRequest {
        PveCapacityRequest {
            configured_node: node.to_string(),
            configured_storage: storage.to_string(),
            rootfs_size_gib,
        }
    }

    #[test]
    fn pve_cache_is_unknown_when_the_configuration_request_changes() {
        let old_request = request("node-a", "pool-a", 10);
        let new_request = request("node-b", "pool-b", 20);
        let cached = PveCapacityCache {
            request: old_request.clone(),
            resolved_node: "node-a".to_string(),
            selected_storage: "pool-a".to_string(),
            capacity: DiskCapacity {
                total: 9_000,
                available: 8_000,
            },
        };

        assert_eq!(
            capacity_for_request(Some(&cached), &old_request),
            Some(cached.capacity)
        );
        assert_eq!(capacity_for_request(Some(&cached), &new_request), None);
    }

    #[test]
    fn changed_request_removes_stale_capacity_before_a_failed_refresh() {
        let old_request = request("node-a", "pool-a", 10);
        let new_request = request("node-b", "pool-b", 20);
        let mut cache = Some(PveCapacityCache {
            request: old_request,
            resolved_node: "node-a".to_string(),
            selected_storage: "pool-a".to_string(),
            capacity: DiskCapacity {
                total: 9_000,
                available: 8_000,
            },
        });

        invalidate_capacity_for_request(&mut cache, &new_request);

        assert_eq!(cache, None);
    }

    #[test]
    fn in_flight_refresh_cannot_publish_after_the_configuration_changes() {
        let old_request = request("node-a", "pool-a", 10);
        let new_request = request("node-b", "pool-b", 20);
        let refreshed = PveCapacityCache {
            request: old_request,
            resolved_node: "node-a".to_string(),
            selected_storage: "pool-a".to_string(),
            capacity: DiskCapacity {
                total: 9_000,
                available: 8_000,
            },
        };
        let mut cache = None;

        publish_capacity_if_current(&mut cache, refreshed, &new_request);

        assert_eq!(cache, None);
    }

    #[test]
    fn worker_wait_is_interrupted_when_its_owner_is_dropped() {
        let owner = Arc::new(());
        let weak_owner = Arc::downgrade(&owner);
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender
                .send(wait_while_alive(
                    &weak_owner,
                    std::time::Duration::from_secs(30),
                ))
                .unwrap();
        });

        drop(owner);

        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(false)
        );
        worker.join().unwrap();
    }
}
