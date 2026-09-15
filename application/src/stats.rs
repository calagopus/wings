use serde::Serialize;
use std::{path::Path, sync::Arc};
use sysinfo::{Disks, Networks, System};
use utoipa::ToSchema;

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

pub struct StatsManager {
    stats: Arc<arc_swap::ArcSwap<SystemStats>>,
}

impl StatsManager {
    #[inline]
    pub fn get_stats(&self) -> Arc<SystemStats> {
        self.stats.load_full()
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        let stats = Arc::new(arc_swap::ArcSwap::new(Arc::new(SystemStats::default())));

        std::thread::spawn({
            let stats = Arc::clone(&stats);

            move || {
                let refresh_kind = sysinfo::RefreshKind::nothing()
                    .with_cpu(sysinfo::CpuRefreshKind::nothing().with_cpu_usage())
                    .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram());

                let mut sys = System::new_with_specifics(refresh_kind);
                let mut disks = Disks::new_with_refreshed_list();
                let mut networks = Networks::new_with_refreshed_list();

                let cpu_model = sys
                    .cpus()
                    .first()
                    .map_or_else(|| "unknown".to_string(), |cpu| cpu.brand().to_string());

                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    sys.refresh_specifics(refresh_kind);
                    networks.refresh(true);
                    for disk in disks.list_mut() {
                        if disk.mount_point() == Path::new("/") {
                            disk.refresh();
                        }
                    }

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

                    let disk = match disks.iter().find(|d| d.mount_point() == Path::new("/")) {
                        Some(d) => d,
                        None => match disks.first() {
                            Some(d) => d,
                            None => continue,
                        },
                    };
                    let total_disk_space = disk.total_space();
                    let used_disk_space = disk.total_space() - disk.available_space();
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

                    stats.store(Arc::new(SystemStats {
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
                    }));
                }
            }
        });

        Self { stats }
    }
}
