use crate::io::abort::{AbortGuard, AbortListener};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

const ROOT: &str = "/sys/fs/cgroup";

pub fn is_unified() -> bool {
    static UNIFIED: OnceLock<bool> = OnceLock::new();

    *UNIFIED.get_or_init(|| Path::new(ROOT).join("cgroup.controllers").exists())
}

fn unified_dir(proc_cgroup: &str) -> Option<PathBuf> {
    for line in proc_cgroup.lines() {
        let Some((hierarchy, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((controllers, path)) = rest.split_once(':') else {
            continue;
        };

        if hierarchy == "0" && controllers.is_empty() && !path.is_empty() && path != "/" {
            return Some(Path::new(ROOT).join(path.trim_start_matches('/')));
        }
    }

    None
}

pub fn io_weight_effective() -> bool {
    static EFFECTIVE: OnceLock<bool> = OnceLock::new();

    *EFFECTIVE.get_or_init(|| {
        if std::fs::read_to_string(Path::new(ROOT).join("io.cost.qos"))
            .is_ok_and(|contents| contents.contains("enable=1"))
        {
            return true;
        }

        let Ok(devices) = std::fs::read_dir("/sys/block") else {
            return false;
        };

        devices.flatten().any(|device| {
            std::fs::read_to_string(device.path().join("queue/scheduler"))
                .is_ok_and(|contents| contents.contains("[bfq]") || contents.contains("[cfq]"))
        })
    })
}

pub fn parse_limit(contents: &str) -> i64 {
    match contents.split_whitespace().next() {
        Some("max") | None => 0,
        Some(quota) => quota.parse::<i64>().unwrap_or(0).max(0),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BurstOutcome {
    Written(u64),
    CgroupGone,
    Unsupported,
    Failed,
}

pub struct CpuCgroup {
    pub quota: PathBuf,
    pub burst: PathBuf,
}

impl CpuCgroup {
    pub fn limit_percent(quota_us: i64, period_us: i64) -> u32 {
        if quota_us <= 0 || period_us <= 0 {
            return 0;
        }

        (quota_us * 100 / period_us) as u32
    }

    pub fn burst_us(quota_us: i64, multiple: f64) -> u64 {
        if quota_us <= 0 {
            return 0;
        }

        (quota_us as f64 * multiple.clamp(0.0, 1.0)) as u64
    }

    pub fn parse(proc_cgroup: &str, unified: bool) -> Option<Self> {
        if unified {
            let dir = unified_dir(proc_cgroup)?;

            return Some(Self {
                quota: dir.join("cpu.max"),
                burst: dir.join("cpu.max.burst"),
            });
        }

        for line in proc_cgroup.lines() {
            let Some((_, rest)) = line.split_once(':') else {
                continue;
            };
            let Some((controllers, path)) = rest.split_once(':') else {
                continue;
            };
            if path.is_empty() {
                continue;
            }

            if controllers.split(',').any(|controller| controller == "cpu") {
                let dir = Path::new(ROOT)
                    .join("cpu")
                    .join(path.trim_start_matches('/'));

                return Some(Self {
                    quota: dir.join("cpu.cfs_quota_us"),
                    burst: dir.join("cpu.cfs_burst_us"),
                });
            }
        }

        None
    }

    pub fn write_process_burst(pid: i64, multiple: f64) -> BurstOutcome {
        if !cfg!(target_os = "linux") {
            return BurstOutcome::Unsupported;
        }

        tokio::task::block_in_place(|| {
            let proc_cgroup = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
                Ok(proc_cgroup) => proc_cgroup,
                Err(err) => {
                    tracing::debug!(pid, "failed to read cgroup of process: {}", err);

                    return BurstOutcome::CgroupGone;
                }
            };

            let Some(cgroup) = Self::parse(&proc_cgroup, is_unified()) else {
                tracing::debug!(pid, "no cpu cgroup found for process");

                return BurstOutcome::Unsupported;
            };

            cgroup.write_burst(pid, multiple)
        })
    }

    pub fn write_burst(&self, pid: i64, multiple: f64) -> BurstOutcome {
        static WARNED_UNSUPPORTED: OnceLock<()> = OnceLock::new();

        let burst_us = match std::fs::read_to_string(&self.quota) {
            Ok(contents) => Self::burst_us(parse_limit(&contents), multiple),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    pid,
                    "cgroup of process vanished before its quota could be read: {}",
                    err
                );

                return BurstOutcome::CgroupGone;
            }
            Err(err) => {
                tracing::debug!(pid, "failed to read cgroup quota of process: {}", err);

                return BurstOutcome::Failed;
            }
        };

        match std::fs::write(&self.burst, burst_us.to_string()) {
            Ok(()) => {
                tracing::debug!(pid, burst_us, "wrote cfs burst to {}", self.burst.display());

                BurstOutcome::Written(burst_us)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if self.quota.exists() {
                    if WARNED_UNSUPPORTED.set(()).is_ok() {
                        tracing::warn!(
                            "cfs burst is not supported by this kernel, {} does not exist",
                            self.burst.display()
                        );
                    }

                    BurstOutcome::Unsupported
                } else {
                    tracing::debug!(pid, "cgroup of process vanished before the burst write");

                    BurstOutcome::CgroupGone
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                if WARNED_UNSUPPORTED.set(()).is_ok() {
                    tracing::warn!(
                        "cfs burst cannot be written on this host (is wings running in a restricted container?), {}: {}",
                        self.burst.display(),
                        err
                    );
                }

                BurstOutcome::Unsupported
            }
            Err(err) => {
                tracing::debug!(pid, "failed to write cfs burst: {}", err);

                BurstOutcome::Failed
            }
        }
    }
}

pub struct StatSample {
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    pub network: Option<(u64, u64, u64, u64)>,
    pub cpu_total_ns: u64,
    pub at: std::time::Instant,
}

pub struct StatFiles {
    pub cpu_stat: PathBuf,
    pub memory_current: PathBuf,
    pub memory_stat: PathBuf,
    pub memory_max: PathBuf,
    pub net_dev: PathBuf,
}

impl StatFiles {
    pub fn resolve(pid: i64) -> Option<Self> {
        if !is_unified() {
            return None;
        }

        let proc_cgroup =
            tokio::task::block_in_place(|| std::fs::read_to_string(format!("/proc/{pid}/cgroup")))
                .ok()?;
        let dir = unified_dir(&proc_cgroup)?;

        Some(Self {
            cpu_stat: dir.join("cpu.stat"),
            memory_current: dir.join("memory.current"),
            memory_stat: dir.join("memory.stat"),
            memory_max: dir.join("memory.max"),
            net_dev: PathBuf::from(format!("/proc/{pid}/net/dev")),
        })
    }

    fn read_sample(&self, host_memory: &mut u64) -> Result<StatSample, std::io::Error> {
        let at = std::time::Instant::now();

        let cpu_stat = std::fs::read_to_string(&self.cpu_stat)?;
        let memory_current = std::fs::read_to_string(&self.memory_current)?;
        let memory_stat = std::fs::read_to_string(&self.memory_stat)?;
        let memory_max = std::fs::read_to_string(&self.memory_max)?;
        let net_dev = std::fs::read_to_string(&self.net_dev);

        let mut memory_bytes = memory_current.trim().parse::<u64>().unwrap_or(0);
        if let Some(inactive_file) = Self::parse_keyed(&memory_stat, "inactive_file")
            && inactive_file < memory_bytes
        {
            memory_bytes -= inactive_file;
        }

        let memory_limit_bytes = match parse_limit(&memory_max) {
            0 => {
                if *host_memory == 0 {
                    *host_memory = std::fs::read_to_string("/proc/meminfo")
                        .ok()
                        .and_then(|meminfo| {
                            meminfo
                                .lines()
                                .find(|line| line.starts_with("MemTotal:"))?
                                .split_whitespace()
                                .nth(1)?
                                .parse::<u64>()
                                .ok()
                        })
                        .map_or(0, |kib| kib * 1024);
                }

                *host_memory
            }
            limit => limit as u64,
        };

        Ok(StatSample {
            memory_bytes,
            memory_limit_bytes,
            network: net_dev.ok().as_deref().and_then(Self::parse_net_dev),
            cpu_total_ns: Self::parse_keyed(&cpu_stat, "usage_usec").unwrap_or(0) * 1000,
            at,
        })
    }

    pub fn parse_keyed(contents: &str, key: &str) -> Option<u64> {
        contents.lines().find_map(|line| {
            let (k, v) = line.split_once(' ')?;

            if k == key {
                v.trim().parse().ok()
            } else {
                None
            }
        })
    }

    pub fn parse_net_dev(contents: &str) -> Option<(u64, u64, u64, u64)> {
        for line in contents.lines().skip(2) {
            let Some((iface, counters)) = line.split_once(':') else {
                continue;
            };
            if iface.trim() == "lo" {
                continue;
            }

            let mut fields = counters.split_whitespace();
            let rx_bytes = fields.next()?.parse().ok()?;
            let rx_packets = fields.next()?.parse().ok()?;
            let tx_bytes = fields.nth(6)?.parse().ok()?;
            let tx_packets = fields.next()?.parse().ok()?;

            return Some((rx_bytes, rx_packets, tx_bytes, tx_packets));
        }

        None
    }
}

pub type SampleReceiver = tokio::sync::mpsc::Receiver<Result<StatSample, std::io::Error>>;
type SampleSender = tokio::sync::mpsc::Sender<Result<StatSample, std::io::Error>>;

struct SamplerEntry {
    files: StatFiles,
    samples: SampleSender,
}

pub struct StatsSampler {
    _guard: AbortGuard,
    listener: AbortListener,
    incoming: Arc<parking_lot::Mutex<Vec<SamplerEntry>>>,
    thread: OnceLock<()>,
}

impl Default for StatsSampler {
    fn default() -> Self {
        let (guard, listener) = AbortGuard::new();

        Self {
            _guard: guard,
            listener,
            incoming: Arc::new(parking_lot::Mutex::new(Vec::new())),
            thread: OnceLock::new(),
        }
    }
}

impl StatsSampler {
    pub fn register(&self, files: StatFiles) -> SampleReceiver {
        let (samples, receiver) = tokio::sync::mpsc::channel(2);

        self.incoming.lock().push(SamplerEntry { files, samples });
        self.thread.get_or_init(|| {
            let listener = self.listener.clone();
            let incoming = Arc::clone(&self.incoming);

            std::thread::spawn(move || Self::run(&listener, &incoming));
        });

        receiver
    }

    fn run(listener: &AbortListener, incoming: &parking_lot::Mutex<Vec<SamplerEntry>>) {
        const PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

        let mut entries = Vec::new();
        let mut host_memory = 0;
        let mut next_tick = std::time::Instant::now() + PERIOD;

        while !listener.is_aborted() {
            match next_tick.checked_duration_since(std::time::Instant::now()) {
                Some(delay) => {
                    std::thread::sleep(delay);
                    next_tick += PERIOD;
                }
                None => next_tick = std::time::Instant::now() + PERIOD,
            }

            entries.append(&mut incoming.lock());
            entries.retain(|entry: &SamplerEntry| {
                if entry.samples.is_closed() {
                    return false;
                }

                !matches!(
                    entry
                        .samples
                        .try_send(entry.files.read_sample(&mut host_memory)),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
                )
            });
        }

        tracing::debug!("cgroup stats sampler thread exiting");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CpuCgroup::limit_percent

    #[test]
    fn limit_percent_is_zero_without_a_quota() {
        assert_eq!(CpuCgroup::limit_percent(-1, 100000), 0);
        assert_eq!(CpuCgroup::limit_percent(100000, 0), 0);
    }

    // CpuCgroup::burst_us

    #[test]
    fn burst_us_never_exceeds_the_quota() {
        assert_eq!(CpuCgroup::burst_us(200000, 1.0), 200000);
        assert_eq!(CpuCgroup::burst_us(200000, 0.5), 100000);
        assert_eq!(CpuCgroup::burst_us(200000, 2.5), 200000);
        assert_eq!(CpuCgroup::burst_us(200000, f64::INFINITY), 200000);
    }

    #[test]
    fn burst_us_is_zero_without_a_quota() {
        assert_eq!(CpuCgroup::burst_us(0, 1.0), 0);
        assert_eq!(CpuCgroup::burst_us(-1, 1.0), 0);
    }

    #[test]
    fn burst_us_is_zero_for_a_non_positive_multiple() {
        assert_eq!(CpuCgroup::burst_us(200000, 0.0), 0);
        assert_eq!(CpuCgroup::burst_us(200000, -1.0), 0);
        assert_eq!(CpuCgroup::burst_us(200000, f64::NAN), 0);
    }

    // parse_limit

    #[test]
    fn parse_limit_reads_the_unified_format() {
        assert_eq!(parse_limit("200000 100000\n"), 200000);
        assert_eq!(parse_limit("max 100000\n"), 0);
    }

    #[test]
    fn parse_limit_reads_the_v1_format() {
        assert_eq!(parse_limit("200000\n"), 200000);
        assert_eq!(parse_limit("-1\n"), 0);
    }

    #[test]
    fn parse_limit_is_zero_for_garbage() {
        assert_eq!(parse_limit(""), 0);
        assert_eq!(parse_limit("not-a-number"), 0);
    }

    struct Kernel {
        quota_us: i64,
        burst_us: u64,
    }

    impl Kernel {
        fn write_quota(&mut self, quota_us: i64) -> Result<(), ()> {
            if quota_us > 0 && self.burst_us > quota_us as u64 {
                return Err(());
            }

            self.quota_us = quota_us;
            Ok(())
        }

        fn write_burst(&mut self, burst_us: u64) -> Result<(), ()> {
            if self.quota_us > 0 && burst_us > self.quota_us as u64 {
                return Err(());
            }

            self.burst_us = burst_us;
            Ok(())
        }
    }

    #[test]
    fn lowering_a_quota_needs_the_burst_cleared_first() {
        let mut kernel = Kernel {
            quota_us: 400000,
            burst_us: CpuCgroup::burst_us(400000, 1.0),
        };

        assert!(kernel.write_quota(100000).is_err());

        assert!(kernel.write_burst(0).is_ok());
        assert!(kernel.write_quota(100000).is_ok());
        assert!(kernel.write_burst(CpuCgroup::burst_us(100000, 1.0)).is_ok());
        assert_eq!(kernel.burst_us, 100000);
    }

    #[test]
    fn raising_a_quota_survives_the_same_ordering() {
        let mut kernel = Kernel {
            quota_us: 100000,
            burst_us: CpuCgroup::burst_us(100000, 1.0),
        };

        assert!(kernel.write_burst(0).is_ok());
        assert!(kernel.write_quota(400000).is_ok());
        assert!(kernel.write_burst(CpuCgroup::burst_us(400000, 1.0)).is_ok());
        assert_eq!(kernel.burst_us, 400000);
    }

    // burst computed from the live quota can never race a concurrent update
    // into EINVAL: whatever quota is in the file at write time bounds the burst.

    #[test]
    fn live_quota_burst_always_satisfies_the_kernel_invariant() {
        let mut kernel = Kernel {
            quota_us: 400000,
            burst_us: 0,
        };

        for live_quota in [400000, 100000, 20000] {
            kernel.quota_us = live_quota;
            assert!(
                kernel
                    .write_burst(CpuCgroup::burst_us(live_quota, 1.0))
                    .is_ok()
            );
        }
    }

    // CpuCgroup::parse

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_resolves_the_unified_line() {
        let cgroup = CpuCgroup::parse("0::/system.slice/docker-3f1a.scope\n", true).unwrap();

        assert_eq!(
            cgroup.burst,
            Path::new("/sys/fs/cgroup/system.slice/docker-3f1a.scope/cpu.max.burst")
        );
        assert_eq!(
            cgroup.quota,
            Path::new("/sys/fs/cgroup/system.slice/docker-3f1a.scope/cpu.max")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_resolves_the_v1_cpu_controller() {
        let proc_cgroup = "12:devices:/docker/3f1a\n\
             4:cpu,cpuacct:/docker/3f1a\n\
             3:memory:/docker/3f1a\n\
             0::/\n";

        let cgroup = CpuCgroup::parse(proc_cgroup, false).unwrap();

        assert_eq!(
            cgroup.burst,
            Path::new("/sys/fs/cgroup/cpu/docker/3f1a/cpu.cfs_burst_us")
        );
        assert_eq!(
            cgroup.quota,
            Path::new("/sys/fs/cgroup/cpu/docker/3f1a/cpu.cfs_quota_us")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ignores_controllers_that_merely_contain_cpu() {
        let proc_cgroup = "5:cpuset:/docker/3f1a\n4:cpuacct:/docker/3f1a\n";

        assert!(CpuCgroup::parse(proc_cgroup, false).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ignores_the_unified_line_on_a_v1_host() {
        assert!(CpuCgroup::parse("0::/docker/3f1a\n", false).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ignores_an_empty_cgroup_path() {
        assert!(CpuCgroup::parse("0::\n", true).is_none());
        assert!(CpuCgroup::parse("", true).is_none());
    }

    // StatFiles::parse_keyed

    #[test]
    fn parse_keyed_finds_the_requested_key() {
        let cpu_stat = "usage_usec 37585\nuser_usec 20000\nsystem_usec 17585\n";

        assert_eq!(StatFiles::parse_keyed(cpu_stat, "usage_usec"), Some(37585));
        assert_eq!(StatFiles::parse_keyed(cpu_stat, "system_usec"), Some(17585));
        assert_eq!(StatFiles::parse_keyed(cpu_stat, "missing"), None);
    }

    #[test]
    fn parse_keyed_does_not_match_key_prefixes() {
        assert_eq!(
            StatFiles::parse_keyed("usage_usec_extra 1\nusage_usec 2\n", "usage_usec"),
            Some(2)
        );
    }

    // StatFiles::parse_net_dev

    #[test]
    fn parse_net_dev_skips_loopback_and_the_header() {
        let net_dev = "Inter-|   Receive                                                |  Transmit\n\
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n\
              eth0:    5000      50    0    0    0     0          0         0     7000      70    0    0    0     0       0          0\n";

        assert_eq!(
            StatFiles::parse_net_dev(net_dev),
            Some((5000, 50, 7000, 70))
        );
    }

    #[test]
    fn parse_net_dev_is_none_without_a_real_interface() {
        assert_eq!(StatFiles::parse_net_dev(""), None);
        assert_eq!(
            StatFiles::parse_net_dev("h1\nh2\n    lo:    1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"),
            None
        );
    }
}
