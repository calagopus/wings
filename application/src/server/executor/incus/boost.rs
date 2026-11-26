//! CPU bursting and the startup and runtime CPU boosts, as the docker runtime applies them.

use super::{IncusExecutor, process::Shared};
use crate::config::Config;
use crate::server::{InnerServer, executor::docker::cgroup::CpuCgroup, state::ServerState};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

/// Boost state of one instance.
#[derive(Default)]
pub(super) struct Cpu {
    /// Held around every change of the CPU limit.
    pub lock: tokio::sync::Mutex<()>,
    /// The limit in percent to report while a boost is active, otherwise 0.
    boosted: AtomicU32,
}

impl Cpu {
    pub(super) fn boosted_percent(&self) -> u32 {
        self.boosted.load(Ordering::Relaxed)
    }

    pub(super) fn clear_burst(&self, pid: Option<u32>) {
        if let Some(pid) = pid {
            CpuCgroup::write_process_burst(i64::from(pid), 0.0);
        }
    }

    pub(super) fn apply_burst(&self, config: &Config, pid: Option<u32>) {
        let burst = config.load().docker.cfs_burst;
        if burst.enabled
            && let Some(pid) = pid
        {
            CpuCgroup::write_process_burst(i64::from(pid), burst.multiple);
        }
    }
}

/// A node-wide count of running boosts, released when dropped.
struct Slot(&'static AtomicU64);

impl Slot {
    fn take(active: &'static AtomicU64, limit: u64) -> Option<Self> {
        active
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < limit).then_some(count + 1)
            })
            .ok()
            .map(|_| Self(active))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn burst_pid(executor: &IncusExecutor, name: &str) -> Option<u32> {
    executor
        .instance_state(name)
        .await
        .ok()
        .map(|state| state.pid)
        .filter(|pid| *pid > 0)
}

/// Puts the configured CPU limit back once a boost is over.
async fn restore(shared: &Shared, server: &InnerServer) {
    let executor = &shared.executor;
    let resources = server
        .configuration
        .read()
        .await
        .convert_container_resources(&executor.config);
    let _guard = shared.cpu.lock.lock().await;
    let pid = burst_pid(executor, &shared.name).await;
    shared.cpu.clear_burst(pid);
    let quota = resources
        .cpu_quota
        .filter(|quota| *quota > 0)
        .map(|quota| (quota, resources.cpu_period.unwrap_or(100_000)));
    if let Err(err) = executor.set_cpu_allowance(&shared.name, quota).await {
        tracing::debug!(instance = %shared.name, "failed to restore the CPU limit after a boost: {err:#}");
    }
    shared.cpu.apply_burst(&executor.config, pid);
}

/// Called right after a server instance starts.
pub(super) async fn on_start(shared: &Arc<Shared>, server: &Arc<InnerServer>) {
    static ACTIVE: AtomicU64 = AtomicU64::new(0);

    let executor = &shared.executor;
    let (boost, resources) = {
        let configuration = server.configuration.read().await;
        (
            configuration.features.startup_cpu_boost(&executor.config),
            configuration.convert_container_resources(&executor.config),
        )
    };
    let quota = resources.cpu_quota.unwrap_or(-1);
    let period = resources.cpu_period.unwrap_or(100_000);
    let slot = (boost.enabled && quota > 0)
        .then(|| Slot::take(&ACTIVE, boost.max_concurrent))
        .flatten();

    let guard = shared.cpu.lock.lock().await;
    if let Some(slot) = slot {
        shared
            .cpu
            .clear_burst(burst_pid(executor, &shared.name).await);
        match executor.set_cpu_allowance(&shared.name, None).await {
            Ok(()) => {
                drop(guard);
                shared
                    .cpu
                    .boosted
                    .store(CpuCgroup::limit_percent(quota, period), Ordering::Relaxed);
                tracing::debug!(
                    instance = %shared.name,
                    "startup boost active, CPU limit lifted until the server is running"
                );
                let shared = Arc::clone(shared);
                let server = Arc::downgrade(server);
                tokio::spawn(async move {
                    if let Some(server) = server.upgrade() {
                        server
                            .state
                            .wait_while_state(
                                ServerState::Starting,
                                Duration::from_secs(boost.timeout),
                            )
                            .await;
                    }
                    if let Some(server) = server.upgrade() {
                        restore(&shared, &server).await;
                    }
                    shared.cpu.boosted.store(0, Ordering::Relaxed);
                    drop(slot);
                });
                return;
            }
            Err(err) => {
                tracing::debug!(instance = %shared.name, "failed to apply the startup boost: {err:#}");
            }
        }
    }
    let pid = burst_pid(executor, &shared.name).await;
    shared.cpu.apply_burst(&executor.config, pid);
}

/// Raises the CPU limit for a while after sustained load. Returns whether a boost began.
pub(super) fn begin_runtime(
    shared: &Arc<Shared>,
    boost: crate::config::DockerRuntimeBoost,
    cpu_limit: i64,
) -> bool {
    static ACTIVE: AtomicU64 = AtomicU64::new(0);

    let Some(slot) = Slot::take(&ACTIVE, boost.max_concurrent) else {
        return false;
    };
    if shared
        .cpu
        .boosted
        .compare_exchange(0, cpu_limit as u32, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        let executor = &shared.executor;
        let period = executor.config.load().docker.cpu_period_us();
        let quota = ((cpu_limit * period / 100) as f64 * boost.multiple.max(1.0)) as i64;
        let applied = {
            let _guard = shared.cpu.lock.lock().await;
            let pid = shared.pid();
            shared.cpu.clear_burst(pid);
            let applied = executor
                .set_cpu_allowance(&shared.name, Some((quota, period)))
                .await;
            shared.cpu.apply_burst(&executor.config, pid);
            applied
        };
        match applied {
            Ok(()) => {
                tracing::debug!(
                    instance = %shared.name,
                    "runtime boost active, CPU limit raised for {}s",
                    boost.duration
                );
                tokio::time::sleep(Duration::from_secs(boost.duration)).await;
                if let Some(server) = shared.server.upgrade() {
                    restore(&shared, &server).await;
                }
            }
            Err(err) => {
                tracing::debug!(instance = %shared.name, "failed to apply the runtime boost: {err:#}");
            }
        }
        shared.cpu.boosted.store(0, Ordering::Relaxed);
        drop(slot);
    });
    true
}
