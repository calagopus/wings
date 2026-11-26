//! Resource usage, read the same way as for docker containers so the panel shows the same numbers.

use super::{InstanceState, boost, process::Shared};
use crate::server::{executor::docker::cgroup, state::ServerState};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn host_cpu_percent() -> u32 {
    std::thread::available_parallelism().map_or(1, |threads| threads.get()) as u32 * 100
}

/// Records when the server started and what CPU limit it currently has.
pub(super) async fn publish_started(shared: &Shared, state: &InstanceState) {
    let Some(server) = shared.server.upgrade() else {
        return;
    };
    let limit = match shared.cpu.boosted_percent() {
        0 => {
            let resources = server
                .configuration
                .read()
                .await
                .convert_container_resources(&shared.executor.config);
            cgroup::CpuCgroup::limit_percent(
                resources.cpu_quota.unwrap_or(0),
                resources.cpu_period.unwrap_or(100_000),
            )
        }
        boosted => boosted,
    };
    let limit = if limit > 0 { limit } else { host_cpu_percent() };
    let since = state
        .started_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .and_then(|started| {
            (chrono::Utc::now() - started.with_timezone(&chrono::Utc))
                .to_std()
                .ok()
        })
        .unwrap_or_default();
    server.resource_usage.send_if_modified(|usage| {
        let changed = usage.started_at.is_none() || usage.cpu_limit_absolute != limit;
        if usage.started_at.is_none() {
            let now = Instant::now();
            usage.started_at = Some(now.checked_sub(since).unwrap_or(now));
        }
        usage.cpu_limit_absolute = limit;
        changed
    });
}

enum Source {
    Unresolved,
    Cgroup(u32, cgroup::SampleReceiver),
    Api,
}

pub(super) async fn run(shared: Arc<Shared>) {
    let mut source = Source::Unresolved;
    let mut previous = None::<(u64, Instant)>;
    let mut streak = 0u64;
    let mut cooldown_until = None::<Instant>;
    let mut tick = crate::utils::aligned_interval(Duration::from_secs(1));

    loop {
        let received = match &mut source {
            Source::Cgroup(pid, samples) if shared.pid() == Some(*pid) => {
                match tokio::time::timeout(Duration::from_secs(3), samples.recv()).await {
                    Ok(Some(Ok(sample))) => Some(sample),
                    _ => {
                        source = Source::Api;
                        continue;
                    }
                }
            }
            Source::Cgroup(..) => {
                source = Source::Unresolved;
                continue;
            }
            _ => {
                tick.tick().await;
                None
            }
        };
        let Some(server) = shared.server.upgrade() else {
            return;
        };
        let disk_bytes = server.filesystem.limiter_usage().await;
        let Some(pid) = shared
            .pid()
            .filter(|_| server.state.get_state() != ServerState::Offline)
        else {
            server.resource_usage.send_modify(|usage| {
                usage.disk_bytes = disk_bytes;
                usage.state = server.state.get_state();
            });
            source = Source::Unresolved;
            previous = None;
            streak = 0;
            continue;
        };
        if matches!(source, Source::Unresolved) {
            source = match cgroup::StatFiles::resolve(i64::from(pid)) {
                Some(files) => Source::Cgroup(pid, shared.executor.stats_sampler.register(files)),
                None => Source::Api,
            };
            if matches!(source, Source::Cgroup(..)) {
                continue;
            }
        }
        let sample = match received {
            Some(sample) => sample,
            None => {
                let Ok(state) = shared.executor.instance_state(&shared.name).await else {
                    continue;
                };
                cgroup::StatSample {
                    memory_bytes: state.memory.get("usage").copied().unwrap_or(0),
                    memory_limit_bytes: state.memory.get("total").copied().unwrap_or(0),
                    network: state.network.get("eth0").map(|nic| {
                        let counters = &nic.counters;
                        (
                            counters.bytes_received,
                            counters.packets_received,
                            counters.bytes_sent,
                            counters.packets_sent,
                        )
                    }),
                    cpu_total_ns: state.cpu.get("usage").copied().unwrap_or(0),
                    at: Instant::now(),
                }
            }
        };

        let cpu_absolute = previous.map_or(0.0, |(total, at)| {
            let used = sample.cpu_total_ns.saturating_sub(total) as f64;
            let elapsed = sample.at.duration_since(at).as_nanos() as f64;
            if elapsed > 0.0 && used > 0.0 {
                (used / elapsed * 100.0 * 1000.0).round() / 1000.0
            } else {
                0.0
            }
        });
        previous = Some((sample.cpu_total_ns, sample.at));
        server.resource_usage.send_modify(|usage| {
            usage.memory_bytes = sample.memory_bytes;
            usage.memory_limit_bytes = sample.memory_limit_bytes;
            usage.disk_bytes = disk_bytes;
            usage.state = server.state.get_state();
            if let Some((rx_bytes, rx_packets, tx_bytes, tx_packets)) = sample.network {
                usage.network.rx_bytes = rx_bytes;
                usage.network.rx_packets = rx_packets;
                usage.network.tx_bytes = tx_bytes;
                usage.network.tx_packets = tx_packets;
            }
            usage.cpu_absolute = cpu_absolute;
        });

        if shared.cpu.boosted_percent() == 0
            && cooldown_until.is_none_or(|until| until <= Instant::now())
            && server.state.get_state() == ServerState::Running
        {
            let (runtime, cpu_limit) = {
                let configuration = server.configuration.read().await;
                (
                    configuration
                        .features
                        .runtime_cpu_boost(&shared.executor.config),
                    configuration.build.cpu_limit,
                )
            };
            if runtime.enabled
                && cpu_limit > 0
                && cpu_absolute >= cpu_limit as f64 * runtime.threshold as f64 / 100.0
            {
                streak += 1;
            } else {
                streak = 0;
            }
            if streak >= runtime.sustained.max(1)
                && boost::begin_runtime(&shared, runtime, cpu_limit)
            {
                streak = 0;
                cooldown_until = Some(
                    Instant::now()
                        + Duration::from_secs(runtime.duration.saturating_add(runtime.cooldown)),
                );
            }
        } else {
            streak = 0;
        }
    }
}
