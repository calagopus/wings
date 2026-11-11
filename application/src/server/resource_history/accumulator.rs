use crate::server::{resources::ResourceUsage, state::ServerState};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    pub n: i64,
    pub cpu_sum: i64,
    pub cpu_max: i64,
    pub mem_sum: i64,
    pub mem_max: i64,
    pub disk: i64,
    pub rx: i64,
    pub tx: i64,
}

impl Bucket {
    fn add(&mut self, sample: &Sample) {
        if sample.running {
            self.n += 1;
            self.cpu_sum += sample.cpu;
            self.cpu_max = self.cpu_max.max(sample.cpu);
            self.mem_sum += sample.mem;
            self.mem_max = self.mem_max.max(sample.mem);
        }
        self.disk = sample.disk;
        self.rx += sample.rx;
        self.tx += sample.tx;
    }

    fn is_idle(&self) -> bool {
        self.n == 0 && self.rx == 0 && self.tx == 0
    }
}

/// One second of usage, cpu in hundredths of a percent, memory and disk in KiB,
/// network as bytes since the previous sample.
#[derive(Debug, Clone, Copy)]
struct Sample {
    running: bool,
    cpu: i64,
    mem: i64,
    disk: i64,
    rx: i64,
    tx: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub memory: i64,
    pub cpu: i64,
}

/// Seconds `[since, until)` a server spent in one state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub since: i64,
    pub until: i64,
    pub state: ServerState,
}

/// Samples further apart than this split a span, the time between them is unknown.
const SPAN_GAP: i64 = 5;

pub struct Row {
    pub step: u64,
    pub b: i64,
    pub bucket: Bucket,
}

struct TierTrack {
    step: u64,
    pending: Vec<(i64, Bucket)>,
    last_written_disk: Option<i64>,
}

pub struct ServerTrack {
    tiers: Vec<TierTrack>,
    network: Option<(u64, u64)>,
    limits: Option<Limits>,
    pending_limits: Option<(i64, Limits)>,
    span: Option<Span>,
    span_dirty: bool,
    closed_spans: Vec<Span>,
}

impl ServerTrack {
    /// `span` is the last stored span, continued when the server is still in its state.
    pub fn new(steps: &[u64], limits: Option<Limits>, span: Option<Span>) -> Self {
        Self {
            tiers: steps
                .iter()
                .map(|&step| TierTrack {
                    step,
                    pending: Vec::new(),
                    last_written_disk: None,
                })
                .collect(),
            network: None,
            limits,
            pending_limits: None,
            span,
            span_dirty: false,
            closed_spans: Vec::new(),
        }
    }

    pub fn push_state(&mut self, ts: i64, state: ServerState) {
        if let Some(span) = &mut self.span
            && span.state == state
            && ts >= span.since
            && ts <= span.until + SPAN_GAP
        {
            if ts + 1 > span.until {
                span.until = ts + 1;
                self.span_dirty = true;
            }
            return;
        }

        if let Some(span) = self.span.take()
            && self.span_dirty
        {
            self.closed_spans.push(span);
        }
        self.span = Some(Span {
            since: ts,
            until: ts + 1,
            state,
        });
        self.span_dirty = true;
    }

    /// Spans changed since the last call, the open one included while it keeps growing.
    pub fn drain_spans(&mut self) -> Vec<Span> {
        let mut spans = std::mem::take(&mut self.closed_spans);
        if self.span_dirty
            && let Some(span) = self.span
        {
            spans.push(span);
        }
        self.span_dirty = false;

        spans
    }

    fn counter_delta(previous: u64, current: u64) -> i64 {
        if current >= previous {
            (current - previous) as i64
        } else {
            current as i64
        }
    }

    pub fn push(&mut self, ts: i64, usage: &ResourceUsage, limits: Limits) {
        let running = usage.state != ServerState::Offline && usage.memory_limit_bytes > 0;
        let network = (usage.network.rx_bytes, usage.network.tx_bytes);
        let (rx, tx) = match self.network.replace(network) {
            Some((rx, tx)) => (
                Self::counter_delta(rx, network.0),
                Self::counter_delta(tx, network.1),
            ),
            None => (0, 0),
        };

        let sample = Sample {
            running,
            cpu: (usage.cpu_absolute.max(0.0) * 100.0).round() as i64,
            mem: (usage.memory_bytes >> 10) as i64,
            disk: (usage.disk_bytes >> 10) as i64,
            rx,
            tx,
        };

        for tier in &mut self.tiers {
            let b = ts.div_euclid(tier.step as i64);
            match tier.pending.last_mut() {
                Some((last, bucket)) if *last == b => bucket.add(&sample),
                _ => {
                    let mut bucket = Bucket::default();
                    bucket.add(&sample);
                    tier.pending.push((b, bucket));
                }
            }
        }

        if running && self.limits != Some(limits) {
            self.limits = Some(limits);
            self.pending_limits = Some((ts, limits));
        }
    }

    pub fn drain(&mut self) -> (Vec<Row>, Option<(i64, Limits)>) {
        let mut rows = Vec::new();

        for tier in &mut self.tiers {
            for (b, bucket) in tier.pending.drain(..) {
                if bucket.is_idle() && tier.last_written_disk == Some(bucket.disk) {
                    continue;
                }

                tier.last_written_disk = Some(bucket.disk);
                rows.push(Row {
                    step: tier.step,
                    b,
                    bucket,
                });
            }
        }

        (rows, self.pending_limits.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::resources::ResourceUsageNetwork;

    fn usage(
        state: ServerState,
        cpu: f64,
        memory: u64,
        disk: u64,
        rx: u64,
        tx: u64,
    ) -> ResourceUsage {
        ResourceUsage {
            memory_bytes: memory,
            disk_bytes: disk,
            state,
            network: ResourceUsageNetwork {
                rx_bytes: rx,
                tx_bytes: tx,
                ..Default::default()
            },
            memory_limit_bytes: if state == ServerState::Offline {
                0
            } else {
                1 << 30
            },
            cpu_absolute: cpu,
            ..Default::default()
        }
    }

    const LIMITS: Limits = Limits {
        memory: 1 << 20,
        cpu: 100,
    };

    fn find(rows: &[Row], step: u64, b: i64) -> Option<Bucket> {
        rows.iter()
            .find(|row| row.step == step && row.b == b)
            .map(|row| row.bucket)
    }

    // ServerTrack
    #[test]
    fn network_first_sample_is_zero_and_reset_counts_new_value() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push(0, &usage(ServerState::Running, 0.0, 0, 0, 1000, 50), LIMITS);
        track.push(1, &usage(ServerState::Running, 0.0, 0, 0, 1500, 80), LIMITS);
        track.push(2, &usage(ServerState::Running, 0.0, 0, 0, 200, 10), LIMITS);

        let (rows, _) = track.drain();
        let bucket = find(&rows, 10, 0).unwrap();
        assert_eq!(bucket.rx, 500 + 200);
        assert_eq!(bucket.tx, 30 + 10);
    }

    #[test]
    fn only_running_samples_count_and_disk_is_latest() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push(
            0,
            &usage(ServerState::Running, 2.5, 2048, 1 << 10, 0, 0),
            LIMITS,
        );
        track.push(
            1,
            &usage(ServerState::Starting, 4.0, 4096 + 1023, 2 << 10, 0, 0),
            LIMITS,
        );
        track.push(
            2,
            &usage(ServerState::Running, -1.0, 0, 3 << 10, 0, 0),
            LIMITS,
        );
        track.push(
            3,
            &usage(ServerState::Offline, 50.0, 1 << 20, 5 << 10, 0, 0),
            LIMITS,
        );

        let (rows, _) = track.drain();
        let bucket = find(&rows, 10, 0).unwrap();
        assert_eq!(bucket.n, 3);
        assert_eq!(bucket.cpu_sum, 650);
        assert_eq!(bucket.cpu_max, 400);
        assert_eq!(bucket.mem_sum, 6);
        assert_eq!(bucket.mem_max, 4);
        assert_eq!(bucket.disk, 5);
    }

    #[test]
    fn starting_without_container_stats_is_not_running() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push(
            0,
            &ResourceUsage {
                memory_limit_bytes: 0,
                ..usage(ServerState::Starting, 0.0, 0, 3 << 10, 0, 0)
            },
            LIMITS,
        );
        track.push(
            1,
            &usage(ServerState::Starting, 1.0, 0, 3 << 10, 0, 0),
            LIMITS,
        );

        let (rows, _) = track.drain();
        let bucket = find(&rows, 10, 0).unwrap();
        assert_eq!(bucket.n, 1);
        assert_eq!(bucket.cpu_sum, 100);
        assert_eq!(bucket.disk, 3);
    }

    #[test]
    fn samples_land_in_every_tier_with_euclidean_bucket_index() {
        let mut track = ServerTrack::new(&[10, 60], None, None);
        track.push(-1, &usage(ServerState::Running, 1.0, 0, 0, 0, 0), LIMITS);
        track.push(59, &usage(ServerState::Running, 1.0, 0, 0, 0, 0), LIMITS);

        let (rows, _) = track.drain();
        assert_eq!(find(&rows, 10, -1).unwrap().n, 1);
        assert_eq!(find(&rows, 60, -1).unwrap().n, 1);
        assert_eq!(find(&rows, 10, 5).unwrap().n, 1);
        assert_eq!(find(&rows, 60, 0).unwrap().n, 1);
    }

    #[test]
    fn filling_bucket_is_drained_incrementally() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push(0, &usage(ServerState::Running, 1.0, 0, 0, 0, 0), LIMITS);
        track.push(1, &usage(ServerState::Running, 1.0, 0, 0, 0, 0), LIMITS);
        assert_eq!(find(&track.drain().0, 10, 0).unwrap().n, 2);

        track.push(2, &usage(ServerState::Running, 1.0, 0, 0, 0, 0), LIMITS);
        let (rows, _) = track.drain();
        assert_eq!(rows.len(), 1);
        assert_eq!(find(&rows, 10, 0).unwrap().n, 1);
    }

    #[test]
    fn idle_bucket_with_unchanged_disk_is_omitted() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push(0, &usage(ServerState::Offline, 0.0, 0, 4096, 0, 0), LIMITS);
        assert_eq!(find(&track.drain().0, 10, 0).unwrap().disk, 4);

        track.push(10, &usage(ServerState::Offline, 0.0, 0, 4096, 0, 0), LIMITS);
        assert!(track.drain().0.is_empty());

        track.push(20, &usage(ServerState::Offline, 0.0, 0, 8192, 0, 0), LIMITS);
        assert_eq!(find(&track.drain().0, 10, 2).unwrap().disk, 8);

        track.push(
            30,
            &usage(ServerState::Offline, 0.0, 0, 8192, 100, 0),
            LIMITS,
        );
        assert_eq!(find(&track.drain().0, 10, 3).unwrap().rx, 100);
    }

    #[test]
    fn limits_are_pending_once_and_only_when_running_and_changed() {
        let limits = |memory, cpu| Limits { memory, cpu };
        let mut track = ServerTrack::new(&[10], Some(limits(1024, 100)), None);

        let running = usage(ServerState::Running, 0.0, 0, 0, 0, 0);
        let offline = usage(ServerState::Offline, 0.0, 0, 0, 0, 0);
        track.push(1, &running, limits(1024, 100));
        track.push(3, &offline, limits(2048, 300));
        assert_eq!(track.drain().1, None);

        track.push(5, &running, limits(2048, 200));
        assert_eq!(track.drain().1, Some((5, limits(2048, 200))));

        track.push(6, &running, limits(2048, 200));
        assert_eq!(track.drain().1, None);
    }

    #[test]
    fn same_state_span_grows_within_gap_and_splits_past_it() {
        let mut track = ServerTrack::new(&[10], None, None);
        for ts in 0..=2 {
            track.push_state(ts, ServerState::Running);
        }
        track.push_state(8, ServerState::Running);
        track.push_state(15, ServerState::Running);

        assert_eq!(
            track.drain_spans(),
            vec![
                Span {
                    since: 0,
                    until: 9,
                    state: ServerState::Running
                },
                Span {
                    since: 15,
                    until: 16,
                    state: ServerState::Running
                },
            ]
        );
    }

    #[test]
    fn state_change_closes_span_and_opens_new_one() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push_state(0, ServerState::Starting);
        track.push_state(1, ServerState::Starting);
        track.push_state(2, ServerState::Running);

        assert_eq!(
            track.drain_spans(),
            vec![
                Span {
                    since: 0,
                    until: 2,
                    state: ServerState::Starting
                },
                Span {
                    since: 2,
                    until: 3,
                    state: ServerState::Running
                },
            ]
        );
    }

    #[test]
    fn resumed_span_is_extended_when_state_continues_within_gap() {
        let stored = Span {
            since: 100,
            until: 110,
            state: ServerState::Running,
        };
        let mut track = ServerTrack::new(&[10], None, Some(stored));
        track.push_state(113, ServerState::Running);

        assert_eq!(
            track.drain_spans(),
            vec![Span {
                until: 114,
                ..stored
            }]
        );
    }

    #[test]
    fn resumed_span_is_not_reemitted_when_state_differs() {
        let stored = Span {
            since: 100,
            until: 110,
            state: ServerState::Running,
        };
        let mut track = ServerTrack::new(&[10], None, Some(stored));
        track.push_state(110, ServerState::Offline);

        assert_eq!(
            track.drain_spans(),
            vec![Span {
                since: 110,
                until: 111,
                state: ServerState::Offline
            }]
        );
    }

    #[test]
    fn open_span_is_drained_again_only_after_it_grew() {
        let mut track = ServerTrack::new(&[10], None, None);
        track.push_state(0, ServerState::Running);
        track.push_state(1, ServerState::Running);
        let open = |until| Span {
            since: 0,
            until,
            state: ServerState::Running,
        };
        assert_eq!(track.drain_spans(), vec![open(2)]);
        assert!(track.drain_spans().is_empty());

        track.push_state(1, ServerState::Running);
        assert_eq!(track.drain_spans(), Vec::new());

        track.push_state(2, ServerState::Running);
        assert_eq!(track.drain_spans(), vec![open(3)]);
    }
}
