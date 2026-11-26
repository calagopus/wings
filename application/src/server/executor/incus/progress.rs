//! Image pull progress: per-layer events for the panel, as docker sends them, and one status
//! line per stage in the console, as the `incus` command prints it.

use crate::models::{PullProgress, PullProgressStatus};
use crate::server::{Server, websocket};
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

/// How often one layer's progress, or one stage's console line, is sent on.
const INTERVAL: Duration = Duration::from_millis(500);

/// The progress of downloading or unpacking all layers together.
#[derive(Default)]
struct Stage {
    layers: HashMap<String, u64>,
    total: u64,
    /// Bytes that were already present, which say nothing about speed.
    skipped: u64,
    started: Option<Instant>,
    printed: Option<Instant>,
    finished: bool,
}

impl Stage {
    /// The console line to print now, if one is due.
    fn line(&mut self, now: Instant, label: &str, speed: bool) -> Option<String> {
        let started = *self.started.get_or_insert(now);
        let done: u64 = self.layers.values().sum();
        let complete = self.total > 0 && done >= self.total;
        if self.finished
            || (!complete
                && self
                    .printed
                    .is_some_and(|at| now.duration_since(at) < INTERVAL))
        {
            return None;
        }
        self.printed = Some(now);
        self.finished = complete;
        let percent = (done.min(self.total) * 100)
            .checked_div(self.total)
            .unwrap_or(0);
        let elapsed = now.duration_since(started).as_secs_f64();
        let transferred = done.saturating_sub(self.skipped);
        Some(if speed && elapsed > 0.0 && transferred > 0 {
            format!(
                "{label}: {percent}% ({:.2}MB/s)",
                transferred as f64 / elapsed / 1e6
            )
        } else {
            format!("{label}: {percent}%")
        })
    }
}

#[derive(Default)]
struct State {
    sent: HashMap<(String, bool), Instant>,
    download: Stage,
    unpack: Stage,
}

pub(super) struct Reporter<'a> {
    server: &'a Server,
    /// Quiet pulls send layer progress but write nothing to the console.
    quiet: bool,
    state: parking_lot::Mutex<State>,
}

impl<'a> Reporter<'a> {
    pub(super) fn new(server: &'a Server, quiet: bool) -> Self {
        Self {
            server,
            quiet,
            state: parking_lot::Mutex::new(State::default()),
        }
    }

    pub(super) fn line(&self, message: &str) {
        if !self.quiet {
            self.server.log_daemon_install(message.into());
        }
    }

    /// A message from Wings itself, marked as such in the console.
    pub(super) fn announce(&self, message: &str) {
        if !self.quiet {
            self.server.log_daemon_with_prelude(message);
        }
    }

    /// Sets how many bytes all layers together hold.
    pub(super) fn expect(&self, total: u64) {
        let mut state = self.state.lock();
        state.download.total = total;
        state.unpack.total = total;
    }

    /// Counts a layer that did not need downloading.
    pub(super) fn cached(&self, id: &str, size: u64) {
        let line = {
            let mut state = self.state.lock();
            state.download.layers.insert(id.into(), size);
            state.download.skipped += size;
            state
                .download
                .line(Instant::now(), "Retrieving image", true)
        };
        if let Some(line) = line {
            self.line(&line);
        }
        self.completed(id);
    }

    /// Reports how far a layer has been downloaded or unpacked.
    pub(super) fn layer(&self, id: &str, status: PullProgressStatus, current: u64, total: u64) {
        let extracting = matches!(status, PullProgressStatus::Extracting);
        let now = Instant::now();
        let (send, line) = {
            let mut state = self.state.lock();
            let key = (id.to_string(), extracting);
            let send = current >= total
                || state
                    .sent
                    .get(&key)
                    .is_none_or(|at| now.duration_since(*at) >= INTERVAL);
            if send {
                state.sent.insert(key, now);
            }
            let (stage, label) = if extracting {
                (&mut state.unpack, "Unpacking image")
            } else {
                (&mut state.download, "Retrieving image")
            };
            stage.layers.insert(id.into(), current);
            (send, stage.line(now, label, !extracting))
        };
        if send {
            self.server
                .websocket
                .send(
                    websocket::WebsocketMessage::builder(
                        websocket::WebsocketEvent::ServerImagePullProgress,
                    )
                    .arg(compact_str::CompactString::from(id))
                    .structured_arg(PullProgress {
                        status,
                        bytes_processed: current as i64,
                        bytes_total: total as i64,
                    })
                    .build(),
                )
                .ok();
        }
        if let Some(line) = line {
            self.line(&line);
        }
    }

    /// Marks a layer's current step as finished.
    pub(super) fn completed(&self, id: &str) {
        self.server
            .websocket
            .send(
                websocket::WebsocketMessage::builder(
                    websocket::WebsocketEvent::ServerImagePullCompleted,
                )
                .arg(compact_str::CompactString::from(id))
                .build(),
            )
            .ok();
    }
}

pub(super) struct Layer {
    pub id: String,
    pub hex: String,
    pub size: u64,
}

/// The layer a process is reading and how far into it, from its open files.
async fn reading(pid: u32, layers: &[Layer]) -> Option<(usize, u64)> {
    let mut descriptors = tokio::fs::read_dir(format!("/proc/{pid}/fd")).await.ok()?;
    let mut result = None;
    while let Ok(Some(entry)) = descriptors.next_entry().await {
        let Ok(target) = tokio::fs::read_link(entry.path()).await else {
            continue;
        };
        if !target
            .parent()
            .is_some_and(|dir| dir.ends_with("blobs/sha256"))
        {
            continue;
        }
        let Some(index) = target.file_name().and_then(|name| {
            layers
                .iter()
                .position(|layer| name == PathBuf::from(&layer.hex).as_os_str())
        }) else {
            continue;
        };
        let info = format!("/proc/{pid}/fdinfo/{}", entry.file_name().to_string_lossy());
        let position = tokio::fs::read_to_string(info).await.ok().and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("pos:"))?
                .trim()
                .parse()
                .ok()
        });
        if let Some(position) = position
            && result.is_none_or(|(found, _)| index > found)
        {
            result = Some((index, position));
        }
    }
    result
}

/// Tracks the unpacking of an image's layers, which happen in order.
pub(super) struct Extraction<'a> {
    reporter: &'a Reporter<'a>,
    layers: Vec<Layer>,
    done: usize,
}

impl<'a> Extraction<'a> {
    pub(super) fn new(reporter: &'a Reporter<'a>, layers: Vec<Layer>) -> Self {
        Self {
            reporter,
            layers,
            done: 0,
        }
    }

    fn complete_before(&mut self, index: usize) {
        while self.done < index {
            let Some(layer) = self.layers.get(self.done) else {
                break;
            };
            self.reporter.layer(
                &layer.id,
                PullProgressStatus::Extracting,
                layer.size,
                layer.size,
            );
            self.reporter.completed(&layer.id);
            self.done += 1;
        }
    }

    /// Follows the unpacking process until the caller stops polling.
    pub(super) async fn follow(&mut self, pid: u32) {
        loop {
            if let Some((index, position)) = reading(pid, &self.layers).await
                && index >= self.done
            {
                self.complete_before(index);
                if let Some(layer) = self.layers.get(index) {
                    self.reporter.layer(
                        &layer.id,
                        PullProgressStatus::Extracting,
                        position.min(layer.size),
                        layer.size,
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub(super) fn finish(&mut self) {
        self.complete_before(self.layers.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stage_prints_like_the_incus_client() {
        let mut stage = Stage {
            total: 4_000_000,
            ..Default::default()
        };
        let start = Instant::now();
        stage.layers.insert("a".into(), 0);
        assert_eq!(
            stage.line(start, "Retrieving image", true).as_deref(),
            Some("Retrieving image: 0%")
        );
        stage.layers.insert("a".into(), 2_000_000);
        assert_eq!(stage.line(start, "Retrieving image", true), None);
        assert_eq!(
            stage
                .line(start + Duration::from_secs(1), "Retrieving image", true)
                .as_deref(),
            Some("Retrieving image: 50% (2.00MB/s)")
        );
        // Completion is always printed, once.
        stage.layers.insert("b".into(), 2_000_000);
        let end = start + Duration::from_millis(1001);
        assert!(
            stage
                .line(end, "Unpacking image", false)
                .is_some_and(|line| line == "Unpacking image: 100%")
        );
        assert_eq!(stage.line(end, "Unpacking image", false), None);
    }
}
