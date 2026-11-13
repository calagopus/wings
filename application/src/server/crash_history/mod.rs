use compact_str::CompactString;
use futures::StreamExt;
use serde::Serialize;
use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    sync::Arc,
};
use storage::{Retention, Storage, StoredCrash};
use utoipa::ToSchema;

mod storage;

pub const MAX_RECORD_SIZE: u64 = 16 * 1024 * 1024;

const PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

#[derive(ToSchema, Serialize)]
pub struct Crash {
    pub id: i64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub exit_code: i32,
    pub oom_killed: bool,

    pub lines: u64,
    pub bytes: u64,
    pub truncated: bool,
}

impl From<StoredCrash> for Crash {
    fn from(crash: StoredCrash) -> Self {
        Self {
            id: crash.at,
            timestamp: chrono::DateTime::from_timestamp_millis(crash.at).unwrap_or_default(),
            exit_code: crash.exit_code,
            oom_killed: crash.oom_killed,
            lines: crash.lines,
            bytes: crash.bytes,
            truncated: crash.truncated,
        }
    }
}

struct Tail {
    lines: VecDeque<CompactString>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    truncated: bool,
}

impl Tail {
    fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            bytes: 0,
            max_lines,
            max_bytes,
            truncated: false,
        }
    }

    fn pop(&mut self) {
        if let Some(line) = self.lines.pop_front() {
            self.bytes -= line.len() + 1;
        }
    }

    fn push(&mut self, line: CompactString) {
        if self.max_lines == 0 {
            return;
        }

        self.bytes += line.len() + 1;
        self.lines.push_back(line);

        while self.lines.len() > self.max_lines {
            self.pop();
        }
        while self.bytes > self.max_bytes && self.lines.len() > 1 {
            self.pop();
            self.truncated = true;
        }
    }

    fn into_text(self) -> Vec<u8> {
        let mut text = Vec::with_capacity(self.bytes);
        for line in &self.lines {
            text.extend_from_slice(line.as_bytes());
            text.push(b'\n');
        }

        text
    }
}

pub struct CrashHistory {
    config: Arc<crate::config::Config>,
    db_path: PathBuf,
    storage: Arc<parking_lot::Mutex<Option<Storage>>>,
}

impl CrashHistory {
    pub fn new(config: &Arc<crate::config::Config>) -> Self {
        Self {
            db_path: config
                .resolve_as_path(|cfg| &cfg.system.root_directory)
                .join("crash_history.db"),
            config: Arc::clone(config),
            storage: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    fn retention(&self) -> Retention {
        let config = self.config.load();
        let config = &config.system.crash_history;

        Retention {
            max_records: config.max_records,
            max_age: config.max_age,
            disk_budget: config.per_server_disk_budget,
        }
    }

    async fn with_storage<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Storage) -> Result<T, anyhow::Error> + Send + 'static,
    ) -> Result<T, anyhow::Error> {
        let db_path = self.db_path.clone();
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || {
            let mut guard = storage.lock();
            let storage = match guard.as_mut() {
                Some(storage) => storage,
                None => guard.insert(Storage::open(&db_path)?),
            };

            f(storage)
        })
        .await?
    }

    pub async fn capture(
        &self,
        server: &crate::server::Server,
        exit_code: i32,
        oom_killed: bool,
    ) -> Option<i64> {
        let (lines, record_size_cap, zstd_level, capture_timeout) = {
            let config = self.config.load();
            let config = &config.system.crash_history;
            if !config.enabled {
                return None;
            }

            (
                config.lines,
                config.record_size_cap.min(MAX_RECORD_SIZE) as usize,
                config.zstd_level,
                std::time::Duration::from_secs(config.capture_timeout),
            )
        };

        let at = chrono::Utc::now().timestamp_millis();
        let mut tail = Tail::new(lines, record_size_cap);

        if lines != 0 {
            let read = tokio::time::timeout(capture_timeout, async {
                let mut stream = server.logs_lines(Some(lines)).await;
                while let Some(line) = stream.next().await {
                    tail.push(line?);
                }

                Ok::<_, anyhow::Error>(())
            })
            .await;

            match read {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::warn!(server = %server.uuid, "failed to read console output of crash: {err:#}");
                }
                Err(_) => {
                    tracing::warn!(server = %server.uuid, "timed out reading console output of crash");
                }
            }
        }

        let crash = StoredCrash {
            at,
            exit_code,
            oom_killed,
            lines: tail.lines.len() as u64,
            bytes: tail.bytes as u64,
            truncated: tail.truncated,
        };
        let text = tail.into_text();
        let uuid = server.uuid;
        let retention = self.retention();

        let stored = self
            .with_storage(move |storage| {
                let log = zstd::bulk::compress(&text, zstd_level)?;
                storage.insert(uuid, &crash, &log, retention)
            })
            .await;

        match stored {
            Ok(id) => Some(id),
            Err(err) => {
                tracing::error!(server = %server.uuid, "failed to store crash: {err:#}");
                None
            }
        }
    }

    pub async fn list(&self, server: uuid::Uuid) -> Result<Vec<Crash>, anyhow::Error> {
        let crashes = self
            .with_storage(move |storage| storage.list(server))
            .await?;

        Ok(crashes.into_iter().map(Crash::from).collect())
    }

    pub async fn log(&self, server: uuid::Uuid, id: i64) -> Result<Option<Vec<u8>>, anyhow::Error> {
        self.with_storage(move |storage| {
            let Some((log, bytes)) = storage.log(server, id)? else {
                return Ok(None);
            };

            Ok(Some(zstd::bulk::decompress(
                &log,
                bytes.min(MAX_RECORD_SIZE) as usize,
            )?))
        })
        .await
    }

    pub async fn delete(&self, server: uuid::Uuid, id: i64) -> Result<bool, anyhow::Error> {
        self.with_storage(move |storage| storage.delete(server, id))
            .await
    }

    pub async fn delete_server(&self, server: uuid::Uuid) {
        if let Err(err) = self
            .with_storage(move |storage| storage.delete_server(server))
            .await
        {
            tracing::warn!(server = %server, "failed to delete crash history: {err:#}");
        }
    }

    pub async fn run(self: Arc<Self>, server_manager: Arc<crate::server::manager::ServerManager>) {
        loop {
            tokio::time::sleep(PRUNE_INTERVAL).await;

            if !server_manager.booted() || !self.config.load().system.crash_history.enabled {
                continue;
            }

            let known: HashSet<uuid::Uuid> = server_manager
                .get_servers()
                .await
                .iter()
                .map(|s| s.uuid)
                .collect();
            let now = chrono::Utc::now().timestamp_millis();
            let retention = self.retention();

            if let Err(err) = self
                .with_storage(move |storage| storage.prune(Some(&known), now, retention))
                .await
            {
                tracing::warn!("failed to prune crash history: {err:#}");
            }
        }
    }

    pub async fn export(
        &self,
        server: uuid::Uuid,
    ) -> Result<Option<tokio::fs::File>, anyhow::Error> {
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
            .await?;
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
        let now = chrono::Utc::now().timestamp_millis();
        let retention = self.retention();

        let result = self
            .with_storage({
                let path = path.clone();
                move |storage| storage.import(server, &path, now, retention)
            })
            .await;
        tokio::fs::remove_file(&path).await.ok();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tail(max_lines: usize, max_bytes: usize, lines: &[&str]) -> Tail {
        let mut tail = Tail::new(max_lines, max_bytes);
        for line in lines {
            tail.push(CompactString::from(*line));
        }
        tail
    }

    fn kept(tail: &Tail) -> Vec<&str> {
        tail.lines.iter().map(|l| l.as_str()).collect()
    }

    // Tail
    #[test]
    fn line_limit_keeps_newest_in_order_without_truncating() {
        let tail = tail(3, 1000, &["a", "bb", "ccc", "dddd", "eeeee"]);

        assert_eq!(kept(&tail), ["ccc", "dddd", "eeeee"]);
        assert!(!tail.truncated);
        assert_eq!(tail.bytes, 4 + 5 + 6);
    }

    #[test]
    fn byte_limit_drops_oldest_and_truncates() {
        let tail = tail(100, 10, &["aaaa", "bbbb", "cccc"]);

        assert_eq!(kept(&tail), ["bbbb", "cccc"]);
        assert!(tail.truncated);
        assert_eq!(tail.bytes, 10);
    }

    #[test]
    fn oversized_newest_line_is_kept_alone() {
        let tail = tail(10, 4, &["ab", "0123456789"]);

        assert_eq!(kept(&tail), ["0123456789"]);
        assert!(tail.truncated);
        assert_eq!(tail.bytes, 11);
    }

    #[test]
    fn zero_max_lines_keeps_nothing() {
        let tail = tail(0, 100, &["a", "b"]);

        assert!(tail.lines.is_empty());
        assert_eq!(tail.bytes, 0);
        assert!(tail.into_text().is_empty());
    }

    #[test]
    fn mixed_limits_keep_bytes_consistent_with_text() {
        let lines: Vec<String> = (0..50).map(|i| "x".repeat(i % 7)).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let tail = tail(8, 20, &refs);

        let expected: String = tail.lines.iter().map(|l| format!("{l}\n")).collect();
        assert!(tail.lines.len() <= 8);
        assert!(tail.bytes <= 20);
        assert_eq!(tail.lines.back().map(|l| l.as_str()), Some(refs[49]));
        let bytes = tail.bytes;
        let text = tail.into_text();
        assert_eq!(text.len(), bytes);
        assert_eq!(text, expected.into_bytes());
    }
}
