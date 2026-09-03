use super::{ConcreteRule, RuleSource, runner::StreamingCommand};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
};
use tokio::io::AsyncBufReadExt;

pub const SET_PREFIX: &str = "wf-";
const ENTRY_BATCH_SIZE: usize = 256;
const RELOAD_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone)]
pub struct FirewallFileAccess {
    pub filesystem: crate::server::filesystem::cap::CapFilesystem,
    pub notifier: Option<crate::server::filesystem::inotify::InotifyServerNotifier>,
    pub server: Option<Weak<crate::server::InnerServer>>,
}

impl FirewallFileAccess {
    pub fn log(&self, message: &str) {
        if let Some(server) = self.server.as_ref().and_then(Weak::upgrade) {
            server.log_daemon(message.into());
        }
    }

    pub fn log_error(&self, message: &str) {
        if let Some(server) = self.server.as_ref().and_then(Weak::upgrade) {
            server.log_daemon_error(message);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SourceFileLimits {
    pub max_entries: usize,
    pub max_bytes: u64,
}

impl SourceFileLimits {
    pub fn from_config(config: &crate::config::Config) -> Self {
        let config = config.load();

        Self {
            max_entries: config.docker.firewall.source_file_max_entries as usize,
            max_bytes: config.docker.firewall.source_file_max_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
}

pub fn source_file_path(file: &str) -> PathBuf {
    crate::server::filesystem::cap::CapFilesystem::resolve_path(Path::new(
        file.trim_start_matches('/'),
    ))
}

pub fn set_base_name(server: uuid::Uuid, path: &Path) -> String {
    let mut server = server.simple().to_string();
    server.truncate(12);

    let hash = blake3::hash(path.as_os_str().as_encoded_bytes());
    let hash = hex::encode(&hash.as_bytes()[..4]);

    format!("{SET_PREFIX}{server}-{hash}")
}

pub fn referenced_files(spec: &super::FirewallServerSpec) -> BTreeMap<PathBuf, String> {
    let mut files = BTreeMap::new();

    for rule in &spec.rules {
        if let Some(file) = &rule.source_file {
            let path = source_file_path(file);
            let set = set_base_name(spec.server, &path);

            files.insert(path, set);
        }
    }

    files
}

pub fn needed_sets(servers: &BTreeMap<uuid::Uuid, Vec<ConcreteRule>>) -> BTreeSet<String> {
    servers
        .values()
        .flatten()
        .filter_map(|rule| match &rule.source {
            RuleSource::Set { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

async fn fingerprint(
    filesystem: &crate::server::filesystem::cap::CapFilesystem,
    path: &Path,
) -> Result<Option<Fingerprint>, std::io::Error> {
    use cap_std::fs::MetadataExt;

    let metadata = match filesystem.async_metadata(path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    if !metadata.is_file() {
        return Ok(None);
    }

    Ok(Some(Fingerprint {
        ino: metadata.ino(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        size: metadata.len(),
    }))
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LoadStats {
    pub entries: usize,
    pub invalid: usize,
}

#[derive(Debug)]
pub enum LoadError {
    TooLarge { max_bytes: u64 },
    TooManyEntries { max_entries: usize },
    Io(std::io::Error),
    Command(anyhow::Error),
    Cleared(Box<LoadError>),
}

impl LoadError {
    #[inline]
    pub fn cleared(err: Self) -> Self {
        Self::Cleared(Box::new(err))
    }

    #[inline]
    fn keeps_entries(&self) -> bool {
        !matches!(self, Self::Cleared(_))
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => {
                write!(f, "file is larger than {max_bytes} bytes")
            }
            Self::TooManyEntries { max_entries } => {
                write!(f, "file has more than {max_entries} entries")
            }
            Self::Io(err) => write!(f, "{err}"),
            Self::Command(err) => write!(f, "{err:#}"),
            Self::Cleared(err) => err.fmt(f),
        }
    }
}

impl From<std::io::Error> for LoadError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

fn parse_line(line: &str) -> Option<Result<cidr::IpCidr, ()>> {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return None;
    }

    Some(
        line.parse::<cidr::IpInet>()
            .map(|inet| inet.network())
            .map_err(|_| ()),
    )
}

pub async fn stream_source_file(
    filesystem: &crate::server::filesystem::cap::CapFilesystem,
    path: &Path,
    limits: SourceFileLimits,
    command: &mut StreamingCommand,
    write_batch: impl Fn(&mut Vec<u8>, &[cidr::IpCidr]),
) -> Result<LoadStats, LoadError> {
    let file = filesystem.async_open(path).await?;
    let mut lines = tokio::io::BufReader::new(file).lines();

    let mut stats = LoadStats::default();
    let mut bytes: u64 = 0;
    let mut batch = Vec::with_capacity(ENTRY_BATCH_SIZE);
    let mut rendered = Vec::new();

    while let Some(line) = lines.next_line().await? {
        bytes += line.len() as u64 + 1;
        if bytes > limits.max_bytes {
            return Err(LoadError::TooLarge {
                max_bytes: limits.max_bytes,
            });
        }

        match parse_line(&line) {
            None => continue,
            Some(Err(())) => {
                stats.invalid += 1;
                continue;
            }
            Some(Ok(entry)) => {
                stats.entries += 1;
                if stats.entries > limits.max_entries {
                    return Err(LoadError::TooManyEntries {
                        max_entries: limits.max_entries,
                    });
                }

                batch.push(entry);
            }
        }

        if batch.len() >= ENTRY_BATCH_SIZE {
            rendered.clear();
            write_batch(&mut rendered, &batch);
            command.write(&rendered).await.map_err(LoadError::Command)?;
            batch.clear();
        }
    }

    if !batch.is_empty() {
        rendered.clear();
        write_batch(&mut rendered, &batch);
        command.write(&rendered).await.map_err(LoadError::Command)?;
    }

    Ok(stats)
}

pub struct SourceFileState {
    set: String,
    fingerprint: Option<Fingerprint>,
    missing_reported: bool,
}

pub struct PendingLoad {
    pub path: PathBuf,
    pub set: String,
    fingerprint: Fingerprint,
}

pub struct ServerSourceFiles {
    pub access: FirewallFileAccess,
    files: BTreeMap<PathBuf, SourceFileState>,
    changed: Arc<tokio::sync::Notify>,
    watch_task: Option<tokio::task::AbortHandle>,
}

impl ServerSourceFiles {
    pub fn new(access: FirewallFileAccess) -> Self {
        Self {
            access,
            files: BTreeMap::new(),
            changed: Arc::new(tokio::sync::Notify::new()),
            watch_task: None,
        }
    }

    pub fn update(&mut self, wanted: BTreeMap<PathBuf, String>) {
        self.files.retain(|path, _| wanted.contains_key(path));

        for (path, set) in wanted {
            self.files.entry(path).or_insert(SourceFileState {
                set,
                fingerprint: None,
                missing_reported: false,
            });
        }

        if let Some(notifier) = &self.access.notifier {
            let paths: Vec<PathBuf> = self
                .files
                .keys()
                .map(|path| self.access.filesystem.base_path.join(path))
                .collect();

            notifier.watch_firewall_files(paths, Arc::clone(&self.changed));
        }
    }

    pub fn ensure_watching(
        &mut self,
        reload: impl Fn() -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    ) {
        if self
            .watch_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return;
        }

        let changed = Arc::clone(&self.changed);
        self.watch_task = Some(
            tokio::spawn(async move {
                loop {
                    changed.notified().await;
                    tokio::time::sleep(RELOAD_DEBOUNCE).await;
                    reload().await;
                }
            })
            .abort_handle(),
        );
    }

    pub fn stop(&mut self) {
        if let Some(task) = self.watch_task.take() {
            task.abort();
        }
        if let Some(notifier) = &self.access.notifier {
            notifier.watch_firewall_files(Vec::new(), Arc::clone(&self.changed));
        }
    }

    pub async fn pending(&mut self, force: bool) -> Vec<PendingLoad> {
        let mut pending = Vec::new();

        for (path, state) in &mut self.files {
            let fingerprint = match fingerprint(&self.access.filesystem, path).await {
                Ok(Some(fingerprint)) => fingerprint,
                Ok(None) => {
                    if !state.missing_reported {
                        state.missing_reported = true;
                        self.access.log_error(&format!(
                            "Firewall source file {} does not exist, the rules referencing it keep their previous entries.",
                            path.display()
                        ));
                    }
                    state.fingerprint = None;

                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        "failed to stat firewall source file: {err}"
                    );

                    continue;
                }
            };
            state.missing_reported = false;

            if !force && state.fingerprint == Some(fingerprint) {
                continue;
            }

            pending.push(PendingLoad {
                path: path.clone(),
                set: state.set.clone(),
                fingerprint,
            });
        }

        pending
    }

    pub fn record(&mut self, pending: PendingLoad, result: Result<LoadStats, LoadError>) {
        let Some(state) = self.files.get_mut(&pending.path) else {
            return;
        };
        state.fingerprint = match &result {
            Err(err) if !err.keeps_entries() => None,
            _ => Some(pending.fingerprint),
        };

        match result {
            Ok(stats) => {
                let mut message = format!(
                    "Firewall source file {} loaded with {} entries",
                    pending.path.display(),
                    stats.entries
                );
                if stats.invalid > 0 {
                    message.push_str(&format!(", {} invalid lines skipped", stats.invalid));
                }
                message.push('.');

                if stats.entries == 0 || stats.invalid > 0 {
                    self.access.log_error(&message);
                } else {
                    self.access.log(&message);
                }
            }
            Err(err) if err.keeps_entries() => {
                self.access.log_error(&format!(
                    "Firewall source file {} could not be loaded, the rules referencing it keep their previous entries: {err}",
                    pending.path.display()
                ));
            }
            Err(err) => {
                self.access.log_error(&format!(
                    "Firewall source file {} could not be loaded after being emptied, the rules referencing it match nothing until it loads: {err}",
                    pending.path.display()
                ));
            }
        }
    }
}

impl Drop for ServerSourceFiles {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_accepts_addresses_networks_and_comments() {
        assert_eq!(
            parse_line("10.0.0.1"),
            Some(Ok("10.0.0.1/32".parse().unwrap()))
        );
        assert_eq!(
            parse_line("  10.0.0.0/8  # office"),
            Some(Ok("10.0.0.0/8".parse().unwrap()))
        );
        assert_eq!(
            parse_line("10.1.2.3/8"),
            Some(Ok("10.0.0.0/8".parse().unwrap()))
        );
        assert_eq!(
            parse_line("2001:db8::1"),
            Some(Ok("2001:db8::1/128".parse().unwrap()))
        );
        assert_eq!(parse_line("# comment"), None);
        assert_eq!(parse_line("   "), None);
        assert_eq!(parse_line("example.com"), Some(Err(())));
    }

    #[test]
    fn set_base_name_fits_ipset_limits_with_a_family_suffix() {
        let name = set_base_name(uuid::Uuid::new_v4(), Path::new("lists/allow.txt"));

        assert_eq!(name.len(), 3 + 12 + 1 + 8);
        assert!(name.starts_with(SET_PREFIX));
        assert!(format!("{name}-4").len() <= 31);
    }

    #[test]
    fn source_file_path_normalizes_like_the_sandbox() {
        assert_eq!(
            source_file_path("/lists/../allow.txt"),
            PathBuf::from("allow.txt")
        );
        assert_eq!(
            source_file_path("./lists/allow.txt"),
            PathBuf::from("lists/allow.txt")
        );
    }
}
