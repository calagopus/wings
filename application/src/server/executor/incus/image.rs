use super::client::{Client, segment};
use super::progress::{Extraction, Layer, Reporter};
use super::registry::{self, Descriptor, Manifest, Registry};
use crate::models::PullProgressStatus;
use anyhow::{Context, ensure};
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::{Mutex, RwLock, Semaphore},
};

const HEARTBEAT: Duration = Duration::from_secs(15);

async fn tail(mut stream: impl AsyncRead + Unpin, keep_tail: bool) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        output.extend_from_slice(buffer.get(..count).unwrap_or_default());
        if output.len() > 65536 {
            if !keep_tail {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "subprocess stdout exceeded 64 KiB",
                ));
            }
            output.drain(..output.len() - 65536);
        }
    }
    Ok(output)
}

/// Reads the output of a subprocess, forwarding it to the console when `reporter` is given.
async fn read_stdout(
    mut stream: impl AsyncRead + Unpin,
    reporter: Option<&Reporter<'_>>,
) -> std::io::Result<Vec<u8>> {
    let Some(reporter) = reporter else {
        return tail(stream, false).await;
    };
    let mut line = Vec::new();
    let mut previous = String::new();
    let mut last = tokio::time::Instant::now() - Duration::from_secs(1);
    let mut buffer = [0; 8192];
    let started = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.tick().await;
    loop {
        let count = tokio::select! {
            count = stream.read(&mut buffer) => count?,
            _ = heartbeat.tick() => {
                if last.elapsed() >= HEARTBEAT {
                    reporter.line(&format!(
                        "Still preparing the image ({} seconds elapsed)...",
                        started.elapsed().as_secs()
                    ));
                }
                continue;
            }
        };
        for &byte in buffer.get(..count).unwrap_or_default() {
            if byte == b'\r' || byte == b'\n' {
                let message = String::from_utf8_lossy(&line).trim().to_string();
                if !message.is_empty()
                    && message != previous
                    && last.elapsed() >= Duration::from_secs(1)
                {
                    tracing::debug!("image conversion: {message}");
                    previous = message;
                    last = tokio::time::Instant::now();
                }
                line.clear();
            } else if !byte.is_ascii_control() && line.len() < 4096 {
                line.push(byte);
            }
        }
        if count == 0 {
            return Ok(Vec::new());
        }
    }
}

pub(super) async fn run(
    executable: &str,
    args: &[String],
    timeout: Duration,
    env: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<Vec<u8>> {
    run_with_progress(executable, args, timeout, env, None, None).await
}

struct ProcessGroup(Option<rustix::process::Pid>);

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
}

async fn run_with_progress(
    executable: &str,
    args: &[String],
    timeout: Duration,
    env: Option<&BTreeMap<String, String>>,
    reporter: Option<&Reporter<'_>>,
    spawned: Option<tokio::sync::oneshot::Sender<u32>>,
) -> anyhow::Result<Vec<u8>> {
    let mut command = tokio::process::Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if let Some(env) = env {
        command.envs(env);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {executable}"))?;
    let mut group = ProcessGroup(
        child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32)),
    );
    if let (Some(spawned), Some(pid)) = (spawned, child.id()) {
        let _ = spawned.send(pid);
    }
    let stdout = child.stdout.take().context("subprocess stdout missing")?;
    let stderr = child.stderr.take().context("subprocess stderr missing")?;
    let result = tokio::time::timeout(timeout, async {
        tokio::try_join!(
            child.wait(),
            read_stdout(stdout, reporter),
            tail(stderr, true)
        )
    })
    .await;
    let Ok(result) = result else {
        let _ = child.kill().await;
        anyhow::bail!("{executable} timed out");
    };
    let (status, stdout, stderr) = result?;
    ensure!(
        status.success(),
        "{executable} failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    group.0 = None;
    Ok(stdout)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Image {
    pub fingerprint: String,
    pub digest: String,
    /// The image's entrypoint followed by its default arguments.
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub workdir: Option<String>,
}

#[derive(Deserialize)]
struct ImageConfig {
    #[serde(default, rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    environment: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    workdir: Option<String>,
}

/// Which cached image a reference resolved to, and when its registry was last asked.
#[derive(Deserialize, Serialize)]
struct Resolved {
    key: String,
    checked: u64,
}

/// A fingerprint as the `incus` command abbreviates it.
fn short(fingerprint: &str) -> &str {
    fingerprint.get(..12).unwrap_or(fingerprint)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) struct Images {
    config: Arc<crate::config::Config>,
    client: Client,
    concurrency: Semaphore,
    locks: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    cache_gate: RwLock<()>,
}

impl Images {
    pub(super) fn new(config: Arc<crate::config::Config>, client: Client) -> Self {
        let concurrency = Semaphore::new(config.load().runtime.incus.max_concurrent_imports);
        Self {
            config,
            client,
            concurrency,
            locks: Mutex::new(HashMap::new()),
            cache_gate: RwLock::new(()),
        }
    }

    fn root(&self) -> PathBuf {
        self.config
            .resolve_as_path(|cfg| &cfg.system.root_directory)
            .join("incus-images")
    }

    pub(super) async fn boot(self: &Arc<Self>) -> anyhow::Result<()> {
        let cfg = self.config.load().runtime.incus.clone();
        super::auth::executable(&cfg.skopeo_path)?;
        run(
            &cfg.incus_path,
            &["--version".into()],
            Duration::from_secs(10),
            None,
        )
        .await?;
        tokio::fs::create_dir_all(self.root().join("refs")).await?;
        tokio::fs::create_dir_all(self.root().join("blobs")).await?;
        // Nothing is importing yet, so anything temporary is left over from a crash, possibly
        // including registry credentials.
        if let Err(error) = self.remove_leftovers().await {
            tracing::warn!("could not remove leftover Incus import files: {error:#}");
        }
        if let Err(error) = self.cleanup().await {
            tracing::warn!("Incus image cleanup skipped: {error:#}");
        }
        let images = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let Some(images) = images.upgrade() else {
                    break;
                };
                if let Err(error) = images.cleanup().await {
                    tracing::warn!("Incus image cleanup skipped: {error:#}");
                }
            }
        });
        Ok(())
    }

    async fn remove_leftovers(&self) -> anyhow::Result<()> {
        let mut entries = tokio::fs::read_dir(self.root()).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if entry.file_type().await?.is_dir() && name.starts_with(".tmp") {
                tokio::fs::remove_dir_all(entry.path()).await?;
            } else if name.ends_with(".tmp") {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
        for directory in ["blobs", "refs"] {
            let mut entries = tokio::fs::read_dir(self.root().join(directory)).await?;
            while let Some(entry) = entries.next_entry().await? {
                if entry.file_name().to_string_lossy().ends_with(".tmp") {
                    tokio::fs::remove_file(entry.path()).await?;
                }
            }
        }
        Ok(())
    }

    /// Removes downloaded layers that no pull has used within the retention period.
    async fn remove_old_blobs(&self, retention: Duration) -> anyhow::Result<()> {
        let mut entries = tokio::fs::read_dir(self.root().join("blobs")).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() && metadata.modified()?.elapsed().unwrap_or_default() >= retention
            {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
        Ok(())
    }

    fn reference_path(&self, reference: &str) -> PathBuf {
        self.root().join("refs").join(format!(
            "{}.json",
            hex::encode(Sha256::digest(reference.as_bytes()))
        ))
    }

    /// The local copy a reference last resolved to, if Incus still has it.
    async fn local(&self, reference: &str) -> Option<(Resolved, Image)> {
        let resolved: Resolved =
            serde_json::from_slice(&tokio::fs::read(self.reference_path(reference)).await.ok()?)
                .ok()?;
        let image = self.cached(&resolved.key).await?;
        Some((resolved, image))
    }

    async fn cached(&self, key: &str) -> Option<Image> {
        let path = self.root().join(format!("{key}.json"));
        let image: Image = serde_json::from_slice(&tokio::fs::read(&path).await.ok()?).ok()?;
        // Records without a working directory predate the settings instances now need.
        image.workdir.as_ref()?;
        self.client
            .optional::<Value>(&format!("/1.0/images/{}", segment(&image.fingerprint)))
            .await
            .ok()??;
        // Rewriting records the last use, which cleanup measures retention from.
        Self::save(&path, &image).await.ok()?;
        Some(image)
    }

    /// Returns an Incus image for an OCI reference, with the pull behaviour of the docker runtime:
    /// a `~` suffix never contacts the registry, `registry_image_fetch_cache` limits how often it
    /// is asked, and a local copy is used when it cannot be reached.
    pub(super) async fn ensure(
        self: &Arc<Self>,
        source: &str,
        server: &crate::server::Server,
        quiet: bool,
    ) -> anyhow::Result<Image> {
        let reference = source.trim_end_matches('~').to_string();
        if source.ends_with('~') {
            return self
                .local(&reference)
                .await
                .map(|(_, image)| image)
                .with_context(|| {
                    format!(
                        "image {reference} ends with ~ so it is never pulled, and this node has no local copy of it"
                    )
                });
        }

        let fetch = self.config.load().docker.registry_image_fetch_cache;
        if let Some((resolved, image)) = self.local(&reference).await {
            let fresh = fetch.enabled && now().saturating_sub(resolved.checked) < fetch.duration;
            if fresh {
                return Ok(image);
            }
            if fetch.background_refresh {
                let images = Arc::clone(self);
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(error) = images.pull(&reference, &server, true).await {
                        tracing::debug!("background image refresh failed: {error:#}");
                    }
                });
                return Ok(image);
            }
        }

        match self.pull(&reference, server, quiet).await {
            Ok(image) => Ok(image),
            Err(error) => {
                tracing::error!(server = %server.uuid, image = %reference, "failed to pull image: {error:#}");
                server.log_daemon_error(&format!("failed to pull image: {error:#}"));
                let Some((_, image)) = self.local(&reference).await else {
                    return Err(error);
                };
                tracing::warn!(
                    server = %server.uuid,
                    image = %reference,
                    "image already exists locally, ignoring pull error"
                );
                Ok(image)
            }
        }
    }

    async fn pull(
        &self,
        reference: &str,
        server: &crate::server::Server,
        quiet: bool,
    ) -> anyhow::Result<Image> {
        let reporter = Reporter::new(server, quiet);
        let _cache_guard = self.cache_gate.read().await;
        reporter.announce(&format!("Retrieving image {reference}"));
        let cfg = self.config.load().runtime.incus.clone();
        let lock = self.lock(format!("pull:{reference}")).await;
        let _guard = lock.lock().await;
        let _permit = self.concurrency.acquire().await?;
        let timeout = Duration::from_secs(cfg.image_import_timeout_seconds);
        let (host, repository) = parse_reference(reference)?;
        let (name, wanted) = registry::split_repository(&repository);
        let credentials =
            crate::server::executor::docker::registry_credentials(&self.config.load(), reference)
                .and_then(|credentials| Some((credentials.username?, credentials.password?)));
        let source = Registry::new(&host, name, credentials.clone())?;
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "powerpc64" => "ppc64le",
            other => other,
        };
        let manifest = tokio::time::timeout(timeout, source.manifest(wanted, architecture))
            .await
            .context("the registry did not answer in time")??;
        let cache_key = hex::encode(Sha256::digest(
            format!("{host}/{name}@{}:{architecture}", manifest.digest).as_bytes(),
        ));
        let artifact_lock = self.lock(format!("import:{cache_key}")).await;
        let _artifact_guard = artifact_lock.lock().await;
        if let Some(image) = self.cached(&cache_key).await {
            self.remember(reference, &cache_key).await?;
            reporter.line(&format!(
                "Image is up to date with fingerprint: {}",
                short(&image.fingerprint)
            ));
            reporter.announce("Instance image is ready");
            return Ok(image);
        }

        let config = self.fetch(&source, &manifest.config, None).await?;
        let process: ImageConfig = serde_json::from_value(
            serde_json::from_slice::<Value>(&tokio::fs::read(&config).await?)
                .context("decoding OCI image configuration")?
                .get("config")
                .cloned()
                .context("OCI image config missing")?,
        )?;
        let environment = process
            .environment
            .unwrap_or_default()
            .iter()
            .map(|entry| {
                let (key, value) = entry
                    .split_once('=')
                    .context("invalid OCI environment entry")?;
                Ok((key.to_owned(), value.to_owned()))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let mut args = process.entrypoint.unwrap_or_default();
        args.extend(process.cmd.unwrap_or_default());
        ensure!(!args.is_empty(), "OCI image has no entrypoint or command");
        let alias = format!("wings-{}", cache_key.get(..58).context("image cache key")?);
        let alias_path = format!("/1.0/images/aliases/{}", segment(&alias));

        // An alias without a cache record is left over from an interrupted import.
        let imported = match self.client.optional::<Value>(&alias_path).await? {
            Some(entry) => entry,
            None => {
                let directory = tempfile::tempdir_in(self.root())?;
                let layers = tokio::time::timeout(
                    timeout,
                    self.download(&source, &manifest, config, directory.path(), &reporter),
                )
                .await
                .context("downloading the image timed out")??;
                let pull = super::auth::PullEnvironment::new(
                    &self.root(),
                    &cfg,
                    credentials,
                    &host,
                    &directory.path().join("layout"),
                )
                .await?;
                let archive = directory.path().join("image.tar.gz");
                let mut extraction = Extraction::new(&reporter, layers);
                let (spawned, pid) = tokio::sync::oneshot::channel();
                let export_args = [
                    "image".into(),
                    "export".into(),
                    format!("oci:{name}@{}", manifest.digest),
                    archive.display().to_string(),
                ];
                let export = run_with_progress(
                    &pull.incus,
                    &export_args,
                    timeout,
                    Some(&pull.environment),
                    Some(&reporter),
                    Some(spawned),
                );
                tokio::select! {
                    result = export => {
                        result?;
                    }
                    () = async {
                        match pid.await {
                            Ok(pid) => extraction.follow(pid).await,
                            Err(_) => std::future::pending().await,
                        }
                    } => {}
                }
                extraction.finish();
                run_with_progress(
                    &pull.incus,
                    &[
                        "image".into(),
                        "import".into(),
                        archive.display().to_string(),
                        format!("{}.root", archive.display()),
                        "local:".into(),
                        "--alias".into(),
                        alias.clone(),
                        "--project".into(),
                        cfg.project.clone(),
                    ],
                    timeout,
                    Some(&pull.environment),
                    Some(&reporter),
                    None,
                )
                .await?;
                self.client.get(&alias_path).await?
            }
        };
        let fingerprint = imported
            .get("target")
            .and_then(Value::as_str)
            .context("Incus import did not create image alias")?
            .to_owned();
        let image = Image {
            fingerprint,
            digest: manifest.digest.clone(),
            args,
            environment,
            workdir: Some(
                process
                    .workdir
                    .filter(|dir| !dir.is_empty())
                    .unwrap_or_else(|| "/".into()),
            ),
        };
        if let Err(error) = self.mark(&image.fingerprint, &cache_key).await {
            // An unmarked image would never be cleaned up, so take it out again.
            let path = format!("/1.0/images/{}", segment(&image.fingerprint));
            if let Err(cleanup) = self
                .client
                .request(reqwest::Method::DELETE, &path, None, None, true)
                .await
            {
                tracing::warn!("could not remove a partially imported image: {cleanup:#}");
            }
            return Err(error);
        }
        Self::save(&self.root().join(format!("{cache_key}.json")), &image).await?;
        self.remember(reference, &cache_key).await?;
        reporter.line(&format!(
            "Image imported with fingerprint: {}",
            short(&image.fingerprint)
        ));
        reporter.announce("Instance image is ready");
        Ok(image)
    }

    /// Returns the path of a blob in the layer cache, downloading it if it is not there.
    async fn fetch(
        &self,
        source: &Registry,
        blob: &Descriptor,
        reporter: Option<&Reporter<'_>>,
    ) -> anyhow::Result<PathBuf> {
        let hex = blob.hex()?;
        let id = hex.get(..12).context("short digest")?;
        let lock = self.lock(format!("blob:{hex}")).await;
        let _guard = lock.lock().await;
        let path = self.root().join("blobs").join(hex);
        if tokio::fs::metadata(&path)
            .await
            .is_ok_and(|metadata| metadata.len() == blob.size)
        {
            // The modification time records the last use, for cleanup.
            std::fs::File::options()
                .append(true)
                .open(&path)?
                .set_modified(std::time::SystemTime::now())?;
            if let Some(reporter) = reporter {
                reporter.cached(id, blob.size);
            }
            return Ok(path);
        }
        source
            .download(blob, &path, |received| {
                if let Some(reporter) = reporter {
                    reporter.layer(id, PullProgressStatus::Pulling, received, blob.size);
                }
            })
            .await?;
        if let Some(reporter) = reporter {
            reporter.completed(id);
        }
        Ok(path)
    }

    async fn fetch_layer(
        &self,
        source: &Registry,
        index: usize,
        layer: Descriptor,
        reporter: &Reporter<'_>,
    ) -> anyhow::Result<(usize, PathBuf)> {
        Ok((index, self.fetch(source, &layer, Some(reporter)).await?))
    }

    /// Downloads the layers and lays them out for skopeo to read. Returns them in order.
    async fn download(
        &self,
        source: &Registry,
        manifest: &Manifest,
        config: PathBuf,
        directory: &Path,
        reporter: &Reporter<'_>,
    ) -> anyhow::Result<Vec<Layer>> {
        let layout = directory.join("layout");
        tokio::fs::create_dir(&layout).await?;
        tokio::fs::write(layout.join("version"), "Directory Transport Version: 1.1\n").await?;
        tokio::fs::write(layout.join("manifest.json"), &manifest.bytes).await?;
        tokio::fs::hard_link(&config, layout.join(manifest.config.hex()?)).await?;

        let mut seen = std::collections::HashSet::new();
        let layers: Vec<&Descriptor> = manifest
            .layers
            .iter()
            .filter(|layer| seen.insert(layer.digest.as_str()))
            .collect();
        reporter.expect(layers.iter().map(|layer| layer.size).sum());
        // As many layers at once as docker downloads by default.
        let downloads: Vec<_> = layers
            .iter()
            .enumerate()
            .map(|(index, layer)| {
                self.fetch_layer(source, index, Descriptor::clone(layer), reporter)
            })
            .collect();
        let paths: Vec<(usize, PathBuf)> = futures::stream::iter(downloads)
            .buffer_unordered(3)
            .try_collect()
            .await?;
        for (index, path) in paths {
            let layer = layers.get(index).context("layer index")?;
            tokio::fs::hard_link(path, layout.join(layer.hex()?)).await?;
        }
        layers
            .iter()
            .map(|layer| {
                let hex = layer.hex()?;
                Ok(Layer {
                    id: hex.get(..12).context("short digest")?.into(),
                    hex: hex.into(),
                    size: layer.size,
                })
            })
            .collect()
    }

    /// Records ownership of an imported image, and that it holds an OCI application.
    async fn mark(&self, fingerprint: &str, cache_key: &str) -> anyhow::Result<()> {
        let path = format!("/1.0/images/{}", segment(fingerprint));
        let (mut metadata, etag) = self
            .client
            .request(reqwest::Method::GET, &path, None, None, true)
            .await?;
        let properties = metadata
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .context("Incus image properties missing")?;
        let owner = format!("wings:{}", self.config.load().uuid);
        // An identical image an administrator imported stays theirs.
        if properties.contains_key("user.wings.cache") || properties.is_empty() {
            properties.insert("user.wings.owner".into(), json!(owner));
            properties.insert("user.wings.cache".into(), json!(cache_key));
        }
        // Incus only runs an image as an OCI application when its properties say it is one, and
        // an image imported from a converted archive does not carry that on its own.
        properties.insert("type".into(), json!("oci"));
        self.client
            .request(
                reqwest::Method::PUT,
                &path,
                Some(&metadata),
                etag.as_deref(),
                true,
            )
            .await?;
        Ok(())
    }

    async fn remember(&self, reference: &str, key: &str) -> anyhow::Result<()> {
        let path = self.reference_path(reference);
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let resolved = Resolved {
            key: key.into(),
            checked: now(),
        };
        tokio::fs::write(&temporary, serde_json::to_vec(&resolved)?).await?;
        tokio::fs::rename(temporary, path).await?;
        Ok(())
    }

    async fn lock(&self, key: String) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    async fn save(path: &Path, image: &Image) -> anyhow::Result<()> {
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        tokio::fs::write(&temporary, serde_json::to_vec(image)?).await?;
        tokio::fs::rename(temporary, path).await?;
        Ok(())
    }

    pub(super) async fn cleanup(&self) -> anyhow::Result<usize> {
        let days = self.config.load().runtime.incus.image_cache_retention_days;
        if days == 0 {
            return Ok(0);
        }
        // Waiting here would make every later pull queue behind this cleanup.
        let Ok(_guard) = self.cache_gate.try_write() else {
            return Ok(0);
        };
        let instances: Vec<super::Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let images: Vec<Value> = self.client.get("/1.0/images?recursion=1").await?;
        let owner = format!("wings:{}", self.config.load().uuid);
        let retention = Duration::from_secs(u64::from(days) * 86400);
        self.remove_old_blobs(retention).await?;
        let mut entries = tokio::fs::read_dir(self.root()).await?;
        let mut removed = 0;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(key) = path.file_stem().and_then(|key| key.to_str()) else {
                continue;
            };
            if path.extension().and_then(|ext| ext.to_str()) != Some("json")
                || key.len() != 64
                || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                continue;
            }
            let file_metadata = entry.metadata().await?;
            if !file_metadata.is_file()
                || file_metadata.modified()?.elapsed().unwrap_or_default() < retention
            {
                continue;
            }
            let Ok(image) = serde_json::from_slice::<Image>(&tokio::fs::read(&path).await?) else {
                continue;
            };
            let Some(cached) = images.iter().find(|candidate| {
                candidate.get("fingerprint").and_then(Value::as_str)
                    == Some(image.fingerprint.as_str())
            }) else {
                tokio::fs::remove_file(&path).await?;
                continue;
            };
            if !collectible(cached, key, &owner, &instances) {
                continue;
            }
            let current: Vec<super::Instance> =
                self.client.get("/1.0/instances?recursion=1").await?;
            let image_path = format!("/1.0/images/{}", segment(&image.fingerprint));
            let metadata: Value = self.client.get(&image_path).await?;
            if !collectible(&metadata, key, &owner, &current) {
                continue;
            }
            self.client
                .request(reqwest::Method::DELETE, &image_path, None, None, true)
                .await?;
            tokio::fs::remove_file(&path).await?;
            removed += 1;
            tracing::info!(fingerprint = %image.fingerprint, "removed unused Incus image");
        }
        Ok(removed)
    }
}

fn collectible(image: &Value, key: &str, owner: &str, instances: &[super::Instance]) -> bool {
    let Some(fingerprint) = image.get("fingerprint").and_then(Value::as_str) else {
        return false;
    };
    let Some(prefix) = key.get(..58) else {
        return false;
    };
    let expected = format!("wings-{prefix}");
    image
        .pointer("/properties/user.wings.owner")
        .and_then(Value::as_str)
        == Some(owner)
        && image
            .pointer("/properties/user.wings.cache")
            .and_then(Value::as_str)
            == Some(key)
        && image
            .get("aliases")
            .and_then(Value::as_array)
            .is_some_and(|aliases| {
                aliases.iter().all(|alias| {
                    alias.get("name").and_then(Value::as_str) == Some(expected.as_str())
                })
            })
        && !instances.iter().any(|instance| {
            instance
                .config
                .get("volatile.base_image")
                .is_none_or(|base| base == fingerprint)
        })
}

pub(super) fn parse_reference(value: &str) -> anyhow::Result<(String, String)> {
    ensure!(
        !value.contains("://") && !value.chars().any(char::is_whitespace),
        "OCI reference must be a registry reference, not a URL"
    );
    let (first, remainder) = value.split_once('/').unwrap_or((value, ""));
    let explicit = !remainder.is_empty()
        && (first.contains('.') || first.contains(':') || first == "localhost");
    let (mut registry, mut repository) = if explicit {
        (first.to_string(), remainder.to_string())
    } else {
        ("docker.io".into(), value.to_string())
    };
    if matches!(
        registry.as_str(),
        "index.docker.io" | "registry-1.docker.io"
    ) {
        registry = "docker.io".into();
    }
    // Official Docker Hub images live under `library/`.
    if registry == "docker.io" && !repository.contains('/') && !repository.is_empty() {
        repository = format!("library/{repository}");
    }
    ensure!(
        !repository.is_empty() && !repository.starts_with('-') && !registry.contains('@'),
        "invalid OCI repository"
    );
    Ok((registry, repository))
}
