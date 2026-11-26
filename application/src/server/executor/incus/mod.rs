mod auth;
mod boost;
mod client;
mod configuration;
mod console;
mod image;
mod instance;
mod network;
mod process;
mod progress;
mod provision;
mod registry;
mod seccomp;
mod stats;
mod storage;
mod terminal;

use super::{ProcessHandle, ProcessStatus, ServerExecutor, StatusReceiver, UsedPort};
use crate::{
    config::Config,
    remote::servers::RawServer,
    server::{
        InnerServer, Server,
        configuration::ServerConfiguration,
        executor::docker::cgroup::StatsSampler,
        filesystem::cap::CapFilesystem,
        firewall::{
            FirewallBackend, FirewallBackendKind, FirewallBinding, FirewallServerSpec,
            nftables::NftablesFirewall,
            noop::NoopFirewall,
            runner::CommandRunner,
            sets::{FirewallFileAccess, SourceFileLimits},
        },
        installation::InstallationScript,
    },
};
use anyhow::{Context, bail, ensure};
use client::{Client, segment};
use configuration::Role;
use instance::{Devices, Instance, InstanceState};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, OnceLock, atomic::Ordering},
    time::Duration,
};
use storage::Storage;

/// Incus could not be asked about an instance that may well be running, so Wings must not go on to
/// replace it.
#[derive(Debug)]
pub(crate) struct RecoveryError(anyhow::Error);
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Incus recovery failed: {:#}", self.0)
    }
}
impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Clone)]
pub struct IncusExecutor {
    pub config: Arc<Config>,
    client: Client,
    images: Arc<image::Images>,
    network: Arc<network::Network>,
    storage: Arc<Storage>,
    firewall: Arc<dyn FirewallBackend>,
    /// Serializes changes to one server's instances without holding up other servers.
    locks: Arc<crate::utils::KeyedLocks<uuid::Uuid>>,
    stats_sampler: Arc<StatsSampler>,
    /// Whether this Incus release accepts a swap limit as a size rather than on or off.
    swap_sizes: Arc<OnceLock<bool>>,
    owner: String,
}

impl IncusExecutor {
    pub fn new(config: Arc<Config>) -> anyhow::Result<Self> {
        let settings = config.load();
        let client = Client::new(&settings.runtime.incus)?;
        let owner = format!("wings:{}", settings.uuid);
        let firewall: Arc<dyn FirewallBackend> = match settings.docker.firewall.backend {
            FirewallBackendKind::Disabled => Arc::new(NoopFirewall::new(false)),
            FirewallBackendKind::Auto | FirewallBackendKind::Nftables => {
                Arc::new(NftablesFirewall::new(
                    Vec::new(),
                    CommandRunner::Local,
                    SourceFileLimits::from_config(&config),
                ))
            }
            _ => bail!("Incus requires the nftables firewall backend or a disabled firewall"),
        };
        let network = Arc::new(network::Network::new(client.clone(), Arc::clone(&config)));
        drop(settings);
        Ok(Self {
            images: Arc::new(image::Images::new(Arc::clone(&config), client.clone())),
            network,
            storage: Arc::new(Storage::new(client.clone(), Arc::clone(&config))),
            config,
            client,
            firewall,
            locks: Arc::new(crate::utils::KeyedLocks::new()),
            stats_sampler: Arc::new(StatsSampler::default()),
            swap_sizes: Arc::new(OnceLock::new()),
            owner,
        })
    }

    pub fn state_root(&self) -> PathBuf {
        self.config
            .resolve_as_path(|cfg| &cfg.system.root_directory)
            .join("incus")
    }

    fn name(uuid: uuid::Uuid) -> String {
        format!("wgs-{uuid}")
    }

    fn instance_path(name: &str) -> String {
        format!("/1.0/instances/{}", segment(name))
    }

    /// Where Incus writes an instance's log files on this host.
    fn log_directory(&self, name: &str) -> PathBuf {
        let config = self.config.load();
        let runtime = &config.runtime.incus;
        let directory = PathBuf::from(&runtime.log_directory);
        if runtime.project == "default" {
            directory.join(name)
        } else {
            directory.join(format!("{}_{name}", runtime.project))
        }
    }

    fn console_log_path(&self, name: &str) -> PathBuf {
        self.log_directory(name).join("console.log")
    }

    fn swap_sizes(&self) -> bool {
        self.swap_sizes.get().copied().unwrap_or(false)
    }

    fn check_owner(&self, instance: &Instance) -> anyhow::Result<()> {
        ensure!(
            instance.config.get("user.wings.owner") == Some(&self.owner),
            "refusing unmanaged Incus instance {}",
            instance.name
        );
        Ok(())
    }

    async fn instance(&self, name: &str) -> anyhow::Result<Instance> {
        Ok(self.instance_with_etag(name).await?.0)
    }

    async fn instance_with_etag(&self, name: &str) -> anyhow::Result<(Instance, Option<String>)> {
        let (instance, etag) = self
            .client
            .get_with_etag::<Instance>(&Self::instance_path(name))
            .await?;
        self.check_owner(&instance)?;
        Ok((instance, etag))
    }

    async fn instance_state(&self, name: &str) -> anyhow::Result<InstanceState> {
        self.client
            .get(&format!("{}/state", Self::instance_path(name)))
            .await
    }

    /// Applies `change` to an instance, retrying if something else modified it meanwhile.
    async fn modify_instance(
        &self,
        name: &str,
        change: impl Fn(&mut Instance),
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.config.load().runtime.incus.operation_timeout_seconds);
        loop {
            let (mut instance, etag) = self.instance_with_etag(name).await?;
            let before = instance.update_body();
            change(&mut instance);
            let body = instance.update_body();
            if body == before {
                return Ok(());
            }
            let result = self
                .client
                .request(
                    Method::PUT,
                    &Self::instance_path(name),
                    Some(&body),
                    etag.as_deref(),
                    true,
                )
                .await;
            match result {
                Ok(_) => return Ok(()),
                Err(err)
                    if (client::is_status(&err, StatusCode::PRECONDITION_FAILED)
                        || client::is_busy(&err))
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Changes only the CPU time limit, given as quota and period in microseconds.
    async fn set_cpu_allowance(&self, name: &str, quota: Option<(i64, i64)>) -> anyhow::Result<()> {
        let allowance = configuration::limit_config(
            &bollard::models::Resources {
                cpu_quota: quota.map(|(quota, _)| quota),
                cpu_period: quota.map(|(_, period)| period),
                ..Default::default()
            },
            false,
        )
        .remove("limits.cpu.allowance");
        self.modify_instance(name, |instance| match &allowance {
            Some(allowance) => {
                instance
                    .config
                    .insert("limits.cpu.allowance".into(), allowance.clone());
            }
            None => {
                instance.config.remove("limits.cpu.allowance");
            }
        })
        .await
    }

    /// Kills an instance. One that is already gone or stopped is not an error.
    async fn force_stop(&self, name: &str) -> anyhow::Result<()> {
        let Err(error) = self.client.state(name, "stop", true).await else {
            return Ok(());
        };
        if client::is_status(&error, StatusCode::NOT_FOUND) {
            return Ok(());
        }
        match self.instance_state(name).await {
            Ok(state) if state.status == "Stopped" => Ok(()),
            _ => Err(error),
        }
    }

    /// The reason liblxc gave for the last failed start, for the error message.
    async fn start_failure_detail(&self, name: &str) -> String {
        let log = tokio::fs::read_to_string(self.log_directory(name).join("lxc.log"))
            .await
            .unwrap_or_default();
        let reasons: Vec<&str> = log
            .lines()
            .filter(|line| line.contains(" ERROR "))
            .filter_map(|line| line.splitn(3, " - ").nth(2))
            .take(3)
            .collect();
        if reasons.is_empty() {
            "Incus could not start the instance".into()
        } else {
            format!(
                "Incus could not start the instance ({})",
                reasons.join("; ")
            )
        }
    }

    /// Claims a server's published ports ahead of starting it.
    async fn claim_ports(&self, name: &str) -> anyhow::Result<network::Claim> {
        let instance = self.instance(name).await?;
        let published = network::published(&instance)?;
        self.network.claim(name, &published).await
    }

    pub async fn remove_instance(&self, name: &str) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.config.load().runtime.incus.operation_timeout_seconds);
        while let Some(instance) = self
            .client
            .optional::<Instance>(&Self::instance_path(name))
            .await?
        {
            self.check_owner(&instance)?;
            let result = async {
                if instance.status != "Stopped" {
                    self.force_stop(name).await?;
                }
                self.client
                    .mutate(Method::DELETE, &Self::instance_path(name), json!({}))
                    .await
            }
            .await;
            match result {
                Ok(_) => break,
                Err(error) if client::is_status(&error, StatusCode::NOT_FOUND) => break,
                Err(error) if client::is_busy(&error) && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(error),
            }
        }
        self.storage
            .delete_volume(&Storage::control_name(name))
            .await?;
        // A server keeps its last output, helpers leave nothing behind.
        let role = Role::of(name);
        if role != Role::Server {
            let mut directories = vec![self.log_directory(name)];
            if role == Role::Script {
                directories.push(self.state_root().join("scripts").join(name));
            }
            for directory in directories {
                match tokio::fs::remove_dir_all(&directory).await {
                    Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                        return Err(err.into());
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Brings an existing instance up to date with the settings that apply without a restart.
    async fn sync_server(&self, server: &Arc<InnerServer>, name: &str) -> anyhow::Result<()> {
        let _guard = self.locks.lock(server.uuid).await;
        let instance = self.instance(name).await?;
        let (resources, bandwidth, mut spec) = {
            let cfg = server.configuration.read().await;
            (
                configuration::resources(&self.config, &cfg, Role::Server),
                cfg.build.bandwidth,
                firewall_spec(&cfg, &instance)?,
            )
        };
        spec.files = Some(FirewallFileAccess {
            filesystem: (*server.filesystem).clone(),
            notifier: Some(server.filesystem.server_notifier().clone()),
            server: Some(Arc::downgrade(server)),
        });
        if let Err(err) = self.firewall.sync(&spec).await {
            tracing::error!(server = %server.uuid, "failed to sync firewall rules: {err:#}");
        }
        let limits = configuration::limit_config(&resources, self.swap_sizes());
        let shaping = self.network.bandwidth_config(bandwidth);
        self.modify_instance(name, |instance| {
            for key in configuration::LIVE_LIMITS {
                instance.config.remove(key);
            }
            instance.config.extend(limits.clone());
            if let Some(device) = instance.devices.get_mut("eth0") {
                device.remove("limits.ingress");
                device.remove("limits.egress");
                device.extend(shaping.clone());
            }
        })
        .await
    }
}

pub fn verify_version(version: &str, extensions: &[String]) -> anyhow::Result<()> {
    let release = version
        .split_once('-')
        .map_or(version, |(release, _)| release);
    let mut parts = release
        .split('.')
        .map(|part| part.parse::<u64>().ok().context("unreadable Incus version"));
    let major = parts.next().context("Incus version missing")??;
    let minor = parts.next().context("Incus minor version missing")??;
    let patch = parts.next().transpose()?.unwrap_or(0);
    ensure!(
        major == 7 && (minor > 0 || patch >= 1),
        "Incus 7.0.1 or a newer 7.x release is required; daemon reports {version}"
    );
    for required in [
        "instance_oci",
        "instance_oci_entrypoint",
        "oci_network_config",
        "proxy_nat",
        "file_storage_volume",
    ] {
        ensure!(
            extensions.iter().any(|extension| extension == required),
            "Incus daemon is missing API extension {required}"
        );
    }
    Ok(())
}

const SCRIPT_START_DEADLINE: Duration = Duration::from_secs(120);

/// Follows a script instance until it stops. Returns `false` if it never reported a status within
/// `start_deadline`, ran past `timeout`, or its monitor ended without reporting a stop.
async fn wait_for_script(
    mut statuses: StatusReceiver,
    forward: tokio::sync::mpsc::Sender<ProcessStatus>,
    start_deadline: Duration,
    timeout: Option<Duration>,
) -> bool {
    let finished = async {
        let mut next = tokio::time::timeout(start_deadline, statuses.recv())
            .await
            .ok()
            .flatten();
        while let Some(status) = next {
            // Nobody is required to listen, so a closed or full channel is fine.
            let _ = forward.try_send(status);
            if matches!(status, ProcessStatus::Stopped { .. }) {
                return true;
            }
            next = statuses.recv().await;
        }
        false
    };
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, finished)
            .await
            .unwrap_or(false),
        None => finished.await,
    }
}

/// The firewall policy of a server: its rules, applied to what its instance publishes.
fn firewall_spec(
    config: &ServerConfiguration,
    instance: &Instance,
) -> anyhow::Result<FirewallServerSpec> {
    let published = network::published(instance)?;
    Ok(FirewallServerSpec {
        server: config.uuid,
        bindings: published
            .iter()
            .flat_map(|(ip, ports)| {
                ports.iter().map(|port| FirewallBinding {
                    ip: (!ip.is_unspecified()).then_some(*ip),
                    port: *port,
                })
            })
            .collect(),
        container_ports: published
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        container_ips: network::addresses(instance)?,
        rules: config.firewall.clone(),
        files: None,
    })
}

#[async_trait::async_trait]
impl ServerExecutor for IncusExecutor {
    async fn boot(&self) -> anyhow::Result<()> {
        let config = self.config.load();
        let runtime = config.runtime.incus.clone();
        ensure!(
            rustix::process::geteuid().as_raw() == 0,
            "the Incus runtime requires Wings to run as root"
        );
        ensure!(
            runtime.network.len() <= 15
                && !runtime.network.is_empty()
                && runtime
                    .network
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
            "invalid Incus bridge name"
        );
        ensure!(
            config.system.user.uid != 0 && config.system.user.gid != 0,
            "Incus requires a non-root Wings data UID/GID"
        );
        ensure!(
            !config.uuid.is_nil(),
            "Incus requires a persistent non-nil Wings node UUID"
        );
        ensure!(
            runtime.max_concurrent_imports > 0
                && runtime.operation_timeout_seconds > 0
                && runtime.image_import_timeout_seconds > 0,
            "Incus timeouts and concurrency must be positive"
        );
        ensure!(
            runtime.project != "default" && !runtime.project.is_empty(),
            "use a dedicated Incus project"
        );
        ensure!(
            !config.system.user.rootless.enabled,
            "Docker rootless settings do not apply to Incus"
        );
        ensure!(
            config.docker.network.mode != "host"
                && !config.docker.network.mode.starts_with("container:"),
            "the Incus runtime does not support docker.network.mode {}",
            config.docker.network.mode
        );
        drop(config);
        ensure!(
            tokio::fs::try_exists(&runtime.log_directory).await?,
            "Incus log directory {} does not exist, set runtime.incus.log_directory",
            runtime.log_directory
        );
        let (server, _) = self
            .client
            .request(Method::GET, "/1.0", None, None, false)
            .await?;
        let version = server
            .pointer("/environment/server_version")
            .and_then(Value::as_str)
            .context("Incus server version missing")?;
        let extensions: Vec<String> = serde_json::from_value(
            server
                .get("api_extensions")
                .cloned()
                .context("Incus extensions missing")?,
        )?;
        verify_version(version, &extensions)?;
        let _ = self.swap_sizes.set(
            extensions
                .iter()
                .any(|extension| extension == "instance_memory_swap_bytes"),
        );
        match self
            .client
            .request(
                Method::GET,
                &format!("/1.0/projects/{}", segment(&runtime.project)),
                None,
                None,
                false,
            )
            .await
        {
            Ok((project, _)) => {
                ensure!(
                    project
                        .pointer("/config/user.wings.owner")
                        .and_then(Value::as_str)
                        == Some(&self.owner),
                    "Incus project {} belongs to something else, set runtime.incus.project",
                    runtime.project
                );
                ensure!(
                    project
                        .pointer("/config/features.networks")
                        .and_then(Value::as_str)
                        == Some("false"),
                    "Incus project must share the default project's managed bridge"
                );
            }
            Err(err) if client::is_status(&err, reqwest::StatusCode::NOT_FOUND) => {
                self.client
                    .request(
                        Method::POST,
                        "/1.0/projects",
                        Some(&json!({
                            "name": runtime.project,
                            "description": self.owner,
                            "config": {
                                "features.images": "true",
                                "features.profiles": "true",
                                "features.storage.volumes": "true",
                                "features.networks": "false",
                                "user.wings.owner": self.owner,
                            },
                        })),
                        None,
                        false,
                    )
                    .await?;
            }
            Err(err) => return Err(err),
        }
        tokio::fs::create_dir_all(self.state_root()).await?;
        self.storage.boot().await?;
        self.images.boot().await?;
        self.network.boot().await?;
        self.firewall.boot().await?;
        Ok(())
    }
    async fn setup_server_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let source = server
            .configuration
            .read()
            .await
            .container
            .image
            .to_string();
        let image = self.images.ensure(&source, server, false).await?;
        let name = Self::name(server.uuid);
        self.create(server, &name, &image, provision::Launch::server())
            .await?;
        process::Handle::connect(self.clone(), server, name, false).await
    }

    async fn attach_server_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let name = Self::name(server.uuid);
        let path = Self::instance_path(&name);
        let mut attempts = 0u32;
        let instance = loop {
            attempts += 1;
            match self.client.optional::<Instance>(&path).await {
                Ok(instance) => break instance,
                Err(_) if attempts < 5 => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(err) => return Err(RecoveryError(err).into()),
            }
        }
        .context("Incus server does not exist")?;
        ensure!(
            instance.status == "Running" || instance.status == "Frozen",
            "Incus server is not running"
        );
        self.check_owner(&instance)?;
        // The game is running: take control of it, and report whatever could not be restored.
        if let Err(err) = self.verify_data_mount(server, &instance).await {
            tracing::error!(server = %server.uuid, "{err:#}");
            server.log_daemon_error(&format!("{err:#}"));
        }
        if let Err(err) = self.sync_server(server, &name).await {
            tracing::error!(server = %server.uuid, "failed to reapply server settings: {err:#}");
        }
        process::Handle::connect(self.clone(), server, name, true).await
    }

    async fn cleanup_server_process(&self, server: &Server) -> anyhow::Result<()> {
        let destroying = server.destroying.load(Ordering::SeqCst);
        let name = Self::name(server.uuid);
        {
            let _guard = self.locks.lock(server.uuid).await;
            if let Err(err) = self.firewall.clear(server.uuid).await {
                tracing::warn!(server = %server.uuid, "failed to clear firewall rules: {err:#}");
            }
            self.remove_instance(&name).await?;
        }
        if destroying || server.suspended.load(Ordering::SeqCst) {
            self.cleanup_owned_helpers(server.uuid).await?;
        }
        if destroying {
            for name in [name, format!("wgi-{}", server.uuid)] {
                let _ = tokio::fs::remove_dir_all(self.log_directory(&name)).await;
            }
        }
        self.network.refresh_nat().await
    }

    async fn setup_installation_process(
        &self,
        server: &Server,
        script: &InstallationScript,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let (_, handle, status_rx) = self.setup_helper(server, script, true).await?;
        Ok((handle, status_rx))
    }
    async fn attach_installation_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let name = format!("wgi-{}", server.uuid);
        let instance = self.instance(&name).await?;
        ensure!(
            instance.status == "Running" || instance.status == "Frozen",
            "Incus installation is not running"
        );
        if let Err(err) = self.prepare_data_mount(server).await {
            tracing::warn!(server = %server.uuid, "failed to restore the data mount: {err:#}");
        }
        process::Handle::connect(self.clone(), server, name, true).await
    }

    async fn cleanup_installation_process(&self, server: &Server) -> anyhow::Result<()> {
        self.remove_instance(&format!("wgi-{}", server.uuid)).await
    }
    async fn setup_script_process(
        &self,
        server: &Server,
        script: &InstallationScript,
        timeout: Option<std::time::Duration>,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let (name, handle, statuses) = self.setup_helper(server, script, false).await?;
        let (forward, status_rx) = tokio::sync::mpsc::channel(8);
        let executor = self.clone();
        let supervised = Arc::clone(&handle);

        // Script callers drop both the handle and the receiver right after starting, so this task
        // watches for the end, and removes a script that never started or ran too long.
        tokio::spawn(async move {
            if !wait_for_script(statuses, forward, SCRIPT_START_DEADLINE, timeout).await {
                tracing::warn!(instance = %name, "Incus script did not finish in time, removing it");
                if let Err(error) = executor.remove_instance(&name).await {
                    tracing::warn!(instance = %name, "could not remove Incus script instance: {error:#}");
                }
            }
            drop(supervised);
        });

        Ok((handle, status_rx))
    }
    async fn resolve_internal_target(
        &self,
        server: &Server,
        port: u16,
    ) -> anyhow::Result<Option<SocketAddr>> {
        let name = Self::name(server.uuid);
        let Some(instance) = self
            .client
            .optional::<Instance>(&Self::instance_path(&name))
            .await?
        else {
            return Ok(None);
        };
        self.check_owner(&instance)?;
        if instance.status != "Running" {
            return Ok(None);
        }
        Ok(network::addresses(&instance)?
            .first()
            .map(|ip| SocketAddr::new(*ip, port)))
    }
    async fn resolve_published_address(&self, _server: &Server) -> Option<IpAddr> {
        None
    }
    async fn container_refs(&self, servers: &[Server]) -> HashMap<uuid::Uuid, String> {
        servers
            .iter()
            .map(|server| (server.uuid, Self::name(server.uuid)))
            .collect()
    }
    async fn used_ports(&self, ips: &[IpAddr]) -> anyhow::Result<HashMap<IpAddr, Vec<UsedPort>>> {
        self.network.used_ports(ips).await
    }
    // Incus shapes traffic itself, on the instance's network device.
    fn bandwidth_enabled(&self) -> bool {
        self.network.bandwidth_enabled()
    }

    async fn bandwidth_ready(&self) -> anyhow::Result<()> {
        ensure!(
            self.network.bandwidth_enabled(),
            "docker.bandwidth.backend is disabled"
        );
        Ok(())
    }

    async fn reconcile_firewall(&self, servers: &[RawServer]) -> anyhow::Result<()> {
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let servers: HashMap<_, _> = servers
            .iter()
            .map(|server| (server.settings.uuid, &server.settings))
            .collect();
        let mut specs = Vec::new();
        for instance in instances {
            if instance.config.get("user.wings.owner") != Some(&self.owner) {
                continue;
            }
            let Some(settings) = instance
                .config
                .get("user.wings.server")
                .and_then(|uuid| uuid.parse::<uuid::Uuid>().ok())
                .filter(|uuid| instance.name == Self::name(*uuid))
                .and_then(|uuid| servers.get(&uuid))
            else {
                continue;
            };
            // One unreadable instance must not leave every other server without its rules.
            let mut spec = match firewall_spec(settings, &instance) {
                Ok(spec) => spec,
                Err(err) => {
                    tracing::error!(
                        server = %settings.uuid,
                        "failed to build firewall rules: {err:#}"
                    );
                    continue;
                }
            };
            if spec.references_files() {
                match CapFilesystem::new(&self.config.data_path(settings.uuid)).await {
                    Ok(filesystem) => {
                        spec.files = Some(FirewallFileAccess {
                            filesystem,
                            notifier: None,
                            server: None,
                        });
                    }
                    Err(err) => tracing::warn!(
                        server = %settings.uuid,
                        "failed to open the server directory for its firewall source files: {err}"
                    ),
                }
            }
            specs.push(spec);
        }
        self.firewall.reconcile(&specs).await
    }
}

impl IncusExecutor {
    async fn cleanup_owned_helpers(&self, uuid: uuid::Uuid) -> anyhow::Result<()> {
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let server = uuid.to_string();
        for instance in instances {
            if instance.is_helper_for(uuid)
                && instance.config.get("user.wings.owner") == Some(&self.owner)
                && instance.config.get("user.wings.server") == Some(&server)
            {
                self.remove_instance(&instance.name).await?;
            }
        }
        Ok(())
    }
}
