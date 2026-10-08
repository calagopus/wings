mod auth;
mod client;
mod configuration;
mod image;
mod instance;
mod network;
mod process;
mod provision;
mod storage;

use super::{ProcessHandle, ServerExecutor, StatusReceiver, UsedPort};
use crate::server::{
    Server,
    configuration::ServerConfiguration,
    firewall::{FirewallBackend, FirewallServerSpec},
};
use anyhow::{Context, ensure};
use client::{Client, segment};
use instance::{Devices, Instance, InstanceState};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use storage::Storage;

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
    pub config: Arc<crate::config::Config>,
    client: Client,
    images: Arc<image::Images>,
    network: Arc<network::Network>,
    storage: Arc<Storage>,
    firewall: Arc<dyn FirewallBackend>,
    provisioning: Arc<tokio::sync::Mutex<()>>,
    owner: String,
}
impl IncusExecutor {
    pub fn new(config: Arc<crate::config::Config>) -> anyhow::Result<Self> {
        let settings = config.load();
        let client = Client::new(&settings.runtime.incus)?;
        let owner = format!("wings:{}", settings.uuid);
        let firewall: Arc<dyn FirewallBackend> = match settings.docker.firewall.backend {
            crate::server::firewall::FirewallBackendKind::Disabled => {
                Arc::new(crate::server::firewall::noop::NoopFirewall::new(false))
            }
            crate::server::firewall::FirewallBackendKind::Auto
            | crate::server::firewall::FirewallBackendKind::Nftables => {
                Arc::new(crate::server::firewall::nftables::NftablesFirewall::new(
                    Vec::new(),
                    crate::server::firewall::runner::CommandRunner::Local,
                    crate::server::firewall::sets::SourceFileLimits::from_config(&config),
                ))
            }
            _ => anyhow::bail!(
                "Incus requires the host nftables firewall backend or explicitly disabled policy"
            ),
        };
        let network = Arc::new(network::Network::new(
            client.clone(),
            &settings.runtime.incus,
            settings.uuid,
        ));
        drop(settings);
        Ok(Self {
            images: Arc::new(image::Images::new(Arc::clone(&config), client.clone())),
            network,
            storage: Arc::new(Storage::new(client.clone(), Arc::clone(&config))),
            config,
            client,
            firewall,
            owner,
            provisioning: Arc::new(tokio::sync::Mutex::new(())),
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

    async fn update_instance(&self, instance: &Instance, etag: Option<&str>) -> anyhow::Result<()> {
        self.check_owner(instance)?;
        self.client
            .request(
                Method::PUT,
                &Self::instance_path(&instance.name),
                Some(&instance.update_body()),
                etag,
                true,
            )
            .await?;
        Ok(())
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
            if instance.status != "Stopped" {
                self.client.state(name, "stop", true).await?;
            }
            let deletion = self
                .client
                .mutate(Method::DELETE, &Self::instance_path(name), json!({}))
                .await;
            match deletion {
                Ok(_) => break,
                Err(error) if client::is_status(&error, reqwest::StatusCode::NOT_FOUND) => break,
                Err(error)
                    if error
                        .downcast_ref::<client::ApiError>()
                        .is_some_and(|error| {
                            error.status == reqwest::StatusCode::BAD_REQUEST
                                && error.message == "Instance is running"
                        })
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(error),
            }
        }
        self.storage
            .delete_volume(&Storage::control_name(name))
            .await?;
        if name.starts_with("wgx-") {
            let staging = self.state_root().join("scripts").join(name);
            if tokio::fs::try_exists(&staging).await? {
                tokio::fs::remove_dir_all(staging).await?;
            }
        }
        Ok(())
    }
    async fn sync_server(
        &self,
        server: &Arc<crate::server::InnerServer>,
        name: &str,
    ) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        let cfg = server.configuration.read().await;
        Self::validate_server(&cfg)?;
        let (mut instance, etag) = self.instance_with_etag(name).await?;
        let image_environment: BTreeMap<String, String> = serde_json::from_str(
            instance
                .config
                .get("user.wings.image-env")
                .context("OCI environment metadata missing; recreate this stopped instance")?,
        )?;
        instance
            .config
            .retain(|key, _| !key.starts_with("environment.") && !key.starts_with("limits."));
        for (key, value) in image_environment {
            instance.config.insert(format!("environment.{key}"), value);
        }
        instance.config.extend(self.resources(&cfg, false)?);
        for entry in cfg.environment(&self.config) {
            let (key, value) = entry.split_once('=').context("invalid environment")?;
            instance
                .config
                .insert(format!("environment.{key}"), value.into());
        }
        instance.config.insert(
            "user.wings.allocations".into(),
            serde_json::to_string(&network::allocations(&cfg)?)?,
        );
        let ip: IpAddr = instance
            .config
            .get("user.wings.ip")
            .context("instance address missing")?
            .parse()?;
        let mut spec = firewall_spec(&cfg, ip)?;
        spec.files = Some(crate::server::firewall::sets::FirewallFileAccess {
            filesystem: (*server.filesystem).clone(),
            notifier: Some(server.filesystem.server_notifier().clone()),
            server: Some(Arc::downgrade(server)),
        });
        self.firewall.sync(&spec).await?;
        self.update_instance(&instance, etag.as_deref()).await?;
        if instance.status == "Running" {
            self.publish(name).await?;
        }
        Ok(())
    }
    async fn publish(&self, name: &str) -> anyhow::Result<()> {
        let instance = self.instance(name).await?;
        let uuid: uuid::Uuid = instance
            .config
            .get("user.wings.server")
            .context("instance server missing")?
            .parse()?;
        let ip = instance
            .config
            .get("user.wings.ip")
            .context("instance address missing")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let state: InstanceState = self
                .client
                .get(&format!("{}/state", Self::instance_path(name)))
                .await?;
            if state
                .network
                .get("eth0")
                .is_some_and(|nic| nic.addresses.iter().any(|address| &address.address == ip))
            {
                break;
            }
            ensure!(
                state.status == "Running",
                "OCI process exited before network publication"
            );
            ensure!(
                tokio::time::Instant::now() < deadline,
                "Incus instance did not acquire its reserved address"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let desired: BTreeMap<IpAddr, BTreeSet<u16>> = serde_json::from_str(
            instance
                .config
                .get("user.wings.allocations")
                .context("allocation journal missing")?,
        )?;
        self.network.sync(uuid, ip, &desired).await
    }
}

pub fn verify_version(version: &str, extensions: &[String]) -> anyhow::Result<()> {
    let release = version
        .split_once('-')
        .map_or(version, |(release, _)| release);
    let mut parts = release.split('.');
    ensure!(
        parts.next() == Some("7") && parts.next() == Some("0"),
        "Incus 7.0 LTS is required; daemon reports {version}"
    );
    let patch = parts.next().and_then(|patch| patch.parse::<u64>().ok());
    ensure!(
        patch.is_some_and(|patch| patch >= 1) && parts.next().is_none(),
        "Incus 7.0.1 or a newer 7.0 LTS maintenance release is required; daemon reports {version}"
    );
    for required in [
        "instance_oci",
        "instance_oci_entrypoint",
        "oci_network_config",
        "network_forward",
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

fn firewall_spec(
    config: &ServerConfiguration,
    private: IpAddr,
) -> anyhow::Result<FirewallServerSpec> {
    let mappings = network::allocations(config)?;
    Ok(FirewallServerSpec {
        server: config.uuid,
        bindings: mappings
            .iter()
            .flat_map(|(ip, ports)| {
                ports
                    .iter()
                    .map(|port| crate::server::firewall::FirewallBinding {
                        ip: (!ip.is_unspecified()).then_some(*ip),
                        port: *port,
                    })
            })
            .collect(),
        container_ports: mappings
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        container_ips: vec![private],
        rules: config.firewall.clone(),
        files: None,
    })
}

#[async_trait::async_trait]
impl ServerExecutor for IncusExecutor {
    async fn boot(&self) -> anyhow::Result<()> {
        let runtime = self.config.load().runtime.incus.clone();
        ensure!(
            rustix::process::geteuid().as_raw() == 0,
            "the current Incus OCI importer requires a root Wings service"
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
            !self.config.load().docker.startup_boost.enabled
                && !self.config.load().docker.runtime_boost.enabled,
            "Incus CPU boosts are not implemented; disable node CPU boosts"
        );
        ensure!(
            self.config.load().system.user.uid != 0 && self.config.load().system.user.gid != 0,
            "Incus requires a non-root Wings data UID/GID for the host bind mount"
        );
        ensure!(
            !self.config.load().uuid.is_nil(),
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
            !self.config.load().system.user.rootless.enabled,
            "Docker rootless settings do not apply to Incus"
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
        let path = format!("/1.0/projects/{}", segment(&runtime.project));
        let existing = self
            .client
            .request(Method::GET, &path, None, None, false)
            .await;
        match existing {
            Ok((project, _)) => {
                ensure!(
                    project
                        .pointer("/config/user.wings.owner")
                        .and_then(Value::as_str)
                        == Some(&self.owner),
                    "refusing unmanaged Incus project"
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
                let body = json!({
                    "name": runtime.project,
                    "description": self.owner,
                    "config": {
                        "features.images": "true",
                        "features.profiles": "true",
                        "features.storage.volumes": "true",
                        "features.networks": "false",
                        "user.wings.owner": self.owner,
                    },
                });
                self.client
                    .request(Method::POST, "/1.0/projects", Some(&body), None, false)
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
        self.create(server, &name, &image, None, false, &HashMap::new())
            .await?;
        process::Handle::connect(self.clone(), server, name, false, true).await
    }
    async fn attach_server_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let name = Self::name(server.uuid);
        let instance = self
            .client
            .optional::<Instance>(&Self::instance_path(&name))
            .await
            .map_err(RecoveryError)?
            .context("Incus server does not exist")?;
        ensure!(
            instance.status == "Running" || instance.status == "Frozen",
            "Incus server is not running"
        );
        async {
            self.verify_data_mount(server, &instance).await?;
            self.sync_server(server, &name).await?;
            process::Handle::connect(self.clone(), server, name, true, true).await
        }
        .await
        .map_err(|error| RecoveryError(error).into())
    }
    async fn cleanup_server_process(&self, server: &Server) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        self.remove_instance(&Self::name(server.uuid)).await?;
        if server.suspended.load(std::sync::atomic::Ordering::SeqCst) {
            self.cleanup_owned_helpers(server.uuid).await?;
        }
        self.firewall.clear(server.uuid).await?;
        Ok(())
    }
    async fn setup_installation_process(
        &self,
        server: &Server,
        script: &crate::server::installation::InstallationScript,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        self.setup_helper(server, script, true).await
    }
    async fn attach_installation_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let name = format!("wgi-{}", server.uuid);
        self.instance(&name).await?;
        self.prepare_data_mount(server).await?;
        process::Handle::connect(self.clone(), server, name, true, false).await
    }
    async fn cleanup_installation_process(&self, server: &Server) -> anyhow::Result<()> {
        self.remove_instance(&format!("wgi-{}", server.uuid)).await
    }
    async fn setup_script_process(
        &self,
        server: &Server,
        script: &crate::server::installation::InstallationScript,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        self.setup_helper(server, script, false).await
    }
    async fn resolve_internal_target(
        &self,
        server: &Server,
        port: u16,
    ) -> anyhow::Result<Option<SocketAddr>> {
        let instance = self.instance(&Self::name(server.uuid)).await?;
        ensure!(
            instance.status == "Running",
            "Incus target instance is not running"
        );
        Ok(Some(SocketAddr::new(
            instance
                .config
                .get("user.wings.ip")
                .context("instance address missing")?
                .parse()?,
            port,
        )))
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
    async fn reconcile_firewall(
        &self,
        servers: &[crate::remote::servers::RawServer],
    ) -> anyhow::Result<()> {
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
            let Some(uuid) = instance
                .config
                .get("user.wings.server")
                .and_then(|uuid| uuid.parse::<uuid::Uuid>().ok())
            else {
                continue;
            };
            if instance.name != Self::name(uuid) {
                continue;
            }
            let Some(settings) = servers.get(&uuid) else {
                self.network.sync(uuid, "", &BTreeMap::new()).await?;
                continue;
            };
            let ip: IpAddr = instance
                .config
                .get("user.wings.ip")
                .context("instance address missing")?
                .parse()?;
            if matches!(instance.status.as_str(), "Running" | "Frozen") {
                let desired = network::allocations(settings)?;
                self.network.sync(uuid, &ip.to_string(), &desired).await?;
            }
            let mut spec = firewall_spec(settings, ip)?;
            if spec.references_files() {
                spec.files = Some(crate::server::firewall::sets::FirewallFileAccess {
                    filesystem: crate::server::filesystem::cap::CapFilesystem::new(
                        &self.config.data_path(uuid),
                    )
                    .await?,
                    notifier: None,
                    server: None,
                });
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
