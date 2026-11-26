use super::{
    IncusExecutor, Instance, InstanceState,
    configuration::{self, BlueprintOptions, Role},
    image, network, process,
    storage::Storage,
};
use crate::server::executor::{ProcessHandle, StatusReceiver};
use crate::server::{Server, firewall::sets::FirewallFileAccess, installation::InstallationScript};
use anyhow::{Context, ensure};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

/// What a new instance is for.
pub(super) struct Launch {
    role: Role,
    /// Replaces the image's own command.
    command: Option<Vec<String>>,
    environment: HashMap<compact_str::CompactString, Value>,
    /// A host directory of helper files and where it is mounted.
    staging: Option<(PathBuf, &'static str)>,
}

impl Launch {
    pub(super) fn server() -> Self {
        Self {
            role: Role::Server,
            command: None,
            environment: HashMap::new(),
            staging: None,
        }
    }
}

impl IncusExecutor {
    pub(super) async fn create(
        &self,
        server: &Server,
        name: &str,
        image: &image::Image,
        launch: Launch,
    ) -> anyhow::Result<()> {
        let _guard = self.locks.lock(server.uuid).await;
        let role = launch.role;
        if let Some(existing) = self
            .client
            .optional::<Instance>(&Self::instance_path(name))
            .await?
        {
            self.check_owner(&existing)?;
            ensure!(
                existing.status == "Stopped",
                "server instance is already running"
            );
            self.remove_instance(name).await?;
        }
        let data = self.prepare_data_mount(server).await?;
        ensure!(
            data.is_absolute() && data.is_dir(),
            "Wings server directory must be initialized before creating an Incus instance"
        );
        server.filesystem.ensure_trash_directory().await;

        let cfg = server.configuration.read().await;
        let mut blueprint = configuration::blueprint(
            &self.config,
            server,
            &cfg,
            BlueprintOptions {
                role,
                image,
                command: launch.command,
                extra_env: &launch.environment,
                swap_sizes: self.swap_sizes(),
            },
        )
        .await?;
        let published = if role == Role::Server {
            self.network.publish_map(&cfg)?
        } else {
            BTreeMap::new()
        };
        // Held until the instance exists, so no other instance can be given the same address.
        let address = self.network.reserve().await?;
        let runtime = self.config.load().runtime.incus.clone();
        let control = Storage::control_name(name);
        self.storage
            .ensure_volume(&control, 16 * 1024 * 1024)
            .await?;

        blueprint.config.extend(address.instance_config());
        blueprint.config.extend(BTreeMap::from([
            ("user.wings.owner".into(), self.owner.clone()),
            ("user.wings.server".into(), server.uuid.to_string()),
            ("user.wings.digest".into(), image.digest.clone()),
            (network::JOURNAL.into(), serde_json::to_string(&published)?),
        ]));
        if role == Role::Server
            && let Some(source) = network::forced_source(&cfg)?
        {
            blueprint
                .config
                .insert(network::SOURCE_NAT.into(), source.to_string());
        }

        let bandwidth = (role == Role::Server).then_some(cfg.build.bandwidth);
        blueprint.devices.insert(
            "root".into(),
            BTreeMap::from([
                ("type".into(), "disk".into()),
                ("path".into(), "/".into()),
                ("pool".into(), runtime.storage_pool.clone()),
                ("size".into(), runtime.root_disk_size),
            ]),
        );
        blueprint
            .devices
            .insert("eth0".into(), self.network.nic(&address, bandwidth));
        blueprint.devices.insert(
            "data".into(),
            BTreeMap::from([
                ("type".into(), "disk".into()),
                (
                    "source".into(),
                    data.to_str()
                        .context("Incus data path is not UTF-8")?
                        .into(),
                ),
                ("path".into(), role.home().into()),
            ]),
        );
        blueprint.devices.insert(
            "control".into(),
            BTreeMap::from([
                ("type".into(), "disk".into()),
                ("pool".into(), runtime.storage_pool),
                ("source".into(), control.clone()),
                ("path".into(), "/opt/wings-control".into()),
            ]),
        );
        if let Some((source, target)) = &launch.staging {
            blueprint.devices.insert(
                "staging".into(),
                BTreeMap::from([
                    ("type".into(), "disk".into()),
                    ("source".into(), source.display().to_string()),
                    ("path".into(), (*target).into()),
                    ("shift".into(), "true".into()),
                ]),
            );
        }
        blueprint
            .devices
            .extend(self.network.proxy_devices(&address, &published)?);

        let body = json!({
            "name": name,
            "type": "container",
            "profiles": [],
            "source": {"type": "image", "fingerprint": image.fingerprint},
            "config": blueprint.config,
            "devices": blueprint.devices,
        });
        let created = async {
            self.client
                .mutate(Method::POST, "/1.0/instances", body)
                .await?;
            let launch_script = blueprint
                .config
                .get("user.wings.launch")
                .context("OCI launch script missing")?;
            let (uid, gid) = (blueprint.uid, blueprint.gid);
            self.client
                .directory(
                    &self.storage.file_path(&control, "process"),
                    uid,
                    gid,
                    "0700",
                )
                .await?;
            for (file, content) in [
                ("process/launch", launch_script.as_bytes().to_vec()),
                ("process/exit", Vec::new()),
            ] {
                self.client
                    .write_file(
                        &self.storage.file_path(&control, file),
                        content,
                        uid,
                        gid,
                        "0600",
                    )
                    .await?;
            }
            if role == Role::Server {
                let instance = self.instance(name).await?;
                let mut spec = super::firewall_spec(&cfg, &instance)?;
                spec.files = Some(FirewallFileAccess {
                    filesystem: (*server.filesystem).clone(),
                    notifier: Some(server.filesystem.server_notifier().clone()),
                    server: Some(Arc::downgrade(server)),
                });
                if let Err(err) = self.firewall.sync(&spec).await {
                    if !spec.rules.is_empty() {
                        return Err(err.context("failed to apply firewall rules"));
                    }
                    tracing::warn!(server = %server.uuid, "failed to clear firewall rules: {err:#}");
                }
            }
            self.network.refresh_nat().await
        }
        .await;
        if let Err(err) = created {
            if let Err(cleanup) = self.remove_instance(name).await {
                tracing::warn!(instance = %name, "could not remove a half-created instance: {cleanup:#}");
            }
            return Err(err);
        }
        Ok(())
    }

    pub(super) async fn prepare_data_mount(&self, server: &Server) -> anyhow::Result<PathBuf> {
        use crate::server::filesystem::limiter::DiskLimiterMode;
        ensure!(
            !server.filesystem.is_uninitialized(),
            "Wings server filesystem is not initialized"
        );
        let mode = self.config.load().system.disk_limiter_mode;
        let limiter = server.filesystem.get_disk_limiter();
        limiter
            .attach()
            .await
            .context("attaching the server disk limiter")?;
        limiter
            .startup()
            .await
            .context("starting the server disk limiter")?;
        let source = server.filesystem.get_base_fs_mount_path().await;
        if mode == DiskLimiterMode::FuseQuota {
            let fuse = crate::server::filesystem::limiter::fuse_quota::FuseQuotaLimiter {
                filesystem: &server.filesystem,
            };
            tokio::time::timeout(
                Duration::from_secs(self.config.load().runtime.incus.operation_timeout_seconds),
                async {
                    loop {
                        let mounted = rustix::fs::statfs(&source)
                            .is_ok_and(|stat| stat.f_type == 0x6573_5546);
                        if mounted && fuse.is_socket_functional().await {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            )
            .await
            .context("waiting for the quota filesystem to mount")?;
        }
        limiter
            .update_disk_limit(server.filesystem.disk_limit() as u64)
            .await
            .context("applying the server data quota")?;
        Ok(source)
    }

    pub(super) async fn verify_data_mount(
        &self,
        server: &Server,
        instance: &Instance,
    ) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.check_owner(instance)?;
        let source = self.prepare_data_mount(server).await?;
        ensure!(
            instance
                .effective_devices()
                .get("data")
                .and_then(|device| device.get("source"))
                == Some(&source.display().to_string()),
            "running Incus server uses a different data mount; stop it before changing filesystem configuration"
        );
        let state: InstanceState = self
            .client
            .get(&format!("{}/state", Self::instance_path(&instance.name)))
            .await?;
        ensure!(state.pid > 0, "running Incus server has no host PID");
        let host = tokio::fs::metadata(&source).await?;
        let guest = tokio::fs::metadata(format!("/proc/{}/root/home/container", state.pid)).await?;
        ensure!(
            host.dev() == guest.dev() && host.ino() == guest.ino(),
            "running Incus server has a stale data mount; stop it before recovering the quota filesystem"
        );
        Ok(())
    }

    pub(super) async fn setup_helper(
        &self,
        server: &Server,
        script: &InstallationScript,
        installation: bool,
    ) -> anyhow::Result<(String, Arc<dyn ProcessHandle>, StatusReceiver)> {
        server.log_daemon_install("[Incus] Preparing server data permissions...".into());
        server
            .filesystem
            .async_chown_path_recursive(&server.filesystem.base_path)
            .await
            .context("preparing Incus helper data permissions")?;
        let image = self
            .images
            // Script containers pull quietly, as with docker.
            .ensure(&script.container_image, server, !installation)
            .await?;
        let (role, name) = if installation {
            (Role::Installer, format!("wgi-{}", server.uuid))
        } else {
            let identity = uuid::Uuid::new_v4().simple().to_string();
            (
                Role::Script,
                format!(
                    "wgx-{}-{}",
                    server.uuid,
                    identity.get(..16).context("helper ID")?
                ),
            )
        };
        let staging = if installation {
            self.config.tmp_data_path(server.uuid)
        } else {
            self.state_root().join("scripts").join(&name)
        };
        let (target, filename) = if installation {
            ("/mnt/install", "install.sh")
        } else {
            ("/mnt/script", "script.sh")
        };
        tokio::fs::create_dir_all(&staging).await?;
        let mut environment = script.environment.clone();
        if installation {
            for (variable, file) in [
                (
                    "INSTALL_STATUS_FILE",
                    crate::server::installation::INSTALL_STATUS_FILE_NAME,
                ),
                (
                    "INSTALL_PROGRESS_FILE",
                    crate::server::installation::INSTALL_PROGRESS_FILE_NAME,
                ),
            ] {
                tokio::fs::write(staging.join(file), []).await?;
                environment.insert(variable.into(), Value::String(format!("{target}/{file}")));
            }
        }
        tokio::fs::write(staging.join(filename), script.script.replace("\r\n", "\n")).await?;
        let launched = async {
            self.create(
                server,
                &name,
                &image,
                Launch {
                    role,
                    command: Some(vec![
                        script.entrypoint.to_string(),
                        format!("{target}/{filename}"),
                    ]),
                    environment,
                    staging: Some((staging.clone(), target)),
                },
            )
            .await?;
            process::Handle::connect(self.clone(), server, name.clone(), false).await
        }
        .await;
        match launched {
            Ok((handle, status_rx)) => Ok((name, handle, status_rx)),
            Err(err) => {
                if let Err(cleanup) = self.remove_instance(&name).await {
                    tracing::warn!(instance = %name, "could not remove a failed helper instance: {cleanup:#}");
                }
                Err(err)
            }
        }
    }
}
