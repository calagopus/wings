use super::{
    Devices, IncusExecutor, Instance, InstanceState, image, network, process, storage::Storage,
};
use crate::server::executor::{ProcessHandle, StatusReceiver};
use crate::server::{Server, installation::InstallationScript};
use anyhow::{Context, ensure};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

impl IncusExecutor {
    pub(super) async fn create(
        &self,
        server: &Server,
        name: &str,
        image: &image::Image,
        command: Option<Vec<String>>,
        installer: bool,
        extra_env: &HashMap<compact_str::CompactString, Value>,
    ) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        let cfg = server.configuration.read().await;
        Self::validate_server(&cfg)?;
        let runtime = self.config.load().runtime.incus.clone();
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
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let address = self.network.allocate(&instances).await?;
        let control = Storage::control_name(name);
        self.storage
            .ensure_volume(&control, 16 * 1024 * 1024)
            .await?;
        let mut config = self.process_config(&cfg, image, installer, command)?;
        config.extend(BTreeMap::from([
            ("user.wings.owner".into(), self.owner.clone()),
            ("user.wings.server".into(), server.uuid.to_string()),
            ("user.wings.ip".into(), address.to_string()),
            ("user.wings.digest".into(), image.digest.clone()),
            (
                "user.wings.image-env".into(),
                serde_json::to_string(&image.environment)?,
            ),
            (
                "user.wings.allocations".into(),
                serde_json::to_string(&network::allocations(&cfg)?)?,
            ),
        ]));
        for (key, value) in extra_env {
            config.insert(
                format!("environment.{key}"),
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            );
        }
        let data_source = self.prepare_data_mount(server).await?;
        ensure!(
            data_source.is_absolute() && data_source.is_dir(),
            "Wings server directory must be initialized before creating an Incus instance"
        );
        let mut devices = Devices::from([
            (
                "root".into(),
                BTreeMap::from([
                    ("type".into(), "disk".into()),
                    ("path".into(), "/".into()),
                    ("pool".into(), runtime.storage_pool.clone()),
                    ("size".into(), runtime.root_disk_size),
                ]),
            ),
            (
                "eth0".into(),
                BTreeMap::from([
                    ("type".into(), "nic".into()),
                    ("network".into(), runtime.network),
                    ("name".into(), "eth0".into()),
                    ("ipv4.address".into(), address.to_string()),
                    ("security.mac_filtering".into(), "true".into()),
                    ("security.ipv4_filtering".into(), "true".into()),
                    ("security.port_isolation".into(), "true".into()),
                ]),
            ),
            (
                "data".into(),
                BTreeMap::from([
                    ("type".into(), "disk".into()),
                    (
                        "source".into(),
                        data_source
                            .to_str()
                            .context("Incus data path is not UTF-8")?
                            .into(),
                    ),
                    (
                        "path".into(),
                        if installer {
                            "/mnt/server"
                        } else {
                            "/home/container"
                        }
                        .into(),
                    ),
                ]),
            ),
            (
                "control".into(),
                BTreeMap::from([
                    ("type".into(), "disk".into()),
                    ("pool".into(), runtime.storage_pool),
                    ("source".into(), control.clone()),
                    ("path".into(), "/opt/wings-control".into()),
                ]),
            ),
        ]);
        if !installer {
            cfg.ensure_vmounts(&self.config).await?;
            for (index, mount) in cfg
                .mounts(&self.config, &server.filesystem)
                .await
                .into_iter()
                .filter(|mount| mount.target != "/home/container")
                .enumerate()
            {
                let source = std::path::Path::new(mount.source.as_str());
                ensure!(
                    source.is_absolute() && source.exists(),
                    "Incus mount source is missing"
                );
                let target = if mount.target == "/etc/hosts" {
                    config.insert("raw.lxc".into(),
                        "lxc.mount.entry = opt/wings-private-hosts etc/hosts none bind,ro,relative,create=file 0 0\n".into());
                    "/opt/wings-private-hosts"
                } else {
                    mount.target.as_str()
                };
                let device = BTreeMap::from([
                    ("type".into(), "disk".into()),
                    ("source".into(), mount.source.to_string()),
                    ("path".into(), target.to_string()),
                    ("readonly".into(), mount.read_only.to_string()),
                ]);
                devices.insert(format!("mount-{index}"), device);
            }
        }
        let body = json!({
            "name": name,
            "type": "container",
            "profiles": [],
            "source": {"type": "image", "fingerprint": image.fingerprint},
            "config": config,
            "devices": devices,
        });
        self.client
            .mutate(Method::POST, "/1.0/instances", body)
            .await?;
        let (mut instance, etag) = self.instance_with_etag(name).await?;
        let uid: u32 = instance
            .config
            .get("oci.uid")
            .context("Incus did not resolve the OCI UID")?
            .parse()?;
        let gid: u32 = instance
            .config
            .get("oci.gid")
            .context("Incus did not resolve the OCI GID")?
            .parse()?;
        instance.config.insert(
            "raw.idmap".into(),
            format!(
                "uid {} {uid}\ngid {} {gid}",
                self.config.load().system.user.uid,
                self.config.load().system.user.gid
            ),
        );
        self.update_instance(&instance, etag.as_deref()).await?;
        self.client
            .directory(
                &self.storage.file_path(&control, "process"),
                uid,
                gid,
                "0700",
            )
            .await?;
        self.client
            .write_file(
                &self.storage.file_path(&control, "process/launch"),
                instance
                    .config
                    .get("user.wings.launch")
                    .context("OCI launch script missing")?
                    .as_bytes()
                    .to_vec(),
                uid,
                gid,
                "0600",
            )
            .await?;
        self.client
            .write_file(
                &self.storage.file_path(&control, "process/exit"),
                Vec::new(),
                uid,
                gid,
                "0600",
            )
            .await?;
        drop(cfg);
        drop(_guard);
        if !installer {
            self.sync_server(server, name).await?;
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
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        server.log_daemon_install("[Incus] Preparing server data permissions...".into());
        server
            .filesystem
            .async_chown_path_recursive(&server.filesystem.base_path)
            .await
            .context("preparing Incus helper data permissions")?;
        let image = self
            .images
            .ensure(&script.container_image, server, installation)
            .await?;
        let name = if installation {
            format!("wgi-{}", server.uuid)
        } else {
            let identity = uuid::Uuid::new_v4().simple().to_string();
            format!(
                "wgx-{}-{}",
                server.uuid,
                identity.get(..16).context("helper ID")?
            )
        };
        let staging = if installation {
            self.config.tmp_data_path(server.uuid)
        } else {
            self.state_root().join("scripts").join(&name)
        };
        tokio::fs::create_dir_all(&staging).await?;
        if installation {
            for filename in [
                crate::server::installation::INSTALL_STATUS_FILE_NAME,
                crate::server::installation::INSTALL_PROGRESS_FILE_NAME,
            ] {
                tokio::fs::write(staging.join(filename), []).await?;
            }
        }
        let target = if installation {
            "/mnt/install"
        } else {
            "/mnt/script"
        };
        let filename = if installation {
            "install.sh"
        } else {
            "script.sh"
        };
        let mut env = script.environment.clone();
        if installation {
            env.insert(
                "INSTALL_STATUS_FILE".into(),
                Value::String(format!(
                    "{target}/{}",
                    crate::server::installation::INSTALL_STATUS_FILE_NAME
                )),
            );
            env.insert(
                "INSTALL_PROGRESS_FILE".into(),
                Value::String(format!(
                    "{target}/{}",
                    crate::server::installation::INSTALL_PROGRESS_FILE_NAME
                )),
            );
        }
        self.create(
            server,
            &name,
            &image,
            Some(vec![
                script.entrypoint.to_string(),
                format!("{target}/{filename}"),
            ]),
            true,
            &env,
        )
        .await?;
        let (mut instance, etag) = self.instance_with_etag(&name).await?;
        instance.devices.insert(
            "staging".into(),
            BTreeMap::from([
                ("type".into(), "disk".into()),
                ("source".into(), staging.display().to_string()),
                ("path".into(), target.into()),
                ("shift".into(), "true".into()),
            ]),
        );
        self.update_instance(&instance, etag.as_deref()).await?;
        tokio::fs::write(staging.join(filename), script.script.replace("\r\n", "\n")).await?;
        process::Handle::connect(self.clone(), server, name, false, false).await
    }
}
