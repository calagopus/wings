use super::client::{Client, is_status, segment};
use anyhow::{Context, ensure};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(super) struct Storage {
    client: Client,
    pool: String,
    owner: String,
    driver: String,
    config: BTreeMap<String, String>,
}
impl Storage {
    pub(super) fn new(client: Client, config: Arc<crate::config::Config>) -> Self {
        let config = config.load();
        let runtime = &config.runtime.incus;
        let pool = runtime.storage_pool.clone();
        let owner = format!("wings:{}", config.uuid);
        Self {
            client,
            pool,
            owner,
            driver: runtime.storage_driver.clone(),
            config: runtime.storage_config.clone(),
        }
    }
    pub(super) fn control_name(instance: &str) -> String {
        format!("wgc-{instance}")
    }
    pub(super) fn path(&self, volume: &str) -> String {
        format!(
            "/1.0/storage-pools/{}/volumes/custom/{}",
            segment(&self.pool),
            segment(volume)
        )
    }
    pub(super) fn file_path(&self, volume: &str, name: &str) -> String {
        format!(
            "{}/files?path={}",
            self.path(volume),
            segment(&format!("/{name}"))
        )
    }
    pub(super) async fn boot(&self) -> anyhow::Result<()> {
        ensure!(
            !self.pool.is_empty(),
            "Incus storage pool name must not be empty"
        );
        let path = format!("/1.0/storage-pools/{}", segment(&self.pool));
        let pool = match self
            .client
            .request(Method::GET, &path, None, None, false)
            .await
        {
            Ok((pool, _)) => pool,
            Err(err) if is_status(&err, StatusCode::NOT_FOUND) => {
                validate_driver(&self.driver)?;
                let mut config = self.config.clone();
                config.insert("user.wings.owner".into(), self.owner.clone());
                let body = json!({
                    "name": self.pool,
                    "driver": self.driver,
                    "description": self.owner,
                    "config": config,
                });
                match self.client.request(Method::POST, "/1.0/storage-pools", Some(&body), None, false).await {
                    Ok(_) => tracing::info!(pool = self.pool, driver = self.driver, "created Incus storage pool"),
                    Err(err) if is_status(&err, StatusCode::CONFLICT) => {},
                    Err(err) => return Err(err).context("creating Incus storage pool; check the driver prerequisites and runtime.incus.storage_config"),
                }
                self.client
                    .request(Method::GET, &path, None, None, false)
                    .await?
                    .0
            }
            Err(err) => return Err(err),
        };
        let pool: StoragePool =
            serde_json::from_value(pool).context("reading Incus storage pool")?;
        validate_driver(&pool.driver)?;
        ensure!(
            pool.status == "Created",
            "Incus storage pool {} is not ready: {}",
            self.pool,
            pool.status
        );
        tracing::info!(
            pool = self.pool,
            driver = pool.driver,
            "using Incus storage pool"
        );
        if pool.driver == "dir" {
            tracing::info!(
                "Incus dir root/control disk quotas require backing-filesystem project quotas; game-data limits use the Wings disk limiter"
            );
        }
        Ok(())
    }
    pub(super) async fn ensure_volume(&self, name: &str, quota: u64) -> anyhow::Result<()> {
        if let Some(volume) = self.client.optional::<Value>(&self.path(name)).await? {
            self.check_owner(&volume)?;
        } else {
            let mut config = std::collections::BTreeMap::from([
                ("user.wings.owner", self.owner.clone()),
                ("security.shifted", "true".to_owned()),
            ]);
            if quota > 0 {
                config.insert("size", quota.to_string());
            }
            let body = json!({
                "name": name,
                "type": "custom",
                "content_type": "filesystem",
                "config": config,
            });
            self.client
                .mutate(
                    Method::POST,
                    &format!("/1.0/storage-pools/{}/volumes/custom", segment(&self.pool)),
                    body,
                )
                .await?;
        }
        Ok(())
    }
    fn check_owner(&self, volume: &Value) -> anyhow::Result<()> {
        ensure!(
            volume
                .pointer("/config/user.wings.owner")
                .and_then(Value::as_str)
                == Some(&self.owner),
            "refusing unmanaged Incus volume"
        );
        ensure!(
            volume.get("content_type").and_then(Value::as_str) == Some("filesystem"),
            "Incus volume is not a filesystem"
        );
        Ok(())
    }
    pub(super) async fn delete_volume(&self, name: &str) -> anyhow::Result<()> {
        let path = self.path(name);
        if let Some(volume) = self.client.optional::<Value>(&path).await? {
            self.check_owner(&volume)?;
            ensure!(
                volume
                    .get("used_by")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "Incus volume is still attached"
            );
            match self.client.mutate(Method::DELETE, &path, json!({})).await {
                Ok(_) => {}
                Err(err) if is_status(&err, StatusCode::NOT_FOUND) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct StoragePool {
    driver: String,
    status: String,
}

fn validate_driver(driver: &str) -> anyhow::Result<()> {
    ensure!(!driver.is_empty(), "Incus storage driver must not be empty");
    ensure!(
        !matches!(driver, "cephfs" | "cephobject"),
        "Incus storage driver {driver} cannot provide container root disks"
    );
    Ok(())
}
