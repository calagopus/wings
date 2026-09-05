use super::{ResponseExt, client::Client};
use crate::server::backup::adapters::BackupAdapter;
use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Debug, ToSchema, Serialize)]
pub struct RawServerBackupPart {
    pub etag: String,
    pub part_number: usize,
}

#[derive(Debug, Default, ToSchema, Serialize)]
pub struct RawServerBackup {
    pub checksum: String,
    pub checksum_type: compact_str::CompactString,
    pub size: u64,
    pub files: u64,
    pub successful: bool,
    pub browsable: bool,
    pub streaming: bool,
    pub parts: Vec<RawServerBackupPart>,
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct ResticBackupConfiguration {
    pub repository: String,
    pub password_file: Option<String>,
    pub retry_lock_seconds: u64,
    pub environment: BTreeMap<String, String>,
}

impl ResticBackupConfiguration {
    #[inline]
    pub fn password(&self) -> Vec<compact_str::CompactString> {
        if let Some(password_file) = &self.password_file {
            vec!["--password-file".into(), password_file.to_compact_string()]
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct PbsBackupConfiguration {
    pub url: String,
    pub datastore: String,
    pub namespace: Option<String>,
    pub token_id: String,
    pub token_secret: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub backup_id_prefix: Option<String>,
    #[serde(default)]
    pub server_uuid: Option<uuid::Uuid>,
    #[serde(default)]
    pub kind: crate::models::ServerBackupKind,
    pub backup_created: chrono::DateTime<chrono::Utc>,
}

impl PbsBackupConfiguration {
    #[inline]
    pub fn group_id(&self) -> Option<compact_str::CompactString> {
        let server_uuid = self.server_uuid?;

        Some(match self.kind {
            crate::models::ServerBackupKind::Server => server_uuid.to_compact_string(),
            crate::models::ServerBackupKind::DatabaseInstance => {
                compact_str::format_compact!("{server_uuid}-db")
            }
        })
    }

    #[inline]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
    }
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct KopiaBackupConfiguration {
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub tags: BTreeMap<String, String>,
}

impl KopiaBackupConfiguration {
    #[inline]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
    }
}

pub async fn set_backup_status(
    client: &Client,
    uuid: uuid::Uuid,
    data: &RawServerBackup,
) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/backups/{}", client.url, uuid))
        .json(data)
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn set_backup_deletion_status(
    client: &Client,
    uuid: uuid::Uuid,
    successful: bool,
) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/backups/{}/deletion", client.url, uuid))
        .json(&json!({
            "successful": successful,
        }))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn set_backup_restore_status(
    client: &Client,
    server: uuid::Uuid,
    uuid: uuid::Uuid,
    successful: bool,
) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/backups/{}/restore", client.url, uuid))
        .json(&json!({
            "server_uuid": server,
            "successful": successful,
        }))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn set_database_backup_restore_status(
    client: &Client,
    uuid: uuid::Uuid,
    database_instance: uuid::Uuid,
    successful: bool,
) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/backups/{}/database/restore", client.url, uuid))
        .json(&json!({
            "database_instance": database_instance,
            "successful": successful,
        }))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn database_backup_source(
    client: &Client,
    uuid: uuid::Uuid,
    database_instance: uuid::Uuid,
) -> Result<reqwest::Response, anyhow::Error> {
    client
        .stream_client
        .get(format!(
            "{}/backups/{}/database/source?instance={}",
            client.url, uuid, database_instance
        ))
        .send()
        .await?
        .error_for_remote_status()
        .await
}

pub async fn database_backup_restore_target(
    client: &Client,
    uuid: uuid::Uuid,
    database_instance: uuid::Uuid,
    body: reqwest::Body,
) -> Result<(), anyhow::Error> {
    client
        .stream_client
        .post(format!(
            "{}/backups/{}/database/restore-target?instance={}",
            client.url, uuid, database_instance
        ))
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn backup_upload_urls(
    client: &Client,
    uuid: uuid::Uuid,
    size: u64,
) -> Result<(u64, Vec<String>), anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .get(format!("{}/backups/{}?size={}", client.url, uuid, size))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        parts: Vec<String>,
        part_size: u64,
    }

    Ok((response.part_size, response.parts))
}

pub async fn backup_s3_part_urls(
    client: &Client,
    uuid: uuid::Uuid,
    from_part: usize,
) -> Result<(u64, Vec<String>), anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .get(format!(
                "{}/backups/{}/s3/parts?from_part={}",
                client.url, uuid, from_part
            ))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        parts: Vec<String>,
        part_size: u64,
    }

    Ok((response.part_size, response.parts))
}

pub async fn backup_restic_configuration(
    client: &Client,
    uuid: uuid::Uuid,
) -> Result<ResticBackupConfiguration, anyhow::Error> {
    let response: ResticBackupConfiguration = super::into_json(
        client
            .client
            .get(format!("{}/backups/{}/restic", client.url, uuid))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    Ok(response)
}

pub async fn backup_pbs_configuration(
    client: &Client,
    uuid: uuid::Uuid,
) -> Result<PbsBackupConfiguration, anyhow::Error> {
    let response: PbsBackupConfiguration = super::into_json(
        client
            .client
            .get(format!("{}/backups/{}/pbs", client.url, uuid))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    Ok(response)
}

pub async fn backup_kopia_configuration(
    client: &Client,
    uuid: uuid::Uuid,
) -> Result<KopiaBackupConfiguration, anyhow::Error> {
    let response: KopiaBackupConfiguration = super::into_json(
        client
            .client
            .get(format!("{}/backups/{}/kopia", client.url, uuid))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    Ok(response)
}

#[allow(clippy::too_many_arguments)]
pub async fn restore_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    backup: Option<uuid::Uuid>,
    backup_name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    oldest: bool,
    truncate_directory: bool,
    restore_startup: bool,
) -> Result<
    (
        BackupAdapter,
        uuid::Uuid,
        Option<compact_str::CompactString>,
    ),
    anyhow::Error,
> {
    let response: Response = super::into_json(
        client
            .client
            .post(format!("{}/servers/{}/backups/restore", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "backup_uuid": backup,
                "backup_name": backup_name,
                "backup_group_uuid": backup_group,
                "oldest": oldest,
                "truncate_directory": truncate_directory,
                "restore_startup": restore_startup,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        adapter: BackupAdapter,
        uuid: uuid::Uuid,
        download_url: Option<compact_str::CompactString>,
    }

    Ok((response.adapter, response.uuid, response.download_url))
}

#[allow(clippy::too_many_arguments)]
pub async fn restore_database_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    backup: Option<uuid::Uuid>,
    backup_name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    oldest: bool,
    source_database_instance: Option<uuid::Uuid>,
    database_instance: Option<uuid::Uuid>,
    request_uuid: uuid::Uuid,
) -> Result<(uuid::Uuid, uuid::Uuid), anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .post(format!(
                "{}/servers/{}/backups/restore-database",
                client.url, server
            ))
            .json(&json!({
                "schedule_uuid": schedule,
                "backup_uuid": backup,
                "backup_name": backup_name,
                "backup_group_uuid": backup_group,
                "oldest": oldest,
                "source_database_instance_uuid": source_database_instance,
                "database_instance_uuid": database_instance,
                "request_uuid": request_uuid,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        uuid: uuid::Uuid,
        database_instance_uuid: uuid::Uuid,
        request_uuid: Option<uuid::Uuid>,
    }

    if response.request_uuid != Some(request_uuid) {
        return Err(anyhow::anyhow!(
            "panel does not support tracking database backup restore requests"
        ));
    }

    Ok((response.uuid, response.database_instance_uuid))
}

#[allow(clippy::too_many_arguments)]
pub async fn delete_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    backup: Option<uuid::Uuid>,
    backup_name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    oldest: bool,
) -> Result<uuid::Uuid, anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .delete(format!("{}/servers/{}/backups", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "backup_uuid": backup,
                "backup_name": backup_name,
                "backup_group_uuid": backup_group,
                "oldest": oldest,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        uuid: uuid::Uuid,
    }

    Ok(response.uuid)
}

#[allow(clippy::too_many_arguments)]
pub async fn delete_database_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    backup: Option<uuid::Uuid>,
    backup_name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    oldest: bool,
    database_instance: Option<uuid::Uuid>,
) -> Result<uuid::Uuid, anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .delete(format!("{}/servers/{}/backups", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "backup_uuid": backup,
                "backup_name": backup_name,
                "backup_group_uuid": backup_group,
                "oldest": oldest,
                "kind": "database_instance",
                "database_instance_uuid": database_instance,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        uuid: uuid::Uuid,
    }

    Ok(response.uuid)
}

#[allow(clippy::too_many_arguments)]
pub async fn move_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    backup: Option<uuid::Uuid>,
    backup_name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    oldest: bool,
    target_backup_group: Option<uuid::Uuid>,
) -> Result<uuid::Uuid, anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .patch(format!("{}/servers/{}/backups", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "backup_uuid": backup,
                "backup_name": backup_name,
                "backup_group_uuid": backup_group,
                "oldest": oldest,
                "target_backup_group_uuid": target_backup_group,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        uuid: uuid::Uuid,
    }

    Ok(response.uuid)
}

#[allow(clippy::too_many_arguments)]
pub async fn move_database_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    backup: Option<uuid::Uuid>,
    backup_name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    oldest: bool,
    target_backup_group: Option<uuid::Uuid>,
    database_instance: Option<uuid::Uuid>,
) -> Result<uuid::Uuid, anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .patch(format!("{}/servers/{}/backups", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "backup_uuid": backup,
                "backup_name": backup_name,
                "backup_group_uuid": backup_group,
                "oldest": oldest,
                "target_backup_group_uuid": target_backup_group,
                "kind": "database_instance",
                "database_instance_uuid": database_instance,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        uuid: uuid::Uuid,
    }

    Ok(response.uuid)
}

pub async fn create_database_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    database_instance: uuid::Uuid,
    name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
) -> Result<(BackupAdapter, uuid::Uuid, compact_str::CompactString), anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .post(format!("{}/servers/{}/backups", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "name": name,
                "backup_group_uuid": backup_group,
                "database_instance_uuid": database_instance,
                "ignored_files": [],
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        adapter: BackupAdapter,
        uuid: uuid::Uuid,
        extension: Option<compact_str::CompactString>,
    }

    let extension = response
        .extension
        .ok_or_else(|| anyhow::anyhow!("panel did not return a database dump extension"))?;

    Ok((response.adapter, response.uuid, extension))
}

pub async fn create_backup(
    client: &Client,
    server: uuid::Uuid,
    schedule: Option<uuid::Uuid>,
    name: Option<&str>,
    backup_group: Option<uuid::Uuid>,
    ignored_files: &[impl Serialize + AsRef<str>],
) -> Result<(BackupAdapter, uuid::Uuid), anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .post(format!("{}/servers/{}/backups", client.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "name": name,
                "backup_group_uuid": backup_group,
                "ignored_files": ignored_files,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        adapter: BackupAdapter,
        uuid: uuid::Uuid,
    }

    Ok((response.adapter, response.uuid))
}
