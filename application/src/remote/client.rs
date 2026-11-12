use super::RequestBuilderExt;
use crate::server::{
    activity::ApiActivity,
    backup::adapters::BackupAdapter,
    installation::InstallationScript,
    schedule::{ApiScheduleCompletionStatus, actions::ResolvedBackupSelector},
};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::Debug;

#[derive(Serialize)]
struct SelectorBody<'a, T> {
    schedule_uuid: Option<uuid::Uuid>,
    #[serde(flatten)]
    selector: &'a ResolvedBackupSelector,
    #[serde(flatten)]
    extra: T,
}

pub struct Client {
    pub(super) config: crate::config::RemoteQuery,

    pub(super) client: reqwest::Client,
    pub(super) stream_client: reqwest::Client,
    pub(super) url: String,
}

impl Client {
    pub fn new(config: &crate::config::InnerConfig, ignore_certificate_errors: bool) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            "User-Agent",
            format!(
                "calagopus wings/v{} (id:{})",
                crate::VERSION,
                config.token_id
            )
            .parse()
            .expect("invalid token_id while constructing http client"),
        );
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/vnd.pterodactyl.v1+json"),
        );
        headers.insert(
            "Authorization",
            format!("Bearer {}.{}", config.token_id, config.token)
                .parse()
                .expect("invalid token while constructing http client"),
        );

        for (key, value) in config.remote_headers.iter() {
            if let Ok(key) = HeaderName::try_from(key)
                && let Ok(value) = value.parse()
            {
                headers.insert(key, value);
            }
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .tls_danger_accept_invalid_certs(ignore_certificate_errors)
            .default_headers(headers.clone())
            .build()
            .expect("failed to build HTTP client");
        let stream_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(config.remote_query.timeout))
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .tls_danger_accept_invalid_certs(ignore_certificate_errors)
            .http1_only()
            .default_headers(headers)
            .build()
            .expect("failed to build streaming HTTP client");

        Self {
            config: config.remote_query,
            client,
            stream_client,
            url: format!("{}/api/remote", config.remote.trim_end_matches('/')),
        }
    }

    async fn retry<T, E: Debug, Fut: Future<Output = Result<T, E>>>(
        &self,
        func: impl Fn() -> Fut,
        should_retry: impl Fn(&E, usize) -> bool,
    ) -> Result<T, E> {
        let mut tries = 0;
        let mut last_err = None;

        while tries < self.config.retry_limit {
            match func().await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    if !should_retry(&err, (tries + 1) as usize) {
                        return Err(err);
                    }

                    tracing::error!("retry attempt {} failed: {:#?}", tries + 1, err);

                    last_err = Some(err);
                    tries += 1;

                    if tries < self.config.retry_limit {
                        let backoff_secs = tries.pow(2);
                        let jitter = rand::random::<f32>() * 0.3;
                        let sleep_duration = std::time::Duration::from_secs_f32(
                            backoff_secs as f32 * (1.0 + jitter),
                        );

                        tokio::time::sleep(sleep_duration).await;
                    }
                }
            }
        }

        Err(last_err.expect("No attempts were made"))
    }

    fn is_client_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<reqwest::Error>()
            .is_some_and(|err| err.status().is_some_and(|s| s.is_client_error()))
            || err
                .downcast_ref::<super::ApiError>()
                .is_some_and(|err| err.status.is_client_error())
    }

    fn skip_client_errors(err: &anyhow::Error, attempt: usize) -> bool {
        attempt <= 3 || !Self::is_client_error(err)
    }

    /// A rejected login is final, and the client is waiting inside its authentication
    /// round trip, so only a few attempts are made and only for server or network errors.
    fn retry_sftp_auth_errors(err: &anyhow::Error, attempt: usize) -> bool {
        attempt < 3 && !Self::is_client_error(err)
    }

    #[tracing::instrument(skip(self, password))]
    pub async fn get_sftp_auth(
        &self,
        r#type: super::AuthenticationType,
        username: &str,
        password: &str,
    ) -> Result<super::SftpAuth, anyhow::Error> {
        tracing::debug!("getting sftp auth");

        self.retry(
            || self.raw_get_sftp_auth(r#type, username, password),
            Self::retry_sftp_auth_errors,
        )
        .await
    }

    async fn raw_get_sftp_auth(
        &self,
        r#type: super::AuthenticationType,
        username: &str,
        password: &str,
    ) -> Result<super::SftpAuth, anyhow::Error> {
        self.client
            .post(format!("{}/sftp/auth", self.url))
            .json(&json!({
                "type": r#type,
                "username": username,
                "password": password,
            }))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self, entries))]
    pub async fn get_permissions(
        &self,
        entries: &[(uuid::Uuid, uuid::Uuid)],
    ) -> Result<super::PermissionsBatch, anyhow::Error> {
        tracing::debug!("getting permissions of {} users", entries.len());

        self.retry(
            || self.raw_get_permissions(entries),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_get_permissions(
        &self,
        entries: &[(uuid::Uuid, uuid::Uuid)],
    ) -> Result<super::PermissionsBatch, anyhow::Error> {
        self.client
            .post(format!("{}/permissions", self.url))
            .json(&json!({
                "entries": entries
                    .iter()
                    .map(|(server, user)| json!({ "server": server, "user": user }))
                    .collect::<Vec<_>>(),
            }))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn send_activity(&self, activity: Vec<ApiActivity>) -> Result<(), anyhow::Error> {
        tracing::debug!("sending {} activity to remote", activity.len());

        self.client
            .post(format!("{}/activity", self.url))
            .json(&json!({
                "data": activity,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn send_schedule_status(
        &self,
        schedules: Vec<ApiScheduleCompletionStatus>,
    ) -> Result<(), anyhow::Error> {
        tracing::debug!("sending {} schedule status to remote", schedules.len());

        self.client
            .post(format!("{}/schedule", self.url))
            .json(&json!({
                "data": schedules,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn reset_state(&self) -> Result<(), anyhow::Error> {
        tracing::info!("resetting remote state");

        self.retry(|| self.raw_reset_state(), Self::skip_client_errors)
            .await
    }

    async fn raw_reset_state(&self) -> Result<(), anyhow::Error> {
        self.client
            .post(format!("{}/servers/reset", self.url))
            .send_remote()
            .await?;

        Ok(())
    }

    pub async fn servers(&self) -> Result<Vec<super::servers::RawServer>, anyhow::Error> {
        tracing::info!("fetching all servers from remote");

        let mut servers = Vec::new();

        let mut page = 1;
        loop {
            tracing::info!("fetching page {} of servers", page);
            let (new_servers, pagination) = self
                .retry(|| self.raw_servers_page(page), Self::skip_client_errors)
                .await?;
            servers.extend(new_servers);

            if pagination.current_page >= pagination.last_page {
                break;
            }

            page += 1;
        }

        tracing::info!("fetched {} servers from remote", servers.len());

        Ok(servers)
    }

    async fn raw_servers_page(
        &self,
        page: usize,
    ) -> Result<(Vec<super::servers::RawServer>, super::Pagination), anyhow::Error> {
        let response: Response = self
            .client
            .get(format!(
                "{}/servers?page={}&per_page={}",
                self.url, page, self.config.boot_servers_per_page
            ))
            .send_remote_json()
            .await?;

        #[derive(Deserialize, Default)]
        struct Response {
            data: Vec<super::servers::RawServer>,
            meta: super::Pagination,
        }

        Ok((response.data, response.meta))
    }

    pub async fn server(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<super::servers::RawServer, anyhow::Error> {
        self.retry(|| self.raw_server(uuid), Self::skip_client_errors)
            .await
    }

    async fn raw_server(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<super::servers::RawServer, anyhow::Error> {
        self.client
            .get(format!("{}/servers/{}", self.url, uuid))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn server_install_script(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<InstallationScript, anyhow::Error> {
        tracing::info!("fetching server install script");

        self.retry(
            || self.raw_server_install_script(uuid),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_server_install_script(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<InstallationScript, anyhow::Error> {
        self.client
            .get(format!("{}/servers/{}/install", self.url, uuid))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_server_install(
        &self,
        uuid: uuid::Uuid,
        successful: bool,
        reinstalled: bool,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting server install status");

        self.retry(
            || self.raw_set_server_install(uuid, successful, reinstalled),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_set_server_install(
        &self,
        uuid: uuid::Uuid,
        successful: bool,
        reinstalled: bool,
    ) -> Result<(), anyhow::Error> {
        self.client
            .post(format!("{}/servers/{}/install", self.url, uuid))
            .json(&json!({
                "successful": successful,
                "reinstall": reinstalled
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_server_transfer(
        &self,
        uuid: uuid::Uuid,
        successful: bool,
        received_backups: &crate::server::backup::transfer::ReceivedBackups,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting server transfer status");

        self.retry(
            || self.raw_set_server_transfer(uuid, successful, received_backups),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_set_server_transfer(
        &self,
        uuid: uuid::Uuid,
        successful: bool,
        received_backups: &crate::server::backup::transfer::ReceivedBackups,
    ) -> Result<(), anyhow::Error> {
        self.client
            .post(format!(
                "{}/servers/{}/transfer/{}",
                self.url,
                uuid,
                if successful { "success" } else { "failure" }
            ))
            .json(&json!({
                "backups": received_backups.uuids,
                "backup_migrations": received_backups.migrations,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_server_startup_variable(
        &self,
        uuid: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        env_variable: &str,
        value: &str,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting server startup variable");

        self.client
            .put(format!("{}/servers/{}/startup/variables", self.url, uuid))
            .json(&json!({
                "schedule_uuid": schedule,
                "env_variable": env_variable,
                "value": value,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_server_startup_command(
        &self,
        uuid: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        command: &str,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting server startup command");

        self.client
            .put(format!("{}/servers/{}/startup/command", self.url, uuid))
            .json(&json!({
                "schedule_uuid": schedule,
                "command": command,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_server_startup_docker_image(
        &self,
        uuid: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        image: &str,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting server startup docker image");

        self.client
            .put(format!(
                "{}/servers/{}/startup/docker-image",
                self.url, uuid
            ))
            .json(&json!({
                "schedule_uuid": schedule,
                "image": image,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_backup_status(
        &self,
        uuid: uuid::Uuid,
        data: &super::backups::RawServerBackup,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting backup status");

        self.retry(
            || self.raw_set_backup_status(uuid, data),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_set_backup_status(
        &self,
        uuid: uuid::Uuid,
        data: &super::backups::RawServerBackup,
    ) -> Result<(), anyhow::Error> {
        self.client
            .post(format!("{}/backups/{}", self.url, uuid))
            .json(data)
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_backup_deletion_status(
        &self,
        uuid: uuid::Uuid,
        successful: bool,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting backup deletion status");

        self.retry(
            || self.raw_set_backup_deletion_status(uuid, successful),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_set_backup_deletion_status(
        &self,
        uuid: uuid::Uuid,
        successful: bool,
    ) -> Result<(), anyhow::Error> {
        self.client
            .post(format!("{}/backups/{}/deletion", self.url, uuid))
            .json(&json!({
                "successful": successful,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_backup_restore_status(
        &self,
        server: uuid::Uuid,
        uuid: uuid::Uuid,
        successful: bool,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting backup restore status");

        self.retry(
            || self.raw_set_backup_restore_status(server, uuid, successful),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_set_backup_restore_status(
        &self,
        server: uuid::Uuid,
        uuid: uuid::Uuid,
        successful: bool,
    ) -> Result<(), anyhow::Error> {
        self.client
            .post(format!("{}/backups/{}/restore", self.url, uuid))
            .json(&json!({
                "server_uuid": server,
                "successful": successful,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_database_backup_restore_status(
        &self,
        uuid: uuid::Uuid,
        database_instance: uuid::Uuid,
        successful: bool,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setting database backup restore status");

        self.retry(
            || self.raw_set_database_backup_restore_status(uuid, database_instance, successful),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_set_database_backup_restore_status(
        &self,
        uuid: uuid::Uuid,
        database_instance: uuid::Uuid,
        successful: bool,
    ) -> Result<(), anyhow::Error> {
        self.client
            .post(format!("{}/backups/{}/database/restore", self.url, uuid))
            .json(&json!({
                "database_instance": database_instance,
                "successful": successful,
            }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn database_backup_source(
        &self,
        uuid: uuid::Uuid,
        database_instance: uuid::Uuid,
    ) -> Result<reqwest::Response, anyhow::Error> {
        tracing::info!("opening database backup source stream");

        self.stream_client
            .get(format!(
                "{}/backups/{}/database/source?instance={}",
                self.url, uuid, database_instance
            ))
            .send_remote()
            .await
    }

    #[tracing::instrument(skip(self, body))]
    pub async fn database_backup_restore_target(
        &self,
        uuid: uuid::Uuid,
        database_instance: uuid::Uuid,
        body: reqwest::Body,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("streaming database backup into restore target");

        self.stream_client
            .post(format!(
                "{}/backups/{}/database/restore-target?instance={}",
                self.url, uuid, database_instance
            ))
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send_remote()
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn create_database_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        database_instance: uuid::Uuid,
        name: Option<&str>,
        backup_group: Option<uuid::Uuid>,
    ) -> Result<(BackupAdapter, uuid::Uuid, compact_str::CompactString), anyhow::Error> {
        tracing::info!("creating database backup");

        let response: Response = self
            .client
            .post(format!("{}/servers/{}/backups", self.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "name": name,
                "backup_group_uuid": backup_group,
                "database_instance_uuid": database_instance,
                "ignored_files": [],
            }))
            .send_remote_json()
            .await?;

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

    #[tracing::instrument(skip(self))]
    pub async fn backup_upload_urls(
        &self,
        uuid: uuid::Uuid,
        size: u64,
    ) -> Result<(u64, Vec<String>), anyhow::Error> {
        tracing::info!("getting backup upload urls");

        self.retry(
            || self.raw_backup_upload_urls(uuid, size),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_backup_upload_urls(
        &self,
        uuid: uuid::Uuid,
        size: u64,
    ) -> Result<(u64, Vec<String>), anyhow::Error> {
        let response: Response = self
            .client
            .get(format!("{}/backups/{}?size={}", self.url, uuid, size))
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            parts: Vec<String>,
            part_size: u64,
        }

        Ok((response.part_size, response.parts))
    }

    #[tracing::instrument(skip(self))]
    pub async fn backup_s3_part_urls(
        &self,
        uuid: uuid::Uuid,
        from_part: usize,
    ) -> Result<(u64, Vec<String>), anyhow::Error> {
        tracing::info!("getting backup S3 part URLs");

        self.retry(
            || self.raw_backup_s3_part_urls(uuid, from_part),
            Self::skip_client_errors,
        )
        .await
    }

    async fn raw_backup_s3_part_urls(
        &self,
        uuid: uuid::Uuid,
        from_part: usize,
    ) -> Result<(u64, Vec<String>), anyhow::Error> {
        let response: Response = self
            .client
            .get(format!(
                "{}/backups/{}/s3/parts?from_part={}",
                self.url, uuid, from_part
            ))
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            parts: Vec<String>,
            part_size: u64,
        }

        Ok((response.part_size, response.parts))
    }

    #[tracing::instrument(skip(self))]
    pub async fn backup_restic_configuration(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<super::backups::ResticBackupConfiguration, anyhow::Error> {
        tracing::info!("getting restic backup configuration");

        self.client
            .get(format!("{}/backups/{}/restic", self.url, uuid))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn backup_pbs_configuration(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<super::backups::PbsBackupConfiguration, anyhow::Error> {
        tracing::info!("getting proxmox backup server backup configuration");

        self.client
            .get(format!("{}/backups/{}/pbs", self.url, uuid))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn backup_kopia_configuration(
        &self,
        uuid: uuid::Uuid,
    ) -> Result<super::backups::KopiaBackupConfiguration, anyhow::Error> {
        tracing::info!("getting kopia backup configuration");

        self.client
            .get(format!("{}/backups/{}/kopia", self.url, uuid))
            .send_remote_json()
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn create_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        name: Option<&str>,
        backup_group: Option<uuid::Uuid>,
        ignored_files: &[impl Serialize + Debug + AsRef<str>],
    ) -> Result<(BackupAdapter, uuid::Uuid), anyhow::Error> {
        tracing::info!("creating backup");

        let response: Response = self
            .client
            .post(format!("{}/servers/{}/backups", self.url, server))
            .json(&json!({
                "schedule_uuid": schedule,
                "name": name,
                "backup_group_uuid": backup_group,
                "ignored_files": ignored_files,
            }))
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            adapter: BackupAdapter,
            uuid: uuid::Uuid,
        }

        Ok((response.adapter, response.uuid))
    }

    #[tracing::instrument(skip(self))]
    pub async fn restore_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        selector: &ResolvedBackupSelector,
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
        tracing::info!("requesting backup restore");

        let response: Response = self
            .client
            .post(format!("{}/servers/{}/backups/restore", self.url, server))
            .json(&SelectorBody {
                schedule_uuid: schedule,
                selector,
                extra: json!({
                    "truncate_directory": truncate_directory,
                    "restore_startup": restore_startup,
                }),
            })
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            adapter: BackupAdapter,
            uuid: uuid::Uuid,
            download_url: Option<compact_str::CompactString>,
        }

        Ok((response.adapter, response.uuid, response.download_url))
    }

    #[tracing::instrument(skip(self))]
    pub async fn restore_database_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        selector: &ResolvedBackupSelector,
        source_database_instance: Option<uuid::Uuid>,
        database_instance: Option<uuid::Uuid>,
        request_uuid: uuid::Uuid,
    ) -> Result<(uuid::Uuid, uuid::Uuid), anyhow::Error> {
        tracing::info!("requesting database backup restore");

        let response: Response = self
            .client
            .post(format!(
                "{}/servers/{}/backups/restore-database",
                self.url, server
            ))
            .json(&SelectorBody {
                schedule_uuid: schedule,
                selector,
                extra: json!({
                    "source_database_instance_uuid": source_database_instance,
                    "database_instance_uuid": database_instance,
                    "request_uuid": request_uuid,
                }),
            })
            .send_remote_json()
            .await?;

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

    #[tracing::instrument(skip(self))]
    pub async fn delete_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        selector: &ResolvedBackupSelector,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        tracing::info!("requesting backup deletion");

        let response: Response = self
            .client
            .delete(format!("{}/servers/{}/backups", self.url, server))
            .json(&SelectorBody {
                schedule_uuid: schedule,
                selector,
                extra: (),
            })
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            uuid: uuid::Uuid,
        }

        Ok(response.uuid)
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_database_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        selector: &ResolvedBackupSelector,
        database_instance: Option<uuid::Uuid>,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        tracing::info!("requesting database backup deletion");

        let response: Response = self
            .client
            .delete(format!("{}/servers/{}/backups", self.url, server))
            .json(&SelectorBody {
                schedule_uuid: schedule,
                selector,
                extra: json!({
                    "kind": "database_instance",
                    "database_instance_uuid": database_instance,
                }),
            })
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            uuid: uuid::Uuid,
        }

        Ok(response.uuid)
    }

    #[tracing::instrument(skip(self))]
    pub async fn move_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        selector: &ResolvedBackupSelector,
        target_backup_group: Option<uuid::Uuid>,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        tracing::info!("requesting backup move");

        let response: Response = self
            .client
            .patch(format!("{}/servers/{}/backups", self.url, server))
            .json(&SelectorBody {
                schedule_uuid: schedule,
                selector,
                extra: json!({
                    "target_backup_group_uuid": target_backup_group,
                }),
            })
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            uuid: uuid::Uuid,
        }

        Ok(response.uuid)
    }

    #[tracing::instrument(skip(self))]
    pub async fn move_database_backup(
        &self,
        server: uuid::Uuid,
        schedule: Option<uuid::Uuid>,
        selector: &ResolvedBackupSelector,
        target_backup_group: Option<uuid::Uuid>,
        database_instance: Option<uuid::Uuid>,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        tracing::info!("requesting database backup move");

        let response: Response = self
            .client
            .patch(format!("{}/servers/{}/backups", self.url, server))
            .json(&SelectorBody {
                schedule_uuid: schedule,
                selector,
                extra: json!({
                    "target_backup_group_uuid": target_backup_group,
                    "kind": "database_instance",
                    "database_instance_uuid": database_instance,
                }),
            })
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            uuid: uuid::Uuid,
        }

        Ok(response.uuid)
    }

    #[cfg(unix)]
    #[tracing::instrument(skip(self))]
    pub async fn tundra_state(&self) -> Result<super::tundra::TunnelState, anyhow::Error> {
        tracing::debug!("fetching tundra state");

        self.client
            .get(format!("{}/tunnel/state", self.url))
            .send_remote_json()
            .await
    }

    #[cfg(unix)]
    #[tracing::instrument(skip(self))]
    pub async fn tundra_store_cert(
        &self,
        cert_sha256: tundra_common::hash::Hash32,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("publishing the tundra certificate digest");

        self.client
            .post(format!("{}/tunnel/cert", self.url))
            .json(&json!({ "cert_sha256": cert_sha256 }))
            .send_remote()
            .await?;

        Ok(())
    }

    #[cfg(unix)]
    #[tracing::instrument(skip(self))]
    pub async fn tundra_connect_token(&self, target: uuid::Uuid) -> Result<String, anyhow::Error> {
        tracing::debug!("requesting a tundra connect token");

        let response: Response = self
            .client
            .get(format!(
                "{}/tunnel/connect-token?target={}",
                self.url, target
            ))
            .send_remote_json()
            .await?;

        #[derive(Deserialize)]
        struct Response {
            jwt: String,
        }

        Ok(response.jwt)
    }
}
