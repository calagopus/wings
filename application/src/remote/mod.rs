use crate::server::{
    activity::ApiActivity, permissions::Permissions, schedule::ApiScheduleCompletionStatus,
};
use client::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

pub mod backups;
pub mod client;
pub mod jwt;
pub mod servers;

#[inline]
pub fn into_json<T: DeserializeOwned>(value: String) -> Result<T, anyhow::Error> {
    match serde_json::from_str(&value) {
        Ok(json) => Ok(json),
        Err(err) => Err(anyhow::anyhow!("failed to parse JSON: {:#?}", err)),
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub status: reqwest::StatusCode,
    pub errors: Vec<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors.is_empty() {
            write!(f, "remote api request failed with status {}", self.status)
        } else {
            write!(
                f,
                "remote api request failed with status {}: {}",
                self.status,
                self.errors.join(", ")
            )
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn message_or(
        err: &anyhow::Error,
        fallback: &'static str,
    ) -> std::borrow::Cow<'static, str> {
        match err.downcast_ref::<ApiError>() {
            Some(api_err) if !api_err.errors.is_empty() => {
                std::borrow::Cow::Owned(format!("panel error: {}", api_err.errors.join(", ")))
            }
            _ => std::borrow::Cow::Borrowed(fallback),
        }
    }
}

#[derive(Deserialize)]
struct ApiErrorBody {
    errors: Vec<String>,
}

pub trait ResponseExt: Sized {
    async fn error_for_remote_status(self) -> Result<reqwest::Response, anyhow::Error>;
}

impl ResponseExt for reqwest::Response {
    async fn error_for_remote_status(self) -> Result<reqwest::Response, anyhow::Error> {
        let status = self.status();
        if status.is_client_error() || status.is_server_error() {
            let body = self.text().await.unwrap_or_default();
            let errors = serde_json::from_str::<ApiErrorBody>(&body)
                .map(|parsed| parsed.errors)
                .unwrap_or_else(|_| {
                    let body = body.trim();
                    if body.is_empty() {
                        Vec::new()
                    } else {
                        vec![body.chars().take(200).collect()]
                    }
                });

            return Err(ApiError { status, errors }.into());
        }

        Ok(self)
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct Pagination {
    current_page: usize,
    last_page: usize,
    total: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationType {
    Password,
    PublicKey,
}

pub async fn get_sftp_auth(
    client: &Client,
    r#type: AuthenticationType,
    username: &str,
    password: &str,
) -> Result<(uuid::Uuid, uuid::Uuid, Permissions, Vec<String>), anyhow::Error> {
    let response: Response = into_json(
        client
            .client
            .post(format!("{}/sftp/auth", client.url))
            .json(&json!({
                "type": r#type,
                "username": username,
                "password": password,
            }))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    pub struct Response {
        user: uuid::Uuid,
        server: uuid::Uuid,

        permissions: Permissions,
        #[serde(default)]
        ignored_files: Vec<String>,
    }

    Ok((
        response.user,
        response.server,
        response.permissions,
        response.ignored_files,
    ))
}

pub async fn send_activity(
    client: &Client,
    activity: Vec<ApiActivity>,
) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/activity", client.url))
        .json(&json!({
            "data": activity,
        }))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn send_schedule_status(
    client: &Client,
    schedules: Vec<ApiScheduleCompletionStatus>,
) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/schedule", client.url))
        .json(&json!({
            "data": schedules,
        }))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn reset_state(client: &Client) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/servers/reset", client.url))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}
