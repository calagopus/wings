use crate::server::permissions::Permissions;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub mod backups;
pub mod client;
pub mod jwt;
pub mod servers;
#[cfg(unix)]
pub mod tundra;

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

pub trait RequestBuilderExt: Sized {
    async fn send_remote(self) -> Result<reqwest::Response, anyhow::Error>;

    async fn send_remote_json<T: DeserializeOwned>(self) -> Result<T, anyhow::Error>;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    async fn send_remote(self) -> Result<reqwest::Response, anyhow::Error> {
        self.send().await?.error_for_remote_status().await
    }

    async fn send_remote_json<T: DeserializeOwned>(self) -> Result<T, anyhow::Error> {
        into_json(self.send_remote().await?.text().await?)
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

#[derive(Deserialize)]
pub struct SftpAuth {
    pub user: uuid::Uuid,
    pub server: uuid::Uuid,

    pub permissions: Permissions,
    #[serde(default)]
    pub ignored_files: Vec<String>,

    pub as_of: Option<i64>,
}

#[derive(Deserialize)]
pub struct UserServerPermissions {
    pub user: uuid::Uuid,
    pub server: uuid::Uuid,

    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub ignored_files: Vec<String>,
}

#[derive(Deserialize)]
pub struct PermissionsBatch {
    pub as_of: i64,
    pub entries: Vec<UserServerPermissions>,
}
