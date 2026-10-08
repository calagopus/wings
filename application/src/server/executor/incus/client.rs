use anyhow::{Context, bail, ensure};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};

#[derive(Clone)]
pub(super) struct Client {
    http: reqwest::Client,
    pub socket: PathBuf,
    pub project: String,
    timeout: Duration,
}

#[derive(Debug)]
pub(super) struct ApiError {
    pub status: StatusCode,
    pub message: String,
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Incus API {}: {}", self.status, self.message)
    }
}
impl std::error::Error for ApiError {}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ResponseType {
    Sync,
    Async,
    Error,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    metadata: Value,
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_code: i32,
    #[serde(default)]
    operation: String,
    #[serde(rename = "type")]
    kind: ResponseType,
}

pub(super) fn segment(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}
pub(super) fn is_status(error: &anyhow::Error, status: StatusCode) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|err| err.status == status)
}

impl Client {
    pub(super) fn new(config: &crate::config::IncusRuntime) -> anyhow::Result<Self> {
        let timeout = Duration::from_secs(config.operation_timeout_seconds);
        Ok(Self {
            http: reqwest::Client::builder()
                .unix_socket(config.socket.clone())
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()?,
            socket: config.socket.clone().into(),
            project: config.project.clone(),
            timeout,
        })
    }

    pub(super) fn url(&self, path: &str, project: bool) -> anyhow::Result<url::Url> {
        anyhow::ensure!(
            path == "/1.0" || path.starts_with("/1.0/") || path.starts_with("/1.0?"),
            "invalid Incus API path"
        );
        let mut url = url::Url::parse(&format!("http://localhost{path}"))?;
        ensure!(
            (url.path() == "/1.0" || url.path().starts_with("/1.0/")) && url.fragment().is_none(),
            "invalid Incus API path"
        );
        if project {
            url.query_pairs_mut().append_pair("project", &self.project);
        }
        Ok(url)
    }

    pub(super) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        etag: Option<&str>,
        project: bool,
    ) -> anyhow::Result<(Value, Option<String>)> {
        let mut request = self.http.request(method, self.url(path, project)?);
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(etag) = etag {
            request = request.header("If-Match", etag);
        }
        let response = request.send().await.context("connecting to Incus")?;
        let (envelope, etag) = Self::decode(response).await?;
        if envelope.kind == ResponseType::Async {
            Self::validate_operation(&envelope.operation)?;
            return Ok((self.wait(&envelope.operation).await?, etag));
        }
        Ok((envelope.metadata, etag))
    }

    async fn decode(response: reqwest::Response) -> anyhow::Result<(Envelope, Option<String>)> {
        let status = response.status();
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let envelope = response.json::<Envelope>().await;
        if !status.is_success() {
            return Err(ApiError {
                status,
                message: envelope
                    .ok()
                    .map(|response| response.error)
                    .filter(|message| !message.is_empty())
                    .unwrap_or_else(|| {
                        status.canonical_reason().unwrap_or("request failed").into()
                    }),
            }
            .into());
        }
        let envelope = envelope.context("decoding Incus response")?;
        if envelope.error_code != 0 || envelope.kind == ResponseType::Error {
            return Err(ApiError {
                status: u16::try_from(envelope.error_code)
                    .ok()
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .filter(|status| status.is_client_error() || status.is_server_error())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                message: envelope.error,
            }
            .into());
        }
        Ok((envelope, etag))
    }

    fn validate_operation(operation: &str) -> anyhow::Result<()> {
        let id = operation
            .strip_prefix("/1.0/operations/")
            .context("missing or invalid Incus operation URL")?;
        ensure!(
            !id.is_empty()
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "invalid Incus operation ID"
        );
        Ok(())
    }

    pub(super) async fn get_with_etag<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> anyhow::Result<(T, Option<String>)> {
        let (value, etag) = self.request(Method::GET, path, None, None, true).await?;
        Ok((
            serde_json::from_value(value).context("decoding Incus metadata")?,
            etag,
        ))
    }

    pub(super) async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        Ok(self.get_with_etag(path).await?.0)
    }
    pub(super) async fn optional<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> anyhow::Result<Option<T>> {
        match self.get(path).await {
            Ok(value) => Ok(Some(value)),
            Err(err) if is_status(&err, StatusCode::NOT_FOUND) => Ok(None),
            Err(err) => Err(err),
        }
    }
    pub(super) async fn mutate(
        &self,
        method: Method,
        path: &str,
        body: Value,
    ) -> anyhow::Result<Value> {
        Ok(self.request(method, path, Some(&body), None, true).await?.0)
    }
    async fn wait(&self, operation: &str) -> anyhow::Result<Value> {
        let mut url = self.url(&format!("{operation}/wait"), true)?;
        url.query_pairs_mut()
            .append_pair("timeout", &self.timeout.as_secs().to_string());
        let response = self.http.get(url).send().await?;
        let (envelope, _) = Self::decode(response).await?;
        ensure!(
            envelope.kind == ResponseType::Sync,
            "invalid Incus operation wait response"
        );
        let code = envelope
            .metadata
            .get("status_code")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if code != 200 {
            bail!(
                "Incus operation failed or timed out: {}",
                envelope
                    .metadata
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("no final result")
            );
        }
        Ok(envelope.metadata)
    }

    pub(super) async fn state(&self, name: &str, action: &str, force: bool) -> anyhow::Result<()> {
        let body = json!({
            "action": action,
            "force": force,
            "timeout": self.timeout.as_secs(),
            "stateful": false,
        });
        self.mutate(
            Method::PUT,
            &format!("/1.0/instances/{}/state", segment(name)),
            body,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn console(&self, name: &str) -> anyhow::Result<(String, Value)> {
        let response = self
            .http
            .post(self.url(&format!("/1.0/instances/{}/console", segment(name)), true)?)
            .json(&json!({"type": "console", "width": 120, "height": 40}))
            .send()
            .await?;
        let (envelope, _) = Self::decode(response).await?;
        ensure!(
            envelope.kind == ResponseType::Async,
            "invalid Incus console response"
        );
        Self::validate_operation(&envelope.operation)?;
        let fds = envelope
            .metadata
            .get("metadata")
            .and_then(|m| m.get("fds"))
            .cloned()
            .context("missing console descriptors")?;
        Ok((envelope.operation, fds))
    }
    pub(super) async fn websocket(
        &self,
        operation: &str,
        secret: &str,
    ) -> anyhow::Result<tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>> {
        Self::validate_operation(operation)?;
        let mut url = self.url(&format!("{operation}/websocket"), true)?;
        url.set_scheme("ws")
            .map_err(|_| anyhow::anyhow!("invalid websocket URL"))?;
        url.query_pairs_mut().append_pair("secret", secret);
        tokio::time::timeout(self.timeout, async {
            let stream = tokio::net::UnixStream::connect(&self.socket).await?;
            Ok::<_, anyhow::Error>(
                tokio_tungstenite::client_async(url.as_str(), stream)
                    .await?
                    .0,
            )
        })
        .await
        .context("connecting to Incus console timed out")?
    }

    pub(super) async fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        self.read_bytes(path, 4096).await
    }
    pub(super) async fn console_buffer(&self, name: &str) -> anyhow::Result<Vec<u8>> {
        self.read_bytes(
            &format!("/1.0/instances/{}/console", segment(name)),
            1024 * 1024,
        )
        .await
    }
    async fn read_bytes(&self, path: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
        let response = self.http.get(self.url(path, true)?).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError {
                status,
                message: "file read failed".into(),
            }
            .into());
        }
        anyhow::ensure!(
            response.content_length().unwrap_or(0) <= limit as u64,
            "oversized Incus status file"
        );
        use futures::StreamExt;
        let mut stream = response.bytes_stream();
        let mut data = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            anyhow::ensure!(
                data.len() + chunk.len() <= limit,
                "oversized Incus status file"
            );
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
    pub(super) async fn directory(
        &self,
        path: &str,
        uid: u32,
        gid: u32,
        mode: &str,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .post(self.url(path, true)?)
            .header("X-Incus-type", "directory")
            .header("X-Incus-mode", mode)
            .header("X-Incus-uid", uid.to_string())
            .header("X-Incus-gid", gid.to_string())
            .send()
            .await?;
        Self::decode(response).await?;
        Ok(())
    }

    pub(super) async fn write_file(
        &self,
        path: &str,
        data: Vec<u8>,
        uid: u32,
        gid: u32,
        mode: &str,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .post(self.url(path, true)?)
            .header("X-Incus-type", "file")
            .header("X-Incus-mode", mode)
            .header("X-Incus-uid", uid.to_string())
            .header("X-Incus-gid", gid.to_string())
            .body(data)
            .send()
            .await?;
        Self::decode(response).await?;
        Ok(())
    }
}
