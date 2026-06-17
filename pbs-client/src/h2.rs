use super::{config::PbsConfig, error::PbsError, naming, tls};
use bytes::Bytes;
use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
};

const WINDOW_SIZE: u32 = (1 << 31) - 2;
const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

fn transport<E: std::fmt::Display>(err: E) -> PbsError {
    PbsError::Transport(err.to_string().into())
}

fn parse_host_port(base_url: &str) -> Result<(String, u16), PbsError> {
    let without_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or_else(|| PbsError::Config("url must start with http:// or https://".into()))?;

    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);

    match host_port.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| PbsError::Config("invalid port in url".into()))?;
            Ok((host.to_string(), port))
        }
        None => Ok((host_port.to_string(), 8007)),
    }
}

pub fn snapshot_query(config: &PbsConfig, backup_id: &str, backup_time: i64) -> String {
    let mut params: Vec<(&str, String)> = vec![
        ("store", config.datastore.to_string()),
        ("backup-type", naming::BACKUP_TYPE.to_string()),
        ("backup-id", backup_id.to_string()),
        ("backup-time", backup_time.to_string()),
    ];
    if let Some(ns) = &config.namespace
        && !ns.is_empty()
    {
        params.push(("ns", ns.to_string()));
    }
    encode_query(&params)
}

pub fn encode_query(params: &[(&str, String)]) -> String {
    let mut out = String::new();
    for (key, value) in params {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&percent_encode(value));
    }
    out
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}

pub fn unwrap_data(body: &[u8]) -> Result<serde_json::Value, PbsError> {
    if body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    let envelope: serde_json::Value =
        serde_json::from_slice(body).map_err(|err| PbsError::Decode(err.to_string().into()))?;
    Ok(envelope
        .get("data")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

struct ConnectionTasks {
    handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct H2Transport {
    send: h2::client::SendRequest<Bytes>,
    authority: String,
    tasks: Arc<ConnectionTasks>,
}

impl H2Transport {
    pub async fn connect(
        config: &PbsConfig,
        protocol: &str,
        endpoint: &str,
        session_query: &str,
    ) -> Result<Self, PbsError> {
        let (host, port) = parse_host_port(config.base_url())?;
        let authority = format!("{host}:{port}");

        let tls_config = tls::build_client_config(&config.fingerprint).map_err(PbsError::Config)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(transport)?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| PbsError::Config("invalid hostname in url".into()))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(transport)?;

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(transport)?;
        let upgrade_task = tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });

        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(format!("/api2/json/{endpoint}?{session_query}"))
            .header(hyper::header::HOST, &authority)
            .header(hyper::header::AUTHORIZATION, config.authorization_header())
            .header(hyper::header::CONNECTION, "upgrade")
            .header(hyper::header::UPGRADE, protocol)
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(transport)?;

        let response = sender.send_request(request).await.map_err(transport)?;
        let status = response.status();
        if status != hyper::StatusCode::SWITCHING_PROTOCOLS {
            return Err(match status {
                hyper::StatusCode::UNAUTHORIZED => PbsError::Unauthorized {
                    token_id: config.token_id.clone(),
                },
                hyper::StatusCode::FORBIDDEN => PbsError::Forbidden {
                    datastore: config.datastore.clone(),
                },
                other => {
                    let body = http_body_util::BodyExt::collect(response.into_body())
                        .await
                        .map(|body| body.to_bytes())
                        .unwrap_or_default();
                    let detail = String::from_utf8_lossy(&body)
                        .chars()
                        .take(512)
                        .collect::<String>();
                    let message = if detail.trim().is_empty() {
                        "PBS did not upgrade the backup protocol connection".to_string()
                    } else {
                        format!("PBS did not upgrade the backup protocol connection: {detail}")
                    };
                    PbsError::Http {
                        status: other.as_u16(),
                        message: message.into(),
                    }
                }
            });
        }

        let upgraded = hyper::upgrade::on(response).await.map_err(transport)?;
        let (send, h2_connection) = h2::client::Builder::new()
            .initial_connection_window_size(WINDOW_SIZE)
            .initial_window_size(WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .handshake(hyper_util::rt::TokioIo::new(upgraded))
            .await
            .map_err(transport)?;
        let driver_task = tokio::spawn(async move {
            let _ = h2_connection.await;
        });

        Ok(Self {
            send,
            authority,
            tasks: Arc::new(ConnectionTasks {
                handles: Mutex::new(vec![upgrade_task, driver_task]),
            }),
        })
    }

    pub async fn close(&self) {
        let handles = {
            let mut guard = self
                .tasks
                .handles
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            std::mem::take(&mut *guard)
        };
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
    }

    fn build_request(
        &self,
        method: hyper::Method,
        path: &str,
        query: &str,
        content_type: Option<&str>,
    ) -> Result<hyper::Request<()>, PbsError> {
        let uri = if query.is_empty() {
            format!("https://{}/{}", self.authority, path)
        } else {
            format!("https://{}/{}?{}", self.authority, path, query)
        };

        let mut builder = hyper::Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header(hyper::header::CONTENT_TYPE, content_type);
        }
        builder.body(()).map_err(transport)
    }

    async fn read_body(&self, response: h2::client::ResponseFuture) -> Result<Vec<u8>, PbsError> {
        let response = response.await.map_err(transport)?;
        let status = response.status();
        let mut body = response.into_body();

        let mut bytes = Vec::new();
        while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
            let chunk = chunk.map_err(transport)?;
            bytes.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }

        if !status.is_success() {
            return Err(PbsError::Http {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(512)
                    .collect::<String>()
                    .into(),
            });
        }

        Ok(bytes)
    }

    async fn read_response(
        &self,
        response: h2::client::ResponseFuture,
    ) -> Result<serde_json::Value, PbsError> {
        unwrap_data(&self.read_body(response).await?)
    }

    pub async fn download(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<u8>, PbsError> {
        let request = self.build_request(hyper::Method::GET, path, &encode_query(params), None)?;
        let (response, _send) = self
            .send
            .clone()
            .send_request(request, true)
            .map_err(transport)?;
        self.read_body(response).await
    }

    pub async fn post(
        &mut self,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<serde_json::Value, PbsError> {
        let request = self.build_request(hyper::Method::POST, path, &encode_query(params), None)?;
        let (response, _send) = self.send.send_request(request, true).map_err(transport)?;
        self.read_response(response).await
    }

    pub async fn upload(
        &mut self,
        method: hyper::Method,
        path: &str,
        params: &[(&str, String)],
        content_type: &str,
        body: Bytes,
    ) -> Result<serde_json::Value, PbsError> {
        let request =
            self.build_request(method, path, &encode_query(params), Some(content_type))?;
        let (response, mut stream) = self.send.send_request(request, false).map_err(transport)?;
        send_with_flow_control(&mut stream, body).await?;
        self.read_response(response).await
    }

    pub async fn send_json(
        &mut self,
        method: hyper::Method,
        path: &str,
        params: &[(&str, String)],
        json: &serde_json::Value,
    ) -> Result<serde_json::Value, PbsError> {
        let body =
            serde_json::to_vec(json).map_err(|err| PbsError::Decode(err.to_string().into()))?;
        self.upload(method, path, params, "application/json", Bytes::from(body))
            .await
    }
}

async fn send_with_flow_control(
    stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
) -> Result<(), PbsError> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());

        let granted = match poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(granted)) => granted,
            Some(Err(err)) => return Err(transport(err)),
            None => return Err(PbsError::Transport("h2 stream closed during upload".into())),
        };

        let take = granted.min(data.len());
        let piece = data.split_to(take);
        stream.send_data(piece, false).map_err(transport)?;
    }

    stream.send_data(Bytes::new(), true).map_err(transport)?;
    Ok(())
}
