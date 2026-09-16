use super::{config::PbsConfig, error::PbsError, naming, tls};
use bytes::Bytes;
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

const WINDOW_SIZE: u32 = (1 << 31) - 2;
const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

fn transport<E: std::fmt::Display>(err: E) -> PbsError {
    PbsError::Transport(err.to_string().into())
}

enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

struct Endpoint {
    authority: String,
    host: String,
    port: u16,
    scheme: &'static str,
}

impl Endpoint {
    fn is_tls(&self) -> bool {
        self.scheme == "https"
    }
}

fn parse_endpoint(base_url: &str) -> Result<Endpoint, PbsError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| PbsError::Config("url is not a valid url".into()))?;

    let (scheme, port) = match url.scheme() {
        "https" => ("https", url.port().unwrap_or(443)),
        "http" => ("http", url.port().unwrap_or(80)),
        _ => {
            return Err(PbsError::Config(
                "url must start with http:// or https://".into(),
            ));
        }
    };

    let host = url
        .host_str()
        .ok_or_else(|| PbsError::Config("url is missing a host".into()))?;

    Ok(Endpoint {
        authority: format!("{host}:{port}"),
        host: host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_string(),
        port,
        scheme,
    })
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
    scheme: &'static str,
    tasks: Arc<ConnectionTasks>,
}

impl H2Transport {
    pub async fn connect(
        config: &PbsConfig,
        protocol: &str,
        endpoint: &str,
        session_query: &str,
    ) -> Result<Self, PbsError> {
        let target = parse_endpoint(config.base_url())?;

        let tls = if target.is_tls() {
            let tls_config = tls::build_client_config(config.fingerprint.as_deref())
                .map_err(PbsError::Config)?;
            let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| PbsError::Config("invalid hostname in url".into()))?;

            Some((
                tokio_rustls::TlsConnector::from(Arc::new(tls_config)),
                server_name,
            ))
        } else {
            None
        };

        let addresses = super::net::lookup_host(&target.host, target.port).await?;
        let tcp = TcpStream::connect(addresses.as_slice())
            .await
            .map_err(transport)?;
        let stream = match tls {
            Some((connector, server_name)) => MaybeTlsStream::Tls(Box::new(
                connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(transport)?,
            )),
            None => MaybeTlsStream::Plain(tcp),
        };

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(transport)?;
        let upgrade_task = tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });

        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(format!("/api2/json/{endpoint}?{session_query}"))
            .header(hyper::header::HOST, &target.authority)
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
            authority: target.authority,
            scheme: target.scheme,
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
            format!("{}://{}/{}", self.scheme, self.authority, path)
        } else {
            format!("{}://{}/{}?{}", self.scheme, self.authority, path, query)
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
