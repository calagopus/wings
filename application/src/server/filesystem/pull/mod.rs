use crate::server::filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem};
use anyhow::Context;
use compact_str::ToCompactString;
use rand::RngExt;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncWriteExt;
use utoipa::ToSchema;

use crate::net::{host_to_ip, is_blocked_ip};

const MAX_REDIRECTS: usize = 10;

static DOWNLOAD_CLIENT: OnceLock<Arc<reqwest::Client>> = OnceLock::new();

fn blocked_cidrs(config: &crate::config::InnerConfig) -> &Vec<cidr::IpCidr> {
    &config.api.remote_download_blocked_cidrs
}

fn get_download_client(
    config: &Arc<crate::config::Config>,
) -> Result<Arc<reqwest::Client>, anyhow::Error> {
    if let Some(client) = DOWNLOAD_CLIENT.get() {
        return Ok(Arc::clone(client));
    }

    let redirect_config = Arc::clone(config);
    let client = Arc::new(
        reqwest::Client::builder()
            .user_agent("Calagopus Wings (https://github.com/calagopus/wings)")
            .connect_timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .dns_resolver(Arc::new(crate::net::BlockedIpResolver::new(
                config,
                blocked_cidrs,
                "pull",
            )))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= MAX_REDIRECTS {
                    return attempt.error(anyhow::anyhow!("too many redirects"));
                }

                if let Some(host) = attempt.url().host_str()
                    && let Some(ip) = host_to_ip(host)
                    && is_blocked_ip(blocked_cidrs(&redirect_config.load()), &ip)
                {
                    tracing::warn!("blocking redirect to internal IP address in pull: {}", ip);
                    return attempt.error(anyhow::anyhow!("IP address {} is blocked", ip));
                }

                attempt.follow()
            }))
            .build()
            .context("failed to build download client")?,
    );

    Ok(Arc::clone(DOWNLOAD_CLIENT.get_or_init(|| client)))
}

#[derive(ToSchema, Serialize)]
pub struct PullQueryResponse {
    pub file_name: Option<compact_str::CompactString>,
    pub file_size: Option<u64>,

    pub final_url: compact_str::CompactString,
    pub headers: HashMap<compact_str::CompactString, compact_str::CompactString>,
}

impl PullQueryResponse {
    pub async fn query(
        config: &Arc<crate::config::Config>,
        url: &str,
    ) -> Result<Self, anyhow::Error> {
        let url = reqwest::Url::parse(url).context("failed to parse download URL")?;

        if let Some(host) = url.host_str()
            && let Some(ip) = host_to_ip(host)
            && is_blocked_ip(blocked_cidrs(&config.load()), &ip)
        {
            tracing::warn!("blocking internal IP address in pull: {}", ip);
            return Err(anyhow::anyhow!("IP address {} is blocked", ip));
        }

        let response = get_download_client(config)?
            .get(url)
            .send()
            .await
            .map_err(|err| err.without_url())
            .context("failed to send HEAD request")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "failed to query download URL: code {}",
                response.status()
            ));
        }

        let mut headers = HashMap::new();
        for (key, value) in response.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(key.to_compact_string(), value_str.to_compact_string());
            }
        }

        let file_name = if let Some(header) = response.headers().get("Content-Disposition")
            && let Ok(header) = header.to_str()
            && let Some(filename) = crate::utils::parse_content_disposition_filename(header)
        {
            Some(filename.into())
        } else {
            None
        };

        Ok(Self {
            file_name,
            file_size: response.content_length().or_else(|| {
                response
                    .headers()
                    .get("Content-Length")
                    .and_then(|c| c.to_str().ok())
                    .and_then(|c| c.parse::<u64>().ok())
            }),
            final_url: response.url().to_compact_string(),
            headers,
        })
    }
}

pub struct Download {
    pub identifier: uuid::Uuid,
    pub progress: Arc<AtomicU64>,
    pub total: u64,
    pub destination: PathBuf,
    pub server: crate::server::Server,
    pub filesystem: Arc<dyn VirtualWritableFilesystem>,
    pub response: Option<reqwest::Response>,
}

impl Download {
    pub async fn new(
        server: crate::server::Server,
        filesystem: Arc<dyn VirtualWritableFilesystem>,
        destination: &Path,
        file_name: Option<compact_str::CompactString>,
        url: compact_str::CompactString,
        use_header: bool,
    ) -> Result<Self, anyhow::Error> {
        let url = reqwest::Url::parse(&url).context("failed to parse download URL")?;

        if let Some(host) = url.host_str()
            && let Some(ip) = host_to_ip(host)
            && is_blocked_ip(blocked_cidrs(&server.app_state.config.load()), &ip)
        {
            tracing::warn!("blocking internal IP address in pull: {}", ip);
            return Err(anyhow::anyhow!("IP address {} is blocked", ip));
        }

        let response = get_download_client(&server.app_state.config)?
            .get(url)
            .send()
            .await
            .map_err(|err| err.without_url())
            .context("failed to send download request")?;
        let mut real_destination = destination.to_path_buf();

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "failed to download file: code {}",
                response.status()
            ));
        }

        let file_name = match file_name {
            Some(file_name) => {
                if !crate::utils::is_single_component_file_name(&file_name) {
                    return Err(anyhow::anyhow!("file name must be a single path component"));
                }

                file_name.to_string()
            }
            None => {
                let header_file_name = if use_header {
                    response
                        .headers()
                        .get("Content-Disposition")
                        .and_then(|header| header.to_str().ok())
                        .and_then(crate::utils::parse_content_disposition_filename)
                        .filter(|file_name| crate::utils::is_single_component_file_name(file_name))
                } else {
                    None
                };

                header_file_name.unwrap_or_else(|| {
                    response
                        .url()
                        .path_segments()
                        .and_then(|mut segments| segments.next_back())
                        .filter(|segment| crate::utils::is_single_component_file_name(segment))
                        .map(|segment| segment.to_string())
                        .unwrap_or_else(|| {
                            let random_string: String = rand::rng()
                                .sample_iter(&rand::distr::Alphanumeric)
                                .take(8)
                                .map(char::from)
                                .collect();

                            format!("download_{random_string}")
                        })
                })
            }
        };

        real_destination.push(file_name);

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&real_destination, FileType::File)
                .await
        {
            return Err(anyhow::anyhow!("file not found"));
        }

        Ok(Self {
            identifier: uuid::Uuid::new_v4(),
            progress: Arc::new(AtomicU64::new(0)),
            total: response.content_length().unwrap_or_else(|| {
                response
                    .headers()
                    .get("Content-Length")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            }),
            destination: real_destination,
            server,
            filesystem,
            response: Some(response),
        })
    }

    pub async fn start(
        &mut self,
    ) -> Result<
        (
            uuid::Uuid,
            tokio::task::JoinHandle<Option<Result<(), anyhow::Error>>>,
        ),
        anyhow::Error,
    > {
        let progress = Arc::clone(&self.progress);
        let destination = self.destination.clone();
        let server = self.server.clone();
        let filesystem = self.filesystem.clone();
        let mut response = self
            .response
            .take()
            .ok_or_else(|| anyhow::anyhow!("response already taken"))?;

        let (identifier, task) = self
            .server
            .filesystem
            .operations
            .add_operation(
                super::operations::FilesystemOperation::Pull {
                    destination_path: self.destination.clone(),
                    start_time: chrono::Utc::now(),
                    bytes_processed: self.progress.clone(),
                    bytes_total: Arc::new(AtomicU64::new(self.total)),
                },
                async move {
                    let mut run_inner = async || -> Result<(), anyhow::Error> {
                        let mut writer = filesystem.async_create_file(&destination).await?;

                        while let Some(chunk) =
                            response.chunk().await.map_err(|err| err.without_url())?
                        {
                            writer.write_all(&chunk).await?;
                            progress.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                        }

                        writer.shutdown().await?;
                        Ok(())
                    };

                    match run_inner().await {
                        Ok(_) => {
                            tracing::info!(
                                server = %server.uuid,
                                "pull completed: {}",
                                destination.to_string_lossy()
                            );

                            Ok(())
                        }
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to pull file: {:#?}",
                                err
                            );

                            Err(err)
                        }
                    }
                },
            )
            .await;

        self.identifier = identifier;

        Ok((identifier, task))
    }

    #[inline]
    pub fn to_api_response(&self) -> crate::models::Download {
        crate::models::Download {
            identifier: self.identifier,
            destination: self.destination.to_string_lossy().to_string(),
            progress: self.progress.load(Ordering::Relaxed),
            total: self.total,
        }
    }
}
