use super::{config::PbsConfig, error::PbsError};
use compact_str::CompactString;
use reqwest::{
    StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use std::time::Duration;

pub struct PbsClient {
    client: reqwest::Client,
    config: PbsConfig,
}

impl PbsClient {
    pub fn new(config: PbsConfig) -> Result<Self, PbsError> {
        config.validate()?;

        let tls = super::tls::build_client_config(config.fingerprint.as_deref())
            .map_err(PbsError::Config)?;

        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&config.authorization_header())
            .map_err(|_| PbsError::Config("token contains invalid header characters".into()))?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);

        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(PbsError::transport)?;

        Ok(Self { client, config })
    }

    fn datastore_path(&self, suffix: &str) -> String {
        format!(
            "{}/api2/json/admin/datastore/{}/{}",
            self.config.base_url(),
            self.config.datastore,
            suffix
        )
    }

    fn ns_query(&self) -> Vec<(&'static str, String)> {
        match &self.config.namespace {
            Some(ns) if !ns.is_empty() => vec![("ns", ns.to_string())],
            _ => Vec::new(),
        }
    }

    pub async fn delete_snapshot(
        &self,
        backup_type: &str,
        backup_id: &str,
        backup_time: i64,
    ) -> Result<(), PbsError> {
        let mut query = self.ns_query();
        query.push(("backup-type", backup_type.to_string()));
        query.push(("backup-id", backup_id.to_string()));
        query.push(("backup-time", backup_time.to_string()));

        let response = self
            .client
            .delete(self.datastore_path("snapshots"))
            .query(&query)
            .send()
            .await
            .map_err(|err| self.map_transport(err))?;

        if response.status() == StatusCode::BAD_REQUEST {
            let message = response.text().await.unwrap_or_default();
            if message.contains("(os error 2)") || message.contains("No such file or directory") {
                return Err(PbsError::SnapshotNotFound {
                    backup_id: backup_id.into(),
                    backup_time,
                });
            }

            return Err(PbsError::Http {
                status: StatusCode::BAD_REQUEST.as_u16(),
                message: truncate_message(&message),
            });
        }

        self.check_status(response).await?;

        Ok(())
    }

    pub async fn check_access(&self) -> Result<(), PbsError> {
        let response = self
            .client
            .get(self.datastore_path("groups"))
            .query(&self.ns_query())
            .send()
            .await
            .map_err(|err| self.map_transport(err))?;

        self.check_status(response).await?;

        Ok(())
    }

    async fn check_status(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response, PbsError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        Err(match status {
            StatusCode::UNAUTHORIZED => PbsError::Unauthorized {
                token_id: self.config.token_id.clone(),
            },
            StatusCode::FORBIDDEN => PbsError::Forbidden {
                datastore: self.config.datastore.clone(),
            },
            StatusCode::NOT_FOUND => PbsError::NotFound {
                datastore: self.config.datastore.clone(),
            },
            other => {
                let message = response.text().await.unwrap_or_default();
                PbsError::Http {
                    status: other.as_u16(),
                    message: truncate_message(&message),
                }
            }
        })
    }

    fn map_transport(&self, err: reqwest::Error) -> PbsError {
        let chain = error_chain(&err);
        if let Some(fingerprint) = &self.config.fingerprint
            && chain.contains("fingerprint mismatch")
        {
            let actual = chain
                .split("server presented ")
                .nth(1)
                .map(|s| {
                    s.split(|c: char| !c.is_ascii_hexdigit())
                        .next()
                        .unwrap_or("")
                })
                .filter(|s| !s.is_empty())
                .map(CompactString::from)
                .unwrap_or_else(|| "unknown".into());

            return PbsError::FingerprintMismatch {
                expected: super::tls::normalize_fingerprint(fingerprint)
                    .map(|b| super::tls::fingerprint_hex(&b))
                    .unwrap_or_else(|_| fingerprint.clone()),
                actual,
            };
        }

        PbsError::Transport(chain.into())
    }
}

fn error_chain(err: &reqwest::Error) -> String {
    let mut out = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

fn truncate_message(message: &str) -> CompactString {
    message.chars().take(512).collect()
}
