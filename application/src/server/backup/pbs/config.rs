use super::error::PbsError;
use compact_str::CompactString;
use serde::Deserialize;
use utoipa::ToSchema;

/// Connection configuration for a Proxmox Backup Server datastore.
///
/// Mirrors the panel-side `BackupConfigsPbs`. The `token_secret` is sensitive
/// and is intentionally redacted from the [`std::fmt::Debug`] output so it can
/// never end up in logs.
#[derive(Clone, Deserialize, ToSchema)]
pub struct PbsConfig {
    /// Base URL of the PBS API, e.g. `https://pbs.example.com:8007`.
    pub url: CompactString,
    pub datastore: CompactString,
    #[serde(default)]
    pub namespace: Option<CompactString>,
    /// PBS user including realm, e.g. `root@pam`.
    pub username: CompactString,
    pub token_name: CompactString,
    pub token_secret: CompactString,
    /// SHA-256 fingerprint of the PBS TLS certificate (any case, colons optional).
    pub fingerprint: CompactString,
    #[serde(default)]
    pub backup_id_prefix: Option<CompactString>,
}

impl std::fmt::Debug for PbsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PbsConfig")
            .field("url", &self.url)
            .field("datastore", &self.datastore)
            .field("namespace", &self.namespace)
            .field("username", &self.username)
            .field("token_name", &self.token_name)
            .field("token_secret", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .field("backup_id_prefix", &self.backup_id_prefix)
            .finish()
    }
}

impl PbsConfig {
    /// Validates the required fields and the fingerprint format.
    pub fn validate(&self) -> Result<(), PbsError> {
        for (name, value) in [
            ("url", &self.url),
            ("datastore", &self.datastore),
            ("username", &self.username),
            ("token_name", &self.token_name),
            ("token_secret", &self.token_secret),
            ("fingerprint", &self.fingerprint),
        ] {
            if value.trim().is_empty() {
                return Err(PbsError::Config(compact_str::format_compact!(
                    "missing required field '{name}'"
                )));
            }
        }

        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(PbsError::Config(
                "url must start with http:// or https://".into(),
            ));
        }

        super::tls::normalize_fingerprint(&self.fingerprint).map_err(PbsError::Config)?;

        Ok(())
    }

    /// The API root with any trailing slash trimmed, e.g. `https://host:8007`.
    pub fn base_url(&self) -> &str {
        self.url.trim_end_matches('/')
    }

    /// The effective backup-id prefix, defaulting to `calagopus`.
    pub fn id_prefix(&self) -> &str {
        self.backup_id_prefix
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("calagopus")
    }
}
