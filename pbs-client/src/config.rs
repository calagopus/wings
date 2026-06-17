use super::error::PbsError;
use compact_str::CompactString;

#[derive(Clone)]
pub struct PbsConfig {
    pub url: CompactString,
    pub datastore: CompactString,
    pub namespace: Option<CompactString>,
    /// Full API token id, e.g. `user@realm!tokenname`.
    pub token_id: CompactString,
    pub token_secret: CompactString,
    pub fingerprint: CompactString,
    pub backup_id_prefix: Option<CompactString>,
}

impl std::fmt::Debug for PbsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PbsConfig")
            .field("url", &self.url)
            .field("datastore", &self.datastore)
            .field("namespace", &self.namespace)
            .field("token_id", &self.token_id)
            .field("token_secret", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .field("backup_id_prefix", &self.backup_id_prefix)
            .finish()
    }
}

impl PbsConfig {
    pub fn validate(&self) -> Result<(), PbsError> {
        for (name, value) in [
            ("url", &self.url),
            ("datastore", &self.datastore),
            ("token_id", &self.token_id),
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

    pub fn authorization_header(&self) -> String {
        format!("PBSAPIToken={}:{}", self.token_id, self.token_secret)
    }

    pub fn base_url(&self) -> &str {
        self.url.trim_end_matches('/')
    }

    pub fn id_prefix(&self) -> &str {
        self.backup_id_prefix
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("calagopus")
    }
}
