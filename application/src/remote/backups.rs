use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Debug, ToSchema, Serialize)]
pub struct RawServerBackupPart {
    pub etag: String,
    pub part_number: usize,
}

#[derive(Debug, Default, ToSchema, Serialize)]
pub struct RawServerBackup {
    pub checksum: String,
    pub checksum_type: compact_str::CompactString,
    pub size: u64,
    pub files: u64,
    pub successful: bool,
    pub browsable: bool,
    pub streaming: bool,
    pub parts: Vec<RawServerBackupPart>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResticConfigurationSource {
    #[default]
    Panel,
    Node,
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct ResticBackupConfiguration {
    pub repository: String,
    pub password_file: Option<String>,
    pub retry_lock_seconds: u64,
    pub environment: BTreeMap<String, String>,
    #[serde(skip)]
    #[schema(ignore)]
    pub source: ResticConfigurationSource,
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct PbsBackupConfiguration {
    pub url: String,
    pub datastore: String,
    pub namespace: Option<String>,
    pub token_id: String,
    pub token_secret: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub backup_id_prefix: Option<String>,
    #[serde(default)]
    pub server_uuid: Option<uuid::Uuid>,
    #[serde(default)]
    pub kind: crate::models::ServerBackupKind,
    pub backup_created: chrono::DateTime<chrono::Utc>,
}

impl PbsBackupConfiguration {
    #[inline]
    pub fn group_id(&self) -> Option<compact_str::CompactString> {
        let server_uuid = self.server_uuid?;

        Some(match self.kind {
            crate::models::ServerBackupKind::Server => server_uuid.to_compact_string(),
            crate::models::ServerBackupKind::DatabaseInstance => {
                compact_str::format_compact!("{server_uuid}-db")
            }
        })
    }

    #[inline]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
    }
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct PbsRepositoryConfiguration {
    pub url: String,
    pub datastore: String,
    pub namespace: Option<String>,
    pub token_id: String,
    pub token_secret: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl PbsRepositoryConfiguration {
    #[inline]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
    }
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct KopiaBackupConfiguration {
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub tags: BTreeMap<String, String>,
}

impl KopiaBackupConfiguration {
    #[inline]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
    }
}
