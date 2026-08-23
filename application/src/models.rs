use crate::server::state::ServerState;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;

#[derive(ToSchema, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum ServerSelector {
    Uuids {
        uuids: std::collections::HashSet<uuid::Uuid>,
    },
    All,
}

impl ServerSelector {
    #[inline]
    pub fn matches(&self, uuid: &uuid::Uuid) -> bool {
        match self {
            Self::Uuids { uuids } => uuids.contains(uuid),
            Self::All => true,
        }
    }
}

#[derive(ToSchema, Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerPowerAction {
    Start,
    Stop,
    Restart,
    Kill,
}

impl FromStr for ServerPowerAction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "restart" => Ok(Self::Restart),
            "kill" => Ok(Self::Kill),
            _ => Err(anyhow::anyhow!(
                "invalid server power action provided: {}",
                s
            )),
        }
    }
}

#[derive(ToSchema, Default, Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerAutoStartBehavior {
    Always,
    #[default]
    UnlessStopped,
    Never,
}

#[derive(ToSchema, Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerBackupStatus {
    Starting,
    Finished,
    Failed,
}

#[derive(ToSchema, Serialize)]
pub struct Server {
    pub state: ServerState,
    pub is_suspended: bool,
    pub utilization: crate::server::resources::ResourceUsage,
    pub configuration: crate::server::configuration::ServerConfiguration,
}

#[derive(ToSchema, Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectorySortingMode {
    #[default]
    NameAsc,
    NameDesc,
    SizeAsc,
    SizeDesc,
    PhysicalSizeAsc,
    PhysicalSizeDesc,
    ModifiedAsc,
    ModifiedDesc,
    CreatedAsc,
    CreatedDesc,
}

#[derive(ToSchema, Serialize)]
pub struct DirectoryEntry {
    pub name: compact_str::CompactString,
    pub mode: compact_str::CompactString,
    pub mode_bits: compact_str::CompactString,
    pub size: u64,
    pub size_physical: u64,
    pub editable: bool,
    pub inner_editable: bool,
    pub directory: bool,
    pub file: bool,
    pub symlink: bool,
    pub r#virtual: bool,
    pub mime: &'static str,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
}

#[derive(ToSchema, Serialize)]
pub struct Download {
    pub identifier: uuid::Uuid,
    pub destination: String,

    pub progress: u64,
    pub total: u64,
}

#[derive(ToSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PullProgressStatus {
    Pulling,
    Extracting,
}

#[derive(ToSchema, Serialize)]
pub struct PullProgress {
    pub status: PullProgressStatus,
    pub bytes_processed: i64,
    pub bytes_total: i64,
}

#[derive(ToSchema, Serialize)]
pub struct TransferProgress {
    pub archive_bytes_processed: u64,
    pub network_bytes_processed: u64,
    pub bytes_total: u64,
    pub files_processed: u64,
}

#[derive(ToSchema, Serialize)]
pub struct BackupProgress {
    pub bytes_processed: u64,
    pub bytes_total: u64,
    pub files_processed: u64,
}

#[derive(ToSchema, Serialize)]
pub struct InstallProgress {
    pub progress: u64,
    pub total: u64,
    pub label: Option<compact_str::CompactString>,
}

#[derive(ToSchema, Serialize, Deserialize, Clone)]
pub struct RenameFile {
    pub from: compact_str::CompactString,
    pub to: compact_str::CompactString,
}

#[derive(ToSchema, Serialize, Deserialize, Clone)]
pub struct CopyFile {
    pub from: compact_str::CompactString,
    pub to: compact_str::CompactString,
}
