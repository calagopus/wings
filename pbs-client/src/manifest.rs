use serde::Serialize;

pub const MANIFEST_BLOB_NAME: &str = "index.json.blob";

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum CryptMode {
    None,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FileInfo {
    pub filename: String,
    pub crypt_mode: CryptMode,
    pub size: u64,
    pub csum: String,
}

impl FileInfo {
    pub fn new(filename: impl Into<String>, size: u64, csum: &[u8; 32]) -> Self {
        Self {
            filename: filename.into(),
            crypt_mode: CryptMode::None,
            size,
            csum: hex::encode(csum),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BackupManifest {
    pub backup_type: String,
    pub backup_id: String,
    pub backup_time: i64,
    pub files: Vec<FileInfo>,
    pub unprotected: serde_json::Value,
}

impl BackupManifest {
    pub fn new(
        backup_type: impl Into<String>,
        backup_id: impl Into<String>,
        backup_time: i64,
    ) -> Self {
        Self {
            backup_type: backup_type.into(),
            backup_id: backup_id.into(),
            backup_time,
            files: Vec::new(),
            unprotected: serde_json::json!({}),
        }
    }

    pub fn add_file(&mut self, file: FileInfo) {
        self.files.push(file);
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}
