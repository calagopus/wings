//! The PBS backup manifest (`index.json.blob`).
//!
//! Field names are kebab-case to match PBS's `BackupManifest`/`FileInfo`. The
//! manifest lists every archive/blob in the snapshot (but not itself), each with
//! its size and checksum. We never sign or encrypt, so `crypt-mode` is always
//! `none` and no signature is emitted.

use serde::Serialize;

/// File name of the manifest blob within a snapshot.
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
    /// Lowercase hex of the file's 32-byte checksum.
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

    /// Serializes the manifest to the JSON bytes that get wrapped in a DataBlob.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_uses_kebab_case_and_hex_csum() {
        let mut manifest = BackupManifest::new("host", "calagopus-test", 1_700_000_000);
        manifest.add_file(FileInfo::new("backup.tar.didx", 1234, &[0xab; 32]));

        let json =
            String::from_utf8(manifest.to_json_bytes().expect("serializes")).expect("valid utf8");

        assert!(json.contains("\"backup-type\":\"host\""));
        assert!(json.contains("\"backup-id\":\"calagopus-test\""));
        assert!(json.contains("\"backup-time\":1700000000"));
        assert!(json.contains("\"crypt-mode\":\"none\""));
        assert!(json.contains("\"filename\":\"backup.tar.didx\""));
        assert!(json.contains(&"ab".repeat(32)));
        assert!(json.contains("\"unprotected\":{}"));
    }
}
