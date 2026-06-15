//! Drives the PBS dynamic-archive write protocol over an [`H2Transport`].
//!
//! Choreography (one snapshot): create the dynamic index, stream the tar through
//! content-defined chunking, upload each chunk as a DataBlob, register the chunk
//! offsets/digests into the index, close the index, upload the metadata + manifest
//! blobs, and finish.
//!
//! Chunking + DataBlob encoding (zstd, SHA-256, CRC) is CPU-bound and runs on a
//! blocking thread; the async side only does the h2 IO, with a small bounded
//! channel providing backpressure.

use super::{
    config::PbsConfig,
    datablob::{self, EncodedBlob},
    error::PbsError,
    h2::H2Transport,
    manifest::{BackupManifest, FileInfo, MANIFEST_BLOB_NAME},
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::io::Read;

/// The single dynamic archive containing the server filesystem tar.
pub const ARCHIVE_NAME: &str = "backup.tar.didx";
/// Sidecar blob holding Calagopus restore metadata.
pub const META_BLOB_NAME: &str = "calagopus.json.blob";

/// Result of uploading the dynamic archive.
pub struct UploadedArchive {
    pub file: FileInfo,
    pub size: u64,
}

/// Computes the dynamic-index checksum: SHA-256 over each chunk's
/// `end_offset (u64 LE) || digest (32 bytes)`. This value is sent to
/// `dynamic_close` and is also the archive's manifest `csum`.
pub fn index_csum(entries: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (end_offset, digest) in entries {
        hasher.update(end_offset.to_le_bytes());
        hasher.update(digest);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub struct PbsBackupWriter {
    transport: H2Transport,
}

impl PbsBackupWriter {
    /// Opens a backup-protocol session for the given group/time.
    pub async fn connect(
        config: &PbsConfig,
        backup_id: &str,
        backup_time: i64,
    ) -> Result<Self, PbsError> {
        let transport = H2Transport::connect(
            config,
            "proxmox-backup-protocol-v1",
            "backup",
            &super::h2::snapshot_query(config, backup_id, backup_time),
        )
        .await?;
        Ok(Self { transport })
    }

    /// Streams a tar (blocking reader) into a dynamic-index archive.
    pub async fn upload_archive<R: Read + Send + 'static>(
        &mut self,
        reader: R,
    ) -> Result<UploadedArchive, PbsError> {
        let wid = self
            .transport
            .post(
                "dynamic_index",
                &[("archive-name", ARCHIVE_NAME.to_string())],
            )
            .await?
            .as_u64()
            .ok_or_else(|| PbsError::Decode("dynamic_index did not return a wid".into()))?;

        // CPU-bound chunking + encoding on a blocking thread.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<EncodedBlob, String>>(4);
        let producer = tokio::task::spawn_blocking(move || {
            for chunk in super::chunker::stream_chunker(reader) {
                let message = match chunk {
                    Ok(chunk) => Ok(datablob::encode_blob(&chunk.data)),
                    Err(err) => Err(err.to_string()),
                };
                let failed = message.is_err();
                if tx.blocking_send(message).is_err() || failed {
                    break;
                }
            }
        });

        let mut entries: Vec<(u64, [u8; 32])> = Vec::new();
        let mut digest_list: Vec<String> = Vec::new();
        let mut offset_list: Vec<u64> = Vec::new();
        let mut end_offset: u64 = 0;

        while let Some(message) = rx.recv().await {
            let blob = message.map_err(|err| PbsError::Transport(err.into()))?;
            // PBS validates the appended offset against its running total *before*
            // this chunk (the chunk's start offset); it then advances the total and
            // records the resulting end offset in the index itself.
            let start_offset = end_offset;
            end_offset += blob.plaintext_size;

            let digest_hex = hex::encode(blob.digest);
            self.transport
                .upload(
                    hyper::Method::POST,
                    "dynamic_chunk",
                    &[
                        ("wid", wid.to_string()),
                        ("digest", digest_hex.clone()),
                        ("size", blob.plaintext_size.to_string()),
                        ("encoded-size", blob.data.len().to_string()),
                    ],
                    "application/octet-stream",
                    Bytes::from(blob.data),
                )
                .await?;

            entries.push((end_offset, blob.digest));
            digest_list.push(digest_hex);
            offset_list.push(start_offset);
        }

        producer
            .await
            .map_err(|err| PbsError::Transport(err.to_string().into()))?;

        if !digest_list.is_empty() {
            self.transport
                .send_json(
                    hyper::Method::PUT,
                    "dynamic_index",
                    &[],
                    &serde_json::json!({
                        "wid": wid,
                        "digest-list": digest_list,
                        "offset-list": offset_list,
                    }),
                )
                .await?;
        }

        let csum = index_csum(&entries);
        self.transport
            .post(
                "dynamic_close",
                &[
                    ("wid", wid.to_string()),
                    ("chunk-count", entries.len().to_string()),
                    ("size", end_offset.to_string()),
                    ("csum", hex::encode(csum)),
                ],
            )
            .await?;

        Ok(UploadedArchive {
            file: FileInfo::new(ARCHIVE_NAME, end_offset, &csum),
            size: end_offset,
        })
    }

    /// Uploads a single blob; its manifest `csum` is the SHA-256 of the encoded
    /// DataBlob bytes (PBS's rule for `.blob` files).
    pub async fn upload_blob(
        &mut self,
        file_name: &str,
        plaintext: &[u8],
    ) -> Result<FileInfo, PbsError> {
        let blob = datablob::encode_blob(plaintext);
        let encoded_csum = datablob::sha256(&blob.data);
        let encoded_size = blob.data.len() as u64;

        self.transport
            .upload(
                hyper::Method::POST,
                "blob",
                &[
                    ("file-name", file_name.to_string()),
                    ("encoded-size", encoded_size.to_string()),
                ],
                "application/octet-stream",
                Bytes::from(blob.data),
            )
            .await?;

        Ok(FileInfo::new(file_name, encoded_size, &encoded_csum))
    }

    /// Uploads the manifest (`index.json.blob`) and finishes the snapshot.
    pub async fn finish(&mut self, manifest: &BackupManifest) -> Result<(), PbsError> {
        let json = manifest
            .to_json_bytes()
            .map_err(|err| PbsError::Decode(err.to_string().into()))?;

        // The manifest blob is not listed within itself.
        self.upload_blob(MANIFEST_BLOB_NAME, &json).await?;
        self.transport.post("finish", &[]).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_csum_matches_manual_computation_and_is_stable() {
        let entries = vec![(1024u64, [0x11u8; 32]), (2048u64, [0x22u8; 32])];

        // Manual reference computation.
        let mut hasher = Sha256::new();
        hasher.update(1024u64.to_le_bytes());
        hasher.update([0x11u8; 32]);
        hasher.update(2048u64.to_le_bytes());
        hasher.update([0x22u8; 32]);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        let csum = index_csum(&entries);
        assert_eq!(csum, expected);

        // Invariant: the value sent to dynamic_close is byte-identical to the
        // archive's manifest FileInfo.csum.
        let file = FileInfo::new(ARCHIVE_NAME, 2048, &csum);
        assert_eq!(file.csum, hex::encode(csum));
    }
}
