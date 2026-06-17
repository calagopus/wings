use super::{
    config::PbsConfig,
    datablob::{self, EncodedBlob},
    error::PbsError,
    h2::H2Transport,
    manifest::{BackupManifest, FileInfo, MANIFEST_BLOB_NAME},
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Read};

pub const ARCHIVE_NAME: &str = "root.pxar.didx";
pub const ARCHIVE_PXAR_NAME: &str = "root.pxar";
pub const META_BLOB_NAME: &str = "calagopus.json.blob";

const MIN_CHUNK_SIZE: usize = 1024 * 1024;
const AVG_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

fn stream_chunker<R: Read>(reader: R) -> fastcdc::v2020::StreamCDC<R> {
    fastcdc::v2020::StreamCDC::new(reader, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
}

pub struct UploadedArchive {
    pub file: FileInfo,
    pub size: u64,
}

enum ChunkMessage {
    Known { digest: [u8; 32], size: u64 },
    New(EncodedBlob),
}

pub fn index_csum(entries: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (end_offset, digest) in entries {
        hasher.update(end_offset.to_le_bytes());
        hasher.update(digest);
    }

    let mut out = [0; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub struct PbsBackupWriter {
    transport: H2Transport,
}

impl PbsBackupWriter {
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

    pub async fn previous_archive_digests(
        &self,
        archive_name: &str,
    ) -> Result<HashSet<[u8; 32]>, PbsError> {
        let index = self
            .transport
            .download("previous", &[("archive-name", archive_name.to_string())])
            .await?;
        Ok(crate::reader::parse_dynamic_index(&index)?
            .into_iter()
            .collect())
    }

    pub async fn upload_archive<R: Read + Send + 'static>(
        &mut self,
        reader: R,
        known_chunks: HashSet<[u8; 32]>,
    ) -> Result<UploadedArchive, PbsError> {
        self.upload_archive_named(ARCHIVE_NAME, reader, known_chunks)
            .await
    }

    pub async fn upload_archive_named<R: Read + Send + 'static>(
        &mut self,
        archive_name: &str,
        reader: R,
        known_chunks: HashSet<[u8; 32]>,
    ) -> Result<UploadedArchive, PbsError> {
        let wid = self
            .transport
            .post(
                "dynamic_index",
                &[("archive-name", archive_name.to_string())],
            )
            .await?
            .as_u64()
            .ok_or_else(|| PbsError::Decode("dynamic_index did not return a wid".into()))?;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<ChunkMessage, String>>(4);
        let producer = tokio::task::spawn_blocking(move || {
            let mut known = known_chunks;
            for chunk in stream_chunker(reader) {
                let message = match chunk {
                    Ok(chunk) => {
                        let digest = datablob::sha256(&chunk.data);
                        if known.contains(&digest) {
                            Ok(ChunkMessage::Known {
                                digest,
                                size: chunk.data.len() as u64,
                            })
                        } else {
                            known.insert(digest);
                            Ok(ChunkMessage::New(datablob::encode_blob(&chunk.data)))
                        }
                    }
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
            let message = message.map_err(|err| PbsError::Transport(err.into()))?;
            let start_offset = end_offset;

            let digest = match message {
                ChunkMessage::Known { digest, size } => {
                    end_offset += size;
                    digest
                }
                ChunkMessage::New(blob) => {
                    end_offset += blob.plaintext_size;
                    self.transport
                        .upload(
                            hyper::Method::POST,
                            "dynamic_chunk",
                            &[
                                ("wid", wid.to_string()),
                                ("digest", hex::encode(blob.digest)),
                                ("size", blob.plaintext_size.to_string()),
                                ("encoded-size", blob.data.len().to_string()),
                            ],
                            "application/octet-stream",
                            Bytes::from(blob.data),
                        )
                        .await?;
                    blob.digest
                }
            };

            entries.push((end_offset, digest));
            digest_list.push(hex::encode(digest));
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
            file: FileInfo::new(archive_name, end_offset, &csum),
            size: end_offset,
        })
    }

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

    pub async fn finish(&mut self, manifest: &BackupManifest) -> Result<(), PbsError> {
        let json = manifest
            .to_json_bytes()
            .map_err(|err| PbsError::Decode(err.to_string().into()))?;

        self.upload_blob(MANIFEST_BLOB_NAME, &json).await?;
        self.transport.post("finish", &[]).await?;
        Ok(())
    }
}
