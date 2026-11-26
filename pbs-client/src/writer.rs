use super::{
    config::PbsConfig,
    datablob::{self, EncodedBlob},
    error::PbsError,
    h2::H2Transport,
    manifest::{BackupManifest, FileInfo, MANIFEST_BLOB_NAME},
};
use bytes::Bytes;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tokio::io::AsyncRead;

pub const ARCHIVE_NAME: &str = "root.pxar.didx";
pub const ARCHIVE_PXAR_NAME: &str = "root.pxar";
pub const META_BLOB_NAME: &str = "calagopus.json.blob";

const MIN_CHUNK_SIZE: usize = 1024 * 1024;
const AVG_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

const INDEX_BATCH_SIZE: usize = 256;
const MAX_UPLOADS_IN_FLIGHT: usize = 4;

fn stream_chunker<R: AsyncRead + Unpin>(reader: R) -> fastcdc::v2020::AsyncStreamCDC<R> {
    fastcdc::v2020::AsyncStreamCDC::new(reader, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
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

    pub async fn upload_archive<R: AsyncRead + Send + Unpin + 'static>(
        &mut self,
        reader: R,
        known_chunks: HashSet<[u8; 32]>,
        compression_threads: usize,
    ) -> Result<UploadedArchive, PbsError> {
        self.upload_archive_named(ARCHIVE_NAME, reader, known_chunks, compression_threads)
            .await
    }

    pub async fn upload_archive_named<R: AsyncRead + Unpin>(
        &mut self,
        archive_name: &str,
        reader: R,
        known_chunks: HashSet<[u8; 32]>,
        compression_threads: usize,
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

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        let producer = async move {
            let mut known = known_chunks;
            let mut chunker = stream_chunker(reader);
            let stream = chunker.as_stream();
            tokio::pin!(stream);

            let mut messages = stream
                .map(|chunk| async move {
                    let chunk = chunk.map_err(|err| err.to_string())?;

                    tokio::task::spawn_blocking(move || {
                        let digest = datablob::sha256(&chunk.data);
                        (chunk, digest)
                    })
                    .await
                    .map_err(|err| err.to_string())
                })
                .buffered(compression_threads.max(1))
                .map(move |hashed| match hashed {
                    Ok((chunk, digest)) => {
                        if known.contains(&digest) {
                            futures::future::Either::Left(std::future::ready(Ok(
                                ChunkMessage::Known {
                                    digest,
                                    size: chunk.data.len() as u64,
                                },
                            )))
                        } else {
                            known.insert(digest);
                            futures::future::Either::Right(async move {
                                tokio::task::spawn_blocking(move || {
                                    ChunkMessage::New(datablob::encode_blob_with_digest(
                                        &chunk.data,
                                        digest,
                                    ))
                                })
                                .await
                                .map_err(|err| err.to_string())
                            })
                        }
                    }
                    Err(err) => futures::future::Either::Left(std::future::ready(Err(err))),
                })
                .buffered(compression_threads.max(1));

            while let Some(message) = messages.next().await {
                let failed = message.is_err();

                if tx.send(message).await.is_err() || failed {
                    break;
                }
            }

            Ok::<_, PbsError>(())
        };

        let consumer = async {
            let mut entries = Vec::new();
            let mut digest_list = Vec::new();
            let mut offset_list = Vec::new();
            let mut end_offset = 0;
            let mut uploads = futures::stream::FuturesOrdered::new();

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
                        if uploads.len() >= MAX_UPLOADS_IN_FLIGHT
                            && let Some(result) = uploads.next().await
                        {
                            result?;
                        }

                        let digest = blob.digest;
                        let mut transport = self.transport.clone();
                        uploads.push_back(async move {
                            transport
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
                                .await
                        });

                        digest
                    }
                };

                entries.push((end_offset, digest));
                digest_list.push(hex::encode(digest));
                offset_list.push(start_offset);

                if digest_list.len() >= INDEX_BATCH_SIZE {
                    while let Some(result) = uploads.next().await {
                        result?;
                    }
                    Self::register_chunks(
                        &mut self.transport,
                        wid,
                        &mut digest_list,
                        &mut offset_list,
                    )
                    .await?;
                }
            }

            while let Some(result) = uploads.next().await {
                result?;
            }
            if !digest_list.is_empty() {
                Self::register_chunks(&mut self.transport, wid, &mut digest_list, &mut offset_list)
                    .await?;
            }

            Ok::<_, PbsError>((entries, end_offset))
        };

        let (_, (entries, end_offset)) = tokio::try_join!(producer, consumer)?;

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

    async fn register_chunks(
        transport: &mut H2Transport,
        wid: u64,
        digest_list: &mut Vec<String>,
        offset_list: &mut Vec<u64>,
    ) -> Result<(), PbsError> {
        transport
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
        digest_list.clear();
        offset_list.clear();

        Ok(())
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

    pub async fn close(&self) {
        self.transport.close().await;
    }
}
