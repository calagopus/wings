use super::{config::PbsConfig, datablob, error::PbsError, h2::H2Transport, writer::ARCHIVE_NAME};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

const DYNAMIC_INDEX_HEADER_SIZE: usize = 4096;
const DYNAMIC_INDEX_ENTRY_SIZE: usize = 40;

pub struct PbsBackupReader {
    transport: H2Transport,
}

impl PbsBackupReader {
    pub async fn connect(
        config: &PbsConfig,
        backup_id: &str,
        backup_time: i64,
    ) -> Result<Self, PbsError> {
        let transport = H2Transport::connect(
            config,
            "proxmox-backup-reader-protocol-v1",
            "reader",
            &super::h2::snapshot_query(config, backup_id, backup_time),
        )
        .await?;
        Ok(Self { transport })
    }

    pub async fn download_file(&mut self, file_name: &str) -> Result<Vec<u8>, PbsError> {
        self.transport
            .download("download", &[("file-name", file_name.to_string())])
            .await
    }

    pub async fn download_chunk_plaintext(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, PbsError> {
        let encoded = self
            .transport
            .download("chunk", &[("digest", hex::encode(digest))])
            .await?;
        datablob::decode_blob(&encoded)
    }

    pub async fn archive_chunk_digests(&mut self) -> Result<Vec<[u8; 32]>, PbsError> {
        let index = self.download_file(ARCHIVE_NAME).await?;
        parse_dynamic_index(&index)
    }

    pub async fn reassemble_archive<W: AsyncWrite + Unpin>(
        mut self,
        writer: &mut W,
        progress: Option<Arc<AtomicU64>>,
    ) -> Result<(), PbsError> {
        for digest in self.archive_chunk_digests().await? {
            let plaintext = self.download_chunk_plaintext(&digest).await?;
            if let Some(progress) = &progress {
                progress.fetch_add(plaintext.len() as u64, Ordering::SeqCst);
            }
            writer
                .write_all(&plaintext)
                .await
                .map_err(|err| PbsError::Transport(err.to_string().into()))?;
        }
        Ok(())
    }
}

pub fn parse_dynamic_index_entries(data: &[u8]) -> Result<Vec<(u64, [u8; 32])>, PbsError> {
    let entries = data
        .get(DYNAMIC_INDEX_HEADER_SIZE..)
        .ok_or_else(|| PbsError::Decode("dynamic index shorter than its header".into()))?;

    if entries.len() % DYNAMIC_INDEX_ENTRY_SIZE != 0 {
        return Err(PbsError::Decode(
            "dynamic index has a truncated entry".into(),
        ));
    }

    let mut out = Vec::with_capacity(entries.len() / DYNAMIC_INDEX_ENTRY_SIZE);
    for entry in entries.chunks_exact(DYNAMIC_INDEX_ENTRY_SIZE) {
        let offset_bytes = entry
            .get(0..8)
            .ok_or_else(|| PbsError::Decode("dynamic index entry too short".into()))?;
        let digest_bytes = entry
            .get(8..DYNAMIC_INDEX_ENTRY_SIZE)
            .ok_or_else(|| PbsError::Decode("dynamic index entry too short".into()))?;

        let mut offset = [0; 8];
        offset.copy_from_slice(offset_bytes);
        let mut digest = [0; 32];
        digest.copy_from_slice(digest_bytes);
        out.push((u64::from_le_bytes(offset), digest));
    }

    Ok(out)
}

pub fn parse_dynamic_index(data: &[u8]) -> Result<Vec<[u8; 32]>, PbsError> {
    Ok(parse_dynamic_index_entries(data)?
        .into_iter()
        .map(|(_, digest)| digest)
        .collect())
}
