//! PBS reader-protocol client: downloads a snapshot's archive index and chunks
//! so the dynamic archive can be reassembled for restore or download.

use super::{
    config::PbsConfig, datablob, error::PbsError, h2::H2Transport, writer::ARCHIVE_NAME,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Dynamic chunk index header size (bytes before the entry table).
const DYNAMIC_INDEX_HEADER_SIZE: usize = 4096;
/// Each entry is `end_offset (u64 LE) || digest (32 bytes)`.
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

    /// Downloads a file (e.g. the manifest or an archive index) raw.
    pub async fn download_file(&mut self, file_name: &str) -> Result<Vec<u8>, PbsError> {
        self.transport
            .download("download", &[("file-name", file_name.to_string())])
            .await
    }

    /// Downloads a chunk by digest and returns its decoded plaintext.
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

    /// Downloads the dynamic archive index and returns its chunk digests in order.
    pub async fn archive_chunk_digests(&mut self) -> Result<Vec<[u8; 32]>, PbsError> {
        let index = self.download_file(ARCHIVE_NAME).await?;
        parse_dynamic_index(&index)
    }

    /// Reassembles the archive: fetches every chunk in order and writes the
    /// decoded tar stream to `writer`, reporting decoded bytes via `progress`.
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

/// Parses a dynamic chunk index (`.didx`): a 4096-byte header followed by
/// fixed-size entries of `end_offset (u64 LE) || digest[32]`. Returns the
/// digests in archive order (offsets are implied by ordering for reassembly).
pub fn parse_dynamic_index(data: &[u8]) -> Result<Vec<[u8; 32]>, PbsError> {
    let entries = data
        .get(DYNAMIC_INDEX_HEADER_SIZE..)
        .ok_or_else(|| PbsError::Decode("dynamic index shorter than its header".into()))?;

    if entries.len() % DYNAMIC_INDEX_ENTRY_SIZE != 0 {
        return Err(PbsError::Decode(
            "dynamic index has a truncated entry".into(),
        ));
    }

    let mut digests = Vec::with_capacity(entries.len() / DYNAMIC_INDEX_ENTRY_SIZE);
    for entry in entries.chunks_exact(DYNAMIC_INDEX_ENTRY_SIZE) {
        let digest_bytes = entry
            .get(8..DYNAMIC_INDEX_ENTRY_SIZE)
            .ok_or_else(|| PbsError::Decode("dynamic index entry too short".into()))?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(digest_bytes);
        digests.push(digest);
    }

    Ok(digests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_index_skips_header_and_reads_entries() {
        let mut data = vec![0u8; DYNAMIC_INDEX_HEADER_SIZE];
        // Entry 1: end-offset 1024, digest 0x11..
        data.extend_from_slice(&1024u64.to_le_bytes());
        data.extend_from_slice(&[0x11u8; 32]);
        // Entry 2: end-offset 2048, digest 0x22..
        data.extend_from_slice(&2048u64.to_le_bytes());
        data.extend_from_slice(&[0x22u8; 32]);

        let digests = parse_dynamic_index(&data).expect("parses");
        assert_eq!(digests, vec![[0x11u8; 32], [0x22u8; 32]]);
    }

    #[test]
    fn parse_index_rejects_truncated_entry() {
        let mut data = vec![0u8; DYNAMIC_INDEX_HEADER_SIZE];
        data.extend_from_slice(&[0u8; 10]); // not a multiple of 40
        assert!(parse_dynamic_index(&data).is_err());
    }
}
