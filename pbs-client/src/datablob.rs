use super::error::PbsError;
use sha2::{Digest, Sha256};

pub const UNCOMPRESSED_BLOB_MAGIC: [u8; 8] = [66, 171, 56, 7, 190, 131, 112, 161];
pub const COMPRESSED_BLOB_MAGIC: [u8; 8] = [49, 185, 88, 66, 111, 182, 163, 127];

const HEADER_SIZE: usize = 12;

const MAX_DECODED_BLOB: usize = 256 * 1024 * 1024;

pub struct EncodedBlob {
    pub data: Vec<u8>,
    pub digest: [u8; 32],
    pub plaintext_size: u64,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0; 32];
    out.copy_from_slice(&digest);
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn encode_blob(plaintext: &[u8]) -> EncodedBlob {
    let digest = sha256(plaintext);

    let compressed = zstd::bulk::compress(plaintext, 1).ok();
    let (magic, payload): ([u8; 8], &[u8]) = match &compressed {
        Some(compressed) if compressed.len() < plaintext.len() => {
            (COMPRESSED_BLOB_MAGIC, compressed.as_slice())
        }
        _ => (UNCOMPRESSED_BLOB_MAGIC, plaintext),
    };

    let crc = crc32(payload);

    let mut data = Vec::with_capacity(HEADER_SIZE + payload.len());
    data.extend_from_slice(&magic);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(payload);

    EncodedBlob {
        data,
        digest,
        plaintext_size: plaintext.len() as u64,
    }
}

pub fn decode_blob(raw: &[u8]) -> Result<Vec<u8>, PbsError> {
    let magic = raw
        .get(..8)
        .ok_or_else(|| PbsError::Decode("blob shorter than header".into()))?;
    let crc_field = raw
        .get(8..12)
        .ok_or_else(|| PbsError::Decode("blob shorter than header".into()))?;
    let payload = raw
        .get(HEADER_SIZE..)
        .ok_or_else(|| PbsError::Decode("blob shorter than header".into()))?;

    let stored_crc = u32::from_le_bytes(
        crc_field
            .try_into()
            .map_err(|_| PbsError::Decode("malformed crc field".into()))?,
    );
    if crc32(payload) != stored_crc {
        return Err(PbsError::Decode("blob crc mismatch".into()));
    }

    if magic == UNCOMPRESSED_BLOB_MAGIC.as_slice() {
        Ok(payload.to_vec())
    } else if magic == COMPRESSED_BLOB_MAGIC.as_slice() {
        zstd::bulk::decompress(payload, MAX_DECODED_BLOB)
            .map_err(|err| PbsError::Decode(compact_str::format_compact!("zstd decode: {err}")))
    } else {
        Err(PbsError::Decode(
            "unknown or encrypted blob magic (encryption is not supported)".into(),
        ))
    }
}
