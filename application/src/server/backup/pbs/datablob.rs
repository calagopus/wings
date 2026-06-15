use super::error::PbsError;
use sha2::{Digest, Sha256};

/// PBS DataBlob magic for unencrypted, uncompressed payloads.
pub const UNCOMPRESSED_BLOB_MAGIC: [u8; 8] = [66, 171, 56, 7, 190, 131, 112, 161];
/// PBS DataBlob magic for unencrypted, zstd-compressed payloads.
pub const COMPRESSED_BLOB_MAGIC: [u8; 8] = [49, 185, 88, 66, 111, 182, 163, 127];

/// Size of the unencrypted DataBlob header: `magic[8] || crc[4]`.
const HEADER_SIZE: usize = 12;

/// Upper bound on a decoded blob, guarding against decompression bombs.
const MAX_DECODED_BLOB: usize = 256 * 1024 * 1024;

/// An encoded PBS DataBlob plus the metadata PBS needs to register it.
pub struct EncodedBlob {
    /// The on-wire blob: `magic[8] || crc_le[4] || payload`.
    pub data: Vec<u8>,
    /// SHA-256 of the **plaintext** — PBS's chunk digest / dedup key.
    pub digest: [u8; 32],
    /// Plaintext length in bytes (PBS `size`).
    pub plaintext_size: u64,
}

/// SHA-256 of a byte slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Encodes plaintext into an unencrypted PBS DataBlob.
///
/// zstd compression is applied only when it actually shrinks the data, matching
/// PBS's own behaviour (otherwise the uncompressed magic is used). The CRC32 is
/// little-endian and covers the payload bytes only (everything after the
/// 12-byte header).
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

/// Decodes an unencrypted PBS DataBlob, verifying its CRC.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_blob_has_exact_header_and_roundtrips() {
        let input = b"hello pbs";
        let blob = encode_blob(input);

        // Small/incompressible input keeps the uncompressed magic.
        assert_eq!(blob.data.get(..8), Some(UNCOMPRESSED_BLOB_MAGIC.as_slice()));
        assert_eq!(blob.plaintext_size, input.len() as u64);
        assert_eq!(blob.digest, sha256(input));

        // CRC is little-endian over the payload only (bytes after the header).
        let payload = blob.data.get(12..).expect("payload present");
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(payload);
        assert_eq!(
            blob.data.get(8..12),
            Some(hasher.finalize().to_le_bytes().as_slice())
        );

        assert_eq!(decode_blob(&blob.data).expect("decodes"), input);
    }

    #[test]
    fn compressible_blob_uses_compressed_magic_and_roundtrips() {
        let input = vec![0u8; 8192];
        let blob = encode_blob(&input);

        assert_eq!(blob.data.get(..8), Some(COMPRESSED_BLOB_MAGIC.as_slice()));
        assert_eq!(blob.digest, sha256(&input));
        assert_eq!(decode_blob(&blob.data).expect("decodes"), input);
    }

    #[test]
    fn corrupt_crc_is_rejected() {
        let mut blob = encode_blob(b"tamper me").data;
        // Flip a payload byte without fixing the CRC.
        if let Some(byte) = blob.get_mut(12) {
            *byte ^= 0xff;
        }
        assert!(decode_blob(&blob).is_err());
    }
}
