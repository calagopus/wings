//! Content-defined chunking for PBS dynamic archives.
//!
//! Real content-defined chunking (FastCDC) is what makes PBS deduplication
//! effective: identical content produces identical chunk boundaries (and thus
//! identical SHA-256 digests), so unchanged regions across backups are uploaded
//! once. PBS uses its own chunker internally, but cross-Calagopus dedup only
//! requires that *our* chunking be deterministic — which FastCDC guarantees.

/// Minimum chunk size (1 MiB).
pub const MIN_CHUNK_SIZE: u32 = 1024 * 1024;
/// Target average chunk size (4 MiB), matching PBS's default granularity.
pub const AVG_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
/// Maximum chunk size (16 MiB).
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Builds a streaming content-defined chunker over a blocking reader.
///
/// Each yielded `ChunkData` carries the chunk bytes plus its offset/length,
/// which the writer encodes into a PBS DataBlob.
pub fn stream_chunker<R: std::io::Read>(reader: R) -> fastcdc::v2020::StreamCDC<R> {
    fastcdc::v2020::StreamCDC::new(reader, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let mut state = 0x1234_5678u32;
        for byte in data.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        data
    }

    #[test]
    fn chunking_is_deterministic_and_covers_all_input() {
        // Larger than MAX_CHUNK_SIZE so it must split into multiple chunks.
        let data = pseudo_random(17 * 1024 * 1024);

        let boundaries = |bytes: &[u8]| -> Vec<(usize, usize)> {
            fastcdc::v2020::FastCDC::new(bytes, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
                .map(|chunk| (chunk.offset, chunk.length))
                .collect()
        };

        let first = boundaries(&data);
        let second = boundaries(&data);

        assert_eq!(first, second, "chunk boundaries must be deterministic");
        assert!(first.len() > 1, "input larger than max chunk must split");

        let covered: usize = first.iter().map(|(_, length)| *length).sum();
        assert_eq!(covered, data.len(), "chunks must cover the whole input");
    }
}
