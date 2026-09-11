use super::looks_incompressible;
use bytes::Bytes;
use flate2::{Compress, Compression, FlushCompress};
use gzp::{FormatSpec, GzpError, check::Crc32, deflate::Gzip};

const STORED_BLOCK_LIMIT: usize = u16::MAX as usize;
const MIN_PROBE_SIZE: usize = 4096;
const MAX_PROBE_LEVEL: u32 = 4;

/// A gzip [`FormatSpec`] that emits raw stored blocks for incompressible input.
#[derive(Copy, Clone, Debug)]
pub struct StoredFallbackGzip;

impl FormatSpec for StoredFallbackGzip {
    type C = Crc32;
    type Compressor = Compress;

    #[inline]
    fn new() -> Self {
        Self
    }

    #[inline]
    fn create_compressor(&self, compression_level: Compression) -> Result<Compress, GzpError> {
        Gzip::new().create_compressor(compression_level)
    }

    #[inline]
    fn needs_dict(&self) -> bool {
        Gzip::new().needs_dict()
    }

    fn encode(
        &self,
        input: &[u8],
        encoder: &mut Compress,
        compression_level: Compression,
        dict: Option<&Bytes>,
        is_last: bool,
    ) -> Result<Vec<u8>, GzpError> {
        if compression_level.level() <= MAX_PROBE_LEVEL
            && input.len() >= MIN_PROBE_SIZE
            && looks_incompressible(input)
        {
            return Ok(stored_blocks(input, is_last));
        }

        let mut buffer = Vec::with_capacity(input.len() + std::cmp::max(128, input.len() / 10));
        if let Some(dict) = dict {
            encoder.set_dictionary(dict.as_ref())?;
        }
        encoder.compress_vec(
            input,
            &mut buffer,
            if is_last {
                FlushCompress::Finish
            } else {
                FlushCompress::Sync
            },
        )?;
        encoder.reset();

        if buffer.len() >= input.len() {
            return Ok(stored_blocks(input, is_last));
        }

        Ok(buffer)
    }

    #[inline]
    fn header(&self, compression_level: Compression) -> Vec<u8> {
        Gzip::new().header(compression_level)
    }

    #[inline]
    fn footer(&self, check: &Crc32) -> Vec<u8> {
        Gzip::new().footer(check)
    }
}

/// Encodes `input` as a sequence of deflate stored blocks.
fn stored_blocks(input: &[u8], is_last: bool) -> Vec<u8> {
    if input.is_empty() {
        return if is_last {
            vec![1, 0, 0, 0xff, 0xff]
        } else {
            Vec::new()
        };
    }

    let blocks = input.len().div_ceil(STORED_BLOCK_LIMIT);
    let mut output = Vec::with_capacity(input.len() + blocks * 5);

    for (index, chunk) in input.chunks(STORED_BLOCK_LIMIT).enumerate() {
        let final_block = is_last && index + 1 == blocks;
        let len = chunk.len() as u16;

        output.push(u8::from(final_block));
        output.extend_from_slice(&len.to_le_bytes());
        output.extend_from_slice(&(!len).to_le_bytes());
        output.extend_from_slice(chunk);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use gzp::{ZWriter, par::compress::ParCompressBuilder};
    use std::io::{Read, Write};

    fn roundtrip(input: &[u8], level: u32, threads: usize) -> Vec<u8> {
        let mut writer = ParCompressBuilder::<StoredFallbackGzip>::new()
            .num_threads(threads)
            .expect("thread count")
            .compression_level(Compression::new(level))
            .from_writer(Vec::new());
        writer.write_all(input).expect("write");
        let compressed = writer.finish().expect("finish");

        let mut decoded = Vec::new();
        flate2::read::MultiGzDecoder::new(compressed.as_slice())
            .read_to_end(&mut decoded)
            .expect("decode");

        assert_eq!(decoded, input, "roundtrip mismatch");
        compressed
    }

    fn random(len: usize) -> Vec<u8> {
        let mut state = 0x7ee0u64;

        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn text(len: usize) -> Vec<u8> {
        std::iter::repeat(b"server_player=true level_spawn=42\n".iter().copied())
            .flatten()
            .take(len)
            .collect()
    }

    #[test]
    fn stores_incompressible_input() {
        let input = random(4 * 1024 * 1024);
        let compressed = roundtrip(&input, 1, 2);

        // stored blocks cost 5 bytes per 65535, so the floor is just above 1.0
        let ratio = compressed.len() as f64 / input.len() as f64;
        assert!(
            ratio < 1.001,
            "expected stored blocks to avoid expansion, got ratio {ratio} ({} for {})",
            compressed.len(),
            input.len()
        );
    }

    #[test]
    fn still_compresses_text() {
        let input = text(4 * 1024 * 1024);
        let compressed = roundtrip(&input, 1, 2);

        assert!(
            compressed.len() < input.len() / 4,
            "expected text to compress, got {} for {}",
            compressed.len(),
            input.len()
        );
    }

    #[test]
    fn roundtrips_edge_cases() {
        roundtrip(&[], 1, 1);
        roundtrip(&random(1), 1, 1);
        roundtrip(&random(STORED_BLOCK_LIMIT), 1, 1);
        roundtrip(&random(STORED_BLOCK_LIMIT * 2), 1, 1);
        roundtrip(&random(STORED_BLOCK_LIMIT * 3 + 7), 1, 2);
    }

    #[test]
    fn roundtrips_mixed_input_at_every_level() {
        let mut input = text(1024 * 1024);
        input.extend_from_slice(&random(1024 * 1024));
        input.extend_from_slice(&text(1024 * 1024));

        for level in [1, 4, 6, 9] {
            roundtrip(&input, level, 2);
        }
    }

    #[test]
    fn external_gzip_accepts_output() {
        let mut input = text(2 * 1024 * 1024);
        input.extend_from_slice(&random(8 * 1024 * 1024));
        input.extend_from_slice(&text(2 * 1024 * 1024));

        let compressed = roundtrip(&input, 1, 2);
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("compat-check.gz");
        std::fs::write(&path, &compressed).expect("write archive");

        let output = match std::process::Command::new("gzip")
            .arg("-dc")
            .arg(&path)
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                eprintln!("skipping external gzip check: {err}");
                return;
            }
        };
        assert!(
            output.status.success(),
            "gzip -dc failed: {:?}",
            output.status
        );
        assert_eq!(output.stdout, input, "gzip -dc output differs");

        let test = std::process::Command::new("gzip")
            .arg("-t")
            .arg(&path)
            .status()
            .expect("run gzip -t");
        assert!(test.success(), "gzip -t rejected the archive");
    }

    #[test]
    fn detects_entropy() {
        assert!(looks_incompressible(&random(1024 * 1024)));
        assert!(!looks_incompressible(&text(1024 * 1024)));
    }
}
