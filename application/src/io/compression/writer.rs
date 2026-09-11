use super::{CompressionLevel, CompressionType, gzip::StoredFallbackGzip};
use gzp::ZWriter;
use std::io::Write;

const GZ_BLOCK_SIZE: usize = 1024 * 1024;

pub enum CompressionWriter<'a, W: Write + Send + 'static> {
    None(W),
    Gz(gzp::par::compress::ParCompress<'a, StoredFallbackGzip, W>),
    Xz(usize, Box<lzma_rust2::XzWriterMt<W>>),
    Lzip(usize, Box<lzma_rust2::LzipWriterMt<W>>),
    Bz2(bzip2::write::BzEncoder<W>),
    Lz4(lzzzz::lz4f::WriteCompressor<W>),
    Zstd(usize, bool, zstd::Encoder<'a, W>),
}

impl<'a, W: Write + Send + 'static> CompressionWriter<'a, W> {
    pub fn new(
        writer: W,
        compression_type: CompressionType,
        compression_level: CompressionLevel,
        threads: usize,
    ) -> std::io::Result<Self> {
        let threads = crate::threading::resolve_threads(threads);

        Ok(match compression_type {
            CompressionType::None => CompressionWriter::None(writer),
            CompressionType::Gz => CompressionWriter::Gz(
                gzp::par::compress::ParCompressBuilder::new()
                    .num_threads(threads)
                    .map_err(std::io::Error::other)?
                    .buffer_size(GZ_BLOCK_SIZE)
                    .map_err(std::io::Error::other)?
                    .compression_level(gzp::Compression::new(compression_level.to_deflate_level()))
                    .from_writer(writer),
            ),
            CompressionType::Xz => CompressionWriter::Xz(
                0,
                Box::new(lzma_rust2::XzWriterMt::new(
                    writer,
                    {
                        let mut options =
                            lzma_rust2::XzOptions::with_preset(compression_level.to_xz_level());
                        options.set_block_size(Some(unsafe {
                            std::num::NonZeroU64::new_unchecked(128 * 1024)
                        }));

                        options
                    },
                    threads as u32,
                )?),
            ),
            CompressionType::Lzip => CompressionWriter::Lzip(
                0,
                Box::new(lzma_rust2::LzipWriterMt::new(
                    writer,
                    {
                        let mut options =
                            lzma_rust2::LzipOptions::with_preset(compression_level.to_lzip_level());
                        options.set_member_size(Some(unsafe {
                            std::num::NonZeroU64::new_unchecked(128 * 1024)
                        }));

                        options
                    },
                    threads as u32,
                )?),
            ),
            CompressionType::Bz2 => CompressionWriter::Bz2(bzip2::write::BzEncoder::new(
                writer,
                bzip2::Compression::new(compression_level.to_bz2_level()),
            )),
            CompressionType::Lz4 => CompressionWriter::Lz4(lzzzz::lz4f::WriteCompressor::new(
                writer,
                lzzzz::lz4f::PreferencesBuilder::new()
                    .compression_level(compression_level.to_lz4_level())
                    .build(),
            )?),
            CompressionType::Zstd => CompressionWriter::Zstd(0, threads > 1, {
                let mut encoder = zstd::Encoder::new(writer, compression_level.to_zstd_level())?;
                if threads > 1 {
                    encoder.multithread(threads as u32).ok();
                }

                encoder
            }),
        })
    }

    pub fn finish(self) -> std::io::Result<W> {
        match self {
            CompressionWriter::None(writer) => Ok(writer),
            CompressionWriter::Gz(mut writer) => {
                Ok(writer.finish().map_err(std::io::Error::other)?)
            }
            CompressionWriter::Xz(_, writer) => Ok(writer.finish()?),
            CompressionWriter::Lzip(_, writer) => Ok(writer.finish()?),
            CompressionWriter::Bz2(writer) => Ok(writer.finish()?),
            CompressionWriter::Lz4(mut writer) => {
                writer.flush()?;
                Ok(writer.into_inner())
            }
            CompressionWriter::Zstd(_, _, writer) => Ok(writer.finish()?),
        }
    }
}

impl<'a, W: Write + Send + 'static> Write for CompressionWriter<'a, W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CompressionWriter::None(writer) => writer.write(buf),
            CompressionWriter::Gz(writer) => writer.write(buf),
            CompressionWriter::Xz(i, writer) => {
                *i += 1;

                if *i % 64 == 0 {
                    writer.flush()?;
                }

                writer.write(buf)
            }
            CompressionWriter::Lzip(i, writer) => {
                *i += 1;

                if *i % 64 == 0 {
                    writer.flush()?;
                }

                writer.write(buf)
            }
            CompressionWriter::Bz2(writer) => writer.write(buf),
            CompressionWriter::Lz4(writer) => writer.write(buf),
            CompressionWriter::Zstd(i, mt, writer) => {
                if *mt {
                    *i += 1;

                    if *i % 64 == 0 {
                        writer.flush()?;
                    }
                }

                writer.write(buf)
            }
        }
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            CompressionWriter::None(writer) => writer.flush(),
            CompressionWriter::Gz(writer) => writer.flush(),
            CompressionWriter::Xz(_, writer) => writer.flush(),
            CompressionWriter::Lzip(_, writer) => writer.flush(),
            CompressionWriter::Bz2(writer) => writer.flush(),
            CompressionWriter::Lz4(writer) => writer.flush(),
            CompressionWriter::Zstd(_, _, writer) => writer.flush(),
        }
    }
}
