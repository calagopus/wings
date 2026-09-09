use super::CompressionType;
use std::{
    io::{Read, Seek},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

pub enum CompressionReader<'a, R: Read> {
    None(R),
    Gz(flate2::read::MultiGzDecoder<R>),
    Xz(Box<lzma_rust2::XzReader<R>>),
    Lzip(Box<lzma_rust2::LzipReader<R>>),
    Bz2(bzip2::read::MultiBzDecoder<R>),
    Lz4(lzzzz::lz4f::ReadDecompressor<'a, R>),
    Zstd(zstd::Decoder<'a, std::io::BufReader<R>>),
}

impl<'a, R: Read> CompressionReader<'a, R> {
    pub fn new(reader: R, compression_type: CompressionType) -> Result<Self, anyhow::Error> {
        Ok(match compression_type {
            CompressionType::None => CompressionReader::None(reader),
            CompressionType::Gz => CompressionReader::Gz(flate2::read::MultiGzDecoder::new(reader)),
            CompressionType::Xz => {
                CompressionReader::Xz(Box::new(lzma_rust2::XzReader::new(reader, true)))
            }
            CompressionType::Lzip => {
                CompressionReader::Lzip(Box::new(lzma_rust2::LzipReader::new(reader)))
            }
            CompressionType::Bz2 => {
                CompressionReader::Bz2(bzip2::read::MultiBzDecoder::new(reader))
            }
            CompressionType::Lz4 => {
                CompressionReader::Lz4(lzzzz::lz4f::ReadDecompressor::new(reader)?)
            }
            CompressionType::Zstd => CompressionReader::Zstd(zstd::Decoder::new(reader)?),
        })
    }

    pub fn into_inner(self) -> R {
        match self {
            CompressionReader::None(reader) => reader,
            CompressionReader::Gz(decoder) => decoder.into_inner(),
            CompressionReader::Xz(decoder) => decoder.into_inner(),
            CompressionReader::Lzip(decoder) => decoder.into_inner(),
            CompressionReader::Bz2(decoder) => decoder.into_inner(),
            CompressionReader::Lz4(decoder) => decoder.into_inner(),
            CompressionReader::Zstd(decoder) => decoder.finish().into_inner(),
        }
    }
}

impl<'a, R: Read> Read for CompressionReader<'a, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CompressionReader::None(reader) => reader.read(buf),
            CompressionReader::Gz(decoder) => decoder.read(buf),
            CompressionReader::Xz(decoder) => decoder.read(buf),
            CompressionReader::Lzip(decoder) => decoder.read(buf),
            CompressionReader::Bz2(decoder) => decoder.read(buf),
            CompressionReader::Lz4(decoder) => decoder.read(buf),
            CompressionReader::Zstd(decoder) => decoder.read(buf),
        }
    }
}

pub enum CompressionReaderMt<'a, R: Read + Seek> {
    None(R),
    Gz(flate2::read::MultiGzDecoder<R>),
    XzMt(Box<lzma_rust2::XzReaderMt<R>>),
    LzipMt(lzma_rust2::LzipReaderMt<R>),
    Bz2(bzip2::read::MultiBzDecoder<R>),
    Lz4(lzzzz::lz4f::ReadDecompressor<'a, R>),
    Zstd(zstd::Decoder<'a, std::io::BufReader<R>>),
}

impl<'a, R: Read + Seek> CompressionReaderMt<'a, R> {
    pub fn new(
        reader: R,
        compression_type: CompressionType,
        threads: usize,
    ) -> std::io::Result<Self> {
        Ok(match compression_type {
            CompressionType::None => CompressionReaderMt::None(reader),
            CompressionType::Gz => {
                CompressionReaderMt::Gz(flate2::read::MultiGzDecoder::new(reader))
            }
            CompressionType::Xz => CompressionReaderMt::XzMt(Box::new(
                lzma_rust2::XzReaderMt::new(reader, true, threads as u32)?,
            )),
            CompressionType::Lzip => {
                CompressionReaderMt::LzipMt(lzma_rust2::LzipReaderMt::new(reader, threads as u32)?)
            }
            CompressionType::Bz2 => {
                CompressionReaderMt::Bz2(bzip2::read::MultiBzDecoder::new(reader))
            }
            CompressionType::Lz4 => {
                CompressionReaderMt::Lz4(lzzzz::lz4f::ReadDecompressor::new(reader)?)
            }
            CompressionType::Zstd => CompressionReaderMt::Zstd(zstd::Decoder::new(reader)?),
        })
    }
}

impl<'a, R: Read + Seek> Read for CompressionReaderMt<'a, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CompressionReaderMt::None(reader) => reader.read(buf),
            CompressionReaderMt::Gz(decoder) => decoder.read(buf),
            CompressionReaderMt::XzMt(decoder) => decoder.read(buf),
            CompressionReaderMt::LzipMt(decoder) => decoder.read(buf),
            CompressionReaderMt::Bz2(decoder) => decoder.read(buf),
            CompressionReaderMt::Lz4(decoder) => decoder.read(buf),
            CompressionReaderMt::Zstd(decoder) => decoder.read(buf),
        }
    }
}

pub enum AsyncCompressionReader {
    None(Box<dyn AsyncRead + Unpin + Send>),
    Compressed {
        inner_completion: Option<tokio::sync::oneshot::Receiver<std::io::Result<()>>>,
        inner_reader: crate::io::pipe::PipeReader,
    },
}

impl AsyncCompressionReader {
    pub fn new(reader: impl Read + Send + 'static, compression_type: CompressionType) -> Self {
        let (inner_reader, inner_writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE * 2);
        let (completion_sender, inner_completion) = tokio::sync::oneshot::channel();

        tokio::task::spawn_blocking(move || {
            let mut writer = inner_writer.into_sync();
            let mut stream = match CompressionReader::new(reader, compression_type) {
                Ok(stream) => stream,
                Err(err) => {
                    let _ = completion_sender.send(Err(std::io::Error::other(err)));
                    return;
                }
            };

            match crate::io::copy(&mut stream, &mut writer) {
                Ok(_) => {}
                Err(err) => {
                    let _ = completion_sender.send(Err(err));
                    return;
                }
            }

            let _ = completion_sender.send(writer.shutdown());
        });

        Self::Compressed {
            inner_completion: Some(inner_completion),
            inner_reader,
        }
    }

    pub fn new_with_async_reader(
        reader: impl AsyncRead + Unpin + Send + 'static,
        compression_type: CompressionType,
    ) -> Self {
        match compression_type {
            CompressionType::None => Self::None(Box::new(reader)),
            compression_type => {
                Self::new(tokio_util::io::SyncIoBridge::new(reader), compression_type)
            }
        }
    }

    pub fn new_mt(
        reader: impl Read + Seek + Send + 'static,
        compression_type: CompressionType,
        threads: usize,
    ) -> Self {
        let (inner_reader, inner_writer) = crate::io::pipe::pipe(crate::BUFFER_SIZE * 4);
        let (completion_sender, inner_completion) = tokio::sync::oneshot::channel();

        tokio::task::spawn_blocking(move || {
            let mut writer = inner_writer.into_sync();
            let mut stream = match CompressionReaderMt::new(reader, compression_type, threads) {
                Ok(stream) => stream,
                Err(err) => {
                    let _ = completion_sender.send(Err(err));
                    return;
                }
            };

            match crate::io::copy(&mut stream, &mut writer) {
                Ok(_) => {}
                Err(err) => {
                    let _ = completion_sender.send(Err(err));
                    return;
                }
            }

            let _ = completion_sender.send(writer.shutdown());
        });

        Self::Compressed {
            inner_completion: Some(inner_completion),
            inner_reader,
        }
    }
}

impl AsyncRead for AsyncCompressionReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if crate::unlikely(buf.remaining() == 0) {
            return Poll::Ready(Ok(()));
        }

        match &mut *self {
            Self::None(reader) => Pin::new(reader).poll_read(cx, buf),
            Self::Compressed {
                inner_completion,
                inner_reader,
            } => {
                let filled = buf.filled().len();
                let read_result = Pin::new(inner_reader).poll_read(cx, buf);
                match &read_result {
                    Poll::Ready(Ok(())) if buf.filled().len() != filled => return read_result,
                    Poll::Ready(Err(_)) => return read_result,
                    Poll::Ready(Ok(())) | Poll::Pending => {}
                }

                if let Some(receiver) = inner_completion {
                    let result = match Pin::new(receiver).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(result)) => result,
                        Poll::Ready(Err(_)) => Err(std::io::Error::other(
                            "decompression task ended without completing the stream",
                        )),
                    };

                    *inner_completion = None;

                    if let Err(err) = result {
                        return Poll::Ready(Err(err));
                    }
                }

                read_result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn async_uncompressed_reader_preserves_buffered_bytes_without_runtime() -> std::io::Result<()> {
        futures::executor::block_on(async {
            let mut reader = BufReader::with_capacity(4, Cursor::new(b"hello world"));
            assert_eq!(reader.fill_buf().await?, b"hell");

            let mut reader =
                AsyncCompressionReader::new_with_async_reader(reader, CompressionType::None);
            let mut prefix = [0; 2];
            reader.read_exact(&mut prefix).await?;
            assert_eq!(&prefix, b"he");

            let mut remaining = Vec::new();
            reader.read_to_end(&mut remaining).await?;
            assert_eq!(remaining, b"llo world");

            Ok(())
        })
    }

    #[test]
    fn async_gzip_reader_decodes_stream() -> std::io::Result<()> {
        tokio_test::block_on(async {
            let input = b"compressed file contents\n".repeat(crate::BUFFER_SIZE);
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&input)?;
            let compressed = encoder.finish()?;

            let (reader, mut writer) = tokio::io::duplex(32);
            let producer = tokio::spawn(async move {
                writer.write_all(&compressed).await?;
                writer.shutdown().await
            });
            let mut reader = BufReader::with_capacity(4, reader);
            assert!(!reader.fill_buf().await?.is_empty());

            let mut reader =
                AsyncCompressionReader::new_with_async_reader(reader, CompressionType::Gz);
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await?;

            assert_eq!(output, input);
            producer.await??;

            Ok(())
        })
    }

    #[test]
    fn async_reader_propagates_input_errors() {
        tokio_test::block_on(async {
            for compression_type in [CompressionType::None, CompressionType::Gz] {
                let reader = tokio_test::io::Builder::new()
                    .read_error(std::io::Error::other("input failed"))
                    .build();

                let mut reader =
                    AsyncCompressionReader::new_with_async_reader(reader, compression_type);
                let err = reader.read_to_end(&mut Vec::new()).await.unwrap_err();

                assert_eq!(err.to_string(), "input failed");
            }
        });
    }

    #[test]
    fn dropping_partial_decompression_releases_the_blocking_worker() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(&vec![b'x'; crate::BUFFER_SIZE * 64])
            .expect("compressing fixture failed");
        let compressed = encoder.finish().expect("finishing fixture failed");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("creating runtime failed");

        let result = runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                for multithreaded in [false, true] {
                    let input = Cursor::new(compressed.clone());
                    let mut reader = if multithreaded {
                        AsyncCompressionReader::new_mt(input, CompressionType::Gz, 2)
                    } else {
                        AsyncCompressionReader::new_with_async_reader(input, CompressionType::Gz)
                    };
                    reader.read_exact(&mut [0; 1]).await?;
                    drop(reader);
                    tokio::task::spawn_blocking(|| ())
                        .await
                        .map_err(std::io::Error::other)?;
                }

                Ok::<_, std::io::Error>(())
            })
            .await
        });

        runtime.shutdown_timeout(std::time::Duration::from_millis(100));
        result
            .expect("decompression held the blocking worker after consumer drop")
            .expect("partial decompression failed");
    }

    #[test]
    fn eof_waits_for_producer_outcome_and_preserves_errors() {
        let (reader, writer) = crate::io::pipe::pipe(1);
        let (sender, completion) = tokio::sync::oneshot::channel();
        let mut reader = AsyncCompressionReader::Compressed {
            inner_completion: Some(completion),
            inner_reader: reader,
        };
        drop(writer);
        let mut output = Vec::new();
        let mut task = tokio_test::task::spawn(reader.read_to_end(&mut output));
        assert!(task.poll().is_pending());
        sender
            .send(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decoder failed after closing output",
            )))
            .expect("sending producer failure failed");
        assert!(matches!(
            task.poll(),
            Poll::Ready(Err(err)) if err.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn abandoned_producer_is_an_error() {
        let (reader, writer) = crate::io::pipe::pipe(1);
        let (sender, completion) = tokio::sync::oneshot::channel();
        let mut reader = AsyncCompressionReader::Compressed {
            inner_completion: Some(completion),
            inner_reader: reader,
        };
        drop(writer);
        drop(sender);
        let err = futures::executor::block_on(reader.read_to_end(&mut Vec::new()))
            .expect_err("abandoned producer reported successful EOF");
        assert_eq!(
            err.to_string(),
            "decompression task ended without completing the stream"
        );
    }
}
