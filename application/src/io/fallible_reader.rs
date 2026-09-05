use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::oneshot,
};

pub type FallibleSimplexReader = FallibleReader<tokio::io::ReadHalf<tokio::io::SimplexStream>>;

pub struct FallibleSignal {
    sender: Option<oneshot::Sender<Option<String>>>,
}

impl FallibleSignal {
    #[inline]
    pub fn succeed(mut self) {
        if let Some(sender) = self.sender.take() {
            sender.send(None).ok();
        }
    }

    #[inline]
    pub fn fail(mut self, err: impl std::fmt::Display) {
        if let Some(sender) = self.sender.take() {
            sender.send(Some(err.to_string())).ok();
        }
    }
}

impl Drop for FallibleSignal {
    #[inline]
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            sender
                .send(Some("producer ended without completing the stream".into()))
                .ok();
        }
    }
}

enum Outcome {
    Waiting(oneshot::Receiver<Option<String>>),
    Succeeded,
    Failed(String),
}

pub struct FallibleReader<R> {
    inner: R,
    outcome: Outcome,
    require_eof: bool,
}

impl<R> FallibleReader<R> {
    #[inline]
    pub fn new(inner: R) -> (Self, FallibleSignal) {
        let (sender, receiver) = oneshot::channel();

        (
            Self {
                inner,
                outcome: Outcome::Waiting(receiver),
                require_eof: false,
            },
            FallibleSignal {
                sender: Some(sender),
            },
        )
    }

    #[inline]
    pub fn new_with_eof(inner: R) -> (Self, FallibleSignal) {
        let (mut reader, signal) = Self::new(inner);
        reader.require_eof = true;

        (reader, signal)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for FallibleReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if crate::unlikely(buf.remaining() == 0) {
            return Poll::Ready(Ok(()));
        }

        let filled = buf.filled().len();
        let read_result = Pin::new(&mut this.inner).poll_read(cx, buf);
        match &read_result {
            Poll::Ready(Ok(())) if buf.filled().len() != filled => return Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => return read_result,
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }

        if let Outcome::Waiting(receiver) = &mut this.outcome {
            let resolved = match Pin::new(receiver).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(None)) => Outcome::Succeeded,
                Poll::Ready(Ok(Some(err))) => Outcome::Failed(err),
                Poll::Ready(Err(_)) => {
                    Outcome::Failed("producer was dropped without completing the stream".into())
                }
            };

            this.outcome = resolved;
        }

        match &this.outcome {
            Outcome::Failed(err) => Poll::Ready(Err(std::io::Error::other(err.clone()))),
            Outcome::Succeeded if !this.require_eof => Poll::Ready(Ok(())),
            _ => read_result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn stream() -> (
        FallibleSimplexReader,
        tokio::io::WriteHalf<tokio::io::SimplexStream>,
        FallibleSignal,
    ) {
        let (reader, writer) = tokio::io::simplex(64);
        let (reader, signal) = FallibleReader::new(reader);

        (reader, writer, signal)
    }

    #[test]
    fn succeeding_producer_waits_for_reader_eof() -> Result<(), std::io::Error> {
        tokio_test::block_on(async {
            let (reader, mut writer) = tokio::io::simplex(64);
            let (mut reader, signal) = FallibleReader::new_with_eof(reader);
            signal.succeed();

            let mut buffer = [0; 8];
            let mut buf = ReadBuf::new(&mut buffer);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(
                Pin::new(&mut reader)
                    .poll_read(&mut cx, &mut buf)
                    .is_pending()
            );

            writer.write_all(b"archive").await?;
            writer.shutdown().await?;
            drop(writer);

            let mut out = Vec::new();
            reader.read_to_end(&mut out).await?;
            assert_eq!(out, b"archive");

            Ok(())
        })
    }

    #[test]
    fn succeeding_producer_reads_to_eof() {
        tokio_test::block_on(async {
            let (mut reader, mut writer, signal) = stream();

            tokio::spawn(async move {
                writer.write_all(b"archive").await.unwrap();
                drop(writer);
                signal.succeed();
            });

            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();

            assert_eq!(out, b"archive");
        });
    }

    #[test]
    fn failing_producer_errors_instead_of_ending() {
        tokio_test::block_on(async {
            let (mut reader, mut writer, signal) = stream();

            tokio::spawn(async move {
                writer.write_all(b"trunc").await.unwrap();
                drop(writer);
                signal.fail("disk went away");
            });

            let mut out = Vec::new();
            let err = reader.read_to_end(&mut out).await.unwrap_err();

            // The bytes already produced still surface; what must not happen is
            // the read completing as if the producer had finished.
            assert_eq!(out, b"trunc");
            assert!(err.to_string().contains("disk went away"), "{err}");
        });
    }

    #[test]
    fn failure_recorded_after_writer_drop_is_still_observed() {
        // The producer releases its writer before recording the outcome, so the
        // reader hits EOF while the outcome is still pending. It must wait
        // rather than report a clean end of stream.
        tokio_test::block_on(async {
            let (mut reader, writer, signal) = stream();

            tokio::spawn(async move {
                drop(writer);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                signal.fail("late failure");
            });

            let mut out = Vec::new();
            let err = reader.read_to_end(&mut out).await.unwrap_err();

            assert!(out.is_empty());
            assert!(err.to_string().contains("late failure"), "{err}");
        });
    }

    #[test]
    fn failure_is_reported_on_every_subsequent_read() {
        tokio_test::block_on(async {
            let (mut reader, writer, signal) = stream();

            tokio::spawn(async move {
                drop(writer);
                signal.fail("disk went away");
            });

            let mut buf = [0; 8];
            let err = reader.read(&mut buf).await.unwrap_err();
            assert!(err.to_string().contains("disk went away"), "{err}");

            // Reading on past the failure must not paper over it by reporting a
            // clean end of stream.
            let err = reader.read(&mut buf).await.unwrap_err();
            assert!(err.to_string().contains("disk went away"), "{err}");
        });
    }

    #[test]
    fn dropped_producer_is_treated_as_failure() {
        tokio_test::block_on(async {
            let (mut reader, writer, signal) = stream();

            tokio::spawn(async move {
                drop(writer);
                drop(signal);
            });

            let mut out = Vec::new();
            let err = reader.read_to_end(&mut out).await.unwrap_err();

            assert!(out.is_empty());
            assert!(err.to_string().contains("without completing"), "{err}");
        });
    }
}
