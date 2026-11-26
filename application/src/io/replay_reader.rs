use crate::io::SafeSliceExt;
use std::{
    io::Cursor,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, Chain, ReadBuf};

/// Records the first `limit` bytes read from `inner` so a consumer that failed before
/// processing anything can be handed the same stream again.
pub struct AsyncReplayReader<R: AsyncRead + Unpin> {
    inner: R,
    recorded: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl<R: AsyncRead + Unpin> AsyncReplayReader<R> {
    pub fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            recorded: Vec::new(),
            limit,
            overflowed: false,
        }
    }

    /// Returns the full stream from its start again, or the bare inner reader when more
    /// than `limit` bytes were read and the start can no longer be replayed.
    pub fn into_replay(self) -> Result<Chain<Cursor<Vec<u8>>, R>, R> {
        if self.overflowed {
            Err(self.inner)
        } else {
            Ok(Cursor::new(self.recorded).chain(self.inner))
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AsyncReplayReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();

        let poll_result = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &poll_result
            && !self.overflowed
        {
            let newly_filled = match buf.filled().get_slice(filled_before..) {
                Ok(slice) => slice,
                Err(err) => return Poll::Ready(Err(err)),
            };

            if self.recorded.len() + newly_filled.len() > self.limit {
                self.overflowed = true;
                self.recorded = Vec::new();
            } else {
                self.recorded.extend_from_slice(newly_filled);
            }
        }

        poll_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Cursor,
        task::{Context, Poll},
    };
    use tokio::io::AsyncWrite;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    async fn read_to_end<R: AsyncRead + Unpin>(mut r: R) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    async fn replay_ok<R: AsyncRead + Unpin>(r: AsyncReplayReader<R>) -> Vec<u8> {
        match r.into_replay() {
            Ok(replay) => read_to_end(replay).await,
            Err(_) => panic!("expected replay within limit"),
        }
    }

    struct FailAfter {
        remaining: usize,
    }

    impl AsyncWrite for FailAfter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining == 0 {
                return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
            }
            let n = buf.len().min(self.remaining);
            self.remaining -= n;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // AsyncReplayReader

    #[test]
    fn passes_bytes_through_unchanged() {
        tokio_test::block_on(async {
            let input = data(10_000);
            let r = AsyncReplayReader::new(Cursor::new(input.clone()), 16);

            assert_eq!(read_to_end(r).await, input);
        });
    }

    #[test]
    fn replay_after_partial_read_yields_full_stream() {
        tokio_test::block_on(async {
            let input = data(1000);
            let mut r = AsyncReplayReader::new(Cursor::new(input.clone()), 100);

            let mut buf = [0; 40];
            r.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), input.get(..40).unwrap());

            assert_eq!(replay_ok(r).await, input);
        });
    }

    #[test]
    fn reading_exactly_limit_still_replays() {
        tokio_test::block_on(async {
            let input = data(100);
            let mut r = AsyncReplayReader::new(Cursor::new(input.clone()), 10);

            let mut buf = [0; 10];
            assert_eq!(r.read(&mut buf).await.unwrap(), 10);

            assert_eq!(replay_ok(r).await, input);
        });
    }

    #[test]
    fn single_read_past_limit_overflows() {
        tokio_test::block_on(async {
            let mut r = AsyncReplayReader::new(Cursor::new(data(100)), 10);

            let mut buf = [0; 11];
            assert_eq!(r.read(&mut buf).await.unwrap(), 11);

            assert!(r.into_replay().is_err());
        });
    }

    #[test]
    fn cumulative_reads_past_limit_overflow() {
        tokio_test::block_on(async {
            let mut r = AsyncReplayReader::new(Cursor::new(data(100)), 10);

            let mut buf = [0; 6];
            assert_eq!(r.read(&mut buf).await.unwrap(), 6);
            let mut buf = [0; 5];
            assert_eq!(r.read(&mut buf).await.unwrap(), 5);

            assert!(r.into_replay().is_err());
        });
    }

    #[test]
    fn overflow_returns_inner_positioned_after_consumed_bytes() {
        tokio_test::block_on(async {
            let input = data(100);
            let mut r = AsyncReplayReader::new(Cursor::new(input.clone()), 10);

            let mut buf = [0; 16];
            assert_eq!(r.read(&mut buf).await.unwrap(), 16);

            let inner = match r.into_replay() {
                Ok(_) => panic!("expected overflow"),
                Err(inner) => inner,
            };
            assert_eq!(read_to_end(inner).await, input.get(16..).unwrap());
        });
    }

    #[test]
    fn zero_limit_replays_empty_stream() {
        tokio_test::block_on(async {
            let mut r = AsyncReplayReader::new(Cursor::new(Vec::new()), 0);

            let mut buf = [0; 8];
            assert_eq!(r.read(&mut buf).await.unwrap(), 0);

            assert!(replay_ok(r).await.is_empty());
        });
    }

    #[test]
    fn zero_limit_overflows_on_any_data() {
        tokio_test::block_on(async {
            let mut r = AsyncReplayReader::new(Cursor::new(data(10)), 0);

            let mut buf = [0; 1];
            assert_eq!(r.read(&mut buf).await.unwrap(), 1);

            assert!(r.into_replay().is_err());
        });
    }

    #[test]
    fn prefilled_read_buf_bytes_are_not_recorded() {
        tokio_test::block_on(async {
            let input = data(8);
            let mut r = AsyncReplayReader::new(Cursor::new(input.clone()), input.len());

            let mut storage = [0; 16];
            let mut buf = ReadBuf::new(&mut storage);
            buf.put_slice(b"junk");
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                Pin::new(&mut r).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(buf.filled().len(), 4 + input.len());

            assert_eq!(replay_ok(r).await, input);
        });
    }

    #[test]
    fn replays_full_stream_after_copy_into_failing_writer() {
        tokio_test::block_on(async {
            let input = data(64 * 1024);
            let mut r = AsyncReplayReader::new(Cursor::new(input.clone()), 32 * 1024);

            let mut writer = FailAfter { remaining: 0 };
            assert!(tokio::io::copy(&mut r, &mut writer).await.is_err());

            assert_eq!(replay_ok(r).await, input);
        });
    }
}
