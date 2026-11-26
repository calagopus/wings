use crate::io::SafeSliceMutExt;
use futures::ready;
use std::{
    io::{self, Read, Seek, SeekFrom},
    ops::Bound,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt, ReadBuf};

pub fn resolve_range(range: (Bound<u64>, Bound<u64>), len: u64) -> io::Result<(u64, u64)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid range specified");

    let last = len.checked_sub(1).ok_or_else(invalid)?;

    let start = match range.0 {
        Bound::Included(start) => start,
        Bound::Excluded(start) => start.checked_add(1).ok_or_else(invalid)?,
        Bound::Unbounded => 0,
    };

    let end = match range.1 {
        Bound::Included(end) => end.min(last),
        Bound::Excluded(end) => end.checked_sub(1).ok_or_else(invalid)?.min(last),
        Bound::Unbounded => last,
    };

    if start > end {
        return Err(invalid());
    }

    Ok((start, end))
}

/// A byte range that resolves to inclusive `(start, end)` offsets against a known length,
/// or `None` when it cannot be satisfied.
pub trait ResolveRange {
    fn resolve(&self, len: u64) -> Option<(u64, u64)>;
}

impl ResolveRange for (Bound<u64>, Bound<u64>) {
    fn resolve(&self, len: u64) -> Option<(u64, u64)> {
        resolve_range(*self, len).ok()
    }
}

fn resolve_or_invalid(range: &impl ResolveRange, len: u64) -> io::Result<(u64, u64)> {
    range
        .resolve(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid range specified"))
}

pub struct RangeReader<R> {
    inner: R,
    start: u64,
    end: u64,
    pos: u64,
}

impl<R: Read + Seek> RangeReader<R> {
    pub fn new(mut inner: R, range: impl ResolveRange, len: u64) -> io::Result<Self> {
        let (start, end) = resolve_or_invalid(&range, len)?;

        inner.seek(SeekFrom::Start(start))?;

        Ok(Self {
            inner,
            start,
            end,
            pos: start,
        })
    }

    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

impl<R: Read + Seek> Read for RangeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if crate::unlikely(self.pos > self.end) {
            return Ok(0);
        }

        let remaining = self.end - self.pos + 1;
        let to_read = remaining.min(buf.len() as u64) as usize;

        let bytes_read = self.inner.read(buf.get_slice_mut(..to_read)?)?;
        self.pos += bytes_read as u64;

        Ok(bytes_read)
    }
}

pub struct AsyncRangeReader<R> {
    inner: R,
    start: u64,
    end: u64,
    pos: u64,
}

impl<R: AsyncRead + AsyncSeek + Unpin> AsyncRangeReader<R> {
    pub async fn new(mut inner: R, range: impl ResolveRange, len: u64) -> io::Result<Self> {
        let (start, end) = resolve_or_invalid(&range, len)?;

        inner.seek(SeekFrom::Start(start)).await?;

        Ok(Self {
            inner,
            start,
            end,
            pos: start,
        })
    }

    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> AsyncRead for AsyncRangeReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;

        if crate::unlikely(me.pos > me.end) {
            return Poll::Ready(Ok(()));
        }

        let remaining = me.end - me.pos + 1;
        let to_read = remaining.min(buf.remaining() as u64) as usize;

        if crate::unlikely(to_read == 0) {
            return Poll::Ready(Ok(()));
        }

        let mut tmp = ReadBuf::new(buf.initialize_unfilled_to(to_read));

        ready!(Pin::new(&mut me.inner).poll_read(cx, &mut tmp))?;

        let bytes_read = tmp.filled().len();

        buf.advance(bytes_read);
        me.pos += bytes_read as u64;

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    fn read_all<R: Read>(mut r: R) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    async fn read_all_async<R: AsyncRead + Unpin>(mut r: R) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    // resolve_range

    #[test]
    fn resolve_unbounded_is_full() {
        assert_eq!(
            resolve_range((Bound::Unbounded, Bound::Unbounded), 10).unwrap(),
            (0, 9)
        );
    }

    #[test]
    fn resolve_inclusive() {
        assert_eq!(
            resolve_range((Bound::Included(2), Bound::Included(5)), 10).unwrap(),
            (2, 5)
        );
    }

    #[test]
    fn resolve_excluded_start() {
        assert_eq!(
            resolve_range((Bound::Excluded(2), Bound::Included(5)), 10).unwrap(),
            (3, 5)
        );
    }

    #[test]
    fn resolve_excluded_end() {
        assert_eq!(
            resolve_range((Bound::Included(2), Bound::Excluded(5)), 10).unwrap(),
            (2, 4)
        );
    }

    #[test]
    fn resolve_inclusive_end_clamped_to_last() {
        assert_eq!(
            resolve_range((Bound::Included(0), Bound::Included(100)), 10).unwrap(),
            (0, 9)
        );
    }

    #[test]
    fn resolve_excluded_end_clamped_to_last() {
        assert_eq!(
            resolve_range((Bound::Included(0), Bound::Excluded(100)), 10).unwrap(),
            (0, 9)
        );
    }

    #[test]
    fn resolve_single_byte_file() {
        assert_eq!(
            resolve_range((Bound::Unbounded, Bound::Unbounded), 1).unwrap(),
            (0, 0)
        );
    }

    #[test]
    fn resolve_last_byte() {
        assert_eq!(
            resolve_range((Bound::Included(9), Bound::Unbounded), 10).unwrap(),
            (9, 9)
        );
    }

    #[test]
    fn resolve_zero_len_errors() {
        let err = resolve_range((Bound::Unbounded, Bound::Unbounded), 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn resolve_start_after_end_errors() {
        assert!(resolve_range((Bound::Included(5), Bound::Included(2)), 10).is_err());
    }

    #[test]
    fn resolve_start_past_last_errors() {
        assert!(resolve_range((Bound::Included(10), Bound::Unbounded), 10).is_err());
    }

    #[test]
    fn resolve_excluded_start_overflow_errors() {
        assert!(resolve_range((Bound::Excluded(u64::MAX), Bound::Unbounded), 10).is_err());
    }

    #[test]
    fn resolve_excluded_end_zero_errors() {
        assert!(resolve_range((Bound::Unbounded, Bound::Excluded(0)), 10).is_err());
    }

    // RangeReader

    #[test]
    fn range_reader_full() {
        let r = RangeReader::new(
            Cursor::new(b"0123456789".to_vec()),
            (Bound::Unbounded, Bound::Unbounded),
            10,
        )
        .unwrap();
        assert_eq!(r.len(), 10);
        assert_eq!(read_all(r), b"0123456789");
    }

    #[test]
    fn range_reader_middle_seeks_to_start() {
        let r = RangeReader::new(
            Cursor::new(b"0123456789".to_vec()),
            (Bound::Included(2), Bound::Included(5)),
            10,
        )
        .unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(read_all(r), b"2345");
    }

    #[test]
    fn range_reader_single_byte() {
        let r = RangeReader::new(
            Cursor::new(b"0123456789".to_vec()),
            (Bound::Included(4), Bound::Included(4)),
            10,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(read_all(r), b"4");
    }

    #[test]
    fn range_reader_end_clamped() {
        let r = RangeReader::new(
            Cursor::new(b"0123456789".to_vec()),
            (Bound::Included(7), Bound::Included(100)),
            10,
        )
        .unwrap();
        assert_eq!(read_all(r), b"789");
    }

    #[test]
    fn range_reader_excluded_end() {
        let r = RangeReader::new(
            Cursor::new(b"0123456789".to_vec()),
            (Bound::Included(0), Bound::Excluded(3)),
            10,
        )
        .unwrap();
        assert_eq!(read_all(r), b"012");
    }

    #[test]
    fn range_reader_chunks_and_stops_at_end() {
        let mut r = RangeReader::new(
            Cursor::new(b"0123456789".to_vec()),
            (Bound::Included(2), Bound::Included(7)),
            10,
        )
        .unwrap();

        let mut buf = [0; 4];
        assert_eq!(r.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf, b"2345");
        assert_eq!(r.read(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"67");
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn range_reader_new_rejects_invalid() {
        assert!(
            RangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Included(5), Bound::Included(2)),
                10,
            )
            .is_err()
        );
    }

    // AsyncRangeReader

    #[test]
    fn async_range_full() {
        tokio_test::block_on(async {
            let r = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Unbounded, Bound::Unbounded),
                10,
            )
            .await
            .unwrap();
            assert_eq!(r.len(), 10);
            assert_eq!(read_all_async(r).await, b"0123456789");
        });
    }

    #[test]
    fn async_range_middle() {
        tokio_test::block_on(async {
            let r = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Included(2), Bound::Included(5)),
                10,
            )
            .await
            .unwrap();
            assert_eq!(r.len(), 4);
            assert_eq!(read_all_async(r).await, b"2345");
        });
    }

    #[test]
    fn async_range_single_byte() {
        tokio_test::block_on(async {
            let r = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Included(4), Bound::Included(4)),
                10,
            )
            .await
            .unwrap();
            assert_eq!(read_all_async(r).await, b"4");
        });
    }

    #[test]
    fn async_range_end_clamped() {
        tokio_test::block_on(async {
            let r = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Included(7), Bound::Included(100)),
                10,
            )
            .await
            .unwrap();
            assert_eq!(read_all_async(r).await, b"789");
        });
    }

    #[test]
    fn async_range_excluded_end() {
        tokio_test::block_on(async {
            let r = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Included(0), Bound::Excluded(3)),
                10,
            )
            .await
            .unwrap();
            assert_eq!(read_all_async(r).await, b"012");
        });
    }

    #[test]
    fn async_range_chunks_and_stops_at_end() {
        tokio_test::block_on(async {
            let mut r = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Included(2), Bound::Included(7)),
                10,
            )
            .await
            .unwrap();

            let mut buf = [0; 4];
            assert_eq!(r.read(&mut buf).await.unwrap(), 4);
            assert_eq!(&buf, b"2345");
            assert_eq!(r.read(&mut buf).await.unwrap(), 2);
            assert_eq!(&buf[..2], b"67");
            assert_eq!(r.read(&mut buf).await.unwrap(), 0);
        });
    }

    #[test]
    fn async_range_new_rejects_invalid() {
        tokio_test::block_on(async {
            let res = AsyncRangeReader::new(
                Cursor::new(b"0123456789".to_vec()),
                (Bound::Unbounded, Bound::Unbounded),
                0,
            )
            .await;
            assert!(res.is_err());
        });
    }
}
