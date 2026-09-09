use crate::io::{SafeWriteExt, UninterruptedReadExt};
use std::{
    io::{IoSlice, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

/// Creates a bounded pipe whose endpoints wake their peer when dropped.
pub fn pipe(capacity: usize) -> (PipeReader, PipeWriter) {
    let (reader, writer) = tokio::io::duplex(capacity);

    (PipeReader { inner: reader }, PipeWriter { inner: writer })
}

/// Copies `reader` into `writer` until end of input, then shuts the pipe down so the
/// consumer sees EOF.
///
/// Returns `false` when the consumer dropped its end mid-stream, which is a normal
/// cancellation rather than a producer failure.
pub fn copy_and_shutdown(
    reader: &mut (impl ?Sized + Read),
    writer: &mut SyncPipeWriter,
) -> std::io::Result<bool> {
    let mut buffer = vec![0; crate::BUFFER_SIZE];

    loop {
        let bytes_read = reader.read_uninterrupted(&mut buffer)?;

        if crate::unlikely(bytes_read == 0) {
            break;
        }

        if let Err(err) = writer.safe_write_all(&buffer, bytes_read) {
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(false);
            }

            return Err(err);
        }
    }

    writer.shutdown()?;

    Ok(true)
}

pub struct PipeReader {
    inner: DuplexStream,
}

impl AsyncRead for PipeReader {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if crate::unlikely(buf.remaining() == 0) {
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub struct PipeWriter {
    inner: DuplexStream,
}

impl PipeWriter {
    #[inline]
    pub fn into_sync(self) -> SyncPipeWriter {
        SyncPipeWriter { inner: self }
    }
}

impl AsyncWrite for PipeWriter {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if crate::unlikely(buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        if crate::unlikely(bufs.iter().all(|buf| buf.is_empty())) {
            return Poll::Ready(Ok(0));
        }

        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

pub struct SyncPipeWriter {
    inner: PipeWriter,
}

impl SyncPipeWriter {
    #[inline]
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        futures::executor::block_on(self.inner.shutdown())
    }

    #[inline]
    pub fn into_inner(self) -> PipeWriter {
        self.inner
    }
}

impl Write for SyncPipeWriter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        futures::executor::block_on(self.inner.write(buf))
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        futures::executor::block_on(self.inner.write_all(buf))
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        futures::executor::block_on(self.inner.flush())
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        futures::executor::block_on(self.inner.write_vectored(bufs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        task::{Wake, Waker},
        time::Duration,
    };
    use tokio::io::AsyncReadExt;

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn reader_drop_wakes_a_writer_blocked_on_full_capacity() {
        let (reader, mut writer) = pipe(1);
        let wakes = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"a"),
            Poll::Ready(Ok(1))
        ));
        assert!(Pin::new(&mut writer).poll_write(&mut cx, b"b").is_pending());

        drop(reader);

        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"b"),
            Poll::Ready(Err(err)) if err.kind() == std::io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn writer_drop_wakes_an_empty_reader() {
        let (mut reader, writer) = pipe(1);
        let wakes = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 1];
        let mut buf = ReadBuf::new(&mut bytes);

        assert!(
            Pin::new(&mut reader)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );

        drop(writer);

        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(buf.filled().is_empty());
    }

    #[test]
    fn writer_drop_preserves_buffered_bytes_before_eof() -> std::io::Result<()> {
        let (mut reader, writer) = pipe(8);
        let mut writer = writer.into_sync();
        writer.write_all(b"buffered")?;
        drop(writer);

        let mut out = Vec::new();
        futures::executor::block_on(reader.read_to_end(&mut out))?;
        assert_eq!(out, b"buffered");

        Ok(())
    }

    #[test]
    fn shutdown_preserves_buffered_bytes_and_rejects_more_writes() -> std::io::Result<()> {
        let (mut reader, writer) = pipe(8);
        let mut writer = writer.into_sync();
        writer.write_all(b"buffered")?;
        writer.shutdown()?;

        let mut out = Vec::new();
        futures::executor::block_on(reader.read_to_end(&mut out))?;
        assert_eq!(out, b"buffered");
        assert_eq!(
            writer.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );

        Ok(())
    }

    #[test]
    fn synchronous_writer_supports_partial_and_vectored_writes() -> std::io::Result<()> {
        let (mut reader, writer) = pipe(3);
        let mut writer = writer.into_sync();
        assert_eq!(writer.write(b"hello")?, 3);
        let mut first = [0; 3];
        futures::executor::block_on(reader.read_exact(&mut first))?;
        assert_eq!(&first, b"hel");

        assert_eq!(
            writer.write_vectored(&[IoSlice::new(b"lo"), IoSlice::new(b"!")])?,
            3
        );
        writer.flush()?;
        writer.shutdown()?;

        let mut out = Vec::new();
        futures::executor::block_on(reader.read_to_end(&mut out))?;
        assert_eq!(out, b"lo!");

        Ok(())
    }

    #[test]
    fn synchronous_writer_preserves_bytes_across_backpressure_without_runtime() {
        let (mut reader, writer) = pipe(7);
        let input: Vec<_> = (0..16384).map(|value| (value % 251) as u8).collect();
        let expected = input.clone();
        let producer = std::thread::spawn(move || -> std::io::Result<()> {
            let mut writer = writer.into_sync();
            writer.write_all(&input)?;
            writer.flush()?;
            writer.shutdown()
        });
        let (finished, result) = mpsc::channel();
        let consumer = std::thread::spawn(move || {
            let mut output = Vec::new();
            let read_result = futures::executor::block_on(reader.read_to_end(&mut output));
            finished.send(read_result.map(|_| output)).unwrap();
        });

        let output = result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        producer.join().unwrap().unwrap();
        consumer.join().unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn dropping_reader_releases_a_blocked_synchronous_writer() {
        let (reader, writer) = pipe(1);
        let mut writer = writer.into_sync();
        writer.write_all(b"a").unwrap();
        let (started, ready) = mpsc::channel();
        let (finished, result) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            started.send(()).unwrap();
            finished.send(writer.write_all(b"blocked")).unwrap();
        });

        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(reader);

        let err = result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        producer.join().unwrap();
    }

    #[test]
    fn synchronous_writer_can_return_to_async_writing() -> std::io::Result<()> {
        let (mut reader, writer) = pipe(8);
        let mut writer = writer.into_sync();
        writer.write_all(b"sync")?;

        futures::executor::block_on(async {
            let mut writer = writer.into_inner();
            writer.write_all(b"more").await?;
            writer.shutdown().await?;

            let mut output = Vec::new();
            reader.read_to_end(&mut output).await?;
            assert_eq!(output, b"syncmore");

            Ok(())
        })
    }

    #[test]
    fn asynchronous_endpoints_preserve_bytes_across_backpressure() -> std::io::Result<()> {
        tokio_test::block_on(async {
            let (mut reader, mut writer) = pipe(7);
            let producer = tokio::spawn(async move {
                writer.write_all(&[42; 4096]).await?;
                writer.shutdown().await
            });

            let mut output = Vec::new();
            reader.read_to_end(&mut output).await?;
            producer.await??;
            assert_eq!(output, vec![42; 4096]);

            Ok(())
        })
    }

    #[test]
    fn zero_length_operations_are_ready_for_empty_full_and_closed_pipes() {
        let (mut reader, mut writer) = pipe(1);
        let mut cx = Context::from_waker(Waker::noop());
        let mut bytes = [];
        let mut buf = ReadBuf::new(&mut bytes);

        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"a"),
            Poll::Ready(Ok(1))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b""),
            Poll::Ready(Ok(0))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write_vectored(&mut cx, &[IoSlice::new(b"")]),
            Poll::Ready(Ok(0))
        ));

        drop(reader);

        let mut writer = writer.into_sync();
        assert_eq!(writer.write(b"").unwrap(), 0);
        assert_eq!(writer.write_vectored(&[]).unwrap(), 0);
        writer.write_all(b"").unwrap();
        assert_eq!(
            writer.write(b"a").unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }
}
