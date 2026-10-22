use std::{io::Read, sync::Arc};

/// A reader that can be handed out while the original owner keeps a handle to
/// take it back once every clone is dropped.
pub struct SharedReader<R: Read> {
    inner: Arc<parking_lot::Mutex<R>>,
}

impl<R: Read> SharedReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(inner)),
        }
    }

    /// Returns the reader, or `None` while a clone is still alive.
    pub fn into_inner(self) -> Option<R> {
        Arc::into_inner(self.inner).map(parking_lot::Mutex::into_inner)
    }
}

impl<R: Read> Clone for SharedReader<R> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<R: Read> Read for SharedReader<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.lock().read(buf)
    }
}
