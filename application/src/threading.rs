use parking_lot::{Condvar, Mutex, RwLock};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub const WALK_IN_FLIGHT_LIMIT: usize = 4096;
pub const WALK_BATCH_SIZE: usize = 32;
pub const WALK_BATCHES_IN_FLIGHT: usize = WALK_IN_FLIGHT_LIMIT / WALK_BATCH_SIZE;

/// Resolves a configured thread count, treating 0 as every available core.
pub fn resolve_threads(threads: usize) -> usize {
    if threads > 0 {
        threads
    } else {
        std::thread::available_parallelism().map_or(1, |threads| threads.get())
    }
}

/// Builds a rayon pool sized by a configured thread count.
pub fn build_pool(threads: usize) -> Result<rayon::ThreadPool, anyhow::Error> {
    Ok(rayon::ThreadPoolBuilder::new()
        .num_threads(resolve_threads(threads))
        .build()?)
}

/// The first error raised by a worker, with a lock free check for hot loops.
pub struct SharedError<E> {
    stopped: AtomicBool,
    error: RwLock<Option<E>>,
}

impl<E> SharedError<E> {
    pub fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            error: RwLock::new(None),
        }
    }

    #[inline]
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    pub fn fail(&self, err: E) {
        self.stopped.store(true, Ordering::Relaxed);
        self.error.write().get_or_insert(err);
    }

    pub fn take(&self) -> Option<E> {
        self.error.write().take()
    }
}

impl<E> Default for SharedError<E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs `func` over `batch` on the pool, stopping at the first error or as soon
/// as another task has already failed.
pub fn spawn_walk_batch<
    'scope,
    T: Send + 'scope,
    F: Fn(T) -> Result<(), anyhow::Error> + Send + 'scope,
>(
    scope: &rayon::Scope<'scope>,
    error: Arc<SharedError<anyhow::Error>>,
    func: F,
    permit: InFlightPermit,
    batch: Vec<T>,
) {
    scope.spawn(move |_| {
        let _permit = permit;

        for entry in batch {
            if crate::unlikely(error.stopped()) {
                return;
            }

            if let Err(err) = func(entry) {
                error.fail(err);
                return;
            }
        }
    });
}

/// A blocking counting semaphore, used to put backpressure on a rayon producer.
pub struct InFlightLimit {
    limit: usize,
    count: Mutex<usize>,
    released: Condvar,
}

pub struct InFlightPermit(Arc<InFlightLimit>);

impl InFlightLimit {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit: limit.max(1),
            count: Mutex::new(0),
            released: Condvar::new(),
        })
    }

    /// Blocks until fewer than `limit` permits are outstanding.
    pub fn acquire(self: &Arc<Self>) -> InFlightPermit {
        let mut count = self.count.lock();
        while *count >= self.limit {
            self.released.wait(&mut count);
        }
        *count += 1;

        InFlightPermit(Arc::clone(self))
    }
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        *self.0.count.lock() -= 1;
        self.0.released.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // resolve_threads

    #[test]
    fn resolve_threads_keeps_a_configured_count() {
        assert_eq!(resolve_threads(1), 1);
        assert_eq!(resolve_threads(7), 7);
    }

    #[test]
    fn resolve_threads_expands_zero_to_every_core() {
        let cores = std::thread::available_parallelism().map_or(1, |threads| threads.get());

        assert_eq!(resolve_threads(0), cores);
    }

    // build_pool

    #[test]
    fn build_pool_sizes_the_pool_from_the_configured_count() -> Result<(), anyhow::Error> {
        assert_eq!(build_pool(3)?.current_num_threads(), 3);

        let cores = std::thread::available_parallelism().map_or(1, |threads| threads.get());
        assert_eq!(build_pool(0)?.current_num_threads(), cores);

        Ok(())
    }

    // SharedError

    #[test]
    fn shared_error_keeps_the_first_failure() {
        let error = SharedError::new();

        assert!(!error.stopped());
        assert!(error.take().is_none());

        error.fail(anyhow::anyhow!("first"));
        error.fail(anyhow::anyhow!("second"));

        assert!(error.stopped());
        assert_eq!(
            error.take().map(|err| err.to_string()),
            Some("first".into())
        );
        assert!(error.take().is_none(), "the error was not taken");
    }

    #[test]
    fn shared_error_stops_every_worker_that_checks_it() {
        let error = Arc::new(SharedError::new());
        let pool = build_pool(4).expect("pool");
        let processed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        pool.in_place_scope(|scope| {
            for index in 0..64 {
                let error = Arc::clone(&error);
                let processed = Arc::clone(&processed);

                scope.spawn(move |_| {
                    if error.stopped() {
                        return;
                    }

                    if index == 0 {
                        error.fail(anyhow::anyhow!("worker {index} failed"));
                        return;
                    }

                    processed.fetch_add(1, Ordering::Relaxed);
                });
            }
        });

        assert!(error.stopped());
        assert!(
            processed.load(Ordering::Relaxed) < 64,
            "no worker observed the failure"
        );
    }

    // InFlightLimit

    #[test]
    fn in_flight_limit_caps_outstanding_permits() {
        let limit = InFlightLimit::new(2);
        let outstanding = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let pool = build_pool(4).expect("pool");
        pool.in_place_scope(|scope| {
            for _ in 0..32 {
                let permit = limit.acquire();
                let outstanding = Arc::clone(&outstanding);
                let peak = Arc::clone(&peak);

                scope.spawn(move |_| {
                    let _permit = permit;

                    let current = outstanding.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    outstanding.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "more permits were outstanding than the limit allows: {}",
            peak.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn in_flight_limit_never_blocks_below_its_limit() {
        let limit = InFlightLimit::new(4);
        let permits: Vec<_> = (0..4).map(|_| limit.acquire()).collect();

        drop(permits);

        // the counter has to come back down, or the next producer deadlocks
        let _permit = limit.acquire();
    }

    #[test]
    fn in_flight_limit_rejects_a_zero_limit() {
        let limit = InFlightLimit::new(0);
        let _permit = limit.acquire();
    }
}
