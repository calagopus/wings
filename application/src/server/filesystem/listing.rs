use crate::io::abort::{AbortGuard, AbortListener};
use std::sync::Arc;
use tokio::{sync::Semaphore, task::JoinSet};

pub struct ListingWork {
    permits: Arc<Semaphore>,
}

impl Default for ListingWork {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(Self::WORKER_LIMIT)),
        }
    }
}

impl ListingWork {
    pub const SMALL_LIMIT: usize = 64;
    const WORKER_LIMIT: usize = 32;
    const BATCH_SIZE: usize = 32;
    const REQUEST_LIMIT: usize = 8;

    pub async fn run<
        T: Send + 'static,
        F: FnOnce(&AbortListener) -> Result<T, anyhow::Error> + Send + 'static,
    >(
        &self,
        work: F,
    ) -> Result<T, anyhow::Error> {
        let (_guard, listener) = AbortGuard::new();
        let permit = Arc::clone(&self.permits).acquire_owned().await?;

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            check_aborted(&listener)?;

            work(&listener)
        })
        .await?
    }

    pub async fn map_ordered<
        T: Send + 'static,
        U: Send + 'static,
        F: Fn(T) -> U + Send + Sync + 'static,
    >(
        &self,
        items: Vec<T>,
        work: F,
    ) -> Result<Vec<U>, anyhow::Error> {
        let count = items.len();
        if count == 0 {
            return Ok(Vec::new());
        }

        let batch_size = if count <= Self::SMALL_LIMIT {
            count
        } else {
            Self::BATCH_SIZE
        };

        let (_guard, listener) = AbortGuard::new();
        let work = Arc::new(work);
        let mut items = items.into_iter();
        let mut jobs = JoinSet::new();
        let mut batches = Vec::with_capacity(count.div_ceil(batch_size));
        let mut next_batch = 0;

        while items.len() > 0 || !jobs.is_empty() {
            while items.len() > 0 && jobs.len() < Self::REQUEST_LIMIT {
                let permit = Arc::clone(&self.permits).acquire_owned().await?;
                let batch: Vec<_> = items.by_ref().take(batch_size).collect();
                let index = next_batch;
                next_batch += 1;

                let work = Arc::clone(&work);
                let listener = listener.clone();

                jobs.spawn_blocking(move || -> Result<_, anyhow::Error> {
                    let _permit = permit;

                    let mut out = Vec::with_capacity(batch.len());
                    for item in batch {
                        check_aborted(&listener)?;

                        out.push(work(item));
                    }

                    Ok((index, out))
                });
            }

            if let Some(result) = jobs.join_next().await {
                batches.push(result??);
            }
        }

        batches.sort_unstable_by_key(|(index, _)| *index);

        let mut out = Vec::with_capacity(count);
        for (_, batch) in batches {
            out.extend(batch);
        }

        Ok(out)
    }
}

pub(super) fn check_aborted(listener: &AbortListener) -> Result<(), std::io::Error> {
    if listener.is_aborted() {
        Err(std::io::Error::other("Directory listing aborted"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        time::Duration,
    };

    #[test]
    fn maps_in_order_with_bounded_request_concurrency() {
        tokio_test::block_on(async {
            let work = ListingWork::default();
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let (sender, receiver) = mpsc::channel();
            let receiver = Mutex::new(receiver);

            let values = work
                .map_ordered((0..512).collect(), {
                    let active = Arc::clone(&active);
                    let peak = Arc::clone(&peak);

                    move |value| {
                        let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(count, Ordering::SeqCst);

                        if value == 0 {
                            receiver
                                .lock()
                                .unwrap()
                                .recv_timeout(Duration::from_secs(5))
                                .unwrap();
                        } else if value == ListingWork::BATCH_SIZE {
                            sender.send(()).unwrap();
                        }

                        std::thread::sleep(Duration::from_millis(1));
                        active.fetch_sub(1, Ordering::SeqCst);

                        value * 2
                    }
                })
                .await
                .unwrap();

            assert_eq!(values, (0..512).map(|value| value * 2).collect::<Vec<_>>());
            assert!((2..=ListingWork::REQUEST_LIMIT).contains(&peak.load(Ordering::SeqCst)));
            assert_eq!(active.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn shares_global_limit_between_requests() {
        tokio_test::block_on(async {
            let work = Arc::new(ListingWork::default());
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let mut requests = JoinSet::new();

            for _ in 0..6 {
                let work = Arc::clone(&work);
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);

                requests.spawn(async move {
                    work.map_ordered((0..256).collect(), move |value| {
                        let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(count, Ordering::SeqCst);

                        std::thread::sleep(Duration::from_millis(2));
                        active.fetch_sub(1, Ordering::SeqCst);

                        value
                    })
                    .await
                    .unwrap()
                });
            }

            while let Some(result) = requests.join_next().await {
                assert_eq!(result.unwrap().len(), 256);
            }

            assert!((2..=ListingWork::WORKER_LIMIT).contains(&peak.load(Ordering::SeqCst)));
            assert_eq!(work.permits.available_permits(), ListingWork::WORKER_LIMIT);
        });
    }

    #[test]
    fn dropping_map_stops_batches_and_returns_permits() {
        tokio_test::block_on(async {
            let work = Arc::new(ListingWork::default());
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let calls = Arc::new(AtomicUsize::new(0));
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

            let task = tokio::spawn({
                let work = Arc::clone(&work);
                let gate = Arc::clone(&gate);
                let calls = Arc::clone(&calls);

                async move {
                    work.map_ordered((0..512).collect(), move |value| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        sender.send(()).unwrap();

                        let (lock, notify) = &*gate;
                        let (released, _) = notify
                            .wait_timeout_while(
                                lock.lock().unwrap(),
                                Duration::from_secs(5),
                                |released| !*released,
                            )
                            .unwrap();

                        assert!(*released);

                        value
                    })
                    .await
                }
            });
            tokio::time::timeout(Duration::from_secs(5), receiver.recv())
                .await
                .unwrap()
                .unwrap();

            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());

            let (lock, notify) = &*gate;
            *lock.lock().unwrap() = true;
            notify.notify_all();

            let permit = tokio::time::timeout(
                Duration::from_secs(5),
                work.permits.acquire_many(ListingWork::WORKER_LIMIT as u32),
            )
            .await
            .unwrap()
            .unwrap();

            assert!((1..=ListingWork::REQUEST_LIMIT).contains(&calls.load(Ordering::SeqCst)));
            drop(permit);

            assert_eq!(
                work.map_ordered(vec![7], |value| value + 1).await.unwrap(),
                vec![8]
            );
        });
    }

    #[test]
    fn dropping_queued_run_does_not_execute_work() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();

        runtime.block_on(async {
            let work = Arc::new(ListingWork::default());
            let called = Arc::new(AtomicUsize::new(0));
            let (release, receiver) = mpsc::channel();
            let (started, ready) = tokio::sync::oneshot::channel();

            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            });

            ready.await.unwrap();

            let task = tokio::spawn({
                let work = Arc::clone(&work);
                let called = Arc::clone(&called);

                async move {
                    work.run(move |_| {
                        called.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
                }
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                while work.permits.available_permits() == ListingWork::WORKER_LIMIT {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();

            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());

            release.send(()).unwrap();
            blocker.await.unwrap();

            let permit = tokio::time::timeout(
                Duration::from_secs(5),
                work.permits.acquire_many(ListingWork::WORKER_LIMIT as u32),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(called.load(Ordering::SeqCst), 0);
            drop(permit);
        });
    }

    #[test]
    fn run_errors_and_panics_release_permits() {
        tokio_test::block_on(async {
            let work = ListingWork::default();
            assert!(
                work.run::<(), _>(|_| Err(anyhow::anyhow!("expected failure")))
                    .await
                    .is_err()
            );
            assert_eq!(work.permits.available_permits(), ListingWork::WORKER_LIMIT);

            assert!(
                work.run::<(), _>(|_| {
                    panic!("expected worker panic");
                })
                .await
                .is_err()
            );
            assert_eq!(work.permits.available_permits(), ListingWork::WORKER_LIMIT);

            assert_eq!(work.run(|_| Ok(7)).await.unwrap(), 7);
        });
    }
}
