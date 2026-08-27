use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, atomic::AtomicUsize},
};

pub struct WebsocketLimiter {
    config: Arc<crate::config::Config>,
    unauthenticated: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
    connections: Arc<AtomicUsize>,

    task: tokio::task::JoinHandle<()>,
}

impl WebsocketLimiter {
    pub fn new(config: Arc<crate::config::Config>) -> Self {
        let unauthenticated = Arc::new(parking_lot::Mutex::new(HashMap::<IpAddr, usize>::new()));

        let task = tokio::spawn({
            let unauthenticated = Arc::clone(&unauthenticated);

            async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                    let mut unauthenticated = unauthenticated.lock();
                    unauthenticated.retain(|_, count| *count > 0);
                }
            }
        });

        Self {
            config,
            unauthenticated,
            connections: Arc::new(AtomicUsize::new(0)),
            task,
        }
    }

    pub fn acquire(&self, ip: IpAddr) -> Option<WebsocketLimiterGuard> {
        let config = self.config.load();
        let max_connections_total = config.system.websocket.max_connections_total;
        let unauthenticated_connections_per_ip =
            config.system.websocket.unauthenticated_connections_per_ip;

        if max_connections_total == 0 {
            self.connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            let current = self
                .connections
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if current >= max_connections_total {
                self.connections
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return None;
            }
        }

        let ip = if unauthenticated_connections_per_ip > 0 {
            let mut unauthenticated = self.unauthenticated.lock();
            let count = unauthenticated.entry(ip).or_default();

            if *count >= unauthenticated_connections_per_ip {
                drop(unauthenticated);
                self.connections
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

                return None;
            }

            *count += 1;
            Some(ip)
        } else {
            None
        };

        Some(WebsocketLimiterGuard {
            unauthenticated: Arc::clone(&self.unauthenticated),
            connections: Arc::clone(&self.connections),
            ip,
        })
    }
}

impl Drop for WebsocketLimiter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct WebsocketLimiterGuard {
    unauthenticated: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
    connections: Arc<AtomicUsize>,
    ip: Option<IpAddr>,
}

impl WebsocketLimiterGuard {
    /// Releases the per-ip unauthenticated slot, keeping the connection counted
    /// against the global total for as long as the guard lives.
    pub fn authenticated(&mut self) {
        if let Some(ip) = self.ip.take() {
            let mut unauthenticated = self.unauthenticated.lock();
            if let Some(count) = unauthenticated.get_mut(&ip)
                && *count > 0
            {
                *count -= 1;
            }
        }
    }
}

impl Drop for WebsocketLimiterGuard {
    fn drop(&mut self) {
        self.authenticated();

        self.connections
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, sync::atomic::Ordering};

    fn limiter_with(
        unauthenticated_connections_per_ip: usize,
        max_connections_total: usize,
    ) -> WebsocketLimiter {
        let config = Arc::new(crate::config::Config::mock());
        {
            let websocket = &mut config.mutate_in_place_for_testing().system.websocket;
            websocket.unauthenticated_connections_per_ip = unauthenticated_connections_per_ip;
            websocket.max_connections_total = max_connections_total;
        }

        WebsocketLimiter::new(config)
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
    }

    #[test]
    fn acquire_blocks_over_per_ip_unauthenticated_limit() {
        tokio_test::block_on(async {
            let limiter = limiter_with(2, 0);
            let _a = limiter.acquire(ip(1)).unwrap();
            let _b = limiter.acquire(ip(1)).unwrap();
            assert!(limiter.acquire(ip(1)).is_none());
        });
    }

    #[test]
    fn acquire_tracks_ips_independently() {
        tokio_test::block_on(async {
            let limiter = limiter_with(1, 0);
            let _a = limiter.acquire(ip(1)).unwrap();
            assert!(limiter.acquire(ip(1)).is_none());
            assert!(limiter.acquire(ip(2)).is_some());
        });
    }

    #[test]
    fn per_ip_limit_disabled_when_zero() {
        tokio_test::block_on(async {
            let limiter = limiter_with(0, 0);
            let mut guards = Vec::new();
            for _ in 0..64 {
                guards.push(limiter.acquire(ip(1)).unwrap());
            }
            // the disabled path never touches the map
            assert!(limiter.unauthenticated.lock().is_empty());
        });
    }

    #[test]
    fn guard_drop_frees_a_per_ip_slot() {
        tokio_test::block_on(async {
            let limiter = limiter_with(1, 0);
            {
                let _a = limiter.acquire(ip(1)).unwrap();
                assert!(limiter.acquire(ip(1)).is_none());
            }
            assert!(limiter.acquire(ip(1)).is_some());
        });
    }

    #[test]
    fn authenticated_frees_a_per_ip_slot() {
        tokio_test::block_on(async {
            let limiter = limiter_with(1, 0);
            let mut guard = limiter.acquire(ip(1)).unwrap();
            assert!(limiter.acquire(ip(1)).is_none());

            guard.authenticated();
            assert!(limiter.acquire(ip(1)).is_some());
        });
    }

    #[test]
    fn authenticated_is_idempotent_and_does_not_underflow() {
        tokio_test::block_on(async {
            let limiter = limiter_with(2, 0);
            let mut guard = limiter.acquire(ip(1)).unwrap();
            guard.authenticated();
            guard.authenticated();
            drop(guard);

            assert_eq!(limiter.unauthenticated.lock().get(&ip(1)).copied(), Some(0));
        });
    }

    #[test]
    fn authenticated_connections_still_count_against_the_total() {
        tokio_test::block_on(async {
            let limiter = limiter_with(0, 2);
            let mut a = limiter.acquire(ip(1)).unwrap();
            let _b = limiter.acquire(ip(2)).unwrap();

            a.authenticated();
            assert!(limiter.acquire(ip(3)).is_none());
        });
    }

    #[test]
    fn acquire_blocks_over_total_limit() {
        tokio_test::block_on(async {
            let limiter = limiter_with(0, 2);
            let _a = limiter.acquire(ip(1)).unwrap();
            let _b = limiter.acquire(ip(2)).unwrap();
            assert!(limiter.acquire(ip(3)).is_none());
        });
    }

    #[test]
    fn total_limit_disabled_when_zero() {
        tokio_test::block_on(async {
            let limiter = limiter_with(0, 0);
            let mut guards = Vec::new();
            for _ in 0..64 {
                guards.push(limiter.acquire(ip(1)).unwrap());
            }
            assert_eq!(limiter.connections.load(Ordering::SeqCst), 64);
        });
    }

    #[test]
    fn rejected_acquire_does_not_leak_the_total_slot() {
        tokio_test::block_on(async {
            let limiter = limiter_with(1, 4);
            let _a = limiter.acquire(ip(1)).unwrap();
            assert!(limiter.acquire(ip(1)).is_none());
            assert_eq!(limiter.connections.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn guard_drop_frees_the_total_slot() {
        tokio_test::block_on(async {
            let limiter = limiter_with(0, 1);
            {
                let _a = limiter.acquire(ip(1)).unwrap();
                assert!(limiter.acquire(ip(2)).is_none());
            }
            assert!(limiter.acquire(ip(2)).is_some());
        });
    }
}
