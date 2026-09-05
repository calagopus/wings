use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
use tundra_common::{
    state::Snapshot,
    sync::{NodeMsg, RemoteMsg},
};

const OUTBOX_DEPTH: usize = 8;
const METRICS_TIMEOUT: Duration = Duration::from_secs(5);

struct Conn {
    id: u64,
    commands: mpsc::Sender<RemoteMsg>,
    snapshots: watch::Sender<Option<Arc<Snapshot>>>,
}

#[derive(Default)]
pub struct Hub {
    conn: parking_lot::Mutex<Option<Conn>>,
    pending: parking_lot::Mutex<HashMap<u64, oneshot::Sender<serde_json::Value>>>,
    connections: AtomicU64,
    requests: AtomicU64,
}

struct PendingRequest<'a> {
    hub: &'a Hub,
    req_id: u64,
}

impl Drop for PendingRequest<'_> {
    fn drop(&mut self) {
        self.hub.pending.lock().remove(&self.req_id);
    }
}

pub struct Registration {
    pub id: u64,
    pub commands: mpsc::Receiver<RemoteMsg>,
    pub snapshots: watch::Receiver<Option<Arc<Snapshot>>>,
}

impl Hub {
    pub fn register(&self) -> Registration {
        let id = self.connections.fetch_add(1, Ordering::Relaxed);
        let (commands, command_rx) = mpsc::channel(OUTBOX_DEPTH);
        let (snapshots, snapshot_rx) = watch::channel(None);

        if let Some(old) = self.conn.lock().replace(Conn {
            id,
            commands,
            snapshots,
        }) {
            tracing::info!(old_conn = old.id, "replacing an existing tundra websocket");
        }

        Registration {
            id,
            commands: command_rx,
            snapshots: snapshot_rx,
        }
    }

    /// A reconnect that raced ahead of the old socket's teardown must not be evicted by it.
    pub fn unregister(&self, id: u64) {
        let mut conn = self.conn.lock();
        if conn.as_ref().is_some_and(|existing| existing.id == id) {
            *conn = None;
        }
    }

    #[inline]
    pub fn disconnect(&self) {
        *self.conn.lock() = None;
    }

    #[inline]
    pub fn connected(&self) -> bool {
        self.conn.lock().is_some()
    }

    /// Snapshots are full state, so a slow daemon may skip intermediate ones.
    pub fn broadcast(&self, snapshot: &Arc<Snapshot>) {
        if let Some(conn) = self.conn.lock().as_ref() {
            let _ = conn.snapshots.send(Some(Arc::clone(snapshot)));
        }
    }

    pub async fn request_metrics(&self) -> Result<serde_json::Value, anyhow::Error> {
        let req_id = self.requests.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();

        let sender = self
            .conn
            .lock()
            .as_ref()
            .map(|conn| conn.commands.clone())
            .ok_or_else(|| anyhow::anyhow!("the tundra daemon is not connected"))?;

        self.pending.lock().insert(req_id, tx);
        let _pending = PendingRequest { hub: self, req_id };
        if let Err(err) = sender.try_send(RemoteMsg::MetricsRequest { req_id }) {
            return Err(anyhow::anyhow!("the tundra daemon outbox is full: {err}"));
        }

        match tokio::time::timeout(METRICS_TIMEOUT, rx).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(anyhow::anyhow!(
                "the tundra daemon websocket closed before replying with metrics"
            )),
            Err(_) => Err(anyhow::anyhow!(
                "the tundra daemon did not reply with metrics within {METRICS_TIMEOUT:?}"
            )),
        }
    }

    pub fn deliver(&self, msg: NodeMsg) {
        let NodeMsg::Metrics { req_id, body } = msg;
        if let Some(tx) = self.pending.lock().remove(&req_id) {
            let _ = tx.send(body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tundra_common::hash::Hash32;

    fn snapshot(epoch: u64) -> Arc<Snapshot> {
        Arc::new(Snapshot {
            epoch,
            jwt_pubkey: Hash32([0; 32]),
            nodes: Vec::new(),
            servers: Vec::new(),
            acls: Vec::new(),
        })
    }

    #[test]
    fn a_second_registration_replaces_the_first() {
        tokio_test::block_on(async {
            let hub = Hub::default();
            let mut old = hub.register();
            let new = hub.register();

            assert_ne!(old.id, new.id);
            assert!(old.commands.recv().await.is_none());

            hub.unregister(old.id);
            assert!(hub.connected());

            hub.unregister(new.id);
            assert!(!hub.connected());
        });
    }

    #[test]
    fn only_the_newest_snapshot_has_to_arrive() {
        tokio_test::block_on(async {
            let hub = Hub::default();
            let mut reg = hub.register();

            for epoch in 1..=(OUTBOX_DEPTH as u64 * 10) {
                hub.broadcast(&snapshot(epoch));
            }

            let latest = reg.snapshots.borrow_and_update().clone().unwrap();
            assert_eq!(latest.epoch, OUTBOX_DEPTH as u64 * 10);
        });
    }

    #[test]
    fn metrics_replies_correlate_by_request_id() {
        tokio_test::block_on(async {
            let hub = Arc::new(Hub::default());
            let mut reg = hub.register();

            let task = tokio::spawn({
                let hub = Arc::clone(&hub);

                async move { hub.request_metrics().await }
            });

            let req_id = match reg.commands.recv().await.unwrap() {
                RemoteMsg::MetricsRequest { req_id } => Some(req_id),
                RemoteMsg::Snapshot { .. } => None,
            }
            .unwrap();
            hub.deliver(NodeMsg::Metrics {
                req_id,
                body: serde_json::json!({ "ok": true }),
            });

            assert_eq!(
                task.await.unwrap().unwrap(),
                serde_json::json!({ "ok": true })
            );

            hub.deliver(NodeMsg::Metrics {
                req_id: 9999,
                body: serde_json::Value::Null,
            });
        });
    }

    #[test]
    fn cancelled_metrics_requests_release_their_pending_entry() {
        tokio_test::block_on(async {
            let hub = Arc::new(Hub::default());
            let mut registration = hub.register();
            let request = tokio::spawn({
                let hub = Arc::clone(&hub);
                async move { hub.request_metrics().await }
            });
            assert!(matches!(
                registration.commands.recv().await,
                Some(RemoteMsg::MetricsRequest { .. })
            ));
            assert_eq!(hub.pending.lock().len(), 1);
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
            assert!(hub.pending.lock().is_empty());
        });
    }

    #[test]
    fn metrics_fail_immediately_while_nothing_is_connected() {
        tokio_test::block_on(async {
            assert!(Hub::default().request_metrics().await.is_err());
        });
    }
}
