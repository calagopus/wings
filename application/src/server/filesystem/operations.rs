use compact_str::ToCompactString;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use utoipa::ToSchema;

fn serialize_arc<S>(value: &Arc<AtomicU64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u64(value.load(std::sync::atomic::Ordering::Relaxed))
}

#[derive(Clone, ToSchema, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FilesystemOperation {
    Compress {
        #[schema(value_type = String)]
        path: PathBuf,
        #[schema(value_type = Vec<String>)]
        files: Vec<PathBuf>,
        #[schema(value_type = String)]
        destination_path: PathBuf,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        files_processed: Arc<AtomicU64>,
    },
    Decompress {
        #[schema(value_type = String)]
        path: PathBuf,
        #[schema(value_type = String)]
        destination_path: PathBuf,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        files_processed: Arc<AtomicU64>,
    },
    Pull {
        #[schema(value_type = String)]
        destination_path: PathBuf,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
    },
    Copy {
        #[schema(value_type = String)]
        path: PathBuf,
        #[schema(value_type = String)]
        destination_path: PathBuf,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        files_processed: Arc<AtomicU64>,
    },
    CopyMany {
        #[schema(value_type = String)]
        path: PathBuf,
        files: Vec<crate::models::CopyFile>,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        files_processed: Arc<AtomicU64>,
    },
    CopyRemote {
        server: uuid::Uuid,
        #[schema(value_type = String)]
        path: PathBuf,
        #[schema(value_type = Vec<String>)]
        files: Vec<PathBuf>,
        destination_server: uuid::Uuid,
        #[schema(value_type = String)]
        destination_path: PathBuf,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        files_processed: Arc<AtomicU64>,
    },
    ExportBackup {
        backup: uuid::Uuid,
        #[schema(value_type = String)]
        destination_path: PathBuf,

        start_time: chrono::DateTime<chrono::Utc>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_processed: Arc<AtomicU64>,
        #[serde(serialize_with = "serialize_arc")]
        #[schema(value_type = u64)]
        bytes_total: Arc<AtomicU64>,
    },
}

pub struct Operation {
    pub filesystem_operation: FilesystemOperation,
    abort_sender: tokio::sync::oneshot::Sender<()>,
}

#[derive(Debug)]
pub enum OperationLimitReached {
    Operations,
    Pulls,
}

impl std::fmt::Display for OperationLimitReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operations => write!(f, "too many concurrent operations"),
            Self::Pulls => write!(f, "too many concurrent pulls"),
        }
    }
}

impl std::error::Error for OperationLimitReached {}

type OperationHandle<T> = (
    uuid::Uuid,
    tokio::task::JoinHandle<Option<Result<T, anyhow::Error>>>,
);

pub struct OperationManager {
    operations: Arc<RwLock<HashMap<uuid::Uuid, Operation>>>,
    sender: tokio::sync::broadcast::Sender<crate::server::websocket::WebsocketMessage>,
    config: Arc<crate::config::Config>,
}

impl OperationManager {
    pub fn new(
        sender: tokio::sync::broadcast::Sender<crate::server::websocket::WebsocketMessage>,
        config: Arc<crate::config::Config>,
    ) -> Self {
        Self {
            operations: Arc::new(RwLock::new(HashMap::new())),
            sender,
            config,
        }
    }

    #[inline]
    pub async fn operations(&self) -> RwLockReadGuard<'_, HashMap<uuid::Uuid, Operation>> {
        self.operations.read().await
    }

    pub async fn pulls(&self) -> Vec<crate::models::Download> {
        self.operations
            .read()
            .await
            .iter()
            .filter_map(
                |(identifier, operation)| match &operation.filesystem_operation {
                    FilesystemOperation::Pull {
                        destination_path,
                        bytes_processed,
                        bytes_total,
                        ..
                    } => Some(crate::models::Download {
                        identifier: *identifier,
                        destination: destination_path.to_string_lossy().to_string(),
                        progress: bytes_processed.load(std::sync::atomic::Ordering::Relaxed),
                        total: bytes_total.load(std::sync::atomic::Ordering::Relaxed),
                    }),
                    _ => None,
                },
            )
            .collect()
    }

    /// Aborts `operation_uuid` only if it is a pull, for the endpoints that predate operations.
    pub async fn abort_pull(&self, operation_uuid: uuid::Uuid) -> bool {
        let mut operations = self.operations.write().await;
        let is_pull = operations.get(&operation_uuid).is_some_and(|operation| {
            matches!(
                operation.filesystem_operation,
                FilesystemOperation::Pull { .. }
            )
        });
        if !is_pull {
            return false;
        }

        if let Some(operation) = operations.remove(&operation_uuid) {
            operation.abort_sender.send(()).ok();
        }

        true
    }

    /// Starts an operation, refusing it once the server already runs
    /// `limits.server_concurrent_operations` operations, or `limits.server_concurrent_pulls`
    /// pulls when it is one.
    pub async fn add_operation<
        T: Send + 'static,
        F: Future<Output = Result<T, anyhow::Error>> + Send + 'static,
    >(
        &self,
        operation: FilesystemOperation,
        f: F,
    ) -> Result<OperationHandle<T>, OperationLimitReached> {
        let (operation_limit, pull_limit) = {
            let config = self.config.load();

            (
                config.limits.server_concurrent_operations,
                config.limits.server_concurrent_pulls,
            )
        };

        let operations = self.operations.write().await;
        if operation_limit != 0 && operations.len() >= operation_limit {
            return Err(OperationLimitReached::Operations);
        }

        if pull_limit != 0
            && matches!(operation, FilesystemOperation::Pull { .. })
            && operations
                .values()
                .filter(|operation| {
                    matches!(
                        operation.filesystem_operation,
                        FilesystemOperation::Pull { .. }
                    )
                })
                .count()
                >= pull_limit
        {
            return Err(OperationLimitReached::Pulls);
        }

        Ok(self.spawn_operation(operations, operation, f))
    }

    /// Starts an operation that is the receiving half of one already counted against a
    /// limit elsewhere, such as the destination side of a cross-server copy.
    pub async fn add_linked_operation<
        T: Send + 'static,
        F: Future<Output = Result<T, anyhow::Error>> + Send + 'static,
    >(
        &self,
        operation: FilesystemOperation,
        f: F,
    ) -> OperationHandle<T> {
        let operations = self.operations.write().await;

        self.spawn_operation(operations, operation, f)
    }

    fn spawn_operation<
        T: Send + 'static,
        F: Future<Output = Result<T, anyhow::Error>> + Send + 'static,
    >(
        &self,
        mut operations: RwLockWriteGuard<'_, HashMap<uuid::Uuid, Operation>>,
        operation: FilesystemOperation,
        f: F,
    ) -> OperationHandle<T> {
        let operation_uuid = uuid::Uuid::new_v4();
        let (abort_sender, abort_receiver) = tokio::sync::oneshot::channel();

        operations.insert(
            operation_uuid,
            Operation {
                filesystem_operation: operation.clone(),
                abort_sender,
            },
        );
        drop(operations);

        let handle = tokio::spawn({
            let operations = self.operations.clone();
            let sender = self.sender.clone();

            async move {
                let progress_task = async {
                    loop {
                        sender
                            .send(
                                crate::server::websocket::WebsocketMessage::builder(
                                    crate::server::websocket::WebsocketEvent::ServerOperationProgress,
                                )
                                .arg(operation_uuid.to_compact_string())
                                .structured_arg(&operation)
                                .build(),
                            )
                            .ok();

                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                };

                let result = tokio::select! {
                    result = f => Some(result),
                    _ = progress_task => None,
                    _ = abort_receiver => None,
                };

                operations.write().await.remove(&operation_uuid);
                if result.is_none() {
                    sender
                        .send(
                            crate::server::websocket::WebsocketMessage::builder(
                                crate::server::websocket::WebsocketEvent::ServerOperationAborted,
                            )
                            .arg(operation_uuid.to_compact_string())
                            .build(),
                        )
                        .ok();
                } else if let Some(Err(err)) = result.as_ref() {
                    let message = if let Some(err) = err.downcast_ref::<&str>() {
                        err.to_string()
                    } else if let Some(err) = err.downcast_ref::<String>() {
                        err.to_string()
                    } else if let Some(err) = err.downcast_ref::<std::io::Error>() {
                        err.to_string()
                    } else if let Some(err) = err.downcast_ref::<zip::result::ZipError>() {
                        match err {
                            zip::result::ZipError::Io(err) => err.to_string(),
                            _ => err.to_string(),
                        }
                    } else if let Some(err) = err.downcast_ref::<sevenz_rust2::Error>() {
                        match err {
                            sevenz_rust2::Error::Io(err, _) => err.to_string(),
                            _ => err.to_string(),
                        }
                    } else {
                        tracing::error!(
                            operation = ?operation_uuid,
                            "unknown operation error: {:#?}",
                            err
                        );

                        String::from("unknown error")
                    };

                    sender
                        .send(
                            crate::server::websocket::WebsocketMessage::builder(
                                crate::server::websocket::WebsocketEvent::ServerOperationError,
                            )
                            .arg(operation_uuid.to_compact_string())
                            .arg(message)
                            .build(),
                        )
                        .ok();
                } else {
                    sender
                        .send(
                            crate::server::websocket::WebsocketMessage::builder(
                                crate::server::websocket::WebsocketEvent::ServerOperationCompleted,
                            )
                            .arg(operation_uuid.to_compact_string())
                            .build(),
                        )
                        .ok();
                }

                result
            }
        });

        (operation_uuid, handle)
    }

    pub async fn abort_operation(&self, operation_uuid: uuid::Uuid) -> bool {
        if let Some(operation) = self.operations.write().await.remove(&operation_uuid) {
            operation.abort_sender.send(()).ok();
            return true;
        }

        false
    }

    pub async fn abort_all(&self) {
        for (_, operation) in self.operations.write().await.drain() {
            operation.abort_sender.send(()).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn manager(operations: usize, pulls: usize) -> OperationManager {
        let config = Arc::new(crate::config::Config::mock());
        {
            let limits = &mut config.mutate_in_place_for_testing().limits;
            limits.server_concurrent_operations = operations;
            limits.server_concurrent_pulls = pulls;
        }

        OperationManager::new(tokio::sync::broadcast::channel(16).0, config)
    }

    fn pull(destination: &str) -> FilesystemOperation {
        FilesystemOperation::Pull {
            destination_path: PathBuf::from(destination),
            start_time: chrono::Utc::now(),
            bytes_processed: Arc::new(AtomicU64::new(7)),
            bytes_total: Arc::new(AtomicU64::new(42)),
        }
    }

    fn copy() -> FilesystemOperation {
        FilesystemOperation::Copy {
            path: PathBuf::from("a"),
            destination_path: PathBuf::from("b"),
            start_time: chrono::Utc::now(),
            bytes_processed: Arc::default(),
            bytes_total: Arc::default(),
            files_processed: Arc::default(),
        }
    }

    async fn pending() -> Result<(), anyhow::Error> {
        std::future::pending::<()>().await;
        Ok(())
    }

    // OperationManager
    #[test]
    fn operation_limit_refuses_without_running_and_frees_on_finish() {
        tokio_test::block_on(async {
            let manager = manager(1, 0);
            let (finish, finished) = tokio::sync::oneshot::channel::<()>();
            let (_, first) = manager
                .add_operation(copy(), async move {
                    finished.await.ok();
                    Ok(1)
                })
                .await
                .expect("first operation should start");

            let ran = Arc::new(AtomicBool::new(false));
            let refused = manager
                .add_operation(copy(), {
                    let ran = Arc::clone(&ran);
                    async move {
                        ran.store(true, Ordering::SeqCst);
                        Ok(2)
                    }
                })
                .await;
            assert!(matches!(refused, Err(OperationLimitReached::Operations)));
            assert!(matches!(
                manager.add_operation(pull("x"), pending()).await,
                Err(OperationLimitReached::Operations)
            ));
            assert_eq!(manager.operations().await.len(), 1);

            finish.send(()).ok();
            assert!(matches!(first.await, Ok(Some(Ok(1)))));
            assert!(!ran.load(Ordering::SeqCst));
            assert!(manager.operations().await.is_empty());

            let (_, next) = manager
                .add_operation(copy(), async { Ok(3) })
                .await
                .expect("slot should be free again");
            assert!(matches!(next.await, Ok(Some(Ok(3)))));
        });
    }

    #[test]
    fn pull_limit_only_applies_to_pulls() {
        tokio_test::block_on(async {
            let manager = manager(0, 1);
            manager
                .add_operation(pull("one"), pending())
                .await
                .expect("first pull should start");

            assert!(matches!(
                manager.add_operation(pull("two"), pending()).await,
                Err(OperationLimitReached::Pulls)
            ));
            manager
                .add_operation(copy(), pending())
                .await
                .expect("non-pull operations ignore the pull limit");
            manager
                .add_operation(copy(), pending())
                .await
                .expect("non-pull operations ignore the pull limit");
            assert_eq!(manager.operations().await.len(), 3);

            manager.abort_all().await;
        });
    }

    #[test]
    fn linked_operations_bypass_but_count_toward_limits() {
        tokio_test::block_on(async {
            let manager = manager(1, 1);
            manager.add_linked_operation(pull("one"), pending()).await;
            manager.add_linked_operation(pull("two"), pending()).await;
            assert_eq!(manager.operations().await.len(), 2);

            assert!(
                manager
                    .add_operation(copy(), async { Ok(()) })
                    .await
                    .is_err()
            );

            manager.abort_all().await;
        });
    }

    #[test]
    fn abort_all_aborts_in_flight_and_leaves_later_operations_alone() {
        tokio_test::block_on(async {
            let manager = manager(0, 0);
            let (_, first) = manager
                .add_operation(copy(), pending())
                .await
                .expect("operation should start");
            let (_, second) = manager.add_linked_operation(pull("x"), pending()).await;

            manager.abort_all().await;
            assert!(matches!(first.await, Ok(None)));
            assert!(matches!(second.await, Ok(None)));
            assert!(manager.operations().await.is_empty());

            let (_, later) = manager
                .add_operation(copy(), async { Ok(5) })
                .await
                .expect("operation should start");
            assert!(matches!(later.await, Ok(Some(Ok(5)))));
        });
    }

    #[test]
    fn abort_pull_only_aborts_pulls() {
        tokio_test::block_on(async {
            let manager = manager(0, 0);
            let (copy_id, copy_handle) = manager
                .add_operation(copy(), pending())
                .await
                .expect("operation should start");
            let (pull_id, pull_handle) = manager
                .add_operation(pull("x"), pending())
                .await
                .expect("operation should start");

            assert!(!manager.abort_pull(copy_id).await);
            assert!(!manager.abort_pull(uuid::Uuid::new_v4()).await);
            assert!(manager.operations().await.contains_key(&copy_id));
            assert!(!copy_handle.is_finished());

            assert!(manager.abort_pull(pull_id).await);
            assert!(matches!(pull_handle.await, Ok(None)));
            assert!(!manager.operations().await.contains_key(&pull_id));
            assert!(!copy_handle.is_finished());

            manager.abort_all().await;
        });
    }

    #[test]
    fn pulls_lists_only_pull_operations() {
        tokio_test::block_on(async {
            let manager = manager(0, 0);
            manager
                .add_operation(copy(), pending())
                .await
                .expect("operation should start");
            let (pull_id, _) = manager
                .add_operation(pull("plugins/a.jar"), pending())
                .await
                .expect("operation should start");

            let pulls = manager.pulls().await;
            assert_eq!(pulls.len(), 1);
            let download = pulls.first().expect("one pull");
            assert_eq!(download.identifier, pull_id);
            assert_eq!(download.destination, "plugins/a.jar");
            assert_eq!(download.progress, 7);
            assert_eq!(download.total, 42);

            manager.abort_all().await;
        });
    }
}
