use super::State;
use crate::{
    remote::backups::ResticBackupConfiguration,
    response::{ApiResponse, ApiResponseResult},
    server::backup::adapters::restic::ResticBackup,
};
use axum::http::StatusCode;
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{process::Command, sync::RwLock};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

mod prune;
mod stats;
mod unlock;

#[derive(ToSchema, Serialize, Clone)]
pub struct ResticTaskResult {
    started: chrono::DateTime<chrono::Utc>,
    finished: chrono::DateTime<chrono::Utc>,
    duration_ms: u128,
    successful: bool,
    data: serde_json::Value,
    stderr: compact_str::CompactString,
}

fn build_restic_command(
    config: &crate::config::Config,
    configuration: &ResticBackupConfiguration,
) -> Command {
    let mut command = ResticBackup::command(config, configuration);
    command.arg("--json");

    command
}

#[derive(Clone, Copy)]
enum RepositoryLock {
    None,
    Shared,
    Exclusive,
}

async fn execute_restic_command(
    config: &crate::config::Config,
    configuration: &ResticBackupConfiguration,
    lock: RepositoryLock,
    args: impl Fn(&mut Command),
    operation: &'static str,
) -> ResticTaskResult {
    let repository_lock = ResticBackup::repository_lock(configuration).await;
    let (_shared_guard, _exclusive_guard) = match lock {
        RepositoryLock::None => (None, None),
        RepositoryLock::Shared => (Some(repository_lock.read().await), None),
        RepositoryLock::Exclusive => (None, Some(repository_lock.write().await)),
    };

    let started = chrono::Utc::now();
    let mut retried = false;
    let output = loop {
        let mut command = build_restic_command(config, configuration);
        args(&mut command);

        let output = command.output().await;
        if let Ok(output) = &output
            && !retried
            && ResticBackup::recover_from_lock_error(
                config,
                configuration,
                output.status,
                &String::from_utf8_lossy(&output.stderr),
            )
            .await
        {
            retried = true;
            continue;
        }

        break output;
    };
    let finished = chrono::Utc::now();
    let duration_ms = (finished - started).num_milliseconds().max(0) as u128;

    match output {
        Ok(output) => {
            let data =
                serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap_or_else(|_| {
                    serde_json::Value::String(String::from_utf8_lossy(&output.stdout).into_owned())
                });

            ResticTaskResult {
                started,
                finished,
                duration_ms,
                successful: output.status.success(),
                data,
                stderr: compact_str::CompactString::from_utf8_lossy(&output.stderr),
            }
        }
        Err(err) => {
            tracing::error!("failed to run restic {}: {:#?}", operation, err);

            ResticTaskResult {
                started,
                finished,
                duration_ms,
                successful: false,
                data: serde_json::Value::Null,
                stderr: compact_str::format_compact!("failed to spawn restic: {err}"),
            }
        }
    }
}

#[derive(ToSchema, Serialize)]
struct Response<'a> {
    result: &'a ResticTaskResult,
}

#[derive(ToSchema, Serialize)]
struct ResponseAccepted {}

struct ResticTask {
    operation: &'static str,
    lock: RepositoryLock,
    running: AtomicBool,
    cache: RwLock<Option<ResticTaskResult>>,
}

struct RunningGuard(&'static AtomicBool);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl ResticTask {
    const fn new(operation: &'static str, lock: RepositoryLock) -> Self {
        Self {
            operation,
            lock,
            running: AtomicBool::new(false),
            cache: RwLock::const_new(None),
        }
    }

    async fn cached(&self) -> ApiResponseResult {
        match &*self.cache.read().await {
            Some(result) => ApiResponse::new_serialized(Response { result }).ok(),
            None => ApiResponse::error(&format!(
                "no restic {} result available yet",
                self.operation
            ))
            .with_status(StatusCode::NOT_FOUND)
            .ok(),
        }
    }

    async fn run(
        &'static self,
        config: Arc<crate::config::Config>,
        configuration: Arc<ResticBackupConfiguration>,
        args: impl Fn(&mut Command) + Send + 'static,
        foreground: bool,
    ) -> ApiResponseResult {
        if self.running.swap(true, Ordering::AcqRel) {
            return ApiResponse::error(&format!(
                "restic {} task is already running",
                self.operation
            ))
            .with_status(StatusCode::CONFLICT)
            .ok();
        }

        let task = tokio::spawn(async move {
            let _running = RunningGuard(&self.running);

            let result =
                execute_restic_command(&config, &configuration, self.lock, args, self.operation)
                    .await;
            *self.cache.write().await = Some(result.clone());

            result
        });

        if !foreground {
            return ApiResponse::new_serialized(ResponseAccepted {})
                .with_status(StatusCode::ACCEPTED)
                .ok();
        }

        let result = task.await?;

        ApiResponse::new_serialized(Response { result: &result }).ok()
    }
}

fn system_restic_configuration(config: &crate::config::Config) -> Arc<ResticBackupConfiguration> {
    Arc::new(ResticBackup::system_configuration(config))
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/stats", stats::router(state))
        .nest("/prune", prune::router(state))
        .nest("/unlock", unlock::router(state))
        .with_state(state.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::time::Duration;

    fn status(response: ApiResponseResult) -> StatusCode {
        response.into_response().status()
    }

    fn configuration(dir: &tempfile::TempDir) -> Arc<ResticBackupConfiguration> {
        Arc::new(ResticBackupConfiguration {
            repository: dir.path().join("repo").to_string_lossy().into_owned(),
            password_file: None,
            retry_lock_seconds: 0,
            environment: Default::default(),
            source: Default::default(),
        })
    }

    // ResticTask

    #[tokio::test(flavor = "multi_thread")]
    async fn restic_task_rejects_a_second_run_while_one_is_running() {
        static TASK: ResticTask = ResticTask::new("test-conflict", RepositoryLock::None);
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::config::Config::mock());

        let first = TASK
            .run(
                config.clone(),
                configuration(&dir),
                |_| std::thread::sleep(Duration::from_millis(500)),
                false,
            )
            .await;
        assert_eq!(status(first), StatusCode::ACCEPTED);

        let second = TASK.run(config, configuration(&dir), |_| {}, true).await;
        assert_eq!(status(second), StatusCode::CONFLICT);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restic_task_caches_the_result_of_a_run() {
        static TASK: ResticTask = ResticTask::new("test-cache", RepositoryLock::None);
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::config::Config::mock());

        assert_eq!(status(TASK.cached().await), StatusCode::NOT_FOUND);

        let run = TASK.run(config, configuration(&dir), |_| {}, true).await;
        assert_eq!(status(run), StatusCode::OK);

        assert_eq!(status(TASK.cached().await), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restic_task_releases_after_the_foreground_request_is_dropped() {
        static TASK: ResticTask = ResticTask::new("test-dropped", RepositoryLock::None);
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::config::Config::mock());

        let dropped = tokio::time::timeout(
            Duration::from_millis(50),
            TASK.run(
                config.clone(),
                configuration(&dir),
                |_| std::thread::sleep(Duration::from_millis(300)),
                true,
            ),
        )
        .await;
        assert!(dropped.is_err());

        let mut released = false;
        for _ in 0..100 {
            if status(TASK.cached().await) == StatusCode::OK {
                let next = TASK
                    .run(config.clone(), configuration(&dir), |_| {}, false)
                    .await;
                released = status(next) != StatusCode::CONFLICT;
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(released);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restic_task_releases_after_a_panicking_run() {
        static TASK: ResticTask = ResticTask::new("test-panic", RepositoryLock::None);
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::config::Config::mock());

        let panicked = TASK
            .run(
                config.clone(),
                configuration(&dir),
                |_| panic!("args"),
                true,
            )
            .await;
        assert!(status(panicked).is_server_error());

        let next = TASK.run(config, configuration(&dir), |_| {}, true).await;
        assert_eq!(status(next), StatusCode::OK);
    }
}
