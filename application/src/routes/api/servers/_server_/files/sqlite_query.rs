use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::sqlite,
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use utoipa::ToSchema;

    fn default_rows() -> u32 {
        sqlite::QUERY_DEFAULT_ROWS
    }

    fn default_read_only() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        file: compact_str::CompactString,

        #[schema(min_length = 1, max_length = 65535)]
        query: String,

        #[schema(default = "true")]
        #[serde(default = "default_read_only")]
        read_only: bool,

        #[schema(minimum = 1, maximum = 1000)]
        #[serde(default = "default_rows")]
        rows: u32,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        results: Vec<sqlite::QueryResultSet>,
    }

    #[cfg(not(target_os = "linux"))]
    fn sqlite_error(err: rusqlite::Error) -> ApiResponseResult {
        let status = match &err {
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::OperationInterrupted =>
            {
                StatusCode::REQUEST_TIMEOUT
            }
            _ => StatusCode::BAD_REQUEST,
        };

        ApiResponse::error(&err.to_string())
            .with_status(status)
            .ok()
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
        (status = REQUEST_TIMEOUT, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "file not found")?;

        if data.query.is_empty() || data.query.len() > sqlite::QUERY_MAX_LENGTH {
            return ApiResponse::error("query length is invalid")
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let parent = Path::new(&data.file)
            .parent()
            .or_api_error(StatusCode::EXPECTATION_FAILED, "file has no parent")?;

        let file_name = Path::new(&data.file)
            .file_name()
            .and_then(|name| name.to_str())
            .or_api_error(StatusCode::EXPECTATION_FAILED, "invalid file name")?;

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, parent, &ignored)
            .await;
        let path = root.join(file_name);

        if !filesystem.is_primary_server_fs() {
            return ApiResponse::error("database must be on the server's own filesystem")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        match filesystem.async_reachable_metadata(&path).await {
            Ok((metadata, _)) if metadata.file_type.is_file() => {}
            _ => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        }

        let max_rows = data.rows.clamp(1, sqlite::QUERY_MAX_ROWS) as usize;

        let Ok(_permit) = server.sqlite_query_semaphore.acquire().await else {
            return ApiResponse::error("sqlite queries are unavailable")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .ok();
        };

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;

            let cap_filesystem = (*server.filesystem).clone();
            let directory =
                match tokio::task::spawn_blocking(move || cap_filesystem.open_listing_dir(&root))
                    .await?
                {
                    Ok(directory) => directory,
                    Err(_) => {
                        return ApiResponse::error("file not found")
                            .with_status(StatusCode::NOT_FOUND)
                            .ok();
                    }
                };

            let user = {
                let config = state.config.load();

                sqlite::sandbox::SandboxUser {
                    uid: config.system.user.uid,
                    gid: config.system.user.gid,
                }
            };
            let outcome = match sqlite::helper::run(sqlite::helper::QueryRequest {
                directory: directory.as_fd(),
                file_name,
                query: &data.query,
                read_only: data.read_only,
                max_rows,
                user,
            })
            .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to run the sqlite query helper: {err:#}"
                    );

                    return ApiResponse::error("failed to run the query helper")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .ok();
                }
            };

            match outcome {
                sqlite::helper::QueryOutcome::Results(results) => {
                    ApiResponse::new_serialized(Response { results }).ok()
                }
                sqlite::helper::QueryOutcome::Failed(message) => ApiResponse::error(&message)
                    .with_status(StatusCode::BAD_REQUEST)
                    .ok(),
                sqlite::helper::QueryOutcome::TimedOut => {
                    ApiResponse::error("query exceeded the time limit")
                        .with_status(StatusCode::REQUEST_TIMEOUT)
                        .ok()
                }
                sqlite::helper::QueryOutcome::Crashed(signal)
                    if signal == rustix::process::Signal::BUS.as_raw() =>
                {
                    ApiResponse::error("the database changed while the query was running")
                        .with_status(StatusCode::BAD_REQUEST)
                        .ok()
                }
                sqlite::helper::QueryOutcome::Crashed(signal) => {
                    tracing::error!(
                        server = %server.uuid,
                        "the sqlite query helper died from signal {signal}"
                    );

                    ApiResponse::error("the query helper crashed")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .ok()
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = &state;

            let jail_metadata = match server.filesystem.async_open(&path).await {
                Ok(file) => match file.metadata().await {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        return ApiResponse::error("file not found")
                            .with_status(StatusCode::NOT_FOUND)
                            .ok();
                    }
                },
                Err(_) => {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            };

            let base = tokio::fs::canonicalize(&server.filesystem.base_path).await?;
            let canonical =
                match tokio::fs::canonicalize(base.join(server.filesystem.relative_path(&path)))
                    .await
                {
                    Ok(canonical) => canonical,
                    Err(_) => {
                        return ApiResponse::error("file not found")
                            .with_status(StatusCode::NOT_FOUND)
                            .ok();
                    }
                };

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;

                let matches = tokio::fs::metadata(&canonical).await.is_ok_and(|metadata| {
                    metadata.dev() == jail_metadata.dev() && metadata.ino() == jail_metadata.ino()
                });
                if !canonical.starts_with(&base) || !matches {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            }
            #[cfg(not(unix))]
            {
                let _ = &jail_metadata;
                if !canonical.starts_with(&base) {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            }

            let flags = if data.read_only {
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            } else {
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            } | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;

            let (connection, interrupt) =
                match tokio::task::spawn_blocking(move || -> Result<_, rusqlite::Error> {
                    let connection = sqlite::open(&canonical, flags)?;
                    connection.busy_timeout(sqlite::QUERY_BUSY_TIMEOUT)?;
                    let interrupt = connection.get_interrupt_handle();

                    Ok((connection, interrupt))
                })
                .await?
                {
                    Ok(pair) => pair,
                    Err(err) => return sqlite_error(err),
                };

            let watchdog = tokio::spawn(async move {
                tokio::time::sleep(sqlite::QUERY_DEADLINE).await;
                interrupt.interrupt();
            });

            let results = tokio::task::spawn_blocking(move || {
                sqlite::run_query(&connection, &data.query, max_rows)
            })
            .await?;
            watchdog.abort();

            match results {
                Ok(results) => ApiResponse::new_serialized(Response { results }).ok(),
                Err(err) => sqlite_error(err),
            }
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
