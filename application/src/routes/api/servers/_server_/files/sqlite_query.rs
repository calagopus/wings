use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
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
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = match crate::server::filesystem::RequestIgnored::compile(&data.ignored) {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "rejecting request, subuser ignored files cannot be compiled: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        if data.query.is_empty() || data.query.len() > sqlite::QUERY_MAX_LENGTH {
            return ApiResponse::error("query length is invalid")
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let parent = match Path::new(&data.file).parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let file_name = match Path::new(&data.file).file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

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

        match filesystem.async_metadata(&path).await {
            Ok(metadata) if metadata.file_type.is_file() => {}
            _ => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        }

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
        let canonical = match tokio::fs::canonicalize(
            base.join(server.filesystem.relative_path(&path)),
        )
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

        let max_rows = data.rows.clamp(1, sqlite::QUERY_MAX_ROWS) as usize;

        let (connection, interrupt) =
            match tokio::task::spawn_blocking(move || -> Result<_, rusqlite::Error> {
                let connection = rusqlite::Connection::open_with_flags(&canonical, flags)?;
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

        let results = match results {
            Ok(results) => results,
            Err(err) => return sqlite_error(err),
        };

        ApiResponse::new_serialized(Response { results }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
