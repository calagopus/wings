use super::State;
use axum::extract::DefaultBodyLimit;
use serde::Deserialize;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

#[derive(Deserialize)]
pub struct FileJwtPayload {
    #[serde(flatten)]
    pub base: crate::remote::jwt::BasePayload,

    pub server_uuid: uuid::Uuid,
    pub user_uuid: uuid::Uuid,
    pub unique_id: compact_str::CompactString,

    #[serde(default)]
    pub ignored_files: Vec<compact_str::CompactString>,
}

impl FileJwtPayload {
    fn ignored(&self) -> Result<Option<ignore::gitignore::Gitignore>, ignore::Error> {
        if self.ignored_files.is_empty() {
            return Ok(None);
        }

        crate::server::filesystem::build_gitignore_matcher(self.ignored_files.iter()).map(Some)
    }
}

type UploadLocks = moka::future::Cache<(uuid::Uuid, std::path::PathBuf), Arc<Mutex<()>>>;
static UPLOAD_LOCKS: LazyLock<UploadLocks> = LazyLock::new(|| moka::future::Cache::new(10240));

/// Returns the per-file upload lock, serializing concurrent `PATCH` slices that
/// append to the same path so their offset checks and writes cannot interleave.
async fn upload_lock(key: (uuid::Uuid, std::path::PathBuf)) -> Arc<Mutex<()>> {
    UPLOAD_LOCKS
        .get_with(key, async { Arc::new(Mutex::new(())) })
        .await
}

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::{
            activity::{Activity, ActivityEvent},
            filesystem::cap::FileType,
        },
    };
    use axum::{
        extract::{ConnectInfo, Multipart, Query},
        http::{HeaderMap, StatusCode},
    };
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::{net::SocketAddr, path::PathBuf};
    use tokio::io::AsyncWriteExt;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        token: String,
        #[serde(default)]
        directory: compact_str::CompactString,
        total_size: Option<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "token" = String, Query,
            description = "The JWT token to use for authentication",
        ),
        (
            "directory" = String, Query,
            description = "The directory to upload the file to",
        ),
        (
            "total_size" = Option<String>, Query,
            description = "total size in bytes the uploaded file will have; lets the server deny an oversized upload before the body is transferred",
        ),
    ), request_body = String)]
    pub async fn route(
        state: GetState,
        headers: HeaderMap,
        connect_info: ConnectInfo<SocketAddr>,
        Query(params): Query<Params>,
        mut multipart: Multipart,
    ) -> ApiResponseResult {
        let payload: super::FileJwtPayload = match state.config.jwt.verify(&params.token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload
            .base
            .validate(&state.config.jwt, Some("file-upload"))
        {
            return ApiResponse::error(&format!("invalid token: {err}"))
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        if !state.config.jwt.limited_jwt_id(&payload.unique_id) {
            return ApiResponse::error("token has already been used")
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let server = match state.server_manager.get_server(payload.server_uuid).await {
            Some(server) => server,
            None => {
                return ApiResponse::error("server not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let total_size = params.total_size.and_then(|s| s.parse::<u64>().ok());
        if let Some(total_size) = total_size {
            let config = state.config.load();
            if config.api.upload_limit.as_bytes() != 0
                && total_size > config.api.upload_limit.as_bytes()
            {
                return ApiResponse::error(&format!(
                    "file size is larger than {}MiB",
                    config.api.upload_limit.as_mib()
                ))
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
            }
            drop(config);

            let disk_limit = server.filesystem.disk_limit();
            if disk_limit > 0
                && total_size
                    > (disk_limit as u64)
                        .saturating_sub(server.filesystem.get_physical_cached_size())
            {
                return ApiResponse::error(
                    "file size is larger than the server's available disk space",
                )
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
            }
        }

        let ignored = match payload.ignored() {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "failed to compile subuser ignored files, denying upload: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let directory = PathBuf::from(params.directory.as_str());

        let metadata = server.filesystem.async_metadata(&directory).await;
        if !metadata.map(|m| m.is_dir()).unwrap_or(true) {
            return ApiResponse::error("directory is not a directory")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let user_ip = Some(state.config.find_ip(&headers, connect_info));

        while let Some(mut field) = multipart.next_field().await? {
            let filename = match field.file_name() {
                Some(name) => name,
                None => {
                    return ApiResponse::error("file name not found")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            };
            let path = directory.join(filename);
            let parent = match path.parent() {
                Some(parent) => parent,
                None => {
                    return ApiResponse::error("file has no parent")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            };

            if ignored
                .as_ref()
                .is_some_and(|o| o.matched(parent, true).is_ignore())
                || server
                    .filesystem
                    .async_is_ignored(parent, FileType::Dir)
                    .await
            {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }

            let file_name = match path.file_name() {
                Some(name) => name,
                None => {
                    return ApiResponse::error("invalid file name")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            };

            let (root, filesystem) = server
                .filesystem
                .resolve_writable_fs(&server, &parent)
                .await;
            let path = root.join(file_name);

            if filesystem.is_primary_server_fs()
                && (ignored
                    .as_ref()
                    .is_some_and(|o| o.matched(&path, false).is_ignore())
                    || server
                        .filesystem
                        .async_is_ignored(&path, FileType::File)
                        .await)
            {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }

            filesystem.async_create_dir_all(&root).await?;

            let mut written_size = 0;
            let mut writer = filesystem.async_create_file(&path).await?;

            server.activity.log_activity(Activity {
                event: ActivityEvent::FileUploaded,
                user: Some(payload.user_uuid),
                ip: user_ip,
                metadata: Some(json!({
                    "files": [filename],
                    "directory": server.filesystem.relative_path(&directory),
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });

            while let Some(chunk) = field.chunk().await? {
                let config = state.config.load();
                if crate::unlikely(
                    config.api.upload_limit.as_bytes() != 0
                        && written_size + chunk.len() as u64 > config.api.upload_limit.as_bytes(),
                ) {
                    return ApiResponse::error(&format!(
                        "file size is larger than {}MiB",
                        config.api.upload_limit.as_mib()
                    ))
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
                }
                drop(config);

                writer.write_all(&chunk).await?;
                written_size += chunk.len() as u64;
            }

            writer.shutdown().await?;
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

mod head {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::filesystem::cap::FileType,
    };
    use axum::{body::Body, extract::Query, http::StatusCode};
    use serde::Deserialize;
    use std::path::PathBuf;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        token: String,
        #[serde(default)]
        directory: compact_str::CompactString,
        file: compact_str::CompactString,
    }

    #[utoipa::path(head, path = "/", responses(
        (status = OK),
        (status = UNAUTHORIZED, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        ("token" = String, Query, description = "The JWT token to use for authentication"),
        ("directory" = String, Query, description = "The directory the file lives in"),
        ("file" = String, Query, description = "The file name (may include a sub-path) within the directory"),
    ))]
    pub async fn route(state: GetState, Query(params): Query<Params>) -> ApiResponseResult {
        let payload: super::FileJwtPayload = match state.config.jwt.verify(&params.token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload
            .base
            .validate(&state.config.jwt, Some("file-upload"))
        {
            return ApiResponse::error(&format!("invalid token: {err}"))
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let server = match state.server_manager.get_server(payload.server_uuid).await {
            Some(server) => server,
            None => {
                return ApiResponse::error("server not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let ignored = match payload.ignored() {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "failed to compile subuser ignored files, denying upload: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let relative = PathBuf::from(params.directory.as_str()).join(params.file.as_str());
        let parent = match relative.parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };
        let file_name = match relative.file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        if ignored
            .as_ref()
            .is_some_and(|o| o.matched(parent, true).is_ignore())
            || server
                .filesystem
                .async_is_ignored(parent, FileType::Dir)
                .await
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs(&server, &parent)
            .await;
        let path = root.join(file_name);

        if filesystem.is_primary_server_fs()
            && (ignored
                .as_ref()
                .is_some_and(|o| o.matched(&path, false).is_ignore())
                || server
                    .filesystem
                    .async_is_ignored(&path, FileType::File)
                    .await)
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let offset = match filesystem.async_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("target is not a file")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }

                metadata.size
            }
            Err(_) => 0,
        };

        ApiResponse::new(Body::empty())
            .with_header("Upload-Offset", &offset.to_string())
            .ok()
    }
}

mod patch {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::{
            activity::{Activity, ActivityEvent},
            filesystem::cap::FileType,
        },
    };
    use axum::{
        body::Body,
        extract::{ConnectInfo, Query},
        http::{HeaderMap, StatusCode},
    };
    use futures::StreamExt;
    use serde::Deserialize;
    use serde_json::json;
    use std::{net::SocketAddr, path::PathBuf};
    use tokio::io::AsyncWriteExt;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        token: String,
        #[serde(default)]
        directory: compact_str::CompactString,
        file: compact_str::CompactString,
    }

    #[utoipa::path(patch, path = "/", responses(
        (status = OK),
        (status = UNAUTHORIZED, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
        (status = CONFLICT, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        ("token" = String, Query, description = "The JWT token to use for authentication"),
        ("directory" = String, Query, description = "The directory to upload the file to"),
        ("file" = String, Query, description = "The file name (may include a sub-path) within the directory"),
    ), request_body = String)]
    pub async fn route(
        state: GetState,
        headers: HeaderMap,
        connect_info: ConnectInfo<SocketAddr>,
        Query(params): Query<Params>,
        body: Body,
    ) -> ApiResponseResult {
        let payload: super::FileJwtPayload = match state.config.jwt.verify(&params.token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload
            .base
            .validate(&state.config.jwt, Some("file-upload"))
        {
            return ApiResponse::error(&format!("invalid token: {err}"))
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let upload_offset = match headers
            .get("Upload-Offset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(offset) => offset,
            None => {
                return ApiResponse::error("missing or invalid Upload-Offset header")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let upload_complete = headers
            .get("Upload-Complete")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim() == "?1");

        let upload_length = headers
            .get("Upload-Length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());

        let server = match state.server_manager.get_server(payload.server_uuid).await {
            Some(server) => server,
            None => {
                return ApiResponse::error("server not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let upload_limit = state.config.load().api.upload_limit.as_bytes();
        if upload_limit != 0 && upload_length.is_some_and(|total| total > upload_limit) {
            return ApiResponse::error(&format!(
                "file size is larger than {}MiB",
                state.config.load().api.upload_limit.as_mib()
            ))
            .with_status(StatusCode::EXPECTATION_FAILED)
            .ok();
        }

        if upload_offset == 0
            && let Some(total_size) = upload_length
        {
            let disk_limit = server.filesystem.disk_limit();
            if disk_limit > 0
                && total_size
                    > (disk_limit as u64)
                        .saturating_sub(server.filesystem.get_physical_cached_size())
            {
                return ApiResponse::error(
                    "file size is larger than the server's available disk space",
                )
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
            }
        }

        let ignored = match payload.ignored() {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "failed to compile subuser ignored files, denying upload: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let relative = PathBuf::from(params.directory.as_str()).join(params.file.as_str());
        let parent = match relative.parent() {
            Some(parent) => parent.to_path_buf(),
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };
        let file_name = match relative.file_name() {
            Some(name) => name.to_owned(),
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        if ignored
            .as_ref()
            .is_some_and(|o| o.matched(&parent, true).is_ignore())
            || server
                .filesystem
                .async_is_ignored(&parent, FileType::Dir)
                .await
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs(&server, &parent)
            .await;
        let path = root.join(&file_name);

        if filesystem.is_primary_server_fs()
            && (ignored
                .as_ref()
                .is_some_and(|o| o.matched(&path, false).is_ignore())
                || server
                    .filesystem
                    .async_is_ignored(&path, FileType::File)
                    .await)
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let lock = super::upload_lock((payload.server_uuid, path.clone())).await;
        let _guard = lock.lock().await;

        filesystem.async_create_dir_all(&root).await?;

        let disk_offset = match filesystem.async_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("target is not a file")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }

                metadata.size
            }
            Err(_) => 0,
        };

        if upload_offset != disk_offset {
            return ApiResponse::error("upload offset does not match the current file length")
                .with_status(StatusCode::CONFLICT)
                .with_header("Upload-Offset", &disk_offset.to_string())
                .ok();
        }

        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).append(true).create(true);
        let mut file = filesystem
            .async_open_file_with_options(&path, options)
            .await?;

        let mut written_size = disk_offset;
        let mut stream = body.into_data_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                std::io::Error::other(format!("failed to read request body: {err}"))
            })?;

            if crate::unlikely(
                upload_limit != 0 && written_size + chunk.len() as u64 > upload_limit,
            ) {
                file.shutdown().await?;

                return ApiResponse::error(&format!(
                    "file size is larger than {}MiB",
                    state.config.load().api.upload_limit.as_mib()
                ))
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
            }

            file.write_all(&chunk).await?;
            written_size += chunk.len() as u64;
        }

        file.shutdown().await?;

        if upload_complete {
            if let Some(total_size) = upload_length
                && written_size != total_size
            {
                return ApiResponse::error(&format!(
                    "upload completed at {written_size} bytes but {total_size} were expected"
                ))
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
            }

            let user_ip = Some(state.config.find_ip(&headers, connect_info));

            server.activity.log_activity(Activity {
                event: ActivityEvent::FileUploaded,
                user: Some(payload.user_uuid),
                ip: user_ip,
                metadata: Some(json!({
                    "files": [file_name.to_string_lossy()],
                    "directory": server.filesystem.relative_path(&parent),
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }

        ApiResponse::new(Body::empty())
            .with_header("Upload-Offset", &written_size.to_string())
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route).layer(DefaultBodyLimit::disable()))
        .routes(routes!(head::route))
        .routes(routes!(patch::route).layer(DefaultBodyLimit::disable()))
        .with_state(state.clone())
}
