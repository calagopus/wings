use super::State;
use crate::{
    response::ApiResponse,
    server::filesystem::{cap::FileType, uploads::part_path, virtualfs::VirtualWritableFilesystem},
};
use axum::{extract::DefaultBodyLimit, http::StatusCode};
use serde::Deserialize;
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, LazyLock},
};
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
    #[serde(default)]
    pub user_name: Option<compact_str::CompactString>,
    pub unique_id: compact_str::CompactString,

    #[serde(flatten)]
    pub ignored_files: crate::routes::token::IgnoredFiles,
}

impl crate::routes::token::TokenPayload for FileJwtPayload {
    #[inline]
    fn base(&self) -> &crate::remote::jwt::BasePayload {
        &self.base
    }
}

const LOCKED_ERROR: &str = "server entered a locked state, upload aborted";

fn issued_before_lock(payload: &FileJwtPayload, server: &crate::server::Server) -> bool {
    payload.base.issued_at.unwrap_or(0) < server.last_locked_at()
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

async fn authenticate(
    state: &crate::routes::AppState,
    token: &str,
) -> Result<(FileJwtPayload, crate::server::Server), ApiResponse> {
    let payload: FileJwtPayload = crate::routes::token::verify(state, token, "file-upload")?;
    let server = crate::routes::token::server(state, payload.server_uuid).await?;

    Ok((payload, server))
}

struct UploadTarget {
    parent: PathBuf,
    file_name: OsString,
    root: PathBuf,
    filesystem: Arc<dyn VirtualWritableFilesystem>,
    path: PathBuf,
    part: PathBuf,
}

/// Resolves the staging `.part` path of a resumable upload, rejecting targets
/// hidden by the subuser's or the server's ignore lists.
async fn resolve_target(
    server: &crate::server::Server,
    payload: &FileJwtPayload,
    directory: &str,
    file: &str,
    action: &str,
) -> Result<UploadTarget, ApiResponse> {
    let not_found = || ApiResponse::error("file not found").with_status(StatusCode::NOT_FOUND);

    let ignored = match payload.ignored_files.compile() {
        Ok(ignored) => ignored,
        Err(err) => {
            tracing::error!(
                server = %server.uuid,
                "failed to compile subuser ignored files, denying {action}: {:#?}",
                err
            );

            return Err(not_found());
        }
    };

    let relative = PathBuf::from(directory).join(file);
    let Some(parent) = relative.parent() else {
        return Err(
            ApiResponse::error("file has no parent").with_status(StatusCode::EXPECTATION_FAILED)
        );
    };
    let Some(file_name) = relative.file_name() else {
        return Err(
            ApiResponse::error("invalid file name").with_status(StatusCode::EXPECTATION_FAILED)
        );
    };

    if ignored
        .as_ref()
        .is_some_and(|o| o.is_ignored_subtree(parent, FileType::Dir))
        || server
            .filesystem
            .async_is_ignored_subtree(parent, FileType::Dir)
            .await
    {
        return Err(not_found());
    }

    let (root, filesystem) = server.filesystem.resolve_writable_fs(server, parent).await;
    let path = root.join(file_name);

    if filesystem.is_primary_server_fs()
        && (ignored
            .as_ref()
            .is_some_and(|o| o.is_ignored(&path, FileType::File))
            || server
                .filesystem
                .async_is_ignored(&path, FileType::File)
                .await)
    {
        return Err(not_found());
    }

    let Some(part) = part_path(&path) else {
        return Err(
            ApiResponse::error("file name too long").with_status(StatusCode::EXPECTATION_FAILED)
        );
    };

    Ok(UploadTarget {
        parent: parent.to_path_buf(),
        file_name: file_name.to_owned(),
        root,
        filesystem,
        path,
        part,
    })
}

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::{
            activity::{Activity, ActivityEvent},
            filesystem::{
                cap::FileType,
                uploads::{NewUpload, part_path},
            },
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
        let (payload, server) = super::authenticate(&state, &params.token).await?;

        crate::routes::token::consume(&state, &payload.unique_id)?;

        let locked = server.locked_signal();
        tokio::pin!(locked);

        if super::issued_before_lock(&payload, &server) {
            return ApiResponse::error(super::LOCKED_ERROR)
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

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

        let ignored = match payload.ignored_files.compile() {
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
                Some(name) => name.to_string(),
                None => {
                    return ApiResponse::error("file name not found")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            };
            let path = directory.join(&filename);
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
                .is_some_and(|o| o.is_ignored_subtree(parent, FileType::Dir))
                || server
                    .filesystem
                    .async_is_ignored_subtree(parent, FileType::Dir)
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
                    .is_some_and(|o| o.is_ignored(&path, FileType::File))
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

            let part = match part_path(&path) {
                Some(part) => part,
                None => {
                    return ApiResponse::error("file name too long")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            };

            let lock = super::upload_lock((payload.server_uuid, part.clone())).await;
            let _lock_guard = lock.lock().await;

            let mut written_size = 0;
            let mut writer = filesystem.async_create_file(&part).await?;

            let guard = if filesystem.is_primary_server_fs() {
                Some(
                    server
                        .filesystem
                        .uploads
                        .register(
                            NewUpload {
                                target: &path,
                                part: &part,
                                user: payload.user_uuid,
                                user_name: payload.user_name.clone(),
                                total: None,
                                uploaded: 0,
                                resumable: false,
                            },
                            &server.filesystem,
                        )
                        .await,
                )
            } else {
                None
            };

            loop {
                let chunk = tokio::select! {
                    chunk = field.chunk() => chunk?,
                    _ = &mut locked => {
                        return ApiResponse::error(super::LOCKED_ERROR)
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                };
                let Some(chunk) = chunk else {
                    break;
                };

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
                if let Some(guard) = &guard {
                    guard.set_progress(written_size);
                }
            }

            writer.shutdown().await?;
            drop(writer);

            filesystem
                .async_rename(&part, &path, FileType::File)
                .await?;

            if let Some(guard) = guard {
                guard.complete().await;
            }

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
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

mod head {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::{body::Body, extract::Query, http::StatusCode};
    use serde::Deserialize;
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
        let (payload, server) = super::authenticate(&state, &params.token).await?;

        let super::UploadTarget {
            filesystem, part, ..
        } = super::resolve_target(&server, &payload, &params.directory, &params.file, "upload")
            .await?;

        let offset = match filesystem.async_metadata(&part).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("staging path is not a file")
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
            filesystem::{cap::FileType, uploads::NewUpload},
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
    use std::net::SocketAddr;
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
        let (payload, server) = super::authenticate(&state, &params.token).await?;

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

        let locked = server.locked_signal();
        tokio::pin!(locked);

        if super::issued_before_lock(&payload, &server) {
            return ApiResponse::error(super::LOCKED_ERROR)
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

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

        let super::UploadTarget {
            parent,
            file_name,
            root,
            filesystem,
            path,
            part,
        } = super::resolve_target(&server, &payload, &params.directory, &params.file, "upload")
            .await?;

        let lock = super::upload_lock((payload.server_uuid, part.clone())).await;
        let _lock_guard = lock.lock().await;

        filesystem.async_create_dir_all(&root).await?;

        let disk_offset = match filesystem.async_metadata(&part).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("staging path is not a file")
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
            .async_open_file_with_options(&part, options)
            .await?;

        let guard = if filesystem.is_primary_server_fs() {
            Some(
                server
                    .filesystem
                    .uploads
                    .register(
                        NewUpload {
                            target: &path,
                            part: &part,
                            user: payload.user_uuid,
                            user_name: payload.user_name.clone(),
                            total: upload_length,
                            uploaded: disk_offset,
                            resumable: true,
                        },
                        &server.filesystem,
                    )
                    .await,
            )
        } else {
            None
        };

        let mut written_size = disk_offset;
        let mut stream = body.into_data_stream();

        loop {
            let chunk = tokio::select! {
                chunk = stream.next() => chunk,
                _ = &mut locked => {
                    file.shutdown().await?;

                    return ApiResponse::error(super::LOCKED_ERROR)
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            };
            let Some(chunk) = chunk else {
                break;
            };

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
            if let Some(guard) = &guard {
                guard.set_progress(written_size);
            }
        }

        file.shutdown().await?;
        drop(file);

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

            filesystem
                .async_rename(&part, &path, FileType::File)
                .await?;

            if let Some(guard) = guard {
                guard.complete().await;
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

mod delete {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::{extract::Query, http::StatusCode};
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        token: String,
        #[serde(default)]
        directory: compact_str::CompactString,
        file: compact_str::CompactString,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        ("token" = String, Query, description = "The JWT token to use for authentication"),
        ("directory" = String, Query, description = "The directory the file lives in"),
        ("file" = String, Query, description = "The file name (may include a sub-path) within the directory"),
    ))]
    pub async fn route(state: GetState, Query(params): Query<Params>) -> ApiResponseResult {
        let (payload, server) = super::authenticate(&state, &params.token).await?;

        let super::UploadTarget {
            filesystem, part, ..
        } = super::resolve_target(
            &server,
            &payload,
            &params.directory,
            &params.file,
            "discard",
        )
        .await?;

        let lock = super::upload_lock((payload.server_uuid, part.clone())).await;
        let _lock_guard = lock.lock().await;

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .uploads
                .owner(&part, &server.filesystem)
                .await
                .is_some_and(|user| user != payload.user_uuid)
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        if let Ok(metadata) = filesystem.async_metadata(&part).await
            && metadata.file_type.is_file()
        {
            filesystem.async_remove_file(&part).await?;
        }

        if filesystem.is_primary_server_fs() {
            server
                .filesystem
                .uploads
                .forget(&part, &server.filesystem)
                .await;
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route).layer(DefaultBodyLimit::disable()))
        .routes(routes!(head::route))
        .routes(routes!(patch::route).layer(DefaultBodyLimit::disable()))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
