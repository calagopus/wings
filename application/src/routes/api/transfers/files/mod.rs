use super::State;
use axum::extract::DefaultBodyLimit;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

mod stat;

mod post {
    use crate::{
        io::abort::AbortGuard,
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::filesystem::{
            archive::{ExtractOptions, create::ArchiveProgress},
            cap::FileType,
        },
    };
    use axum::{
        extract::Multipart,
        http::{HeaderMap, StatusCode},
    };
    use serde::{Deserialize, Serialize};
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, atomic::AtomicU64},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[derive(Deserialize)]
    pub struct FileTransferJwtPayload {
        #[serde(flatten)]
        pub base: crate::remote::jwt::BasePayload,

        pub server: uuid::Uuid,
        pub root: compact_str::CompactString,

        pub destination_path: compact_str::CompactString,
    }

    impl crate::routes::token::TokenPayload for FileTransferJwtPayload {
        #[inline]
        fn base(&self) -> &crate::remote::jwt::BasePayload {
            &self.base
        }
    }

    fn remap_root_path(path: &Path, files: &[crate::models::CopyFile]) -> PathBuf {
        for file in files {
            if let Ok(stripped) = path.strip_prefix(Path::new(&file.from)) {
                return if stripped.as_os_str().is_empty() {
                    PathBuf::from(&file.to)
                } else {
                    Path::new(&file.to).join(stripped)
                };
            }
        }

        path.to_path_buf()
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
        (status = CONFLICT, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        headers: HeaderMap,
        mut multipart: Multipart,
    ) -> ApiResponseResult {
        let key = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let (r#type, token) = match key.split_once(' ') {
            Some((t, tok)) => (t, tok),
            None => {
                return ApiResponse::error("invalid authorization header")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .with_header("WWW-Authenticate", "Bearer")
                    .ok();
            }
        };

        if r#type != "Bearer" {
            return ApiResponse::error("invalid authorization header")
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let payload: FileTransferJwtPayload =
            crate::routes::token::verify(&state, token, "transfer")?;

        let subject = crate::routes::token::subject_uuid(&payload.base)?;

        let server = crate::routes::token::server(&state, subject).await?;

        let total_bytes: u64 = headers
            .get("Total-Bytes")
            .map_or(Ok(0), |v| v.to_str().unwrap_or_default().parse())?;
        let mut root_files_field = match multipart.next_field().await? {
            Some(field) if field.name() == Some("root-files") => field,
            _ => {
                return ApiResponse::error("transfer did not start with root-files")
                    .with_status(StatusCode::BAD_REQUEST)
                    .ok();
            }
        };
        let root_files = crate::utils::read_limited_multipart_bytes(
            &mut root_files_field,
            super::super::MAX_ROOT_FILES_LEN,
        )
        .await
        .or_api_error(StatusCode::BAD_REQUEST, "invalid root-files")?;
        drop(root_files_field);
        let root_files: Vec<crate::models::CopyFile> = serde_json::from_slice(&root_files)
            .or_api_error(StatusCode::BAD_REQUEST, "invalid root-files")?;

        let progress = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(total_bytes));
        let files_processed = Arc::new(AtomicU64::new(0));

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs(&server, &payload.destination_path)
            .await;

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored_subtree(&root, FileType::Dir)
                .await
        {
            return ApiResponse::error("destination not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        filesystem.async_create_dir_all(&root).await?;

        let (_, task) = server
            .filesystem
            .operations
            .add_linked_operation(
                crate::server::filesystem::operations::FilesystemOperation::CopyRemote {
                    server: payload.server,
                    path: PathBuf::from(&payload.root),
                    files: root_files.iter().map(|file| PathBuf::from(&file.from)).collect(),
                    destination_server: server.uuid,
                    destination_path: PathBuf::from(&payload.destination_path),
                    start_time: chrono::Utc::now(),
                    bytes_processed: progress.clone(),
                    bytes_total: total.clone(),
                    files_processed: files_processed.clone(),
                },
                {
                    let runtime = tokio::runtime::Handle::current();
                    let server = server.clone();
                    let filesystem = filesystem.clone();
                    let state = state.clone();
                    let files_processed = files_processed.clone();

                    async move {
                        let (_guard, listener) = AbortGuard::new();

                        tokio::task::spawn_blocking(move || {
                            let mut archive_checksum = None;
                            let mut archive_received = false;

                            while let Some(mut field) = runtime.block_on(multipart.next_field())? {
                                match field.name() {
                                    Some("archive") => {
                                        archive_received = true;
                                        archive_checksum = Some(super::super::extract_transfer_archive(
                                            &runtime,
                                            field,
                                            &server,
                                            &listener,
                                            state.config.load().system.transfers.download_limit.as_bytes(),
                                            root.clone(),
                                            filesystem.clone(),
                                            ArchiveProgress::new(progress.clone(), files_processed.clone()),
                                            ExtractOptions {
                                                map_path: Some(Arc::new({
                                                    let root_files = root_files.clone();

                                                    move |path| remap_root_path(path, &root_files)
                                                })),
                                                count_written: true,
                                                ..Default::default()
                                            },
                                        )?);
                                    }
                                    Some("checksum") => {
                                        let archive_checksum = match archive_checksum.take() {
                                            Some(checksum) => hex::encode(checksum),
                                            None => {
                                                return Err(anyhow::anyhow!(
                                                    "archive checksum does not match multipart checksum, None to be found"
                                                ));
                                            }
                                        };

                                        let checksum = runtime.block_on(
                                            crate::utils::read_limited_multipart_field(
                                                &mut field,
                                                super::super::MAX_CHECKSUM_LEN,
                                            ),
                                        )?;

                                        if archive_checksum != checksum {
                                            return Err(anyhow::anyhow!(
                                                "archive checksum does not match multipart checksum, {checksum} != {archive_checksum}"
                                            ));
                                        }
                                    }
                                    Some("root-files") => {
                                        return Err(anyhow::anyhow!(
                                            "root-files must be the first transfer field"
                                        ));
                                    }
                                    _ => {}
                                }
                            }

                            if !archive_received {
                                return Err(anyhow::anyhow!("transfer did not contain an archive"));
                            }

                            // the checksum field takes the computed hash, anything left over
                            // means the sender never provided one to compare against.
                            if archive_checksum.is_some() {
                                return Err(anyhow::anyhow!(
                                    "transfer did not contain an archive checksum, cannot verify integrity"
                                ));
                            }

                            Ok(())
                        }).await?
                    }
                },
            )
            .await;

        match task.await {
            Ok(Some(Ok(()))) => {}
            Ok(None) => {
                return ApiResponse::error("file transfer aborted")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
            Ok(Some(Err(err))) => {
                tracing::error!(
                    server = %server.uuid,
                    "server file transfer failed: {:#?}",
                    err,
                );

                return ApiResponse::error("file transfer failed")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "server file transfer failed: {:#?}",
                    err,
                );

                return ApiResponse::error("file transfer failed")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route).layer(DefaultBodyLimit::disable()))
        .nest("/stat", stat::router(state))
        .with_state(state.clone())
}
