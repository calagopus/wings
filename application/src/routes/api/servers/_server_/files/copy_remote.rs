use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        io::{
            SafeAsyncWriteExt, SafeDigestExt, compression::CompressionLevel,
            counting_reader::AsyncCountingReader,
        },
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::{
            filesystem::{
                cap::FileType,
                virtualfs::{AsyncDirectoryStreamWalkFn, IsIgnoredFn, VirtualWalkEntry},
            },
            transfer::TransferArchiveFormat,
        },
    };
    use axum::http::StatusCode;
    use futures::FutureExt;
    use serde::{Deserialize, Serialize};
    use sha1::Digest;
    use std::{
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use utoipa::ToSchema;

    fn foreground() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        url: String,
        token: String,

        #[serde(default)]
        archive_format: TransferArchiveFormat,
        #[serde(default, deserialize_with = "crate::deserialize::deserialize_optional")]
        compression_level: Option<CompressionLevel>,

        #[serde(default)]
        root: compact_str::CompactString,
        files: Vec<crate::models::CopyFile>,

        destination_server: uuid::Uuid,
        destination_path: compact_str::CompactString,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
        #[serde(default)]
        destination_ignored: Vec<compact_str::CompactString>,

        #[serde(default = "foreground")]
        foreground: bool,
    }

    #[derive(ToSchema, Serialize)]
    pub struct Response {}

    #[derive(ToSchema, Serialize)]
    pub struct ResponseAccepted {
        identifier: uuid::Uuid,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = ACCEPTED, body = inline(ResponseAccepted)),
        (status = NOT_FOUND, body = ApiError),
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
        let (source_ignored, destination_ignored) = match (
            crate::server::filesystem::RequestIgnored::compile(&data.ignored),
            crate::server::filesystem::RequestIgnored::compile(&data.destination_ignored),
        ) {
            (Ok(source), Ok(destination)) => (source, destination),
            (Err(err), _) | (_, Err(err)) => {
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

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, Path::new(&data.root), &source_ignored)
            .await;

        let metadata = filesystem.async_metadata(&root).await;
        if !metadata.map_or(true, |m| m.file_type.is_dir()) {
            return ApiResponse::error("path is not a directory")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        if filesystem.is_primary_server_fs()
            && server
                .filesystem
                .async_is_ignored(&root, FileType::Dir)
                .await
        {
            return ApiResponse::error("path not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let mut total_size = 0;
        for file in &data.files {
            let directory_entry = match filesystem
                .async_directory_entry_buffer(&root.join(&file.from), &[])
                .await
            {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            total_size += directory_entry.size;
        }

        let bytes_processed = Arc::new(AtomicU64::new(0));
        let bytes_total = Arc::new(AtomicU64::new(total_size));
        let files_processed = Arc::new(AtomicU64::new(0));

        if data.url.is_empty() {
            let destination_server = match state
                .server_manager
                .get_server(data.destination_server)
                .await
            {
                Some(server) => server,
                None => {
                    return ApiResponse::error("destination server not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            };

            let (destination_path, destination_filesystem) = destination_server
                .filesystem
                .resolve_writable_fs_ignoring(
                    &destination_server,
                    &data.destination_path,
                    &destination_ignored,
                )
                .await;

            let (tx, rx) = tokio::sync::oneshot::channel::<()>();

            let ignored = vec![
                server.filesystem.get_ignored(),
                destination_server.filesystem.get_ignored(),
            ];
            let mut ignored = IsIgnoredFn::from(ignored);
            if let Some(source_ignored) = source_ignored.filter(&server) {
                ignored = ignored.merge(source_ignored);
            }

            let (identifier, task) = server
                .filesystem
                .operations
                .add_operation(
                    crate::server::filesystem::operations::FilesystemOperation::CopyRemote {
                        server: server.uuid,
                        path: PathBuf::from(&data.root),
                        files: data.files.iter().map(|file| PathBuf::from(&file.from)).collect(),
                        destination_server: data.destination_server,
                        destination_path: PathBuf::from(&data.destination_path),
                        start_time: chrono::Utc::now(),
                        bytes_processed: bytes_processed.clone(),
                        bytes_total: bytes_total.clone(),
                        files_processed: files_processed.clone(),
                    },
                    {
                        let server = server.clone();
                        let root = root.clone();
                        let files = Arc::new(data.files.clone());
                        let filesystem = filesystem.clone();
                        let destination_server = destination_server.clone();
                        let destination_path = Arc::new(destination_path);
                        let destination_filesystem = destination_filesystem.clone();
                        let bytes_processed = bytes_processed.clone();
                        let files_processed = files_processed.clone();

                        async move {
                            let inner = async {
                                let mut walker = filesystem
                                    .async_walk_dir_files_stream(
                                        &root,
                                        files.iter().map(|file| PathBuf::from(&file.from)).collect(),
                                        ignored,
                                    )
                                    .await?;

                                walker
                                    .run_multithreaded(
                                        state.config.load().api.file_copy_threads,
                                        AsyncDirectoryStreamWalkFn::from({
                                            let server = server.clone();
                                            let filesystem = filesystem.clone();
                                            let source_path = Arc::new(root);
                                            let files = Arc::clone(&files);
                                            let destination_server = destination_server.clone();
                                            let destination_path = Arc::new(destination_path);
                                            let destination_filesystem = destination_filesystem.clone();
                                            let bytes_processed = Arc::clone(&bytes_processed);
                                            let files_processed = Arc::clone(&files_processed);

                                            move |entry: VirtualWalkEntry, stream| {
                                                let path = entry.path;

                                                let server = server.clone();
                                                let filesystem = filesystem.clone();
                                                let source_path = Arc::clone(&source_path);
                                                let files = Arc::clone(&files);
                                                let destination_server = destination_server.clone();
                                                let destination_path = Arc::clone(&destination_path);
                                                let destination_filesystem = destination_filesystem.clone();
                                                let bytes_processed = Arc::clone(&bytes_processed);
                                                let files_processed = Arc::clone(&files_processed);

                                                async move {
                                                    let metadata =
                                                        match filesystem.async_symlink_metadata(&path).await {
                                                            Ok(metadata) => metadata,
                                                            Err(_) => return Ok(()),
                                                        };

                                                    let relative_path = match path.strip_prefix(&*source_path) {
                                                        Ok(p) => p,
                                                        Err(_) => return Ok(()),
                                                    };
                                                    let destination_relative_path = files
                                                        .iter()
                                                        .find_map(|file| {
                                                            let stripped = relative_path.strip_prefix(Path::new(&file.from)).ok()?;
                                                            if stripped.as_os_str().is_empty() {
                                                                Some(PathBuf::from(&file.to))
                                                            } else {
                                                                Some(Path::new(&file.to).join(stripped))
                                                            }
                                                        })
                                                        .unwrap_or_else(|| relative_path.to_path_buf());
                                                    let source_path = source_path.join(relative_path);
                                                    let destination_path = destination_path.join(destination_relative_path);

                                                    if metadata.file_type.is_file() {
                                                        if let Some(parent) = destination_path.parent() {
                                                            destination_filesystem.async_create_dir_all(&parent).await?;
                                                        }

                                                        if filesystem.is_primary_server_fs()
                                                            && destination_filesystem.is_primary_server_fs()
                                                        {
                                                            server
                                                                .filesystem
                                                                .async_quota_copy(
                                                                    &source_path,
                                                                    &destination_path,
                                                                    &destination_server,
                                                                    Some(&bytes_processed),
                                                                )
                                                                .await?;
                                                        } else {
                                                            let mut reader = AsyncCountingReader::new_with_bytes_read(
                                                                stream,
                                                                Arc::clone(&bytes_processed),
                                                            );

                                                            let mut writer = destination_filesystem
                                                                .async_create_file(&destination_path)
                                                                .await?;
                                                            destination_filesystem
                                                                .async_set_permissions(&destination_path, metadata.file_type, metadata.permissions)
                                                                .await?;

                                                            tokio::io::copy(&mut reader, &mut writer).await?;
                                                            writer.shutdown().await?;
                                                        }

                                                        files_processed.fetch_add(1, Ordering::Relaxed);
                                                    } else if metadata.file_type.is_dir() {
                                                        destination_filesystem.async_create_dir_all(&destination_path).await?;
                                                        destination_filesystem
                                                            .async_set_permissions(&destination_path, metadata.file_type, metadata.permissions)
                                                            .await?;

                                                        bytes_processed.fetch_add(metadata.size, Ordering::Relaxed);
                                                    } else if metadata.file_type.is_symlink() && let Ok(target) = filesystem.async_read_symlink(&source_path).await {
                                                        if let Err(err) = destination_filesystem.async_create_symlink(&target, &destination_path).await {
                                                            tracing::debug!(path = %destination_path.display(), "failed to create symlink from copy: {:?}", err);
                                                        } else {
                                                            files_processed.fetch_add(1, Ordering::Relaxed);
                                                        }
                                                    }

                                                    Ok(())
                                                }
                                            }
                                        }),
                                    )
                                    .await?;

                                Ok(())
                            };

                            tokio::select! {
                                res = inner => res,
                                _ = rx =>
                                    Err(anyhow::anyhow!("copy process aborted by another source"))
                            }
                        }
                    },
                )
                .await;

            let (_, destination_task) = destination_server
                .filesystem
                .operations
                .add_operation(
                    crate::server::filesystem::operations::FilesystemOperation::CopyRemote {
                        server: server.uuid,
                        path: PathBuf::from(data.root),
                        files: data
                            .files
                            .iter()
                            .map(|file| PathBuf::from(&file.from))
                            .collect(),
                        destination_server: data.destination_server,
                        destination_path: PathBuf::from(data.destination_path),
                        start_time: chrono::Utc::now(),
                        bytes_processed: bytes_processed.clone(),
                        bytes_total: bytes_total.clone(),
                        files_processed: files_processed.clone(),
                    },
                    async move {
                        let _tx = tx;

                        match task.await {
                            Ok(Some(Ok(()))) => Ok(()),
                            Ok(None) => {
                                Err(anyhow::anyhow!("copy process aborted by another source"))
                            }
                            Ok(Some(Err(err))) => Err(err),
                            Err(err) => Err(err.into()),
                        }
                    },
                )
                .await;

            if data.foreground {
                match destination_task.await {
                    Ok(Some(Ok(()))) => {}
                    Ok(None) => {
                        return ApiResponse::error("copy process aborted by another source")
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                    Ok(Some(Err(err))) => {
                        tracing::error!(
                            server = %server.uuid,
                            root = %root.display(),
                            "failed to copy to a remote: {:#?}",
                            err,
                        );

                        return ApiResponse::error(&format!("failed to copy to a remote: {err}"))
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            root = %root.display(),
                            "failed to copy to a remote: {:#?}",
                            err,
                        );

                        return ApiResponse::error("failed to copy to a remote")
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                }

                ApiResponse::new_serialized(Response {}).ok()
            } else {
                ApiResponse::new_serialized(ResponseAccepted { identifier })
                    .with_status(StatusCode::ACCEPTED)
                    .ok()
            }
        } else {
            let (identifier, task) = server
                .filesystem
                .operations
                .add_operation(
                    crate::server::filesystem::operations::FilesystemOperation::CopyRemote {
                        server: server.uuid,
                        path: root.clone(),
                        files: data.files.iter().map(|file| PathBuf::from(&file.from)).collect(),
                        destination_server: data.destination_server,
                        destination_path: PathBuf::from(data.destination_path),
                        start_time: chrono::Utc::now(),
                        bytes_processed: bytes_processed.clone(),
                        bytes_total: bytes_total.clone(),
                        files_processed: files_processed.clone(),
                    },
                    {
                        let root = root.clone();
                        let files = data.files.clone();
                        let server = server.clone();
                        let files_processed = files_processed.clone();

                        async move {
                            let (checksum_sender, checksum_receiver) =
                                tokio::sync::oneshot::channel();
                            let (mut checksummed_reader, mut checksummed_writer) =
                                tokio::io::simplex(crate::BUFFER_SIZE);
                            let (reader, mut writer) = tokio::io::simplex(crate::BUFFER_SIZE);

                            let archive_task = async {
                                let is_ignored = if filesystem.is_primary_server_fs() {
                                    server.filesystem.get_ignored().into()
                                } else {
                                    Default::default()
                                };

                                let mut reader = filesystem
                                    .async_read_dir_files_archive(
                                        &root,
                                        files.into_iter().map(|file| PathBuf::from(file.from)).collect(),
                                        data.archive_format.into(),
                                        data.compression_level.unwrap_or_else(|| {
                                            state.config.load().system.backups.compression_level
                                        }),
                                        crate::server::filesystem::archive::create::ArchiveProgress::new(bytes_processed, files_processed),
                                        is_ignored,
                                    )
                                    .await?;

                                tokio::io::copy(&mut reader, &mut checksummed_writer).await?;
                                checksummed_writer.shutdown().await?;

                                Ok::<_, anyhow::Error>(())
                            };

                            let checksum_task = async {
                                let mut hasher = sha2::Sha256::new();

                                let mut buffer = vec![0; crate::BUFFER_SIZE];
                                loop {
                                    let bytes_read = checksummed_reader.read(&mut buffer).await?;
                                    if crate::unlikely(bytes_read == 0) {
                                        break;
                                    }

                                    hasher.safe_update(&buffer, bytes_read)?;
                                    writer.safe_write_all(&buffer, bytes_read).await?;
                                }

                                checksum_sender.send(hex::encode(hasher.finalize())).ok();
                                writer.shutdown().await?;

                                Ok::<_, anyhow::Error>(())
                            };

                            let form = reqwest::multipart::Form::new()
                                .part(
                                    "archive",
                                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                                        tokio_util::io::ReaderStream::with_capacity(
                                            reader,
                                            crate::BUFFER_SIZE,
                                        ),
                                    ))
                                    .file_name(format!(
                                        "archive.{}",
                                        data.archive_format.extension()
                                    ))
                                    .mime_str("application/x-tar")?,
                                )
                                .part(
                                    "checksum",
                                    reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(
                                        checksum_receiver.into_stream(),
                                    ))
                                    .file_name("checksum")
                                    .mime_str("text/plain")?,
                                );

                            let response = reqwest::Client::builder()
                                .connect_timeout(std::time::Duration::from_secs(15))
                                .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
                                .build()?
                                .post(&data.url)
                                .header("Authorization", &data.token)
                                .header("Total-Bytes", bytes_total.load(Ordering::Relaxed))
                                .header("Root-Files", serde_json::to_string(&data.files)?)
                                .multipart(form)
                                .send();

                            let (_, _, response) =
                                tokio::try_join!(archive_task, checksum_task, async {
                                    Ok(response.await?)
                                })?;

                            if !response.status().is_success() {
                                let status = response.status();
                                let body: serde_json::Value =
                                    response.json().await.unwrap_or_default();

                                if let Some(message) = body.get("error").and_then(|m| m.as_str()) {
                                    return Err(anyhow::anyhow!(message.to_string()));
                                } else {
                                    return Err(anyhow::anyhow!(
                                        "remote server responded with an error (status: {status})"
                                    ));
                                }
                            }

                            Ok(())
                        }
                    },
                )
                .await;

            if data.foreground {
                match task.await {
                    Ok(Some(Ok(()))) => {}
                    Ok(None) => {
                        return ApiResponse::error("copy process aborted by another source")
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                    Ok(Some(Err(err))) => {
                        tracing::error!(
                            server = %server.uuid,
                            root = %root.display(),
                            "failed to copy to a remote: {:#?}",
                            err,
                        );

                        return ApiResponse::error(&format!("failed to copy to a remote: {err}"))
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            root = %root.display(),
                            "failed to copy to a remote: {:#?}",
                            err,
                        );

                        return ApiResponse::error("failed to copy to a remote")
                            .with_status(StatusCode::EXPECTATION_FAILED)
                            .ok();
                    }
                }

                ApiResponse::new_serialized(Response {}).ok()
            } else {
                ApiResponse::new_serialized(ResponseAccepted { identifier })
                    .with_status(StatusCode::ACCEPTED)
                    .ok()
            }
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
