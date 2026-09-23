use super::State;
use axum::extract::DefaultBodyLimit;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

mod post {
    use crate::{
        io::{
            abort::{AbortGuard, AbortReader},
            compression::{CompressionType, reader::CompressionReader},
            counting_writer::CountingWriter,
            hash_reader::HashReader,
            limited_reader::LimitedReader,
        },
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::{filesystem::cap::FileType, transfer::TransferArchiveFormat},
        utils::PortablePermissions,
    };
    use axum::{
        extract::Multipart,
        http::{HeaderMap, StatusCode},
    };
    use futures::TryStreamExt;
    use serde::{Deserialize, Serialize};
    use sha1::Digest;
    use std::{
        io::Write,
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
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

        let payload: FileTransferJwtPayload = match state.config.jwt.verify(token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload.base.validate(&state.config.jwt, Some("transfer")) {
            return ApiResponse::error(&format!("invalid token: {err}"))
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let subject: uuid::Uuid = match payload.base.subject {
            Some(subject) => match subject.parse() {
                Ok(subject) => subject,
                Err(_) => {
                    return ApiResponse::error("invalid token")
                        .with_status(StatusCode::UNAUTHORIZED)
                        .ok();
                }
            },
            None => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        let server = match state.server_manager.get_server(subject).await {
            Some(server) => server,
            None => {
                return ApiResponse::error("server not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let total_bytes: u64 = headers
            .get("Total-Bytes")
            .map_or(Ok(0), |v| v.to_str().unwrap_or_default().parse())?;
        let root_files: Vec<crate::models::CopyFile> = serde_json::from_str(
            headers
                .get("Root-Files")
                .map_or("[]", |v| v.to_str().unwrap_or("[]")),
        )?;

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
                                        let file_name = field.file_name().unwrap_or("archive.tar.gz").to_string();
                                        let reader =
                                            tokio_util::io::StreamReader::new(field.into_stream().map_err(|err| {
                                                std::io::Error::other(format!("failed to read multipart field: {err}"))
                                            }));
                                        let reader = AbortReader::new(
                                            tokio_util::io::SyncIoBridge::new(reader),
                                            listener.clone(),
                                        );
                                        let reader = LimitedReader::new_with_bytes_per_second(
                                            reader,
                                            state.config.load().system.transfers.download_limit.as_bytes(),
                                        );
                                        let reader = HashReader::new_with_hasher(reader, sha2::Sha256::new());
                                        let mut reader = CompressionReader::new(
                                            reader,
                                            TransferArchiveFormat::from_str(&file_name)
                                                .map_or(CompressionType::Gz, |f| f.compression_format()),
                                        )?;

                                        if TransferArchiveFormat::from_str(&file_name)
                                            .is_ok_and(|f| f.is_itaf())
                                        {
                                            let archive =
                                                itaf::decoder::ItafDecoder::new(&mut reader)?;
                                            let entries = archive.entries();

                                            let mut read_buffer =
                                                vec![0; crate::TRANSFER_BUFFER_SIZE];
                                            for entry in entries {
                                                let mut entry = entry?;
                                                let rel = entry.enclosed_path();
                                                if rel.as_os_str().is_empty() || rel.is_absolute()
                                                {
                                                    continue;
                                                }

                                                let destination_path =
                                                    Path::new(&payload.destination_path)
                                                        .join(remap_root_path(&rel, &root_files));

                                                let is_dir = matches!(
                                                    &entry,
                                                    itaf::decoder::ArchiveEntry::Directory(_)
                                                );
                                                if filesystem.is_primary_server_fs()
                                                    && server
                                                        .filesystem
                                                        .is_ignored(&destination_path, FileType::from_is_dir(is_dir))
                                                {
                                                    continue;
                                                }

                                                match &mut entry {
                                                    itaf::decoder::ArchiveEntry::Directory(dir) => {
                                                        filesystem
                                                            .create_dir_all(&destination_path)?;
                                                        filesystem.set_permissions(
                                                            &destination_path,
                                                            FileType::Dir,
                                                            PortablePermissions::from_mode_dir(
                                                                dir.metadata().mode,
                                                            ),
                                                        )?;
                                                    }
                                                    itaf::decoder::ArchiveEntry::File(
                                                        file_entry,
                                                    ) => {
                                                        if let Some(parent) =
                                                            destination_path.parent()
                                                        {
                                                            filesystem.create_dir_all(&parent)?;
                                                        }

                                                        let writer = filesystem
                                                            .create_file(&destination_path)?;
                                                        let mut writer =
                                                            CountingWriter::new_with_bytes_written(
                                                                writer,
                                                                progress.clone(),
                                                            );

                                                        crate::io::copy_shared(
                                                            &mut read_buffer,
                                                            file_entry,
                                                            &mut writer,
                                                        )?;
                                                        writer.flush()?;
                                                        files_processed
                                                            .fetch_add(1, Ordering::Relaxed);
                                                    }
                                                    itaf::decoder::ArchiveEntry::Symlink(sym) => {
                                                        let target = sym.target().to_path_buf();
                                                        if let Err(err) = filesystem
                                                            .create_symlink(
                                                                &target,
                                                                &destination_path,
                                                            )
                                                        {
                                                            tracing::debug!(
                                                                path = %destination_path.display(),
                                                                "failed to create symlink from itaf archive: {:#?}",
                                                                err
                                                            );
                                                        } else {
                                                            files_processed
                                                                .fetch_add(1, Ordering::Relaxed);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }

                                            let mut inner = reader.into_inner();
                                            crate::io::copy_shared(
                                                &mut read_buffer,
                                                &mut inner,
                                                &mut std::io::sink(),
                                            )?;
                                            archive_checksum = Some(inner.finish());
                                        } else {
                                            let mut archive = tar::Archive::new(reader);
                                            archive.set_ignore_zeros(true);
                                            let entries = archive.entries()?;

                                            let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
                                            for entry in entries {
                                                let mut entry = entry?;
                                                let path = entry.path()?;

                                                if path.is_absolute() {
                                                    continue;
                                                }

                                                let destination_path = Path::new(&payload.destination_path)
                                                    .join(remap_root_path(&path, &root_files));
                                                let header = entry.header();

                                                let is_dir = header.entry_type() == tar::EntryType::Directory;
                                                if filesystem.is_primary_server_fs()
                                                    && server
                                                        .filesystem
                                                        .is_ignored(&destination_path, FileType::from_is_dir(is_dir))
                                                {
                                                    continue;
                                                }

                                                match header.entry_type() {
                                                    tar::EntryType::Directory => {
                                                        filesystem.create_dir_all(&destination_path)?;
                                                        if let Ok(permissions) =
                                                            header.mode().map(PortablePermissions::from_mode_dir)
                                                        {
                                                            filesystem.set_permissions(
                                                                &destination_path,
                                                                FileType::Dir,
                                                                permissions,
                                                            )?;
                                                        }
                                                    }
                                                    tar::EntryType::Regular => {
                                                        if let Some(parent) = destination_path.parent() {
                                                            filesystem.create_dir_all(&parent)?;
                                                        }

                                                        let writer = filesystem.create_file(&destination_path)?;
                                                        let mut writer = CountingWriter::new_with_bytes_written(
                                                            writer,
                                                            progress.clone()
                                                        );

                                                        crate::io::copy_shared(
                                                            &mut read_buffer,
                                                            &mut entry,
                                                            &mut writer,
                                                        )?;
                                                        writer.flush()?;
                                                        files_processed.fetch_add(1, Ordering::Relaxed);
                                                    }
                                                    tar::EntryType::Symlink => {
                                                        let link = entry
                                                            .link_name()
                                                            .unwrap_or_default()
                                                            .unwrap_or_default();

                                                        if let Err(err) =
                                                            filesystem.create_symlink(&link, &destination_path)
                                                        {
                                                            tracing::debug!(
                                                                path = %destination_path.display(),
                                                                "failed to create symlink from archive: {:#?}",
                                                                err
                                                            );
                                                        } else {
                                                            files_processed.fetch_add(1, Ordering::Relaxed);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }

                                            let mut inner = archive.into_inner().into_inner();
                                            crate::io::copy_shared(
                                                &mut read_buffer,
                                                &mut inner,
                                                &mut std::io::sink(),
                                            )?;
                                            archive_checksum = Some(inner.finish());
                                        }
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
        .with_state(state.clone())
}
