use super::State;
use axum::extract::DefaultBodyLimit;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

const MAX_CHECKSUM_LEN: usize = 1024;

mod _server_;
mod capabilities;
mod files;
mod query;
mod ws;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use std::{collections::BTreeMap, sync::atomic::Ordering};

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = BTreeMap<uuid::Uuid, crate::models::TransferProgress>),
        (status = NOT_FOUND, body = ApiError),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        let mut transfers = BTreeMap::new();

        for server in state.server_manager.get_servers().await.iter() {
            if let Some(outgoing_transfer) = server.outgoing_transfer.read().await.as_ref() {
                transfers.insert(
                    server.uuid,
                    crate::models::TransferProgress {
                        archive_bytes_processed: outgoing_transfer
                            .bytes_archived
                            .load(Ordering::Relaxed),
                        network_bytes_processed: outgoing_transfer
                            .bytes_sent
                            .load(Ordering::Relaxed),
                        bytes_total: outgoing_transfer.bytes_total.load(Ordering::Relaxed),
                        files_processed: outgoing_transfer.files_archived.load(Ordering::Relaxed),
                    },
                );
            }
        }

        ApiResponse::new_serialized(transfers).ok()
    }
}

mod post {
    use crate::{
        io::{
            abort::{AbortGuard, AbortReader},
            compression::{CompressionType, reader::CompressionReader},
            hash_reader::HashReader,
            limited_reader::LimitedReader,
        },
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::{filesystem::archive::Archive, transfer::TransferArchiveFormat},
        utils::PortablePermissions,
    };
    use axum::{
        extract::Multipart,
        http::{HeaderMap, StatusCode},
    };
    use futures::TryStreamExt;
    use serde::Serialize;
    use sha1::Digest;
    use std::{io::Write, str::FromStr};
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

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

        let payload: crate::remote::jwt::BasePayload =
            crate::routes::token::verify(&state, token, "transfer")?;

        let subject = crate::routes::token::subject_uuid(&payload)?;

        let is_multiplex = headers.contains_key("Multiplex-Stream");
        let multiplex_stream_count: usize = headers
            .get("Multiplex-Stream-Count")
            .map_or(Ok(0), |v| v.to_str().unwrap_or_default().parse::<usize>())?
            .min(crate::server::transfer::MAX_MULTIPLEX_STREAMS);

        let server = if !is_multiplex {
            if state.server_manager.get_server(subject).await.is_some() {
                return ApiResponse::error("server with this uuid already exists")
                    .with_status(StatusCode::CONFLICT)
                    .ok();
            }

            let server_data = state.config.client.server(subject).await?;
            let server = state
                .server_manager
                .create_server(
                    &state,
                    server_data,
                    crate::server::manager::ServerCreation::Transferred,
                )
                .await;

            server.set_transferring(true).await;
            server
        } else {
            let mut tries = 0;

            loop {
                if let Some(server) = state.server_manager.get_server(subject).await
                    && server.is_transferring()
                    && server.incoming_transfer.read().await.is_some()
                {
                    break server;
                }

                tries += 1;

                if tries >= 40 {
                    return ApiResponse::error("unable to find transfer for multiplex")
                        .with_status(StatusCode::CONFLICT)
                        .ok();
                }

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        };

        let handle = tokio::spawn({
            let runtime = tokio::runtime::Handle::current();
            let server = server.clone();
            let state = state.clone();

            async move {
                let (guard, listener) = AbortGuard::new();

                let handle = tokio::task::spawn_blocking(
                    move || -> Result<
                        crate::server::backup::transfer::ReceivedBackups,
                        anyhow::Error,
                    > {
                        let mut archive_checksum = None;
                        let mut archive_received = false;
                        let mut backup_receiver =
                            crate::server::backup::transfer::BackupReceiver::new(
                                state.0.clone(),
                                listener.clone(),
                            );

                        loop {
                            let mut field = match runtime.block_on(multipart.next_field()) {
                                Ok(Some(field)) => field,
                                Ok(None) => break,
                                Err(err) => {
                                    return Err(anyhow::anyhow!(
                                        "failed to read transfer multipart field: {err}"
                                    ));
                                }
                            };

                            if field.name() == Some("archive") {
                                archive_received = true;
                                let file_name =
                                    field.file_name().unwrap_or("archive.tar.gz").to_string();
                                let reader = tokio_util::io::StreamReader::new(
                                    field.into_stream().map_err(|err| {
                                        std::io::Error::other(format!(
                                            "failed to read multipart field: {err}"
                                        ))
                                    }),
                                );
                                let reader = tokio_util::io::SyncIoBridge::new(reader);
                                let reader = AbortReader::new(reader, listener.clone());
                                let reader = LimitedReader::new_with_bytes_per_second(
                                    reader,
                                    state
                                        .config
                                        .load()
                                        .system
                                        .transfers
                                        .download_limit
                                        .as_bytes(),
                                );
                                let reader =
                                    HashReader::new_with_hasher(reader, sha2::Sha256::new());
                                let mut reader = CompressionReader::new(
                                    reader,
                                    TransferArchiveFormat::from_str(&file_name)
                                        .map_or(CompressionType::Gz, |f| f.compression_format()),
                                )?;

                                if TransferArchiveFormat::from_str(&file_name)
                                    .is_ok_and(|f| f.is_itaf())
                                {
                                    let archive = itaf::decoder::ItafDecoder::new(&mut reader)?;
                                    let mut directory_entries = chunked_vec::ChunkedVec::new();
                                    let mut last_parent = None;
                                    let entries = archive.entries();

                                    let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
                                    for entry in entries {
                                        let mut entry = entry?;
                                        let destination_path = entry.enclosed_path();
                                        if destination_path.as_os_str().is_empty() {
                                            continue;
                                        }

                                        match &mut entry {
                                            itaf::decoder::ArchiveEntry::Directory(dir) => {
                                                server
                                                    .filesystem
                                                    .create_chowned_dir_all(&destination_path)?;

                                                let meta = dir.metadata();
                                                server.filesystem.set_permissions(
                                                    &destination_path,
                                                    PortablePermissions::from_mode_dir(meta.mode),
                                                )?;

                                                if directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES {
                                                    directory_entries.push((destination_path, meta.modified));
                                                }
                                            }
                                            itaf::decoder::ArchiveEntry::File(file_entry) => {
                                                if let Some(parent) = destination_path.parent()
                                                    && last_parent.as_deref() != Some(parent)
                                                {
                                                    server
                                                        .filesystem
                                                        .create_chowned_dir_all(parent)?;
                                                    last_parent = Some(parent.to_path_buf());
                                                }

                                                let meta = file_entry.metadata();
                                                let mut writer =
                                                    crate::server::filesystem::file::ServerFile::new(
                                                        server.clone(),
                                                        &destination_path,
                                                        Some(PortablePermissions::from_mode_file(meta.mode)),
                                                        Some(meta.modified),
                                                    )?
                                                    .ignorant();

                                                crate::io::copy_shared(
                                                    &mut read_buffer,
                                                    file_entry,
                                                    &mut writer,
                                                )?;
                                                writer.flush()?;
                                            }
                                            itaf::decoder::ArchiveEntry::Symlink(sym) => {
                                                let target = sym.target().to_path_buf();
                                                let meta_modified = sym.metadata().modified;

                                                if let Some(parent) = destination_path.parent()
                                                    && !parent.as_os_str().is_empty()
                                                {
                                                    server
                                                        .filesystem
                                                        .create_chowned_dir_all(parent)?;
                                                }

                                                if let Err(err) = server
                                                    .filesystem
                                                    .symlink(target, &destination_path)
                                                {
                                                    tracing::debug!(
                                                        path = %destination_path.display(),
                                                        "failed to create symlink from itaf archive: {:#?}",
                                                        err
                                                    );
                                                } else {
                                                    server.filesystem.set_times(
                                                        &destination_path,
                                                        meta_modified,
                                                        None,
                                                    )?;
                                                }
                                            }
                                            itaf::decoder::ArchiveEntry::Hardlink(link) => {
                                                let target_path = link.enclosed_target();
                                                if target_path.as_os_str().is_empty() {
                                                    tracing::debug!(
                                                        path = %destination_path.display(),
                                                        "skipping hardlink with invalid target: {}",
                                                        target_path.display()
                                                    );
                                                    continue;
                                                }

                                                if let Some(parent) = destination_path.parent()
                                                    && !parent.as_os_str().is_empty()
                                                {
                                                    server
                                                        .filesystem
                                                        .create_chowned_dir_all(parent)?;
                                                }

                                                if let Err(err) = server.filesystem.hard_link(
                                                    &target_path,
                                                    &server.filesystem,
                                                    &destination_path,
                                                ) {
                                                    tracing::debug!(
                                                        path = %destination_path.display(),
                                                        target = %target_path.display(),
                                                        "failed to create hardlink from itaf archive: {:#?}",
                                                        err
                                                    );
                                                }
                                            }
                                        }
                                    }

                                    for (destination_path, modified_time) in directory_entries {
                                        server.filesystem.set_times(
                                            &destination_path,
                                            modified_time,
                                            None,
                                        )?;
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
                                    let mut directory_entries = chunked_vec::ChunkedVec::new();
                                    let mut last_parent = None;
                                    let entries = archive.entries()?;

                                    let mut read_buffer = vec![0; crate::TRANSFER_BUFFER_SIZE];
                                    for entry in entries {
                                        let mut entry = entry?;
                                        let path = server.filesystem.relative_path(&entry.path()?);

                                        if path.as_os_str().is_empty() {
                                            continue;
                                        }

                                        let destination_path = path.as_path();
                                        let header = entry.header();

                                        match header.entry_type() {
                                            tar::EntryType::Directory => {
                                                server
                                                    .filesystem
                                                    .create_chowned_dir_all(destination_path)?;
                                                if let Ok(permissions) = header
                                                    .mode()
                                                    .map(PortablePermissions::from_mode_dir)
                                                {
                                                    server.filesystem.set_permissions(
                                                        destination_path,
                                                        permissions,
                                                    )?;
                                                }

                                                if let Ok(modified_time) = header.mtime() && directory_entries.len() < Archive::MAX_DIRECTORY_MTIME_ENTRIES {
                                                    directory_entries.push((
                                                        destination_path.to_path_buf(),
                                                        modified_time,
                                                    ));
                                                }
                                            }
                                            tar::EntryType::Regular => {
                                                if let Some(parent) = destination_path.parent()
                                                    && last_parent.as_deref() != Some(parent)
                                                {
                                                    server
                                                        .filesystem
                                                        .create_chowned_dir_all(parent)?;
                                                    last_parent = Some(parent.to_path_buf());
                                                }

                                                let mut writer =
                                                crate::server::filesystem::file::ServerFile::new(
                                                    server.clone(),
                                                    destination_path,
                                                    header.mode().map(PortablePermissions::from_mode_file).ok(),
                                                    header
                                                        .mtime()
                                                        .map(|t| std::time::UNIX_EPOCH + std::time::Duration::from_secs(t))
                                                        .ok(),
                                                )?
                                                .ignorant();

                                                crate::io::copy_shared(
                                                    &mut read_buffer,
                                                    &mut entry,
                                                    &mut writer,
                                                )?;
                                                writer.flush()?;
                                            }
                                            tar::EntryType::Symlink => {
                                                let link = entry
                                                    .link_name()
                                                    .unwrap_or_default()
                                                    .unwrap_or_default();

                                                if let Err(err) = server
                                                    .filesystem
                                                    .symlink(link, destination_path)
                                                {
                                                    tracing::debug!(
                                                        path = %destination_path.display(),
                                                        "failed to create symlink from archive: {:#?}",
                                                        err
                                                    );
                                                } else if let Ok(modified_time) = header.mtime() {
                                                    server.filesystem.set_times(
                                                        destination_path,
                                                        std::time::UNIX_EPOCH
                                                            + std::time::Duration::from_secs(
                                                                modified_time,
                                                            ),
                                                        None,
                                                    )?;
                                                }
                                            }
                                            _ => {}
                                        }
                                    }

                                    for (destination_path, modified_time) in directory_entries {
                                        server.filesystem.set_times(
                                            &destination_path,
                                            std::time::UNIX_EPOCH
                                                + std::time::Duration::from_secs(modified_time),
                                            None,
                                        )?;
                                    }

                                    let mut inner = archive.into_inner().into_inner();
                                    crate::io::copy_shared(
                                        &mut read_buffer,
                                        &mut inner,
                                        &mut std::io::sink(),
                                    )?;
                                    archive_checksum = Some(inner.finish());
                                }
                            } else if field.name() == Some("checksum") {
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
                                        super::MAX_CHECKSUM_LEN,
                                    ),
                                )?;

                                if archive_checksum != checksum {
                                    return Err(anyhow::anyhow!(
                                        "archive checksum does not match multipart checksum, {checksum} != {archive_checksum}"
                                    ));
                                }
                            } else if field.name() == Some("install-logs") {
                                let file = match runtime.block_on(crate::server::installation::ServerInstaller::create_install_logs(&server)) {
                                    Ok(file) => file,
                                    Err(err) => {
                                        tracing::error!(
                                            "failed to create install logs file: {:#?}",
                                            err
                                        );
                                        continue;
                                    }
                                };
                                let mut file = runtime.block_on(file.into_std());

                                while let Some(chunk) = runtime.block_on(field.chunk())? {
                                    if let Err(err) = file.write_all(&chunk) {
                                        tracing::error!(
                                            "failed to write install logs chunk: {:#?}",
                                            err
                                        );
                                        break;
                                    }
                                }

                                if let Err(err) = file.flush() {
                                    tracing::error!(
                                        "failed to flush install logs file: {:#?}",
                                        err
                                    );
                                }
                            } else if field.name() == Some("diff-db") {
                                let file = match runtime.block_on(server.diff.prepare_import()) {
                                    Ok(file) => file,
                                    Err(err) => {
                                        tracing::error!(
                                            "failed to create file history database: {:#?}",
                                            err
                                        );
                                        continue;
                                    }
                                };
                                let mut file = runtime.block_on(file.into_std());

                                while let Some(chunk) = runtime.block_on(field.chunk())? {
                                    if let Err(err) = file.write_all(&chunk) {
                                        tracing::error!(
                                            "failed to write file history database chunk: {:#?}",
                                            err
                                        );
                                        break;
                                    }
                                }

                                if let Err(err) = file.flush() {
                                    tracing::error!(
                                        "failed to flush file history database: {:#?}",
                                        err
                                    );
                                }
                            } else if field.name().is_some_and(|n| n.starts_with("backup-")) {
                                backup_receiver.handle_field(&runtime, field)?;
                            }
                        }

                        if !archive_received {
                            return Err(anyhow::anyhow!("transfer did not contain an archive"));
                        }

                        if archive_checksum.is_some() {
                            return Err(anyhow::anyhow!(
                                "transfer did not contain an archive checksum, cannot verify integrity"
                            ));
                        }

                        backup_receiver.into_received()
                    },
                );

                let backups = handle.await??;

                drop(guard);
                Ok(backups)
            }
        });

        if is_multiplex {
            let (sender, receiver) = tokio::sync::oneshot::channel();

            {
                let mut server_transfer = server.incoming_transfer.write().await;

                let incoming_transfer = match &mut *server_transfer {
                    Some(transfer)
                        if transfer.multiplex_receivers.len() < transfer.expected_streams =>
                    {
                        transfer
                    }
                    _ => {
                        drop(server_transfer);
                        handle.abort();

                        return ApiResponse::error("unable to get incoming transfer for multiplex")
                            .with_status(StatusCode::CONFLICT)
                            .ok();
                    }
                };

                incoming_transfer
                    .multiplex_abort_handles
                    .push(handle.abort_handle());
                incoming_transfer.multiplex_receivers.push(receiver);
            }

            match handle.await {
                Ok(Ok(_)) => {
                    tracing::info!(
                        server = %server.uuid,
                        "server transfer completed successfully"
                    );

                    sender.send(Ok(())).ok();
                }
                Ok(Err(err)) => {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to complete server transfer: {:#?}",
                        err
                    );

                    sender.send(Err(err)).ok();

                    return ApiResponse::error("failed to complete server transfer")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to complete server transfer: {:#?}",
                        err
                    );

                    sender.send(Err(err.into())).ok();

                    return ApiResponse::error("failed to complete server transfer")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }
            }
        } else {
            server.incoming_transfer.write().await.replace(
                crate::server::transfer::IncomingServerTransfer {
                    main_handle: handle.abort_handle(),
                    expected_streams: multiplex_stream_count,
                    multiplex_abort_handles: vec![],
                    multiplex_receivers: vec![],
                },
            );

            let (result_tx, result_rx) = tokio::sync::oneshot::channel::<bool>();

            if multiplex_stream_count > 0 {
                tokio::spawn({
                    let server = server.clone();
                    let state = state.clone();
                    async move {
                        let mut tries = 0;

                        loop {
                            {
                                let guard = server.incoming_transfer.read().await;
                                if guard.as_ref().is_some_and(|t| {
                                    t.multiplex_receivers.len() >= multiplex_stream_count
                                }) {
                                    break;
                                }
                            }
                            tries += 1;
                            if tries > 10 {
                                tracing::error!(
                                    server = %server.uuid,
                                    "timed out waiting for multiplex streams to connect"
                                );
                                state
                                    .config
                                    .client
                                    .set_server_transfer(subject, false, &Default::default())
                                    .await
                                    .ok();

                                result_tx.send(false).ok();
                                return;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }

                        let mut incoming = match server.incoming_transfer.write().await.take() {
                            Some(t) => t,
                            None => {
                                result_tx.send(false).ok();
                                return;
                            }
                        };

                        match incoming.try_join_handles(handle).await {
                            Ok(received_backups) => {
                                tracing::info!(
                                    server = %server.uuid,
                                    "server transfer completed successfully"
                                );
                                if state
                                    .config
                                    .client
                                    .set_server_transfer(subject, true, &received_backups)
                                    .await
                                    .is_ok()
                                {
                                    server.set_transferring(false).await;
                                    server
                                        .websocket
                                        .send(
                                            crate::server::websocket::WebsocketMessage::builder(
                                                crate::server::websocket::WebsocketEvent::ServerTransferStatus,
                                            )
                                            .arg("completed")
                                            .build(),
                                        )
                                        .ok();
                                    result_tx.send(true).ok();
                                } else {
                                    state
                                        .config
                                        .client
                                        .set_server_transfer(subject, false, &Default::default())
                                        .await
                                        .ok();

                                    result_tx.send(false).ok();
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to complete server transfer: {:#?}",
                                    err
                                );
                                state
                                    .config
                                    .client
                                    .set_server_transfer(subject, false, &Default::default())
                                    .await
                                    .ok();

                                result_tx.send(false).ok();
                            }
                        }
                    }
                });
            } else {
                tokio::spawn({
                    let server = server.clone();
                    let state = state.clone();
                    async move {
                        match handle.await {
                            Ok(Ok(received_backups)) => {
                                tracing::info!(
                                    server = %server.uuid,
                                    "server transfer completed successfully"
                                );
                                if state
                                    .config
                                    .client
                                    .set_server_transfer(subject, true, &received_backups)
                                    .await
                                    .is_ok()
                                {
                                    server.set_transferring(false).await;
                                    server
                                        .websocket
                                        .send(
                                            crate::server::websocket::WebsocketMessage::builder(
                                                crate::server::websocket::WebsocketEvent::ServerTransferStatus,
                                            )
                                            .arg("completed")
                                            .build(),
                                        )
                                        .ok();
                                    result_tx.send(true).ok();
                                } else {
                                    state
                                        .config
                                        .client
                                        .set_server_transfer(subject, false, &Default::default())
                                        .await
                                        .ok();

                                    result_tx.send(false).ok();
                                }
                            }
                            Ok(Err(err)) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to complete server transfer: {:#?}",
                                    err
                                );
                                state
                                    .config
                                    .client
                                    .set_server_transfer(subject, false, &Default::default())
                                    .await
                                    .ok();

                                result_tx.send(false).ok();
                            }
                            Err(err) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to complete server transfer: {:#?}",
                                    err
                                );
                                state
                                    .config
                                    .client
                                    .set_server_transfer(subject, false, &Default::default())
                                    .await
                                    .ok();

                                result_tx.send(false).ok();
                            }
                        }
                    }
                });
            }

            if !result_rx.await.unwrap_or(false) {
                return ApiResponse::error("failed to complete server transfer")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(
            routes!(get::route).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::routes::api::auth,
            )),
        )
        .routes(routes!(post::route).layer(DefaultBodyLimit::disable()))
        .nest(
            "/capabilities",
            capabilities::router(state).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::routes::api::auth,
            )),
        )
        .nest("/query", query::router(state))
        .nest(
            "/ws",
            ws::router(state).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::routes::api::auth,
            )),
        )
        .nest("/files", files::router(state))
        .nest(
            "/{server}",
            _server_::router(state).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::routes::api::auth,
            )),
        )
        .with_state(state.clone())
}
