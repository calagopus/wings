use super::ServerHandle;
use crate::{
    io::{SafeDigestExt, SafeSliceExt, SafeWriteExt},
    server::{
        activity::{Activity, ActivityEvent},
        filesystem::{RenameParents, cap::FileType},
        permissions::Permission,
    },
    utils::PortablePermissions,
};
use russh_sftp::protocol::{Status, StatusCode};
use serde::{Deserialize, Serialize};
use sha1::Digest;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::bytes::BufMut;

fn map_ser_err(err: impl Into<russh_sftp::client::error::Error>) -> StatusCode {
    let err = err.into();
    tracing::error!("russh serialization error: {}", err);

    StatusCode::Failure
}

pub async fn handle_extended(
    sftp_session: &mut super::SftpSession,
    id: u32,
    command: String,
    data: Vec<u8>,
) -> Result<russh_sftp::protocol::Packet, StatusCode> {
    if !sftp_session.allow_action() {
        return Err(StatusCode::PermissionDenied);
    }

    tracing::debug!("sftp extended command: {}", command);

    match command.as_str() {
        "check-file" | "check-file-name" => {
            if !sftp_session.has_permission(Permission::FileReadContent) {
                return Err(StatusCode::PermissionDenied);
            }

            #[derive(Deserialize)]
            struct CheckFileName {
                file_name: String,
                hash: String,

                start_offset: u64,
                length: u64,
            }

            let request: CheckFileName = match russh_sftp::de::from_bytes(&mut data.into()) {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            let file_name = if command == "check-file-name" {
                request.file_name
            } else {
                match sftp_session.handles.get(request.file_name.as_str()) {
                    Some(ServerHandle::File(handle)) => handle.path.to_string_lossy().to_string(),
                    _ => return Err(StatusCode::NoSuchFile),
                }
            };

            let path = match sftp_session
                .server
                .filesystem
                .async_canonicalize(&file_name)
                .await
            {
                Ok(path) => path,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };

            if let Ok(metadata) = sftp_session
                .server
                .filesystem
                .async_symlink_metadata(&path)
                .await
            {
                if !metadata.is_file() {
                    return Err(StatusCode::NoSuchFile);
                }

                if sftp_session
                    .async_is_ignored(&path, metadata.file_type().into())
                    .await
                {
                    return Err(StatusCode::NoSuchFile);
                }

                let mut file = match sftp_session.server.filesystem.async_open(&path).await {
                    Ok(file) => file,
                    Err(_) => return Err(StatusCode::NoSuchFile),
                };

                if request.start_offset != 0 {
                    file.seek(SeekFrom::Start(request.start_offset))
                        .await
                        .map_err(|_| StatusCode::Failure)?;
                }
                let mut total_bytes_read = 0;
                let hash_algorithm = request.hash.split(',').next().unwrap_or("");

                #[inline]
                fn bytes(length: u64, bytes_read: usize, total_bytes_read: u64) -> usize {
                    if length > 0 {
                        if total_bytes_read > length {
                            (length
                                .saturating_sub(total_bytes_read.saturating_sub(bytes_read as u64)))
                                as usize
                        } else {
                            bytes_read
                        }
                    } else {
                        bytes_read
                    }
                }

                let mut run_hash = async || -> Result<Vec<u8>, std::io::Error> {
                    let mut buffer = vec![0; crate::BUFFER_SIZE];

                    Ok(match hash_algorithm {
                        "md5" => {
                            let mut hasher = md5::Context::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.safe_write_all(&buffer, take)?;

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            (*hasher.finalize()).into()
                        }
                        "crc32" => {
                            let mut hasher = crc32fast::Hasher::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.update(buffer.get_slice(..take)?);

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            hasher.finalize().to_be_bytes().to_vec()
                        }
                        "sha1" => {
                            let mut hasher = sha1::Sha1::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.safe_update(&buffer, take)?;

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            (*hasher.finalize()).into()
                        }
                        "sha224" => {
                            let mut hasher = sha2::Sha224::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.safe_update(&buffer, take)?;

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            (*hasher.finalize()).into()
                        }
                        "sha256" => {
                            let mut hasher = sha2::Sha256::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.safe_update(&buffer, take)?;

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            (*hasher.finalize()).into()
                        }
                        "sha384" => {
                            let mut hasher = sha2::Sha384::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.safe_update(&buffer, take)?;

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            (*hasher.finalize()).into()
                        }
                        "sha512" => {
                            let mut hasher = sha2::Sha512::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                total_bytes_read += bytes_read as u64;

                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                let take = bytes(request.length, bytes_read, total_bytes_read);
                                hasher.safe_update(&buffer, take)?;

                                if crate::unlikely(
                                    request.length != 0 && total_bytes_read >= request.length,
                                ) {
                                    break;
                                }
                            }

                            (*hasher.finalize()).into()
                        }
                        _ => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "unsupported hash algorithm",
                            ));
                        }
                    })
                };

                let hash = match run_hash().await {
                    Ok(hash) => hash,
                    Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                        return Err(StatusCode::BadMessage);
                    }
                    Err(err) => {
                        tracing::error!(
                            "failed to compute hash for file {}: {}",
                            path.display(),
                            err
                        );
                        return Err(StatusCode::Failure);
                    }
                };

                #[derive(Serialize)]
                struct CheckFileNameReply<'a> {
                    hash_algorithm: &'a str,

                    #[serde(serialize_with = "russh_sftp::ser::data_serialize")]
                    hash: Vec<u8>,
                }

                Ok(russh_sftp::protocol::Packet::ExtendedReply(
                    russh_sftp::protocol::ExtendedReply {
                        id,
                        data: russh_sftp::ser::to_bytes(&CheckFileNameReply {
                            hash_algorithm,
                            hash,
                        })
                        .map_err(map_ser_err)?
                        .into(),
                    },
                ))
            } else {
                Err(StatusCode::OpUnsupported)
            }
        }
        "copy-file" => {
            if sftp_session.state.config.load().system.sftp.read_only {
                return Err(StatusCode::PermissionDenied);
            }

            if !sftp_session.has_permission(Permission::FileReadContent)
                || !sftp_session.has_permission(Permission::FileCreate)
            {
                return Err(StatusCode::PermissionDenied);
            }

            #[derive(Deserialize)]
            struct CopyFileRequest {
                source: String,
                destination: String,
                overwrite: u8,
            }

            let request: CopyFileRequest = match russh_sftp::de::from_bytes(&mut data.into()) {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            let source_path = match sftp_session
                .server
                .filesystem
                .async_canonicalize(&request.source)
                .await
            {
                Ok(path) => path,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };

            let metadata = match sftp_session
                .server
                .filesystem
                .async_symlink_metadata(&source_path)
                .await
            {
                Ok(metadata) => metadata,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };

            if !metadata.is_file() {
                return Err(StatusCode::NoSuchFile);
            }

            if sftp_session
                .async_is_ignored(&source_path, FileType::File)
                .await
            {
                return Err(StatusCode::NoSuchFile);
            }

            let destination_path = Path::new(&request.destination);

            if sftp_session
                .async_is_ignored(destination_path, FileType::File)
                .await
            {
                return Err(StatusCode::NoSuchFile);
            }

            if let Ok(metadata) = sftp_session
                .server
                .filesystem
                .async_symlink_metadata(destination_path)
                .await
            {
                if metadata.is_dir() {
                    return Err(StatusCode::NoSuchFile);
                }
                if request.overwrite == 0 {
                    return Err(StatusCode::Failure);
                }
            }

            sftp_session
                .server
                .filesystem
                .async_quota_copy(&source_path, &destination_path, &sftp_session.server, None)
                .await
                .map_err(|_| StatusCode::NoSuchFile)?;

            sftp_session.server.activity.log_activity(Activity {
                event: ActivityEvent::SftpCreate,
                user: Some(sftp_session.user_uuid),
                ip: Some(sftp_session.user_ip),
                metadata: Some(serde_json::json!({
                    "files": [sftp_session.server.filesystem.relative_path(destination_path)],
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });

            Ok(russh_sftp::protocol::Packet::Status(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            }))
        }
        "space-available" => {
            #[derive(Serialize)]
            struct SpaceAvailableReply {
                total_space: u64,
                available_space: u64,

                total_user_space: u64,
                available_user_space: u64,
            }

            let (total_space, available_space) = match sftp_session.server.filesystem.disk_limit() {
                0 => {
                    let disks = sysinfo::Disks::new();

                    let mut path = sftp_session.server.filesystem.base_path.clone();
                    let disk;
                    loop {
                        if let Some(d) = disks.iter().find(|d| d.mount_point() == path) {
                            disk = d;
                            break;
                        }

                        if !path.pop() {
                            disk = match disks.first() {
                                Some(d) => d,
                                None => return Err(StatusCode::Failure),
                            };
                            break;
                        }
                    }

                    let total_space = disk.total_space();
                    let free_space = disk.available_space();

                    (total_space, free_space)
                }
                total => (
                    total as u64,
                    (total as u64)
                        .saturating_sub(sftp_session.server.filesystem.limiter_usage().await),
                ),
            };

            Ok(russh_sftp::protocol::Packet::ExtendedReply(
                russh_sftp::protocol::ExtendedReply {
                    id,
                    data: russh_sftp::ser::to_bytes(&SpaceAvailableReply {
                        total_space,
                        available_space,

                        total_user_space: total_space,
                        available_user_space: available_space,
                    })
                    .map_err(map_ser_err)?
                    .into(),
                },
            ))
        }
        "limits@openssh.com" => {
            #[derive(Serialize)]
            struct LimitsReply {
                max_packet_length: u64,
                max_read_length: u64,
                max_write_length: u64,
                max_handle_count: u64,
            }

            Ok(russh_sftp::protocol::Packet::ExtendedReply(
                russh_sftp::protocol::ExtendedReply {
                    id,
                    data: russh_sftp::ser::to_bytes(&LimitsReply {
                        max_packet_length: 32 * 1024,
                        max_read_length: 128 * 1024,
                        max_write_length: 128 * 1024,
                        max_handle_count: sftp_session
                            .state
                            .config
                            .load()
                            .system
                            .sftp
                            .limits
                            .max_handles_per_channel
                            as u64,
                    })
                    .map_err(map_ser_err)?
                    .into(),
                },
            ))
        }
        "fstatvfs@openssh.com" | "statvfs@openssh.com" => {
            #[derive(Serialize)]
            struct StatVfsReply {
                block_size: u64,
                fragment_size: u64,
                total_blocks: u64,
                free_blocks: u64,
                available_blocks: u64,
                total_file_nodes: u64,
                free_file_nodes: u64,
                available_file_nodes: u64,
                filesystem_id: u64,
                mount_flags: u64,
                max_filename_length: u64,
            }

            let (total_space, free_space) = match sftp_session.server.filesystem.disk_limit() {
                0 => {
                    let disks = sysinfo::Disks::new();

                    let mut path = sftp_session.server.filesystem.base_path.clone();
                    let disk;
                    loop {
                        if let Some(d) = disks.iter().find(|d| d.mount_point() == path) {
                            disk = d;
                            break;
                        }

                        if !path.pop() {
                            disk = match disks.first() {
                                Some(d) => d,
                                None => return Err(StatusCode::Failure),
                            };
                            break;
                        }
                    }

                    let total_space = disk.total_space();
                    let free_space = disk.available_space();

                    (total_space, free_space)
                }
                total => (
                    total as u64,
                    (total as u64)
                        .saturating_sub(sftp_session.server.filesystem.limiter_usage().await),
                ),
            };

            Ok(russh_sftp::protocol::Packet::ExtendedReply(
                russh_sftp::protocol::ExtendedReply {
                    id,
                    data: russh_sftp::ser::to_bytes(&StatVfsReply {
                        block_size: 4096,
                        fragment_size: 4096,
                        total_blocks: total_space / 4096,
                        free_blocks: free_space / 4096,
                        available_blocks: free_space / 4096,
                        total_file_nodes: 0,
                        free_file_nodes: 0,
                        available_file_nodes: 0,
                        filesystem_id: 0,
                        mount_flags: sftp_session.state.config.load().system.sftp.read_only as u64,
                        max_filename_length: 255,
                    })
                    .map_err(map_ser_err)?
                    .into(),
                },
            ))
        }
        "hardlink@openssh.com" => {
            #[derive(Deserialize)]
            struct HardlinkRequest {
                target: String,
                link_name: String,
            }

            let request: HardlinkRequest = match russh_sftp::de::from_bytes(&mut data.into()) {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            if sftp_session.state.config.load().system.sftp.read_only {
                return Err(StatusCode::PermissionDenied);
            }

            if !sftp_session.has_permission(Permission::FileCreate) {
                return Err(StatusCode::PermissionDenied);
            }

            let linkpath = PathBuf::from(request.link_name);
            let targetpath = PathBuf::from(request.target);

            if linkpath == targetpath {
                return Err(StatusCode::NoSuchFile);
            }

            let targetpath = match sftp_session
                .server
                .filesystem
                .async_canonicalize(&targetpath)
                .await
            {
                Ok(path) => path,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };

            let metadata = match sftp_session
                .server
                .filesystem
                .async_symlink_metadata(&targetpath)
                .await
            {
                Ok(metadata) => metadata,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };

            if !metadata.is_file()
                || sftp_session
                    .async_is_ignored(&targetpath, metadata.file_type().into())
                    .await
                || sftp_session
                    .async_is_ignored(&linkpath, FileType::File)
                    .await
            {
                return Err(StatusCode::NoSuchFile);
            }

            if sftp_session
                .server
                .filesystem
                .async_hard_link(&targetpath, &sftp_session.server.filesystem, &linkpath)
                .await
                .is_err()
            {
                return Err(StatusCode::Failure);
            }

            sftp_session.server.activity.log_activity(Activity {
                event: ActivityEvent::SftpCreate,
                user: Some(sftp_session.user_uuid),
                ip: Some(sftp_session.user_ip),
                metadata: Some(serde_json::json!({
                    "files": [sftp_session.server.filesystem.relative_path(&linkpath)],
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });

            Ok(russh_sftp::protocol::Packet::Status(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            }))
        }
        "fsync@openssh.com" => {
            #[derive(Deserialize)]
            struct FsyncRequest {
                handle: String,
            }

            let request: FsyncRequest = match russh_sftp::de::from_bytes(&mut data.into()) {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            if sftp_session.state.config.load().system.sftp.read_only {
                return Err(StatusCode::PermissionDenied);
            }

            if !sftp_session.has_permission(Permission::FileUpdate) {
                return Err(StatusCode::PermissionDenied);
            }

            let handle = match sftp_session.handles.get_mut(request.handle.as_str()) {
                Some(ServerHandle::File(handle)) => handle,
                _ => return Err(StatusCode::NoSuchFile),
            };

            tokio::task::spawn_blocking({
                let file = Arc::clone(&handle.file);

                move || file.lock().sync_all()
            })
            .await
            .map_err(|_| StatusCode::Failure)?
            .map_err(|_| StatusCode::Failure)?;

            Ok(russh_sftp::protocol::Packet::Status(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            }))
        }
        "lsetstat@openssh.com" => {
            #[derive(Deserialize)]
            struct LsetStatRequest {
                handle: String,
                attrs: russh_sftp::protocol::FileAttributes,
            }

            let request: LsetStatRequest = match russh_sftp::de::from_bytes(&mut data.into()) {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            if sftp_session.state.config.load().system.sftp.read_only {
                return Err(StatusCode::PermissionDenied);
            }

            if !sftp_session.has_permission(Permission::FileUpdate) {
                return Err(StatusCode::PermissionDenied);
            }

            let handle = match sftp_session.handles.get_mut(request.handle.as_str()) {
                Some(ServerHandle::File(handle)) => handle,
                _ => return Err(StatusCode::NoSuchFile),
            };

            if let Some(permissions) = request.attrs.permissions {
                sftp_session
                    .server
                    .filesystem
                    .async_set_symlink_permissions(
                        &handle.path,
                        PortablePermissions::from_mode_file(permissions),
                    )
                    .await
                    .map_err(|_| StatusCode::Failure)?;
            }

            Ok(russh_sftp::protocol::Packet::Status(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            }))
        }
        "users-groups-by-id@openssh.com" => {
            #[derive(Deserialize)]
            struct UsersGroupsByIdRequest {
                users: Vec<u8>,
                groups: Vec<u8>,
            }

            #[derive(Serialize)]
            struct UsersGroupsByIdReply {
                users: Vec<u8>,
                groups: Vec<u8>,
            }

            let request: UsersGroupsByIdRequest = match russh_sftp::de::from_bytes(&mut data.into())
            {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            if !sftp_session.has_permission(Permission::FileRead) {
                return Err(StatusCode::PermissionDenied);
            }

            let mut users = tokio_util::bytes::BytesMut::new();
            for uid in request.users.chunks(4) {
                let uid = match uid.try_into() {
                    Ok(bytes) => u32::from_be_bytes(bytes),
                    Err(_) => continue,
                };

                if uid == 0 {
                    let config = sftp_session.state.config.load();
                    let username = &config.system.username;

                    users.put_u32(username.len() as u32);
                    users.extend(username.as_bytes());
                } else {
                    users.put_u32(0);
                }
            }

            let mut groups = tokio_util::bytes::BytesMut::new();
            for gid in request.groups.chunks(4) {
                let gid = match gid.try_into() {
                    Ok(bytes) => u32::from_be_bytes(bytes),
                    Err(_) => continue,
                };

                if gid == 0 {
                    let config = sftp_session.state.config.load();
                    let username = &config.system.username;

                    groups.put_u32(username.len() as u32);
                    groups.extend(username.as_bytes());
                } else {
                    groups.put_u32(0);
                }
            }

            Ok(russh_sftp::protocol::Packet::ExtendedReply(
                russh_sftp::protocol::ExtendedReply {
                    id,
                    data: russh_sftp::ser::to_bytes(&UsersGroupsByIdReply {
                        users: users.into(),
                        groups: groups.into(),
                    })
                    .map_err(map_ser_err)?
                    .into(),
                },
            ))
        }
        "posix-rename@openssh.com" => {
            #[derive(Deserialize)]
            struct PosixRenameRequest {
                oldpath: String,
                newpath: String,
            }

            let request: PosixRenameRequest = match russh_sftp::de::from_bytes(&mut data.into()) {
                Ok(request) => request,
                Err(_) => return Err(StatusCode::BadMessage),
            };

            if sftp_session.state.config.load().system.sftp.read_only {
                return Err(StatusCode::PermissionDenied);
            }

            if !sftp_session.has_permission(Permission::FileUpdate) {
                return Err(StatusCode::PermissionDenied);
            }

            let old_path = match sftp_session
                .server
                .filesystem
                .async_canonicalize(&request.oldpath)
                .await
            {
                Ok(path) => path,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };
            let new_path = PathBuf::from(request.newpath);

            let old_metadata = match sftp_session
                .server
                .filesystem
                .async_symlink_metadata(&old_path)
                .await
            {
                Ok(metadata) => metadata,
                Err(_) => return Err(StatusCode::NoSuchFile),
            };

            if sftp_session
                .async_is_ignored(&old_path, old_metadata.file_type().into())
                .await
                || sftp_session
                    .async_is_ignored(&new_path, old_metadata.file_type().into())
                    .await
            {
                return Err(StatusCode::Failure);
            }

            let activity = Activity {
                event: ActivityEvent::SftpRename,
                user: Some(sftp_session.user_uuid),
                ip: Some(sftp_session.user_ip),
                metadata: Some(serde_json::json!({
                    "files": [
                        {
                            "from": sftp_session.server.filesystem.relative_path(&old_path),
                            "to": sftp_session.server.filesystem.relative_path(&new_path),
                        }
                    ],
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            };

            if sftp_session
                .server
                .filesystem
                .rename_path(
                    &old_path,
                    &new_path,
                    if sftp_session.has_permission(Permission::FileCreate) {
                        RenameParents::Create
                    } else {
                        RenameParents::Require
                    },
                )
                .await
                .is_err()
            {
                return Err(StatusCode::NoSuchFile);
            }

            let new_path = sftp_session.server.filesystem.diff_key(&new_path).await;
            let new_key = new_path.to_string_lossy().to_string();
            let replaced = match sftp_session
                .server
                .diff
                .rename_file(&old_path.to_string_lossy(), &new_key)
                .await
            {
                Ok(replaced) => replaced,
                Err(err) => {
                    tracing::error!("failed to rename file in diff storage: {:?}", err);
                    None
                }
            };

            if let Some(before) = replaced {
                let file_size_cap = sftp_session
                    .state
                    .config
                    .load()
                    .system
                    .file_history
                    .file_size_cap;

                match sftp_session
                    .server
                    .filesystem
                    .async_read_to_vec(&new_path, file_size_cap.saturating_add(1) as usize)
                    .await
                {
                    Ok(after) if after.len() as u64 <= file_size_cap => {
                        if let Err(err) = sftp_session
                            .server
                            .diff
                            .record_edit(&new_key, before, after, Some(sftp_session.user_uuid))
                            .await
                        {
                            tracing::warn!(
                                server = %sftp_session.server.uuid,
                                path = %new_key,
                                "diff: sftp record_edit on replace failed: {err:#}"
                            );
                        }
                    }
                    Ok(_) => {
                        tracing::debug!(
                            server = %sftp_session.server.uuid,
                            path = %new_key,
                            "diff: sftp replace content exceeds file_size_cap; not recorded"
                        );
                    }
                    Err(err) => {
                        tracing::debug!(
                            server = %sftp_session.server.uuid,
                            path = %new_key,
                            "diff: sftp failed to read replaced content: {err}"
                        );
                    }
                }
            }

            sftp_session.server.activity.log_activity(activity);

            Ok(russh_sftp::protocol::Packet::Status(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            }))
        }
        _ => Err(StatusCode::OpUnsupported),
    }
}
