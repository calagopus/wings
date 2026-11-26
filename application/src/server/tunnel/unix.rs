use crate::{
    response::ApiResponse,
    routes::api::servers::_server_::GetServer,
    server::filesystem::cap::{CapFilesystem, FileType},
};
use axum::{
    extract::WebSocketUpgrade,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::Query;
use serde::Deserialize;
use std::{io::ErrorKind, path::Path};

#[derive(Deserialize)]
pub struct Params {
    path: compact_str::CompactString,

    #[serde(default)]
    ignored: Vec<compact_str::CompactString>,
}

pub async fn handle_ws(
    ws: WebSocketUpgrade,
    server: GetServer,
    Query(params): Query<Params>,
) -> Response {
    let not_found = || ApiResponse::error("socket not found").with_status(StatusCode::NOT_FOUND);

    let ignored = match crate::routes::token::ignored(&server, &params.ignored, "socket not found")
    {
        Ok(ignored) => ignored,
        Err(response) => return response.into_response(),
    };

    let path = Path::new(&params.path);
    if ignored.is_ignored(&server, path, FileType::File).await {
        return not_found().into_response();
    }

    let mount_path = server.filesystem.get_base_fs_mount_path().await;
    let connected = if mount_path == server.filesystem.base_path {
        server.filesystem.async_connect_unix(path).await
    } else {
        match CapFilesystem::new(&mount_path).await {
            Ok(filesystem) => filesystem.async_connect_unix(path).await,
            Err(err) => Err(err),
        }
    };

    let stream = match connected {
        Ok((stream, opened_path)) => {
            if ignored
                .is_ignored(&server, &opened_path, FileType::File)
                .await
            {
                return not_found().into_response();
            }

            stream
        }
        Err(err) => {
            let response = match err.kind() {
                ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::PermissionDenied => {
                    not_found()
                }
                ErrorKind::InvalidInput => ApiResponse::error("file is not a socket")
                    .with_status(StatusCode::EXPECTATION_FAILED),
                ErrorKind::ConnectionRefused => {
                    ApiResponse::error("socket is not accepting connections")
                        .with_status(StatusCode::CONFLICT)
                }
                _ if err.raw_os_error() == Some(rustix::io::Errno::PROTOTYPE.raw_os_error()) => {
                    ApiResponse::error("only stream sockets are supported")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                }
                _ => {
                    tracing::error!(server = %server.uuid, "failed to connect to unix socket: {:?}", err);

                    ApiResponse::error("failed to connect to socket")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                }
            };

            return response.into_response();
        }
    };

    ws.max_message_size(super::stream::MAX_MESSAGE_SIZE)
        .max_frame_size(super::stream::MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| {
            let (read, write) = stream.into_split();
            super::stream::pipe(socket, read, write)
        })
}
