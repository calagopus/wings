use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        io::{compression::reader::AsyncCompressionReader, fixed_reader::AsyncFixedReader},
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::{HeaderMap, StatusCode};
    use axum_extra::extract::Query;
    use serde::Deserialize;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        file: compact_str::CompactString,

        #[schema(default = "false")]
        #[serde(default)]
        download: bool,
        max_size: Option<u64>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = String),
        (status = NOT_FOUND, body = ApiError),
        (status = PAYLOAD_TOO_LARGE, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "file" = String, Query,
            description = "The file to view contents of",
        ),
        (
            "download" = bool, Query,
            description = "Whether to add 'download headers' to the file",
        ),
        (
            "max_size" = Option<u64>, Query,
            description = "The maximum size of the file to return. If the file is larger than this, an error will be returned.",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
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

        let metadata = match filesystem.async_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }

                metadata
            }
            Err(_) => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        if data.max_size.is_some_and(|s| metadata.size > s) {
            return ApiResponse::error("file size exceeds maximum allowed size")
                .with_status(StatusCode::PAYLOAD_TOO_LARGE)
                .ok();
        }

        let file_read = filesystem.async_read_file(&path, None).await?;
        let mut reader = BufReader::new(file_read.reader);

        let header = reader.fill_buf().await?;
        let (compression_type, archive_type) =
            crate::server::filesystem::archive::Archive::detect(path, header);
        if !matches!(
            archive_type,
            crate::server::filesystem::archive::ArchiveType::None
        ) {
            return ApiResponse::error("file is an archive, cannot view contents")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let reader = AsyncCompressionReader::new(
            tokio_util::io::SyncIoBridge::new(reader),
            compression_type,
        );

        let mut headers = HeaderMap::new();

        if matches!(
            compression_type,
            crate::io::compression::CompressionType::None
        ) {
            headers.insert("Content-Length", metadata.size.into());
        }

        if data.download {
            headers.insert(
                "Content-Disposition",
                format!(
                    "attachment; filename={}",
                    serde_json::Value::String(file_name.to_string_lossy().to_string())
                )
                .parse()?,
            );
            headers.insert("Content-Type", "application/octet-stream".parse()?);
        }

        let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if matches!(
            compression_type,
            crate::io::compression::CompressionType::None
        ) {
            Box::new(AsyncFixedReader::new_with_fixed_bytes(
                reader,
                metadata.size as usize,
            ))
        } else if let Some(max_size) = data.max_size {
            Box::new(reader.take(max_size))
        } else {
            Box::new(reader)
        };

        ApiResponse::new_stream(reader).with_headers(headers).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
