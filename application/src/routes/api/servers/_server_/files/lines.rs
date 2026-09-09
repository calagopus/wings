use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        io::{
            compression::reader::AsyncCompressionReader,
            tail::{ReadLinesError, async_read_lines},
        },
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use axum_extra::extract::Query;
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use utoipa::ToSchema;

    const MAX_LINES: u64 = 10_000;
    const MAX_CONTENT_BYTES: usize = 1024 * 1024;
    const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        file: compact_str::CompactString,
        start_line: u64,
        end_line: u64,
        max_size: Option<u64>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        start_line: Option<u64>,
        end_line: Option<u64>,
        content: String,
        eof: bool,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
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
            description = "The file to read lines from",
        ),
        (
            "start_line" = u64, Query,
            description = "First line, one-based and inclusive",
        ),
        (
            "end_line" = u64, Query,
            description = "Last line, inclusive. At most 10000 lines, 1 MiB returned and 64 MiB scanned after decompression",
        ),
        (
            "max_size" = Option<u64>, Query,
            description = "Maximum bytes of selected line content after decompression, capped at 1 MiB; excludes skipped lines",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
        if data.start_line == 0 || data.end_line < data.start_line {
            return ApiResponse::error("invalid line range")
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }
        if data.end_line - data.start_line >= MAX_LINES {
            return ApiResponse::error("line range exceeds maximum allowed lines")
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

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

        match filesystem.async_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            }
            Err(_) => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

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

        let reader = AsyncCompressionReader::new_with_async_reader(reader, compression_type);

        match async_read_lines(
            reader,
            data.start_line,
            data.end_line,
            MAX_SCAN_BYTES,
            data.max_size.map_or(MAX_CONTENT_BYTES, |max_size| {
                max_size.min(MAX_CONTENT_BYTES as u64) as usize
            }),
        )
        .await
        {
            Ok(lines) => ApiResponse::new_serialized(Response {
                start_line: lines.start_line,
                end_line: lines.end_line,
                content: lines.content,
                eof: lines.eof,
            })
            .ok(),
            Err(ReadLinesError::Limit) => {
                ApiResponse::error("line read exceeds maximum scan or content size")
                    .with_status(StatusCode::PAYLOAD_TOO_LARGE)
                    .ok()
            }
            Err(ReadLinesError::InvalidUtf8) => {
                ApiResponse::error("selected lines are not valid UTF-8")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok()
            }
            Err(ReadLinesError::Io(err)) => Err(err.into()),
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
