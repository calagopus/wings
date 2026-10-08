use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        io::{
            SafeSliceExt,
            compression::reader::AsyncCompressionReader,
            fixed_reader::AsyncFixedReader,
            read_stream::{ReadStream, read_chunk},
        },
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::virtualfs::{
            AsyncReadableFileStream, FileMetadata, ReadableFileStream,
        },
    };
    use axum::http::{HeaderMap, StatusCode};
    use axum_extra::extract::Query;
    use futures::StreamExt;
    use serde::Deserialize;
    use std::{io::Read, path::Path};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    use utoipa::ToSchema;

    const INLINE_READ_LIMIT: u64 = 4 * crate::BUFFER_SIZE as u64;
    const DETECT_HEADER_SIZE: usize = 8 * 1024;

    enum FileHead {
        Missing,
        TooLarge,
        Inline(FileMetadata, Vec<u8>),
        Stream(FileMetadata, ReadableFileStream, Vec<u8>),
        AsyncStream(FileMetadata),
    }

    enum StreamSource {
        Blocking(ReadableFileStream, Vec<u8>),
        Async(BufReader<AsyncReadableFileStream>),
    }

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
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "file not found")?;

        let parent = Path::new(&data.file)
            .parent()
            .or_api_error(StatusCode::EXPECTATION_FAILED, "file has no parent")?;

        let file_name = Path::new(&data.file)
            .file_name()
            .or_api_error(StatusCode::EXPECTATION_FAILED, "invalid file name")?;

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, parent, &ignored)
            .await;
        let path = root.join(file_name);

        let head = {
            let path = path.clone();
            let max_size = data.max_size;

            tokio::task::spawn_blocking({
                let filesystem = filesystem.clone();

                move || -> Result<FileHead, anyhow::Error> {
                    let metadata = match filesystem.reachable_metadata(&path) {
                        Ok((metadata, _)) if metadata.file_type.is_file() => metadata,
                        _ => return Ok(FileHead::Missing),
                    };

                    if max_size.is_some_and(|s| metadata.size > s) {
                        return Ok(FileHead::TooLarge);
                    }

                    if metadata.size > INLINE_READ_LIMIT && !filesystem.is_fast() {
                        return Ok(FileHead::AsyncStream(metadata));
                    }

                    let mut file_read = filesystem.read_file(&path, None)?;

                    if metadata.size > INLINE_READ_LIMIT {
                        let first = read_chunk(
                            &mut file_read.reader,
                            metadata.size.min(crate::FILE_STREAM_BUFFER_SIZE as u64) as usize,
                        )?;

                        return Ok(FileHead::Stream(metadata, file_read.reader, first));
                    }

                    let mut buffer =
                        Vec::with_capacity(file_read.size.min(INLINE_READ_LIMIT + 1) as usize);
                    (&mut file_read.reader)
                        .take(INLINE_READ_LIMIT + 1)
                        .read_to_end(&mut buffer)?;

                    if buffer.len() as u64 > INLINE_READ_LIMIT {
                        return Ok(FileHead::Stream(metadata, file_read.reader, buffer));
                    }

                    Ok(FileHead::Inline(metadata, buffer))
                }
            })
            .await
            .map_err(anyhow::Error::from)??
        };

        let (metadata, source) = match head {
            FileHead::Missing => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
            FileHead::Inline(metadata, buffer) => {
                let (compression_type, archive_type) =
                    crate::server::filesystem::archive::Archive::detect(&path, &buffer);
                if !matches!(
                    archive_type,
                    crate::server::filesystem::archive::ArchiveType::None
                ) {
                    return ApiResponse::error("file is an archive, cannot view contents")
                        .with_status(StatusCode::EXPECTATION_FAILED)
                        .ok();
                }

                let mut headers = HeaderMap::new();
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

                if matches!(
                    compression_type,
                    crate::io::compression::CompressionType::None
                ) {
                    headers.insert("Content-Length", metadata.size.into());

                    return ApiResponse::new(axum::body::Body::from(buffer))
                        .with_headers(headers)
                        .ok();
                }

                let reader = AsyncCompressionReader::new_with_async_reader(
                    std::io::Cursor::new(buffer),
                    compression_type,
                );
                let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> =
                    if let Some(max_size) = data.max_size {
                        Box::new(reader.take(max_size))
                    } else {
                        Box::new(reader)
                    };

                return ApiResponse::new_stream(reader).with_headers(headers).ok();
            }
            FileHead::TooLarge => {
                return ApiResponse::error("file size exceeds maximum allowed size")
                    .with_status(StatusCode::PAYLOAD_TOO_LARGE)
                    .ok();
            }
            FileHead::Stream(metadata, reader, first) => {
                (metadata, StreamSource::Blocking(reader, first))
            }
            FileHead::AsyncStream(metadata) => {
                let file_read = filesystem.async_read_file(&path, None).await?;
                let mut reader = BufReader::new(file_read.reader);
                reader.fill_buf().await?;

                (metadata, StreamSource::Async(reader))
            }
        };

        let header = match &source {
            StreamSource::Blocking(_, first) => {
                first.get_slice(..first.len().min(DETECT_HEADER_SIZE))?
            }
            StreamSource::Async(reader) => reader.buffer(),
        };
        let (compression_type, archive_type) =
            crate::server::filesystem::archive::Archive::detect(&path, header);
        if !matches!(
            archive_type,
            crate::server::filesystem::archive::ArchiveType::None
        ) {
            return ApiResponse::error("file is an archive, cannot view contents")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let mut headers = HeaderMap::new();

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

        let uncompressed = matches!(
            compression_type,
            crate::io::compression::CompressionType::None
        );
        if uncompressed {
            headers.insert("Content-Length", metadata.size.into());
        }

        let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> = match source {
            StreamSource::Blocking(reader, mut first) if uncompressed => {
                // the file may have grown since it was stat'ed, the body must still
                // match Content-Length
                first.truncate(metadata.size as usize);

                let remaining = metadata.size - first.len() as u64;
                let body =
                    futures::stream::once(std::future::ready(Ok(bytes::Bytes::from(first)))).chain(
                        ReadStream::new(reader, remaining, crate::FILE_STREAM_BUFFER_SIZE),
                    );

                return ApiResponse::new(axum::body::Body::from_stream(body))
                    .with_headers(headers)
                    .ok();
            }
            StreamSource::Async(reader) if uncompressed => Box::new(
                AsyncFixedReader::new_with_fixed_bytes(reader, metadata.size as usize),
            ),
            StreamSource::Blocking(reader, first) => Box::new(AsyncCompressionReader::new(
                Read::chain(std::io::Cursor::new(first), reader),
                compression_type,
            )),
            StreamSource::Async(reader) => Box::new(AsyncCompressionReader::new_with_async_reader(
                reader,
                compression_type,
            )),
        };
        let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> = match data.max_size {
            Some(max_size) if !uncompressed => Box::new(reader.take(max_size)),
            _ => reader,
        };

        ApiResponse::new_stream_with_capacity(reader, crate::FILE_STREAM_BUFFER_SIZE)
            .with_headers(headers)
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
