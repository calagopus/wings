use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        io::fixed_reader::AsyncFixedReader,
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::filesystem::{cap::FileType, virtualfs::ByteRange},
    };
    use axum::{
        extract::Query,
        http::{HeaderMap, StatusCode},
    };
    use serde::Deserialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        token: String,
    }

    #[derive(Deserialize)]
    pub struct FileJwtPayload {
        #[serde(flatten)]
        pub base: crate::remote::jwt::BasePayload,

        pub file_path: compact_str::CompactString,
        #[serde(flatten)]
        pub ignored_files: crate::routes::token::IgnoredFiles,
        pub server_uuid: uuid::Uuid,
        pub unique_id: compact_str::CompactString,
    }

    impl crate::routes::token::TokenPayload for FileJwtPayload {
        #[inline]
        fn base(&self) -> &crate::remote::jwt::BasePayload {
            &self.base
        }
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = String),
        (status = UNAUTHORIZED, body = String),
        (status = NOT_FOUND, body = String),
        (status = EXPECTATION_FAILED, body = String),
    ), params(
        (
            "token" = String, Query,
            description = "The JWT token to use for authentication",
        ),
    ))]
    pub async fn route(
        state: GetState,
        headers: HeaderMap,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        let payload: FileJwtPayload =
            crate::routes::token::verify(&state, &data.token, "file-download")?;

        crate::routes::token::consume(&state, &payload.unique_id)?;

        let server = crate::routes::token::server(&state, payload.server_uuid).await?;

        let parent = match Path::new(&payload.file_path).parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("file has no parent")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let file_name = match Path::new(&payload.file_path).file_name() {
            Some(name) => name,
            None => {
                return ApiResponse::error("invalid file name")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
        };

        let (root, filesystem) = server.filesystem.resolve_readable_fs(&server, parent).await;
        let path = root.join(file_name);

        let metadata = match filesystem.async_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type.is_file() {
                    return ApiResponse::error("file not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                } else {
                    metadata
                }
            }
            Err(_) => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let ignored = match payload.ignored_files.compile() {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "failed to compile subuser ignored files, denying download: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        if filesystem.is_primary_server_fs()
            && ignored
                .as_ref()
                .is_some_and(|o| o.is_ignored(&path, FileType::File))
        {
            return ApiResponse::error("file not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let file_read = match filesystem
            .async_read_file(&path, ByteRange::from_headers(&headers))
            .await
        {
            Ok(file) => file,
            Err(_) => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let mut headers = file_read.headers();
        headers.insert(
            "Content-Disposition",
            format!(
                "attachment; filename={}",
                serde_json::Value::String(file_name.to_string_lossy().to_string())
            )
            .parse()?,
        );
        headers.insert("Content-Type", "application/octet-stream".parse()?);

        if let Some(modified) = &metadata.modified {
            let modified = chrono::DateTime::from_timestamp(
                modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                0,
            )
            .unwrap_or_default();

            headers.insert("Last-Modified", modified.to_rfc2822().parse()?);
        }

        let reader =
            AsyncFixedReader::new_with_fixed_bytes(file_read.reader, file_read.size as usize);

        if file_read.reader_range.is_some() {
            ApiResponse::new_stream_with_capacity(reader, crate::FILE_STREAM_BUFFER_SIZE)
                .with_headers(headers)
                .with_status(StatusCode::PARTIAL_CONTENT)
                .ok()
        } else {
            ApiResponse::new_stream_with_capacity(reader, crate::FILE_STREAM_BUFFER_SIZE)
                .with_headers(headers)
                .ok()
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
