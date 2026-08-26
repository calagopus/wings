use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        io::fixed_reader::AsyncFixedReader,
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::filesystem::virtualfs::ByteRange,
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
        #[serde(default)]
        pub ignored_files: Vec<compact_str::CompactString>,
        pub server_uuid: uuid::Uuid,
        pub unique_id: compact_str::CompactString,
    }

    impl FileJwtPayload {
        fn ignored(&self) -> Result<Option<ignore::gitignore::Gitignore>, ignore::Error> {
            if self.ignored_files.is_empty() {
                return Ok(None);
            }

            crate::server::filesystem::build_gitignore_matcher(self.ignored_files.iter()).map(Some)
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
        let payload: FileJwtPayload = match state.config.jwt.verify(&data.token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload
            .base
            .validate(&state.config.jwt, Some("file-download"))
        {
            return ApiResponse::error(&format!("invalid token: {err}"))
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        if !state.config.jwt.limited_jwt_id(&payload.unique_id) {
            return ApiResponse::error("token has already been used")
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let server = match state.server_manager.get_server(payload.server_uuid).await {
            Some(server) => server,
            None => {
                return ApiResponse::error("server not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

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

        let ignored = match payload.ignored() {
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
                .is_some_and(|o| o.matched(&path, false).is_ignore())
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
            ApiResponse::new_stream(reader)
                .with_headers(headers)
                .with_status(StatusCode::PARTIAL_CONTENT)
                .ok()
        } else {
            ApiResponse::new_stream(reader).with_headers(headers).ok()
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
