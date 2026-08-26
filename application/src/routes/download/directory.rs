use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::filesystem::archive::StreamableArchiveFormat,
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

        #[serde(default)]
        archive_format: StreamableArchiveFormat,
    }

    #[derive(Deserialize)]
    pub struct FolderJwtPayload {
        #[serde(flatten)]
        pub base: crate::remote::jwt::BasePayload,

        pub file_path: compact_str::CompactString,
        #[serde(default)]
        pub ignored_files: Vec<compact_str::CompactString>,
        pub server_uuid: uuid::Uuid,
        pub unique_id: compact_str::CompactString,
    }

    impl FolderJwtPayload {
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
    pub async fn route(state: GetState, Query(data): Query<Params>) -> ApiResponseResult {
        let payload: FolderJwtPayload = match state.config.jwt.verify(&data.token) {
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

        let (path, filesystem) = server
            .filesystem
            .resolve_readable_fs(&server, Path::new(&payload.file_path))
            .await;

        let file_name = match path.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => {
                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let mut folder_ascii = String::new();
        folder_ascii.reserve_exact(file_name.len() + 8);

        for c in file_name.chars() {
            if c.is_ascii() {
                folder_ascii.push(c);
            } else {
                folder_ascii.push('_');
            }
        }

        folder_ascii.push('.');
        folder_ascii.push_str(data.archive_format.extension());

        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            format!(
                "attachment; filename={}",
                serde_json::Value::String(folder_ascii)
            )
            .parse()?,
        );
        headers.insert("Content-Type", data.archive_format.mime_type().parse()?);

        let metadata = filesystem.async_symlink_metadata(&path).await;
        if let Ok(metadata) = metadata {
            if !metadata.file_type.is_dir() {
                return ApiResponse::error("directory not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        } else {
            return ApiResponse::error("directory not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let mut ignore = crate::server::filesystem::virtualfs::IsIgnoredFn::default();
        if filesystem.is_primary_server_fs() {
            ignore = server.filesystem.get_ignored().into();

            match payload.ignored() {
                Ok(Some(ignored)) => ignore = ignore.merge(ignored.into()),
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to compile subuser ignored files, denying download: {:#?}",
                        err
                    );

                    return ApiResponse::error("directory not found")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }
            }
        }

        let reader = filesystem
            .async_read_dir_archive(
                &path,
                data.archive_format,
                state.config.load().system.backups.compression_level,
                crate::server::filesystem::archive::create::ArchiveProgress::default(),
                ignore,
            )
            .await?;

        ApiResponse::new_stream(reader).with_headers(headers).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
