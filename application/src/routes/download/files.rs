use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::filesystem::archive::{StreamableArchiveFormat, generated_archive_name},
    };
    use axum::{
        extract::Query,
        http::{HeaderMap, StatusCode},
    };
    use serde::Deserialize;
    use std::path::{Path, PathBuf};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        token: String,

        #[serde(default)]
        archive_format: StreamableArchiveFormat,
    }

    #[derive(Deserialize)]
    pub struct FilesJwtPayload {
        #[serde(flatten)]
        pub base: crate::remote::jwt::BasePayload,

        pub file_path: compact_str::CompactString,
        pub file_paths: Vec<compact_str::CompactString>,
        #[serde(flatten)]
        pub ignored_files: crate::routes::token::IgnoredFiles,
        pub server_uuid: uuid::Uuid,
        pub unique_id: compact_str::CompactString,
    }

    impl crate::routes::token::TokenPayload for FilesJwtPayload {
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
    pub async fn route(state: GetState, Query(data): Query<Params>) -> ApiResponseResult {
        let payload: FilesJwtPayload =
            crate::routes::token::verify(&state, &data.token, "file-download")?;

        crate::routes::token::consume(&state, &payload.unique_id)?;

        let server = crate::routes::token::server(&state, payload.server_uuid).await?;

        let (path, filesystem) = server
            .filesystem
            .resolve_readable_fs(&server, Path::new(&payload.file_path))
            .await;

        let archive_name = generated_archive_name(data.archive_format.extension());

        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            format!(
                "attachment; filename={}",
                serde_json::Value::String(archive_name.into_string())
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

            match payload.ignored_files.compile() {
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
            .async_read_dir_files_archive(
                &path,
                payload.file_paths.into_iter().map(PathBuf::from).collect(),
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
