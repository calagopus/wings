use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        root: compact_str::CompactString,

        files: Vec<compact_str::CompactString>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        deleted: usize,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "file not found")?;

        let mut deleted_count = 0;
        let mut failed_count = 0;
        for file in data.files {
            let (source, filesystem) = server
                .filesystem
                .resolve_writable_fs_ignoring(&server, Path::new(&data.root).join(&file), &ignored)
                .await;
            if source.as_os_str().is_empty() || source == Path::new(&data.root) {
                continue;
            }

            let metadata = match filesystem.async_symlink_metadata(&source).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            let result = if filesystem.is_primary_server_fs() {
                if ignored
                    .is_ignored_resolved_parent(&server, &source, metadata.file_type)
                    .await
                {
                    continue;
                }

                if metadata.file_type.is_file() {
                    let path = server.filesystem.diff_key(&source).await;

                    if let Err(err) = server.diff.forget_file(&path.to_string_lossy(), None).await {
                        tracing::error!("failed to forget file from diff storage: {:?}", err);
                    }
                }

                server.filesystem.truncate_path(&source).await
            } else if metadata.file_type.is_dir() {
                filesystem.async_remove_dir_all(&source).await
            } else {
                filesystem.async_remove_file(&source).await
            };

            match result {
                Ok(()) => deleted_count += 1,
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        path = %source.display(),
                        "failed to delete file: {:#?}",
                        err,
                    );

                    failed_count += 1;
                }
            }
        }

        if failed_count > 0 {
            return ApiResponse::error(&format!(
                "failed to delete {failed_count} file{}",
                if failed_count == 1 { "" } else { "s" }
            ))
            .with_status(StatusCode::EXPECTATION_FAILED)
            .ok();
        }

        ApiResponse::new_serialized(Response {
            deleted: deleted_count,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
