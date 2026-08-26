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

        let mut deleted_count = 0;
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

            if if filesystem.is_primary_server_fs() {
                if metadata.file_type.is_file() {
                    let path = server.filesystem.diff_key(&source).await;

                    if let Err(err) = server.diff.forget_file(&path.to_string_lossy(), None).await {
                        tracing::error!("failed to forget file from diff storage: {:?}", err);
                    }
                }

                server.filesystem.truncate_path(&source).await.is_ok()
            } else if metadata.file_type.is_dir() {
                filesystem.async_remove_dir_all(&source).await.is_ok()
            } else {
                filesystem.async_remove_file(&source).await.is_ok()
            } {
                deleted_count += 1;
            }
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
