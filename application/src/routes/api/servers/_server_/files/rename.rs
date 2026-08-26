use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod put {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        root: compact_str::CompactString,

        #[schema(inline)]
        files: Vec<crate::models::RenameFile>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        renamed: usize,
    }

    #[utoipa::path(put, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
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

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(&server, &data.root, &ignored)
            .await;

        let mut renamed_count = 0;
        for file in data.files {
            let from = root.join(file.from);
            if from == root {
                continue;
            }

            let to = root.join(file.to);
            if to == root {
                continue;
            }

            if from == to {
                continue;
            }

            let from_metadata = match filesystem.async_metadata(&from).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if filesystem.async_metadata(&to).await.is_ok()
                || (filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(&to, from_metadata.file_type)
                        .await)
            {
                continue;
            }

            if filesystem.is_primary_server_fs() {
                let from_path = server
                    .filesystem
                    .async_canonicalize(&from)
                    .await
                    .unwrap_or_else(|_| server.filesystem.relative_path(&from));
                let to_path = server.filesystem.relative_path(&to);

                if let Err(err) = server.filesystem.rename_path(&from, &to).await {
                    tracing::debug!(
                        server = %server.uuid,
                        "failed to rename file: {:#?}",
                        err
                    );
                } else {
                    renamed_count += 1;
                }

                if let Err(err) = server
                    .diff
                    .rename_file(&from_path.to_string_lossy(), &to_path.to_string_lossy())
                    .await
                {
                    tracing::error!("failed to rename file in diff storage: {:?}", err);
                }
            } else if filesystem
                .async_rename(&from, &to, from_metadata.file_type)
                .await
                .is_ok()
            {
                renamed_count += 1;
            }
        }

        ApiResponse::new_serialized(Response {
            renamed: renamed_count,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(put::route))
        .with_state(state.clone())
}
