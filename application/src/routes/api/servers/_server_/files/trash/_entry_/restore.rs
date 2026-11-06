use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::trash::{InnerRestoreOutcome, TrashEntry, inner_path},
    };
    use axum::{extract::Path, http::StatusCode};
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct RestoreFile {
        from: compact_str::CompactString,
        to: Option<compact_str::CompactString>,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[schema(inline)]
        files: Vec<RestoreFile>,

        #[serde(default)]
        overwrite: bool,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    pub struct RestoredFile {
        from: compact_str::CompactString,
        to: compact_str::CompactString,
        restoration: Option<uuid::Uuid>,
    }

    #[derive(ToSchema, Serialize)]
    pub struct RestoreConflict {
        from: compact_str::CompactString,
        destination: crate::models::DirectoryEntry,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        #[schema(inline)]
        restored: Vec<RestoredFile>,
        #[schema(inline)]
        conflicts: Vec<RestoreConflict>,
        entry: Option<TrashEntry>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "entry" = uuid::Uuid,
            description = "The trash entry uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        server: GetServer,
        Path((_server, entry_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let meta = server
            .filesystem
            .trash
            .get_visible(&server, entry_id, &ignored)
            .await
            .or_api_error(StatusCode::NOT_FOUND, "entry not found")?;

        let mut restored = Vec::new();
        let mut conflicts = Vec::new();
        for RestoreFile { from, to } in data.files {
            let Some(inner) = inner_path(&from).filter(|inner| !inner.as_os_str().is_empty())
            else {
                continue;
            };

            let Some(file_type) = server
                .filesystem
                .trash
                .inner_file_type(&server, entry_id, &meta, &inner)
                .await
            else {
                continue;
            };

            if server
                .filesystem
                .trash
                .is_inner_ignored(&server, &meta, &inner, file_type, &ignored)
                .await
            {
                continue;
            }

            let target = match to {
                Some(to) => server.filesystem.relative_path(std::path::Path::new(&to)),
                None => std::path::PathBuf::from(meta.path.as_str()).join(&inner),
            };

            if ignored
                .is_ignored_resolved(&server, &target, file_type)
                .await
                || server.filesystem.async_is_protected_path(&target).await
            {
                continue;
            }

            match server
                .filesystem
                .trash
                .restore_inner(&server, entry_id, &inner, &target, data.overwrite)
                .await
            {
                Ok(InnerRestoreOutcome::Restored(restoration)) => restored.push(RestoredFile {
                    from: inner.to_string_lossy().as_ref().into(),
                    to: target.to_string_lossy().as_ref().into(),
                    restoration: restoration.map(|restoration| restoration.id),
                }),
                Ok(InnerRestoreOutcome::Conflict) => {
                    let (Some(parent), Some(file_name)) = (target.parent(), target.file_name())
                    else {
                        continue;
                    };

                    let (parent, filesystem) = server
                        .filesystem
                        .resolve_readable_fs_ignoring(&server, parent, &ignored)
                        .await;

                    if let Ok(destination) = filesystem
                        .async_directory_entry(&parent.join(file_name))
                        .await
                    {
                        conflicts.push(RestoreConflict {
                            from: inner.to_string_lossy().as_ref().into(),
                            destination,
                        });
                    }
                }
                Ok(InnerRestoreOutcome::Missing) => {}
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        entry = %entry_id,
                        path = %inner.display(),
                        "failed to restore from trash entry: {:#?}",
                        err
                    );
                }
            }
        }

        let entry = server
            .filesystem
            .trash
            .visible_entry(&server, entry_id, &ignored)
            .await;

        ApiResponse::new_serialized(Response {
            restored,
            conflicts,
            entry,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
