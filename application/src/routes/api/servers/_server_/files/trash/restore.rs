use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::trash::{RestoreOutcome, TrashEntry},
    };
    use serde::{Deserialize, Serialize};
    use std::path::{Path, PathBuf};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct RestoreEntry {
        uuid: uuid::Uuid,
        path: Option<compact_str::CompactString>,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[schema(inline)]
        entries: Vec<RestoreEntry>,

        #[serde(default)]
        overwrite: bool,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    pub struct RestoreConflict {
        uuid: uuid::Uuid,
        destination: crate::models::DirectoryEntry,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        restored: Vec<TrashEntry>,
        #[schema(inline)]
        conflicts: Vec<RestoreConflict>,
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
    ), request_body = inline(Payload))]
    pub async fn route(
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "entry not found")?;

        let mut restored = Vec::new();
        let mut conflicts = Vec::new();
        for RestoreEntry { uuid, path } in data.entries {
            let Some(meta) = server
                .filesystem
                .trash
                .get_visible(&server, uuid, &ignored)
                .await
            else {
                continue;
            };

            let target = match path {
                Some(path) => server.filesystem.relative_path(Path::new(&path)),
                None => PathBuf::from(meta.path.as_str()),
            };

            if ignored
                .is_ignored_resolved(&server, &target, meta.file_type())
                .await
                || server.filesystem.async_is_protected_path(&target).await
            {
                continue;
            }

            match server
                .filesystem
                .trash
                .restore(&server, uuid, &target, data.overwrite)
                .await
            {
                Ok(RestoreOutcome::Restored(entry)) => restored.push(entry),
                Ok(RestoreOutcome::Conflict) => {
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
                        conflicts.push(RestoreConflict { uuid, destination });
                    }
                }
                Ok(RestoreOutcome::Missing) => {}
                Err(err) => {
                    tracing::error!(
                        server = %server.uuid,
                        entry = %uuid,
                        "failed to restore trash entry: {:#?}",
                        err
                    );
                }
            }
        }

        ApiResponse::new_serialized(Response {
            restored,
            conflicts,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
