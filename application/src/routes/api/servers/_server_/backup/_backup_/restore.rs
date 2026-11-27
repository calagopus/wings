use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::backup::adapters::BackupAdapter,
    };
    use axum::{extract::Path, http::StatusCode};
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        adapter: BackupAdapter,
        truncate_directory: bool,
        download_url: Option<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = ACCEPTED, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
        (status = CONFLICT, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "backup" = uuid::Uuid,
            description = "The backup uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Path((_server, backup_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        if data.adapter == BackupAdapter::S3 && data.download_url.is_none() {
            return ApiResponse::error("unable to restore s3 backup without download_url")
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let backup = match state
            .backup_manager
            .find_adapter(&state, data.adapter, backup_id)
            .await?
        {
            Some(backup) => backup,
            None => {
                return ApiResponse::error("backup not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let Some(reservation) = state.backup_manager.reserve_restore(&server) else {
            return ApiResponse::error("server is already restoring a backup")
                .with_status(StatusCode::CONFLICT)
                .ok();
        };

        tokio::spawn(async move {
            if let Err(err) = state
                .backup_manager
                .restore_reserved(
                    reservation,
                    &backup,
                    &server,
                    data.truncate_directory,
                    data.download_url,
                )
                .await
            {
                tracing::error!(
                    server = %server.uuid,
                    backup = %backup.uuid(),
                    adapter = ?backup.adapter(),
                    "failed to restore backup: {:#?}",
                    err
                );
            }
        });

        ApiResponse::new_serialized(Response {})
            .with_status(StatusCode::ACCEPTED)
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
