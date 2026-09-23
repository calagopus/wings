use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        io::compression::CompressionLevel,
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        url: String,
        token: String,

        #[serde(default)]
        archive_format: crate::server::transfer::TransferArchiveFormat,
        #[serde(default, deserialize_with = "crate::deserialize::deserialize_optional")]
        compression_level: Option<CompressionLevel>,
        #[serde(
            default,
            deserialize_with = "crate::deserialize::deserialize_defaultable"
        )]
        backups: Vec<uuid::Uuid>,
        #[serde(default)]
        delete_backups: bool,
        #[serde(default)]
        multiplex_streams: usize,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = ACCEPTED, body = inline(Response)),
        (status = CONFLICT, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        if server.is_system_locked_state() {
            return ApiResponse::error("server is locked")
                .with_status(StatusCode::CONFLICT)
                .ok();
        }

        if server.set_transferring(true).await {
            return ApiResponse::error("server is locked")
                .with_status(StatusCode::CONFLICT)
                .ok();
        }

        let mut transfer = crate::server::transfer::OutgoingServerTransfer::new(
            &server,
            data.archive_format,
            data.compression_level
                .unwrap_or_else(|| state.config.load().system.backups.compression_level),
        );

        if transfer
            .start(
                &state.backup_manager,
                data.url,
                data.token,
                data.backups,
                data.delete_backups,
                data.multiplex_streams
                    .min(crate::server::transfer::MAX_MULTIPLEX_STREAMS),
            )
            .is_ok()
        {
            server.outgoing_transfer.write().await.replace(transfer);
        } else {
            server.set_transferring(false).await;

            return ApiResponse::error("failed to start server transfer")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        ApiResponse::new_serialized(Response {})
            .with_status(StatusCode::ACCEPTED)
            .ok()
    }
}

mod delete {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(server: GetServer) -> ApiResponseResult {
        if !server.is_transferring() {
            return ApiResponse::error("server is not transferring")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        server.set_transferring(false).await;
        if let Some(transfer) = server.outgoing_transfer.write().await.take()
            && let Some(handle) = transfer.task.as_ref()
        {
            handle.abort();
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
