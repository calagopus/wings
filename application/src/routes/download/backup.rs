use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::filesystem::{archive::StreamableArchiveFormat, virtualfs::ByteRange},
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
    pub struct BackupJwtPayload {
        #[serde(flatten)]
        pub base: crate::remote::jwt::BasePayload,

        pub server_uuid: Option<uuid::Uuid>,
        pub backup_uuid: uuid::Uuid,
        pub unique_id: compact_str::CompactString,
        #[serde(default)]
        pub database: bool,
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
        let payload: BackupJwtPayload = match state.config.jwt.verify(&data.token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload
            .base
            .validate(&state.config.jwt, Some("backup-download"))
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

        if let Some(server_uuid) = payload.server_uuid
            && state.server_manager.get_server(server_uuid).await.is_none()
        {
            return ApiResponse::error("server not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        }

        let backup = match state
            .backup_manager
            .find(&state, payload.backup_uuid)
            .await?
        {
            Some(backup) => backup,
            None => {
                return ApiResponse::error("backup not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let download = if payload.database {
            backup.download_database(&state).await
        } else {
            backup
                .download(
                    &state,
                    data.archive_format,
                    ByteRange::from_headers(&headers),
                )
                .await
        };

        match download {
            Ok(response) => response,
            Err(err) => {
                tracing::error!("failed to download backup: {:?}", err);

                ApiResponse::error("failed to download backup")
                    .with_status(StatusCode::EXPECTATION_FAILED)
            }
        }
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
