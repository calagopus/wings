use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::transfer::TransferCapabilities,
    };
    use axum::http::{HeaderMap, StatusCode};

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = TransferCapabilities),
        (status = UNAUTHORIZED, body = ApiError),
    ))]
    pub async fn route(state: GetState, headers: HeaderMap) -> ApiResponseResult {
        let key = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let (r#type, token) = match key.split_once(' ') {
            Some((t, tok)) => (t, tok),
            None => {
                return ApiResponse::error("invalid authorization header")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .with_header("WWW-Authenticate", "Bearer")
                    .ok();
            }
        };

        if r#type != "Bearer" {
            return ApiResponse::error("invalid authorization header")
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        let payload: crate::remote::jwt::BasePayload = match state.config.jwt.verify(token) {
            Ok(payload) => payload,
            Err(_) => {
                return ApiResponse::error("invalid token")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .ok();
            }
        };

        if let Err(err) = payload.validate(&state.config.jwt, Some("transfer")).await {
            return ApiResponse::error(&format!("invalid token: {err}"))
                .with_status(StatusCode::UNAUTHORIZED)
                .ok();
        }

        ApiResponse::new_serialized(TransferCapabilities::from_config(&state.config.load())).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
