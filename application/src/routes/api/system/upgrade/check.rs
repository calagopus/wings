use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        upgrade::ReleaseProvider,
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        token: Option<compact_str::CompactString>,
        #[serde(default)]
        force: bool,
    }

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        current_version: &'a str,
        latest_version: Option<String>,
        update_available: bool,
        checked_at: chrono::DateTime<chrono::Utc>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_IMPLEMENTED, body = inline(ApiError)),
        (status = BAD_GATEWAY, body = inline(ApiError)),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        if !matches!(state.container_type, crate::routes::AppContainerType::None) {
            return ApiResponse::error(
                "upgrades are not supported in containerized environments, update the image instead",
            )
            .with_status(StatusCode::NOT_IMPLEMENTED)
            .ok();
        }

        let provider = ReleaseProvider::available().or_api_error(
            StatusCode::NOT_IMPLEMENTED,
            "this build has no release provider for this platform",
        )?;

        let client = reqwest::Client::builder()
            .user_agent("Calagopus Wings (https://github.com/calagopus/wings)")
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()?;
        let token = data.token.as_deref();

        let check = match crate::upgrade::check(provider, &client, token, data.force).await {
            Ok(check) => check,
            Err(err) => {
                return ApiResponse::error(&err)
                    .with_status(StatusCode::BAD_GATEWAY)
                    .ok();
            }
        };

        let current = crate::upgrade::current_version()?;
        let update_available = check
            .latest
            .as_ref()
            .is_some_and(|latest| *latest > current);

        ApiResponse::new_serialized(Response {
            current_version: &state.version,
            latest_version: check.latest.map(|latest| latest.to_string()),
            update_available,
            checked_at: check.checked_at,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
