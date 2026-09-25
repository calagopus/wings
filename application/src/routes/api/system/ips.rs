use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::Serialize;
    use std::{collections::BTreeSet, net::IpAddr};
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        #[schema(value_type = Vec<String>)]
        ips: BTreeSet<IpAddr>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        if !matches!(state.container_type, crate::routes::AppContainerType::None) {
            return ApiResponse::new_serialized(Response {
                ips: BTreeSet::new(),
            })
            .ok();
        }

        let ips =
            crate::utils::assignable_host_ips(state.config.load().docker.network.name.clone())
                .await?;

        ApiResponse::new_serialized(Response { ips }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
