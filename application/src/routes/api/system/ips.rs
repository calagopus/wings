use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::Serialize;
    use std::{collections::BTreeSet, net::IpAddr};
    use sysinfo::Networks;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        #[schema(value_type = Vec<String>)]
        ips: BTreeSet<IpAddr>,
    }

    fn is_assignable(ip: &IpAddr) -> bool {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return false;
        }

        match ip {
            IpAddr::V4(ip) => !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
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

        let docker_network_name = state.config.load().docker.network.name.clone();
        let networks = tokio::task::spawn_blocking(Networks::new_with_refreshed_list).await?;

        let ips = networks
            .iter()
            .filter(|(name, _)| {
                *name != &docker_network_name
                    && !name.starts_with("docker")
                    && !name.starts_with("br-")
                    && !name.starts_with("veth")
            })
            .flat_map(|(_, data)| data.ip_networks())
            .map(|network| network.addr)
            .filter(is_assignable)
            .collect();

        ApiResponse::new_serialized(Response { ips }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
