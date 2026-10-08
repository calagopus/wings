use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        server::permissions::Permissions,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        servers: HashSet<uuid::Uuid>,
        user: uuid::Uuid,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = CONFLICT, body = inline(ApiError)),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        for server in state.server_manager.get_servers().await.iter() {
            if data.servers.is_empty() || data.servers.contains(&server.uuid) {
                server.user_permissions.set_pushed_permissions(
                    data.user,
                    Permissions::default(),
                    Some(&[] as &[&str]),
                );
            }
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
