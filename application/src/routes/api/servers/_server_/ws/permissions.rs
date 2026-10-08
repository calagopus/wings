use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::api::servers::_server_::GetServer,
        server::permissions::Permissions,
    };
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct PayloadPermissions {
        user: uuid::Uuid,

        #[schema(value_type = Vec<String>)]
        permissions: Permissions,
        #[serde(default)]
        ignored_files: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[schema(inline)]
        user_permissions: Vec<PayloadPermissions>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
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
        for user_permission in data.user_permissions {
            server.user_permissions.set_pushed_permissions(
                user_permission.user,
                user_permission.permissions,
                Some(&user_permission.ignored_files),
            );
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
