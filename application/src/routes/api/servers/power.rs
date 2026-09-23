use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        servers: crate::models::ServerSelector,
        action: crate::models::ServerPowerAction,
        wait_seconds: Option<u64>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        affected: usize,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = ACCEPTED, body = inline(Response)),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let aquire_timeout = data.wait_seconds.map(std::time::Duration::from_secs);

        let spawn_task = |server: crate::server::Server| {
            tokio::spawn(async move {
                if let Err(err) = server.power_action(data.action, aquire_timeout).await {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to {} server: {:#?}",
                        data.action.to_str(),
                        err
                    );
                }
            });
        };

        let mut affected = 0;
        for server in state.server_manager.get_servers().await.iter() {
            if !data.servers.matches(&server.uuid) {
                continue;
            }

            affected += 1;

            spawn_task(server.clone());
        }

        ApiResponse::new_serialized(Response { affected })
            .with_status(StatusCode::ACCEPTED)
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
