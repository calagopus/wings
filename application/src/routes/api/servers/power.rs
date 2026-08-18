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
                match data.action {
                    crate::models::ServerPowerAction::Start => {
                        if let Err(err) = server.start(aquire_timeout, false).await {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to start server: {:#?}",
                                err
                            );
                        }
                    }
                    crate::models::ServerPowerAction::Stop => {
                        let auto_kill = server.configuration.read().await.auto_kill;
                        if let Err(err) = if auto_kill.enabled && auto_kill.seconds > 0 {
                            server
                                .stop_with_kill_timeout(
                                    std::time::Duration::from_secs(auto_kill.seconds),
                                    false,
                                )
                                .await
                        } else {
                            server.stop(aquire_timeout, false).await
                        } {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to stop server: {:#?}",
                                err
                            );
                        }
                    }
                    crate::models::ServerPowerAction::Restart => {
                        let auto_kill = server.configuration.read().await.auto_kill;
                        if let Err(err) = if auto_kill.enabled && auto_kill.seconds > 0 {
                            server
                                .restart_with_kill_timeout(
                                    aquire_timeout,
                                    std::time::Duration::from_secs(auto_kill.seconds),
                                )
                                .await
                        } else {
                            server.restart(None).await
                        } {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to auto kill server: {:#?}",
                                err
                            );
                        }
                    }
                    crate::models::ServerPowerAction::Kill => {
                        if let Err(err) = server.kill(false).await {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to kill server: {:#?}",
                                err
                            );
                        }
                    }
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
