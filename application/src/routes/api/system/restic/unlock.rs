use super::{RepositoryLock, ResticBackupConfiguration, ResticTask, State};
use utoipa_axum::{router::OpenApiRouter, routes};

static TASK: ResticTask = ResticTask::new("unlock", RepositoryLock::None);

mod get {
    use crate::{response::ApiResponseResult, routes::ApiError};

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(super::super::Response)),
        (status = NOT_FOUND, body = ApiError),
    ))]
    pub async fn route() -> ApiResponseResult {
        super::TASK.cached().await
    }
}

mod post {
    use crate::{
        response::ApiResponseResult,
        routes::{ApiError, GetState, api::system::restic::system_restic_configuration},
    };
    use serde::Deserialize;
    use utoipa::ToSchema;

    fn foreground() -> bool {
        true
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        configuration: Option<super::ResticBackupConfiguration>,
        #[serde(default)]
        remove_all: bool,
        #[serde(default = "foreground")]
        foreground: bool,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(super::super::Response)),
        (status = ACCEPTED, body = inline(super::super::ResponseAccepted)),
        (status = CONFLICT, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let configuration = data
            .configuration
            .map(std::sync::Arc::new)
            .unwrap_or_else(|| system_restic_configuration(&state.config));

        let args = move |command: &mut tokio::process::Command| {
            command.arg("unlock");

            if data.remove_all {
                command.arg("--remove-all");
            }
        };

        super::TASK
            .run(state.config.clone(), configuration, args, data.foreground)
            .await
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .routes(routes!(post::route))
        .with_state(state.clone())
}
