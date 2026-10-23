use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod check;

mod post {
    use crate::{
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
        upgrade::{ReleaseProvider, VersionRequest},
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use utoipa::ToSchema;

    static UPGRADE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        version: compact_str::CompactString,
        token: Option<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        applied: bool,
        version: Option<String>,
    }

    async fn busy_reason(state: &crate::routes::AppState) -> Option<String> {
        if !state.server_manager.booted() {
            return Some("servers are still booting".to_string());
        }

        let backups = state.backup_manager.active();
        if backups > 0 {
            return Some(format!("{backups} backup operation(s) are running"));
        }

        for server in state.server_manager.get_servers().await.iter() {
            if server.is_system_locked_state() {
                return Some(format!(
                    "server {} is installing, restoring or transferring",
                    server.uuid
                ));
            }
            if !server.filesystem.operations.operations().await.is_empty() {
                return Some(format!(
                    "server {} has filesystem operations running",
                    server.uuid
                ));
            }
        }

        None
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = ACCEPTED, body = inline(Response)),
        (status = BAD_REQUEST, body = inline(ApiError)),
        (status = NOT_FOUND, body = inline(ApiError)),
        (status = CONFLICT, body = inline(ApiError)),
        (status = NOT_IMPLEMENTED, body = inline(ApiError)),
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

        if state.config.load().ignore_panel_wings_upgrades {
            return ApiResponse::new_serialized(Response {
                applied: false,
                version: None,
            })
            .ok();
        }

        let provider = ReleaseProvider::available().or_api_error(
            StatusCode::NOT_IMPLEMENTED,
            "this build has no release provider for this platform",
        )?;
        let request: VersionRequest = data.version.parse().or_api_error(
            StatusCode::BAD_REQUEST,
            "version must be a semver version or latest",
        )?;

        let Ok(guard) = UPGRADE_LOCK.try_lock() else {
            return ApiResponse::error("an upgrade is already in progress")
                .with_status(StatusCode::CONFLICT)
                .ok();
        };

        if let Some(reason) = busy_reason(&state).await {
            return ApiResponse::error(&format!("unable to upgrade right now: {reason}"))
                .with_status(StatusCode::CONFLICT)
                .ok();
        }

        let executable = crate::upgrade::executable()?;
        let client = reqwest::Client::builder()
            .user_agent("Calagopus Wings (https://github.com/calagopus/wings)")
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()?;
        let token = data.token.as_deref();

        let release = provider
            .resolve(&client, &request, token)
            .await?
            .or_api_error(
                StatusCode::NOT_FOUND,
                "release or release asset for this platform not found",
            )?;

        let current = crate::upgrade::current_version()?;
        if release.version < current {
            return ApiResponse::error(&format!(
                "refusing to downgrade from {current} to {}",
                release.version
            ))
            .with_status(StatusCode::CONFLICT)
            .ok();
        }
        if release.version == current && crate::GIT_BRANCH == "unknown" {
            return ApiResponse::error(&format!("already running {current}"))
                .with_status(StatusCode::CONFLICT)
                .ok();
        }

        let staged = crate::upgrade::download(&client, &release, token, &executable).await?;
        crate::upgrade::smoke_test(&staged, &release.version).await?;

        tokio::spawn({
            let state = Arc::clone(&state);
            let version = release.version.clone();

            async move {
                let _guard = guard;

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                if let Some(reason) = busy_reason(&state).await {
                    tracing::error!("aborting upgrade to {}: {}", version, reason);
                    return;
                }
                if let Err(err) = state.server_manager.persist(&state.config).await {
                    tracing::error!("aborting upgrade to {}: {:?}", version, err);
                    return;
                }

                tracing::info!(
                    "upgrading from {} to {}, restarting",
                    crate::VERSION,
                    version
                );
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;

                let err = crate::upgrade::replace_and_restart(staged, &executable);
                tracing::error!("failed to upgrade to {}: {:?}", version, err);
            }
        });

        ApiResponse::new_serialized(Response {
            applied: true,
            version: Some(release.version.to_string()),
        })
        .with_status(StatusCode::ACCEPTED)
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .nest("/check", check::router(state))
        .with_state(state.clone())
}
