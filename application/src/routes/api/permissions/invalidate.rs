use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        remote::UserServerPermissions,
        response::{ApiResponse, ApiResponseResult},
        routes::{GetState, State},
        server::Server,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use utoipa::ToSchema;

    const REFETCH_CHUNK: usize = 100;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        as_of: i64,

        #[serde(default)]
        users: HashSet<uuid::Uuid>,
        servers: Option<crate::models::ServerSelector>,

        #[serde(default)]
        revoke_users: HashSet<uuid::Uuid>,
        #[serde(default)]
        revoke_credentials: HashSet<uuid::Uuid>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        state
            .config
            .jwt
            .revoke(&data.revoke_users, &data.revoke_credentials, data.as_of);

        let mut refetch = Vec::new();
        for server in state.server_manager.get_servers().await.iter() {
            for &user in &data.revoke_users {
                server.user_permissions.revoke(user, data.as_of);
            }

            let mut users = HashSet::new();
            if data
                .servers
                .as_ref()
                .is_some_and(|servers| servers.matches(&server.uuid))
            {
                users.extend(server.user_permissions.invalidate_all(data.as_of));
            }
            for &user in &data.users {
                if server.user_permissions.invalidate(user, data.as_of) {
                    users.insert(user);
                }
            }

            refetch.extend(
                users
                    .into_iter()
                    .filter(|user| !data.revoke_users.contains(user))
                    .map(|user| (server.clone(), user)),
            );
        }

        if !refetch.is_empty() {
            tokio::spawn(refetch_permissions(state.0, refetch, data.as_of));
        }

        ApiResponse::new_serialized(Response {}).ok()
    }

    async fn refetch_permissions(state: State, entries: Vec<(Server, uuid::Uuid)>, as_of: i64) {
        for chunk in entries.chunks(REFETCH_CHUNK) {
            let pairs: Vec<_> = chunk
                .iter()
                .map(|(server, user)| (server.uuid, *user))
                .collect();

            let batch = match state.config.client.get_permissions(&pairs).await {
                Ok(batch) => batch,
                Err(err) => {
                    tracing::error!(
                        "failed to refetch invalidated permissions, revoking them: {:#?}",
                        err
                    );

                    for (server, user) in chunk {
                        server.user_permissions.revoke(*user, as_of);
                    }

                    continue;
                }
            };

            let mut fetched: HashMap<_, _> = batch
                .entries
                .into_iter()
                .map(|entry| ((entry.server, entry.user), entry))
                .collect();

            for (server, user) in chunk {
                match fetched.remove(&(server.uuid, *user)) {
                    Some(UserServerPermissions {
                        permissions: Some(permissions),
                        ignored_files,
                        ..
                    }) => {
                        server.user_permissions.set_fetched_permissions(
                            *user,
                            permissions,
                            Some(&ignored_files),
                            batch.as_of,
                        );
                    }
                    _ => server.user_permissions.revoke(*user, batch.as_of),
                }
            }
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
