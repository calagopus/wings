use crate::server::{Server, state::ServerState};
use compact_str::CompactString;
use gamedig::{GAMES, Game, protocols::types::TimeoutSettings};
use serde::Serialize;
use std::{net::SocketAddr, time::Duration};
use utoipa::ToSchema;

pub const CACHE_TTL: Duration = Duration::from_secs(30);

/// The response returned for a single server game query.
#[derive(ToSchema, Serialize, Debug, Clone)]
pub struct GameDigResponse {
    /// Whether a `gamedig_*` egg feature is configured for this server.
    pub enabled: bool,
    /// The detected game identifier, if enabled.
    pub game: Option<CompactString>,
    /// Whether the game server responded to the query.
    pub online: bool,
    /// The amount of players currently connected.
    pub players_online: Option<u32>,
    /// The maximum amount of players that can connect.
    pub players_maximum: Option<u32>,
    /// The current map name, when provided by the game protocol.
    pub map: Option<CompactString>,
    /// The game version reported by the server, when provided.
    pub version: Option<CompactString>,
}

impl GameDigResponse {
    fn disabled() -> Self {
        Self {
            enabled: false,
            game: None,
            online: false,
            players_online: None,
            players_maximum: None,
            map: None,
            version: None,
        }
    }

    fn offline(game: &str) -> Self {
        Self {
            enabled: true,
            game: Some(game.into()),
            online: false,
            players_online: None,
            players_maximum: None,
            map: None,
            version: None,
        }
    }
}

/// Maps an egg feature to the gamedig game identifier used to query it.
const FEATURE_GAMES: &[(&str, &str)] = &[
    ("gamedig_minecraft", "minecraft"),
    ("gamedig_tf2", "teamfortress2"),
    ("gamedig_csgo", "csgo"),
    ("gamedig_css", "css"),
    ("gamedig_zomboid", "projectzomboid"),
];

/// Looks through the egg features for a `gamedig_*` feature.
fn detect_game(features: &[CompactString]) -> Option<&'static str> {
    for feature in features {
        for (name, game) in FEATURE_GAMES {
            if feature == *name {
                return Some(game);
            }
        }
    }

    None
}

fn perform_query(game: &Game, target: &SocketAddr, game_id: &'static str) -> GameDigResponse {
    let timeout_settings = TimeoutSettings::new(
        Some(Duration::from_secs(4)),
        Some(Duration::from_secs(4)),
        Some(Duration::from_secs(4)),
        0,
    );

    let Ok(timeout_settings) = timeout_settings else {
        return GameDigResponse::disabled();
    };

    match gamedig::games::query::query_with_timeout(
        game,
        &target.ip(),
        Some(target.port()),
        Some(timeout_settings),
    ) {
        Ok(response) => {
            let data = response.as_json();
            GameDigResponse {
                enabled: true,
                game: Some(game_id.into()),
                online: true,
                players_online: Some(data.players_online),
                players_maximum: Some(data.players_maximum),
                map: data.map.map(Into::into),
                version: data.game_version.map(Into::into),
            }
        }
        Err(err) => {
            tracing::debug!(
                target = %target,
                game = %game_id,
                "gamedig query failed: {err}"
            );
            GameDigResponse::offline(game_id)
        }
    }
}

async fn query_game_server(
    game: Game,
    target: SocketAddr,
    game_id: &'static str,
) -> GameDigResponse {
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || perform_query(&game, &target, game_id)),
    )
    .await
    .map_or_else(
        |_| {
            tracing::debug!(
                target = %target,
                game = %game_id,
                "gamedig query timed out"
            );
            GameDigResponse::offline(game_id)
        },
        |result| {
            result.unwrap_or_else(|err| {
                tracing::error!(
                    target = %target,
                    game = %game_id,
                    "gamedig query task failed: {err}"
                );
                GameDigResponse::offline(game_id)
            })
        },
    )
}

pub async fn query_server(server: &Server, state: &crate::routes::AppState) -> GameDigResponse {
    let configuration = server.configuration.read().await;

    let Some(game_id) = detect_game(&configuration.egg.features) else {
        return GameDigResponse::disabled();
    };

    if server.state.get_state() != ServerState::Running {
        return GameDigResponse::offline(game_id);
    }

    let Some(allocation_port) = configuration.allocations.default.as_ref().map(|d| d.port) else {
        return GameDigResponse::offline(game_id);
    };

    drop(configuration);

    let Some(game) = GAMES.get(game_id).cloned() else {
        return GameDigResponse::offline(game_id);
    };

    let target = match state
        .executor
        .resolve_internal_target(server, allocation_port)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => {
            tracing::debug!(
                server = %server.uuid,
                game = %game_id,
                "no internal target could be resolved for gamedig query"
            );
            return GameDigResponse::offline(game_id);
        }
        Err(err) => {
            tracing::debug!(
                server = %server.uuid,
                game = %game_id,
                "failed to resolve internal target for gamedig query: {err}"
            );
            return GameDigResponse::offline(game_id);
        }
    };

    state
        .gamedig_cache
        .get_with(server.uuid, query_game_server(game, target, game_id))
        .await
}
