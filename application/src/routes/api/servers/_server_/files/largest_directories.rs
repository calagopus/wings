use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::extract::Query;
    use axum::http::StatusCode;
    use compact_str::ToCompactString;
    use serde::Deserialize;
    use std::path::{Path, PathBuf};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default)]
        directory: compact_str::CompactString,
        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = Vec<crate::models::DirectoryEntry>),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "directory" = String, Query,
            description = "The directory to analyze",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
        let ignore = if data.ignored.is_empty() {
            None
        } else {
            crate::server::filesystem::build_gitignore_matcher(data.ignored.iter()).ok()
        };

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs(&server, Path::new(&data.directory))
            .await;

        if !filesystem.is_primary_server_fs() {
            return ApiResponse::error("filesystem does not support this operation")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let is_ignored = match ignore {
            Some(ignore) => vec![server.filesystem.get_ignored(), ignore],
            None => vec![server.filesystem.get_ignored()],
        };
        let is_path_ignored = |path: &Path, is_dir: bool| {
            is_ignored
                .iter()
                .any(|gi| gi.matched(path, is_dir).is_ignore())
        };

        let root = server
            .filesystem
            .async_canonicalize(&root)
            .await
            .unwrap_or(root);

        let mut entries = Vec::new();
        let directories = server.filesystem.disk_usage.read().await;

        let Some(root_usage) = directories.get_path(&root) else {
            return ApiResponse::error("directory not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok();
        };

        let mut stack = Vec::with_capacity(32);
        stack.push((PathBuf::new(), root_usage));

        while let Some((usage_path, usage)) = stack.pop() {
            if !usage_path.as_os_str().is_empty() {
                if is_path_ignored(&root.join(&usage_path), true) {
                    continue;
                }

                let self_size = usage.space.get_logical().saturating_sub(
                    usage
                        .get_entries()
                        .iter()
                        .map(|u| u.1.space.get_logical())
                        .sum::<u64>(),
                );

                if self_size > 0 {
                    entries.push((usage_path.clone(), self_size));
                }
            }

            for (sub_path, sub_usage) in usage.get_entries() {
                stack.push((usage_path.join(sub_path), sub_usage));
            }
        }

        entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));

        let total: u64 = entries.iter().map(|(_, size)| *size).sum();
        let threshold = (total as u128 * 90 / 100) as u64;

        const MIN_ENTRIES: usize = 10;
        const MAX_ENTRIES: usize = 50;

        let mut cumulative: u64 = 0;
        let cutoff = entries
            .iter()
            .position(|(_, size)| {
                cumulative = cumulative.saturating_add(*size);
                cumulative >= threshold
            })
            .map(|i| i + 1)
            .unwrap_or(entries.len());

        let cutoff = cutoff.clamp(MIN_ENTRIES, MAX_ENTRIES).min(entries.len());

        entries.truncate(cutoff);

        drop(directories);

        let mut directory_entries = Vec::new();
        directory_entries.reserve_exact(entries.len());

        for (path, _) in entries {
            let abs_path = root.join(&path);

            let metadata = match server.filesystem.async_symlink_metadata(&abs_path).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            let mut entry = server
                .filesystem
                .to_api_entry_buffer(
                    abs_path,
                    &metadata,
                    crate::server::filesystem::DirectoryEntryOptions {
                        directory_size: true,
                        ..Default::default()
                    },
                    None,
                    None,
                    None,
                )
                .await;
            entry.name = path.to_string_lossy().to_compact_string();

            directory_entries.push(entry);
        }

        directory_entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.size));

        ApiResponse::new_serialized(directory_entries).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
