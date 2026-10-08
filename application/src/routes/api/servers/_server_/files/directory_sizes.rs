use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::{
            cap::FileType,
            usage::DiskUsage,
            virtualfs::{IgnoreVerdict, IsIgnoredFn},
        },
    };
    use axum::http::StatusCode;
    use axum_extra::extract::Query;
    use compact_str::CompactString;
    use serde::Deserialize;
    use std::path::Path;
    use utoipa::ToSchema;

    const DEFAULT_DEPTH: usize = 2;
    const MAX_DEPTH: usize = 4;
    const MAX_CHILDREN: usize = 64;
    const MIN_CHILD_SHARE: u64 = 100;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default)]
        directory: CompactString,
        depth: Option<usize>,
        #[serde(default)]
        ignored: Vec<CompactString>,
    }

    fn files_size(usage: &DiskUsage) -> u64 {
        usage.space.get_logical().saturating_sub(
            usage
                .get_entries()
                .iter()
                .map(|(_, child)| child.space.get_logical())
                .sum::<u64>(),
        )
    }

    fn build(
        name: &str,
        usage: &DiskUsage,
        path: &Path,
        root: &Path,
        descend_only: bool,
        depth: usize,
        is_ignored: &IsIgnoredFn,
    ) -> crate::models::DirectorySizes {
        let size = usage.space.get_logical();
        let own = files_size(usage);

        let mut result = crate::models::DirectorySizes {
            name: name.into(),
            size,
            size_physical: usage.space.get_physical(),
            files_size: if descend_only { 0 } else { own },
            inaccessible_size: if descend_only { own } else { 0 },
            other_size: 0,
            other_count: 0,
            truncated: false,
            children: Vec::new(),
        };

        if depth == 0 {
            result.truncated = size > own;
            return result;
        }

        let mut visible = Vec::with_capacity(usage.get_entries().len());
        for (child_name, child) in usage.get_entries() {
            let child_path = path.join(child_name.as_str());

            match is_ignored(FileType::Dir, root.join(&child_path)) {
                IgnoreVerdict::Keep(_) => visible.push((child_name, child, child_path, false)),
                IgnoreVerdict::Descend(_) => visible.push((child_name, child, child_path, true)),
                IgnoreVerdict::Skip => result.inaccessible_size += child.space.get_logical(),
            }
        }

        visible
            .sort_unstable_by_key(|(_, child, _, _)| std::cmp::Reverse(child.space.get_logical()));

        let threshold = size / MIN_CHILD_SHARE;
        for (position, (child_name, child, child_path, child_descend_only)) in
            visible.into_iter().enumerate()
        {
            let child_size = child.space.get_logical();

            if child_size == 0 || child_size < threshold || position >= MAX_CHILDREN {
                result.other_size += child_size;
                result.other_count += 1;
            } else {
                result.children.push(build(
                    child_name,
                    child,
                    &child_path,
                    root,
                    child_descend_only,
                    depth - 1,
                    is_ignored,
                ));
            }
        }

        result
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = crate::models::DirectorySizes),
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
            description = "The directory to break down",
        ),
        (
            "depth" = Option<usize>, Query,
            description = "How many levels of subdirectories to include, 1 to 4",
            example = 2,
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "directory not found")?;

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs(&server, Path::new(&data.directory))
            .await;

        if !filesystem.is_primary_server_fs() {
            return ApiResponse::error("filesystem does not support this operation")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let is_ignored = IsIgnoredFn::from(server.filesystem.get_ignored());
        let is_ignored = match ignored.filter(&server) {
            Some(ignored) => is_ignored.merge(ignored),
            None => is_ignored,
        };

        let root = server
            .filesystem
            .async_canonicalize(&root)
            .await
            .unwrap_or(root);

        let depth = data.depth.unwrap_or(DEFAULT_DEPTH).clamp(1, MAX_DEPTH);

        let sizes = {
            let directories = server.filesystem.disk_usage.read().await;
            let empty = DiskUsage::default();
            let root_usage = directories.get_path(&root).unwrap_or(&empty);

            build(
                &data.directory,
                root_usage,
                Path::new(""),
                &root,
                false,
                depth,
                &is_ignored,
            )
        };

        ApiResponse::new_serialized(sizes).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
