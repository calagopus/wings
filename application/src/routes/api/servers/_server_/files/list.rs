use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use std::path::Path;

    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::{
            RequestIgnored,
            cap::FileType,
            uploads::{UploadEntry, target_name},
            virtualfs::CheckedDirectoryListing,
        },
    };
    use axum::http::StatusCode;
    use axum_extra::extract::Query;
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        #[serde(default, alias = "directory")]
        root: compact_str::CompactString,
        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,

        per_page: Option<usize>,
        page: Option<usize>,

        #[serde(default)]
        sort: crate::models::DirectorySortingMode,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        total: usize,

        filesystem_primary: bool,
        filesystem_writable: bool,
        filesystem_fast: bool,

        entries: Vec<crate::models::DirectoryEntry>,
        uploads: Vec<UploadEntry>,
    }

    async fn upload_entries(
        server: &crate::server::Server,
        root: &Path,
        entries: &[crate::models::DirectoryEntry],
        ignored: &RequestIgnored,
    ) -> Vec<UploadEntry> {
        let tracked = server
            .filesystem
            .uploads
            .in_directory(root, &server.filesystem)
            .await;
        let directory = server.filesystem.relative_path(root);
        let directory = directory.to_string_lossy();

        let mut uploads = Vec::with_capacity(tracked.len());
        for upload in tracked {
            if !ignored
                .is_ignored_resolved(
                    server,
                    &root.join(upload.target_name.as_str()),
                    FileType::File,
                )
                .await
            {
                uploads.push(upload);
            }
        }

        for entry in entries {
            if !entry.file
                || target_name(&entry.name).is_none()
                || uploads.iter().any(|upload| upload.name == entry.name)
            {
                continue;
            }

            uploads.push(UploadEntry::orphan(&entry.name, &directory, entry.size));
        }

        uploads
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
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
            description = "The directory to list files from",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
        (
            "per_page" = usize, Query,
            description = "The number of entries to return per page",
        ),
        (
            "page" = usize, Query,
            description = "The page number to return",
        ),
        (
            "sort" = crate::models::DirectorySortingMode, Query,
            description = "The sorting mode to use",
        ),
    ))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        Query(data): Query<Params>,
    ) -> ApiResponseResult {
        let per_page = match data.per_page {
            Some(per_page) => Some(per_page),
            None => match state.config.load().api.directory_entry_limit {
                0 => None,
                limit => Some(limit),
            },
        };
        let page = data.page.unwrap_or(1);

        let ignored = crate::routes::token::ignored(&server, &data.ignored, "directory not found")?;

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, Path::new(&data.root), &ignored)
            .await;

        let is_ignored = if filesystem.is_primary_server_fs() {
            server.filesystem.symlink_name_filter()
        } else {
            Default::default()
        };

        let entries = match filesystem
            .async_read_dir_checked(&root, per_page, page, is_ignored, data.sort)
            .await?
        {
            CheckedDirectoryListing::Listing(entries) => entries,
            CheckedDirectoryListing::NotDirectory => {
                return ApiResponse::error("path not a directory")
                    .with_status(StatusCode::EXPECTATION_FAILED)
                    .ok();
            }
            CheckedDirectoryListing::NotFound => {
                return ApiResponse::error("path not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let uploads = if filesystem.is_primary_server_fs() {
            upload_entries(&server, &root, &entries.entries, &ignored).await
        } else {
            Vec::new()
        };

        ApiResponse::new_serialized(Response {
            total: entries.total_entries,
            filesystem_primary: filesystem.is_primary_server_fs(),
            filesystem_writable: filesystem.is_writable(),
            filesystem_fast: filesystem.is_fast(),
            entries: entries.entries,
            uploads,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
