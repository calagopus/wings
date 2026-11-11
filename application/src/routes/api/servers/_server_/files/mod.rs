use super::State;
use crate::{
    response::ApiResponse,
    server::{Server, filesystem::VIRTUAL_PATH_MESSAGE},
};
use axum::http::StatusCode;
use std::path::{Path, PathBuf};
use utoipa_axum::router::OpenApiRouter;

mod chmod;
mod compress;
mod contents;
mod copy;
mod copy_many;
mod copy_remote;
mod create_directory;
mod create_symlink;
mod decompress;
mod delete;
mod directory_sizes;
mod fingerprints;
mod ignore_matches;
mod largest_directories;
mod lines;
mod list;
mod list_directory;
mod operations;
mod pull;
mod rename;
mod revisions;
mod search;
mod sqlite_query;
mod stat;
mod trash;
mod write;

async fn reject_protected(server: &Server, path: &Path) -> Result<(), ApiResponse> {
    if server.filesystem.async_is_protected_path(path).await {
        return Err(
            ApiResponse::error(VIRTUAL_PATH_MESSAGE).with_status(StatusCode::EXPECTATION_FAILED)
        );
    }

    Ok(())
}

async fn reject_any_protected(server: &Server, paths: &[PathBuf]) -> Result<(), ApiResponse> {
    for path in paths {
        reject_protected(server, path).await?;
    }

    Ok(())
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/contents", contents::router(state))
        .nest("/lines", lines::router(state))
        .nest("/list-directory", list_directory::router(state))
        .nest("/list", list::router(state))
        .nest("/rename", rename::router(state))
        .nest("/copy", copy::router(state))
        .nest("/copy-many", copy_many::router(state))
        .nest("/copy-remote", copy_remote::router(state))
        .nest("/write", write::router(state))
        .nest("/create-directory", create_directory::router(state))
        .nest("/create-symlink", create_symlink::router(state))
        .nest("/largest-directories", largest_directories::router(state))
        .nest("/delete", delete::router(state))
        .nest("/directory-sizes", directory_sizes::router(state))
        .nest("/chmod", chmod::router(state))
        .nest("/search", search::router(state))
        .nest("/ignore-matches", ignore_matches::router(state))
        .nest("/sqlite-query", sqlite_query::router(state))
        .nest("/stat", stat::router(state))
        .nest("/fingerprints", fingerprints::router(state))
        .nest("/pull", pull::router(state))
        .nest("/compress", compress::router(state))
        .nest("/decompress", decompress::router(state))
        .nest("/operations", operations::router(state))
        .nest("/revisions", revisions::router(state))
        .nest("/trash", trash::router(state))
        .with_state(state.clone())
}
