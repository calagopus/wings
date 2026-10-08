use super::State;
use crate::server::filesystem::virtualfs::VirtualReadableFilesystem;
use std::path::Path;
use utoipa_axum::router::OpenApiRouter;

mod backup;
mod directory;
mod file;
mod files;

async fn reachable_dir(filesystem: &dyn VirtualReadableFilesystem, path: &Path) -> bool {
    match filesystem.async_symlink_metadata(&path).await {
        Ok(metadata) if metadata.file_type.is_dir() => filesystem
            .async_resolve_reachable(metadata.file_type, &path)
            .await
            .is_ok(),
        _ => false,
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/file", file::router(state))
        .nest("/files", files::router(state))
        .nest("/directory", directory::router(state))
        .nest("/backup", backup::router(state))
        .with_state(state.clone())
}
