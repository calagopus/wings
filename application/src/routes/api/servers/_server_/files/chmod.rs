use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::virtualfs::{AsyncDirectoryWalkFn, VirtualWalkEntry},
        utils::PortablePermissions,
    };
    use serde::{Deserialize, Serialize};
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct ChmodFile {
        file: compact_str::CompactString,
        mode: compact_str::CompactString,
        #[serde(default)]
        recursive: bool,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        root: compact_str::CompactString,

        #[schema(inline)]
        files: Vec<ChmodFile>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        updated: usize,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
        (status = EXPECTATION_FAILED, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let mut updated_count = 0;
        for file in data.files {
            let (source, filesystem) = server
                .filesystem
                .resolve_writable_fs(&server, Path::new(&data.root).join(&file.file))
                .await;
            if source.as_os_str().is_empty() || source == Path::new(&data.root) {
                continue;
            }

            let metadata = match filesystem.async_symlink_metadata(&source).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            let mode = match u32::from_str_radix(&file.mode, 8) {
                Ok(mode) => mode,
                Err(_) => continue,
            };

            if filesystem
                .async_set_permissions(
                    &source,
                    metadata.file_type,
                    PortablePermissions::from_mode_file(mode),
                )
                .await
                .is_ok()
            {
                updated_count += 1;

                if metadata.file_type.is_dir() && file.recursive {
                    let updated_count_arc = Arc::new(AtomicUsize::new(0));

                    let walker = async {
                        let mut walker = filesystem
                            .async_walk_dir(&source, vec![server.filesystem.get_ignored()].into())
                            .await?;

                        walker
                            .run_multithreaded(
                                state.config.load().system.check_permissions_on_boot_threads,
                                AsyncDirectoryWalkFn::from({
                                    let filesystem = filesystem.clone();
                                    let updated_count_arc = updated_count_arc.clone();
                                    let mode = PortablePermissions::from_mode_file(mode);

                                    move |entry: VirtualWalkEntry| {
                                        let file_type = entry.file_type;
                                        let path = entry.path;

                                        let filesystem = filesystem.clone();
                                        let updated_count_arc = updated_count_arc.clone();

                                        async move {
                                            if !file_type.is_file() && !file_type.is_dir() {
                                                return Ok(());
                                            }

                                            if filesystem
                                                .async_set_permissions(&path, file_type, mode)
                                                .await
                                                .is_ok()
                                            {
                                                updated_count_arc.fetch_add(1, Ordering::Relaxed);
                                            }

                                            Ok(())
                                        }
                                    }
                                }),
                            )
                            .await
                    };

                    if let Err(err) = walker.await {
                        tracing::warn!("error while walking directory for chmod: {:?}", err);
                    }

                    updated_count += updated_count_arc.load(Ordering::Relaxed);
                }
            }
        }

        ApiResponse::new_serialized(Response {
            updated: updated_count,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
