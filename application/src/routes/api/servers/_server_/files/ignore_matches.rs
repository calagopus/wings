use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        io::abort::AbortGuard,
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::{
            cap::FileType,
            ignore_list::IgnoreList,
            virtualfs::{IsIgnoredFn, VirtualWalkEntry},
        },
    };
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use utoipa::ToSchema;

    const MAX_PATTERNS: usize = 32;
    const MAX_PATTERN_LENGTH: usize = 1024;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[schema(max_items = 32)]
        patterns: Vec<compact_str::CompactString>,
        #[schema(minimum = 1)]
        limit: usize,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        counts: Vec<Option<usize>>,
    }

    pub(super) struct MatchCounter {
        lists: Vec<Option<IgnoreList>>,
        counts: Vec<AtomicUsize>,
        unsaturated: AtomicUsize,
        limit: usize,
    }

    impl MatchCounter {
        pub(super) fn new<S: AsRef<str>>(patterns: &[S], limit: usize) -> Self {
            let lists: Vec<_> = patterns
                .iter()
                .map(|pattern| {
                    let mut builder = IgnoreList::builder();
                    builder.try_push_line(pattern.as_ref()).ok()?;
                    builder.build().ok()
                })
                .collect();

            Self {
                counts: lists.iter().map(|_| AtomicUsize::new(0)).collect(),
                unsaturated: AtomicUsize::new(if limit == 0 {
                    0
                } else {
                    lists.iter().flatten().count()
                }),
                lists,
                limit,
            }
        }

        pub(super) fn saturated(&self) -> bool {
            self.unsaturated.load(Ordering::Relaxed) == 0
        }

        pub(super) fn record(&self, file_type: FileType, path: &Path) {
            for (list, count) in self.lists.iter().zip(&self.counts) {
                let Some(list) = list else {
                    continue;
                };

                if count.load(Ordering::Relaxed) >= self.limit || !list.is_ignored(path, file_type)
                {
                    continue;
                }

                if count.fetch_add(1, Ordering::Relaxed) + 1 == self.limit {
                    self.unsaturated.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        pub(super) fn counts(&self) -> Vec<Option<usize>> {
            self.lists
                .iter()
                .zip(&self.counts)
                .map(|(list, count)| {
                    list.as_ref()
                        .map(|_| count.load(Ordering::Relaxed).min(self.limit))
                })
                .collect()
        }
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
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
        if data.patterns.len() > MAX_PATTERNS {
            return ApiResponse::error("too many patterns").ok();
        }
        if data
            .patterns
            .iter()
            .any(|pattern| pattern.len() > MAX_PATTERN_LENGTH)
        {
            return ApiResponse::error("pattern is too long").ok();
        }

        let ignored = crate::routes::token::ignored(&server, &data.ignored, "root not found")?;

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(&server, Path::new("/"), &ignored)
            .await;

        if !filesystem.is_primary_server_fs() {
            return ApiResponse::error("filesystem does not support this operation")
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok();
        }

        let counter = Arc::new(MatchCounter::new(&data.patterns, data.limit));

        if !counter.saturated() {
            let (_guard, listener) = AbortGuard::new();

            tokio::task::spawn_blocking({
                let counter = Arc::clone(&counter);

                move || {
                    let mut walker = filesystem.walk_dir(&root, IsIgnoredFn::default())?;

                    let result = walker.run_parallel(
                        state.config.load().api.file_search_threads,
                        None,
                        crate::server::filesystem::virtualfs::DirectoryWalkFn::from({
                            let counter = Arc::clone(&counter);

                            move |entry: VirtualWalkEntry| {
                                if crate::unlikely(listener.is_aborted() || counter.saturated()) {
                                    return Err(anyhow::anyhow!("walk stopped"));
                                }

                                let path = entry.path.strip_prefix(&root).unwrap_or(&entry.path);
                                counter.record(entry.file_type, path);

                                Ok(())
                            }
                        }),
                    );

                    if counter.saturated() {
                        return Ok(());
                    }

                    result
                }
            })
            .await??;
        }

        ApiResponse::new_serialized(Response {
            counts: counter.counts(),
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
