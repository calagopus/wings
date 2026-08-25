use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        io::{
            SafeSliceExt, SafeSliceMutExt, UninterruptedReadExt,
            abort::{AbortGuard, AbortReader},
        },
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::virtualfs::{DirectoryWalkFn, VirtualWalkEntry},
    };
    use axum::http::StatusCode;
    use ignore::{gitignore::GitignoreBuilder, overrides::OverrideBuilder};
    use parking_lot::Mutex;
    use serde::{Deserialize, Serialize};
    use std::{
        cell::RefCell,
        io::{BufRead, BufReader, Read},
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use utoipa::ToSchema;

    thread_local! {
        static SEARCH_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    struct Needle {
        finder: memchr::memmem::Finder<'static>,
        case_insensitive: bool,
    }

    impl Needle {
        fn new(substr: &str, case_insensitive: bool) -> Self {
            let bytes = if case_insensitive {
                substr.to_ascii_lowercase().into_bytes()
            } else {
                substr.as_bytes().to_vec()
            };

            Self {
                finder: memchr::memmem::Finder::new(&bytes).into_owned(),
                case_insensitive,
            }
        }

        fn len(&self) -> usize {
            self.finder.needle().len()
        }

        fn is_empty(&self) -> bool {
            self.finder.needle().is_empty()
        }
    }

    fn search_in_stream(
        reader: &mut (dyn std::io::Read + Unpin + Send),
        needle: &Needle,
    ) -> Result<bool, std::io::Error> {
        if needle.is_empty() {
            return Ok(true);
        }

        let needle_len = needle.len();

        SEARCH_SCRATCH.with(|scratch| {
            let mut buffer = scratch.borrow_mut();
            let required = std::cmp::max(crate::BUFFER_SIZE, needle_len) + needle_len;
            if buffer.len() < required {
                buffer.resize(required, 0);
            }

            let mut valid_bytes = 0;

            loop {
                let bytes_read = reader.read_uninterrupted(
                    buffer.get_slice_mut(valid_bytes..valid_bytes + crate::BUFFER_SIZE)?,
                )?;

                if crate::unlikely(bytes_read == 0) {
                    return Ok(false);
                }

                let data_end = valid_bytes + bytes_read;

                if needle.case_insensitive {
                    buffer
                        .get_slice_mut(valid_bytes..data_end)?
                        .make_ascii_lowercase();
                }

                if crate::unlikely(needle.finder.find(buffer.get_slice(..data_end)?).is_some()) {
                    return Ok(true);
                }

                if data_end >= needle_len {
                    let keep_len = needle_len - 1;
                    buffer.copy_within(data_end - keep_len..data_end, 0);
                    valid_bytes = keep_len;
                } else {
                    valid_bytes = data_end;
                }
            }
        })
    }

    #[derive(ToSchema, Deserialize)]
    pub struct PayloadV1 {
        #[serde(default)]
        root: compact_str::CompactString,
        query: compact_str::CompactString,
        #[serde(default)]
        include_content: bool,

        limit: Option<usize>,
        max_size: Option<u64>,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct PathFilter {
        include: Vec<compact_str::CompactString>,
        #[serde(default)]
        exclude: Vec<compact_str::CompactString>,
        #[serde(default)]
        case_insensitive: bool,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct SizeFilter {
        #[serde(default)]
        min: u64,
        max: u64,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct ContentFilter {
        query: compact_str::CompactString,
        max_search_size: u64,
        #[serde(default)]
        include_unmatched: bool,
        #[serde(default)]
        case_insensitive: bool,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct PayloadV2 {
        #[serde(default)]
        root: compact_str::CompactString,
        #[schema(inline)]
        path_filter: Option<PathFilter>,
        #[schema(inline)]
        size_filter: Option<SizeFilter>,
        #[schema(inline)]
        content_filter: Option<ContentFilter>,

        per_page: usize,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Payload {
        V1(PayloadV1),
        V2(PayloadV2),
    }

    impl utoipa::PartialSchema for Payload {
        fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
            PayloadV2::schema()
        }
    }

    impl utoipa::ToSchema for Payload {
        fn name() -> std::borrow::Cow<'static, str> {
            PayloadV2::name()
        }

        fn schemas(
            schemas: &mut Vec<(
                String,
                utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
            )>,
        ) {
            PayloadV2::schemas(schemas)
        }
    }

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        results: &'a [crate::models::DirectoryEntry],
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
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
        let results_count = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(Mutex::new(Vec::new()));
        let (_guard, listener) = AbortGuard::new();

        match data {
            Payload::V1(data) => {
                let limit = data.limit.unwrap_or(100).min(500);
                let max_size = data.max_size.unwrap_or(512 * 1024);

                let (root, filesystem) = server
                    .filesystem
                    .resolve_readable_fs(&server, Path::new(&data.root))
                    .await;

                let metadata = filesystem.async_metadata(&root).await;
                if !metadata.map_or(true, |m| m.file_type.is_dir()) {
                    return ApiResponse::error("root is not a directory")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }

                let ignored = if filesystem.is_primary_server_fs() {
                    server.filesystem.get_ignored().into()
                } else {
                    Default::default()
                };

                let needle = Arc::new(Needle::new(&data.query, true));

                tokio::task::spawn_blocking({
                    let root = Arc::new(root);
                    let results = Arc::clone(&results);
                    let listener = listener.clone();

                    move || {
                        let mut walker = filesystem.walk_dir(&*root, ignored)?;

                        let result = walker.run_multithreaded(
                            state.config.load().api.file_search_threads,
                            DirectoryWalkFn::from({
                                let handle = tokio::runtime::Handle::current();
                                let filesystem = filesystem.clone();
                                let results_count = Arc::clone(&results_count);
                                let results = Arc::clone(&results);
                                let data = Arc::new(data);
                                let needle = Arc::clone(&needle);
                                let listener = listener.clone();

                                move |entry: VirtualWalkEntry| {
                                    let file_type = entry.file_type;
                                    let path = entry.path;

                                    if crate::unlikely(
                                        listener.is_aborted()
                                            || results_count.load(Ordering::Relaxed) >= limit,
                                    ) {
                                        return Err(anyhow::anyhow!("walk stopped"));
                                    }

                                    if !file_type.is_file() {
                                        return Ok(());
                                    }

                                    if path.to_string_lossy().contains(data.query.as_str()) {
                                        let mut entry = handle
                                            .block_on(filesystem.async_directory_entry(&path))?;
                                        entry.name = match path.strip_prefix(&*root) {
                                            Ok(path) => path.to_string_lossy().into(),
                                            Err(_) => return Ok(()),
                                        };

                                        if results_count.fetch_add(1, Ordering::Relaxed) < limit {
                                            results.lock().push(entry);
                                        }
                                        return Ok(());
                                    }

                                    if !data.include_content || !filesystem.is_fast() {
                                        return Ok(());
                                    }

                                    let metadata = match filesystem.symlink_metadata(&path) {
                                        Ok(metadata) => metadata,
                                        Err(_) => return Ok(()),
                                    };

                                    if metadata.size > max_size {
                                        return Ok(());
                                    }

                                    let file_read = match filesystem.read_file(&path, None) {
                                        Ok(reader) => reader,
                                        Err(_) => return Ok(()),
                                    };
                                    let reader =
                                        AbortReader::new(file_read.reader, listener.clone());
                                    let mut reader = BufReader::new(reader);
                                    let buffer = match reader.fill_buf() {
                                        Ok(buffer) => {
                                            match buffer.get_slice(..buffer.len().min(64)) {
                                                Ok(slice) => slice.to_vec(),
                                                Err(_) => return Ok(()),
                                            }
                                        }
                                        Err(_) => return Ok(()),
                                    };

                                    if !crate::utils::is_valid_utf8_slice(&buffer) {
                                        return Ok(());
                                    }

                                    if search_in_stream(&mut (&mut reader).take(max_size), &needle)?
                                    {
                                        let mut entry = handle.block_on(
                                            filesystem.async_directory_entry_buffer(&path, &buffer),
                                        )?;
                                        entry.name = match path.strip_prefix(&*root) {
                                            Ok(path) => path.to_string_lossy().into(),
                                            Err(_) => return Ok(()),
                                        };

                                        if results_count.fetch_add(1, Ordering::Relaxed) < limit {
                                            results.lock().push(entry);
                                        }
                                    }

                                    Ok(())
                                }
                            }),
                        );

                        if results_count.load(Ordering::Relaxed) >= limit {
                            return Ok(());
                        }

                        result
                    }
                })
                .await??;
            }
            Payload::V2(data) => {
                let (root, filesystem) = server
                    .filesystem
                    .resolve_readable_fs(&server, Path::new(&data.root))
                    .await;

                let metadata = filesystem.async_metadata(&root).await;
                if !metadata.map_or(true, |m| m.file_type.is_dir()) {
                    return ApiResponse::error("root is not a directory")
                        .with_status(StatusCode::NOT_FOUND)
                        .ok();
                }

                let mut override_builder = OverrideBuilder::new("/");
                let mut ignore_builder = GitignoreBuilder::new("/");

                if let Some(path_filter) = &data.path_filter {
                    override_builder.case_insensitive(path_filter.case_insensitive)?;
                    ignore_builder.case_insensitive(path_filter.case_insensitive)?;

                    for glob in &path_filter.include {
                        override_builder.add(glob).ok();
                    }
                    for glob in &path_filter.exclude {
                        ignore_builder.add_line(None, glob).ok();
                    }
                }

                let has_path_includes = data
                    .path_filter
                    .as_ref()
                    .is_some_and(|pf| !pf.include.is_empty());
                let path_includes = Arc::new(override_builder.build()?);

                let ignored = if filesystem.is_primary_server_fs() {
                    vec![server.filesystem.get_ignored(), ignore_builder.build()?].into()
                } else {
                    ignore_builder.build()?.into()
                };

                let needle = data
                    .content_filter
                    .as_ref()
                    .map(|cf| Arc::new(Needle::new(&cf.query, cf.case_insensitive)));

                let per_page = data.per_page;

                tokio::task::spawn_blocking({
                    let root = Arc::new(root);
                    let results = Arc::clone(&results);
                    let listener = listener.clone();

                    move || {
                        let mut walker = filesystem.walk_dir(&*root, ignored)?;

                        let result = walker.run_multithreaded(
                            state.config.load().api.file_search_threads,
                            DirectoryWalkFn::from({
                                let handle = tokio::runtime::Handle::current();
                                let filesystem = filesystem.clone();
                                let results_count = Arc::clone(&results_count);
                                let results = Arc::clone(&results);
                                let data = Arc::new(data);
                                let root = Arc::clone(&root);
                                let path_includes = Arc::clone(&path_includes);
                                let needle = needle.clone();
                                let listener = listener.clone();

                                move |entry: VirtualWalkEntry| {
                                    let file_type = entry.file_type;
                                    let path = entry.path;

                                    if crate::unlikely(
                                        listener.is_aborted()
                                            || results_count.load(Ordering::Relaxed)
                                                >= data.per_page,
                                    ) {
                                        return Err(anyhow::anyhow!("walk stopped"));
                                    }

                                    if !file_type.is_file() {
                                        return Ok(());
                                    }

                                    if has_path_includes
                                        && !path_includes.matched(&path, false).is_whitelist()
                                    {
                                        return Ok(());
                                    }

                                    let size = if data.size_filter.is_some()
                                        || data.content_filter.is_some()
                                    {
                                        match filesystem.symlink_metadata(&path) {
                                            Ok(metadata) => metadata.size,
                                            Err(_) => return Ok(()),
                                        }
                                    } else {
                                        0
                                    };

                                    if let Some(size_filter) = &data.size_filter
                                        && !(size_filter.min..size_filter.max).contains(&size)
                                    {
                                        return Ok(());
                                    }

                                    let mut local_buffer = [0; 128];
                                    let buffer = if let Some(content_filter) = &data.content_filter
                                        && filesystem.is_fast()
                                        && (size <= content_filter.max_search_size
                                            || content_filter.include_unmatched)
                                    {
                                        let file_read = match filesystem.read_file(&path, None) {
                                            Ok(reader) => reader,
                                            Err(_) => return Ok(()),
                                        };
                                        let reader =
                                            AbortReader::new(file_read.reader, listener.clone());
                                        let mut reader = BufReader::new(reader);
                                        let buffer = match reader.fill_buf() {
                                            Ok(buffer) => buffer,
                                            Err(_) => return Ok(()),
                                        };

                                        let buf_len = buffer.len().min(128);
                                        local_buffer
                                            .get_slice_mut(..buf_len)?
                                            .copy_from_slice(buffer.get_slice(..buf_len)?);

                                        if size <= content_filter.max_search_size {
                                            if !crate::utils::is_valid_utf8_slice(
                                                local_buffer.get_slice(..buf_len)?,
                                            ) {
                                                return Ok(());
                                            }

                                            if let Some(needle) = &needle
                                                && !search_in_stream(
                                                    &mut (&mut reader)
                                                        .take(content_filter.max_search_size),
                                                    needle,
                                                )?
                                            {
                                                return Ok(());
                                            }
                                        }

                                        local_buffer.get_slice(..buf_len)?
                                    } else if data
                                        .content_filter
                                        .as_ref()
                                        .is_some_and(|cf| !cf.include_unmatched)
                                    {
                                        return Ok(());
                                    } else if filesystem.is_fast() {
                                        let mut file_read = match filesystem.read_file(&path, None)
                                        {
                                            Ok(reader) => reader,
                                            Err(_) => return Ok(()),
                                        };
                                        let bytes_read = match file_read
                                            .reader
                                            .read_uninterrupted(&mut local_buffer)
                                        {
                                            Ok(bytes_read) => bytes_read,
                                            Err(_) => return Ok(()),
                                        };

                                        local_buffer.get_slice(..bytes_read)?
                                    } else {
                                        &[]
                                    };

                                    let mut entry = handle.block_on(
                                        filesystem.async_directory_entry_buffer(&path, buffer),
                                    )?;
                                    entry.name = match path.strip_prefix(&*root) {
                                        Ok(path) => path.to_string_lossy().into(),
                                        Err(_) => return Ok(()),
                                    };

                                    if results_count.fetch_add(1, Ordering::Relaxed) < data.per_page
                                    {
                                        results.lock().push(entry);
                                    }

                                    Ok(())
                                }
                            }),
                        );

                        if results_count.load(Ordering::Relaxed) >= per_page {
                            return Ok(());
                        }

                        result
                    }
                })
                .await??;
            }
        }

        ApiResponse::new_serialized(Response {
            results: &results.lock(),
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
