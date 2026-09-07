use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        config::ApiFileSearchContext,
        io::{
            SafeSliceExt, SafeSliceMutExt, UninterruptedReadExt,
            abort::{AbortGuard, AbortListener, AbortReader},
        },
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState, api::servers::_server_::GetServer},
        server::filesystem::virtualfs::{
            DirectoryWalkFilterFn, DirectoryWalkFn, IsIgnoredFn, VirtualReadableFilesystem,
            VirtualWalkEntry,
        },
    };
    use axum::http::StatusCode;
    use ignore::{gitignore::GitignoreBuilder, overrides::OverrideBuilder};
    use parking_lot::Mutex;
    use serde::{Deserialize, Serialize};
    use std::{
        cell::RefCell,
        io::Read,
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

    struct SearchResults {
        entries: Vec<crate::models::DirectoryEntry>,
        content_matches: Option<Vec<ContentMatches>>,
        context_bytes: usize,
        max_context_bytes: usize,
    }

    impl SearchResults {
        fn push(&mut self, entry: crate::models::DirectoryEntry, matches: Option<ContentMatches>) {
            if let Some(mut matches) = matches
                && let Some(content_matches) = &mut self.content_matches
            {
                matches.file = entry.name.clone();
                limit_context(&mut matches, self.max_context_bytes - self.context_bytes);
                self.context_bytes += matches
                    .blocks
                    .iter()
                    .map(|b| b.content.len())
                    .sum::<usize>();
                content_matches.push(matches);
            }

            self.entries.push(entry);
        }
    }

    fn limit_context(matches: &mut ContentMatches, mut remaining: usize) {
        matches.blocks.retain(|block| {
            if block.content.len() > remaining {
                matches.truncated = true;
                false
            } else {
                remaining -= block.content.len();
                true
            }
        });
    }

    enum Matcher {
        Exact(Box<memchr::memmem::Finder<'static>>),
        CaseInsensitive(aho_corasick::AhoCorasick),
    }

    struct Needle {
        matcher: Matcher,
        len: usize,
    }

    impl Needle {
        fn new(substr: &str, case_insensitive: bool) -> Result<Self, anyhow::Error> {
            let needs_folding =
                case_insensitive && substr.bytes().any(|byte| byte.is_ascii_alphabetic());
            let matcher = if needs_folding {
                Matcher::CaseInsensitive(
                    aho_corasick::AhoCorasick::builder()
                        .ascii_case_insensitive(true)
                        .build([substr])?,
                )
            } else {
                Matcher::Exact(Box::new(
                    memchr::memmem::Finder::new(substr.as_bytes()).into_owned(),
                ))
            };

            Ok(Self {
                matcher,
                len: substr.len(),
            })
        }

        #[inline]
        fn find(&self, haystack: &[u8]) -> Option<usize> {
            match &self.matcher {
                Matcher::Exact(finder) => finder.find(haystack),
                Matcher::CaseInsensitive(automaton) => {
                    automaton.find(haystack).map(|found| found.start())
                }
            }
        }

        fn len(&self) -> usize {
            self.len
        }

        fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    enum Scan {
        Binary,
        NoMatch,
        Match(Option<ContentMatches>),
    }

    fn search_in_stream(
        reader: &mut (dyn std::io::Read + Unpin + Send),
        needle: &Needle,
        head: &mut [u8],
    ) -> Result<(Scan, usize), std::io::Error> {
        let needle_len = needle.len();

        SEARCH_SCRATCH.with(|scratch| {
            let mut buffer = scratch.borrow_mut();
            let required = std::cmp::max(crate::BUFFER_SIZE, needle_len) + needle_len;
            if buffer.len() < required {
                buffer.resize(required, 0);
            }

            let mut valid_bytes = 0;
            let mut head_len = None;

            loop {
                let bytes_read = reader.read_uninterrupted(
                    buffer.get_slice_mut(valid_bytes..valid_bytes + crate::BUFFER_SIZE)?,
                )?;
                let data_end = valid_bytes + bytes_read;

                let head_len = match head_len {
                    Some(head_len) => head_len,
                    None => {
                        let len = data_end.min(head.len());
                        head.get_slice_mut(..len)?
                            .copy_from_slice(buffer.get_slice(..len)?);
                        if !crate::utils::is_valid_utf8_slice(head.get_slice(..len)?) {
                            return Ok((Scan::Binary, len));
                        }
                        if needle.is_empty() {
                            return Ok((Scan::Match(None), len));
                        }

                        *head_len.insert(len)
                    }
                };

                if crate::unlikely(bytes_read == 0) {
                    return Ok((Scan::NoMatch, head_len));
                }

                if crate::unlikely(needle.find(buffer.get_slice(..data_end)?).is_some()) {
                    return Ok((Scan::Match(None), head_len));
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

    fn search_with_context(
        reader: &mut impl Read,
        needle: &Needle,
        context: &MatchContext,
        max_size: u64,
        size: u64,
        max_context_bytes: usize,
        head: &mut [u8],
    ) -> std::io::Result<(Scan, usize)> {
        let max_size = usize::try_from(max_size)
            .ok()
            .filter(|size| *size < isize::MAX as usize)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "search size is too large")
            })?;
        let mut bytes = Vec::with_capacity(size.min(max_size as u64) as usize + 1);
        reader.take(max_size as u64 + 1).read_to_end(&mut bytes)?;

        let head_len = bytes.len().min(head.len());
        head.get_slice_mut(..head_len)?
            .copy_from_slice(bytes.get_slice(..head_len)?);
        if !crate::utils::is_valid_utf8_slice(head.get_slice(..head_len)?) {
            return Ok((Scan::Binary, head_len));
        }

        let mut truncated = bytes.len() > max_size;
        bytes.truncate(max_size);

        let complete_end = if truncated {
            memchr::memrchr(b'\n', &bytes).map_or(0, |offset| offset + 1)
        } else {
            bytes.len()
        };
        let mut spans = Vec::new();
        let mut cursor = 0;

        while let Some(offset) = needle.find(bytes.get_slice(cursor..)?) {
            if spans.len() == context.max_matches {
                truncated = true;
                break;
            }

            let start = cursor + offset;
            spans.push((start, start + needle.len()));
            cursor = start + 1;
        }

        if spans.is_empty() {
            return Ok((Scan::NoMatch, head_len));
        }

        let mut windows: Vec<(usize, usize)> = Vec::new();
        for &(start, end) in &spans {
            if end > complete_end {
                truncated = true;
                continue;
            }

            let window_start = memchr::memchr_iter(b'\n', bytes.get_slice(..start)?)
                .rev()
                .nth(context.before)
                .map_or(0, |offset| offset + 1);
            let window_end = memchr::memchr_iter(b'\n', bytes.get_slice(end - 1..complete_end)?)
                .nth(context.after)
                .map_or(complete_end, |offset| end + offset);

            if let Some((_, previous_end)) = windows.last_mut()
                && window_start <= *previous_end
            {
                *previous_end = (*previous_end).max(window_end);
            } else {
                windows.push((window_start, window_end));
            }
        }

        let mut result = ContentMatches {
            file: compact_str::CompactString::default(),
            truncated,
            blocks: Vec::new(),
        };
        let mut remaining = max_context_bytes.min(bytes.len());
        let mut line_cursor = 0;
        let mut line_number = 1;

        for (start, end) in windows {
            if end - start > remaining {
                result.truncated = true;
                continue;
            }

            let content = match std::str::from_utf8(bytes.get_slice(start..end)?) {
                Ok(content) => content,
                Err(_) => {
                    result.truncated = true;
                    continue;
                }
            };
            line_number +=
                memchr::memchr_iter(b'\n', bytes.get_slice(line_cursor..start)?).count() as u64;
            line_cursor = start;
            let end_line = line_number
                + memchr::memchr_iter(b'\n', content.as_bytes()).count() as u64
                - u64::from(content.ends_with('\n'));
            let matches = spans
                .iter()
                .filter_map(|&(match_start, match_end)| {
                    (match_start >= start && match_end <= end).then_some(MatchSpan {
                        start_byte: match_start.saturating_sub(start),
                        end_byte: match_end.saturating_sub(start),
                    })
                })
                .collect();
            remaining -= content.len();
            result.blocks.push(MatchBlock {
                start_line: line_number,
                end_line,
                content: content.to_owned(),
                matches,
            });
        }

        Ok((Scan::Match(Some(result)), head_len))
    }

    fn open_walked_file(
        entry: &VirtualWalkEntry,
        filesystem: &dyn VirtualReadableFilesystem,
        listener: &AbortListener,
    ) -> Option<Box<dyn Read + Send>> {
        let reader: Box<dyn Read + Send> = match entry.open_source() {
            Some(Ok(file)) => Box::new(file),
            Some(Err(_)) => return None,
            None => filesystem.read_file(&entry.path, None).ok()?.reader,
        };

        Some(Box::new(AbortReader::new(reader, listener.clone())))
    }

    fn walked_directory_entry(
        entry: &VirtualWalkEntry,
        filesystem: &dyn VirtualReadableFilesystem,
        metadata: Option<cap_std::fs::Metadata>,
        buffer: &[u8],
        handle: &tokio::runtime::Handle,
    ) -> Result<crate::models::DirectoryEntry, anyhow::Error> {
        let metadata = metadata.or_else(|| entry.source_metadata().and_then(Result::ok));
        if let Some(metadata) = metadata
            && let Some(directory_entry) =
                filesystem.directory_entry_from_metadata(&entry.path, &metadata, Some(buffer))
        {
            return Ok(directory_entry);
        }

        handle.block_on(filesystem.async_directory_entry_buffer(&entry.path, buffer))
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
    pub struct MatchContext {
        before: usize,
        after: usize,
        #[schema(minimum = 1)]
        max_matches: usize,
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
        #[schema(inline)]
        match_context: Option<MatchContext>,

        per_page: usize,
    }

    impl PayloadV2 {
        fn validate_match_context(
            &self,
            limits: &ApiFileSearchContext,
        ) -> Result<(), &'static str> {
            let Some(context) = &self.match_context else {
                return Ok(());
            };

            if context.max_matches == 0 || context.max_matches > limits.max_matches {
                return Err("match count exceeds the configured context search limit");
            }
            if self
                .content_filter
                .as_ref()
                .is_none_or(|filter| filter.query.is_empty())
            {
                return Err("match context requires a nonempty content query");
            }

            Ok(())
        }
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
    struct MatchSpan {
        start_byte: usize,
        end_byte: usize,
    }

    #[derive(ToSchema, Serialize)]
    struct MatchBlock {
        start_line: u64,
        end_line: u64,
        content: String,
        matches: Vec<MatchSpan>,
    }

    #[derive(ToSchema, Serialize)]
    struct ContentMatches {
        file: compact_str::CompactString,
        truncated: bool,
        blocks: Vec<MatchBlock>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        results: &'a [crate::models::DirectoryEntry],
        #[serde(skip_serializing_if = "Option::is_none")]
        content_matches: Option<&'a [ContentMatches]>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
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
        let context_limits = state.config.load().api.file_search_context;
        let include_context = matches!(&data, Payload::V2(data) if data.match_context.is_some());
        if let Payload::V2(data) = &data
            && let Err(err) = data.validate_match_context(&context_limits)
        {
            return ApiResponse::error(err).ok();
        }

        let results_count = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(Mutex::new(SearchResults {
            entries: Vec::new(),
            content_matches: include_context.then(Vec::new),
            context_bytes: 0,
            max_context_bytes: context_limits.max_response_size as usize,
        }));
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

                let needle = match Needle::new(&data.query, true) {
                    Ok(needle) => Arc::new(needle),
                    Err(_) => return ApiResponse::error("invalid query").ok(),
                };

                tokio::task::spawn_blocking({
                    let root = Arc::new(root);
                    let results = Arc::clone(&results);
                    let listener = listener.clone();

                    move || {
                        let mut walker = filesystem.walk_dir(&*root, IsIgnoredFn::default())?;

                        let result = walker.run_parallel(
                            state.config.load().api.file_search_threads,
                            Some(DirectoryWalkFilterFn::from(
                                |file_type: crate::server::filesystem::cap::FileType, _: &Path| {
                                    file_type.is_file()
                                },
                            )),
                            DirectoryWalkFn::from({
                                let handle = tokio::runtime::Handle::current();
                                let filesystem = filesystem.clone();
                                let results_count = Arc::clone(&results_count);
                                let results = Arc::clone(&results);
                                let data = Arc::new(data);
                                let needle = Arc::clone(&needle);
                                let listener = listener.clone();

                                move |entry: VirtualWalkEntry| {
                                    if crate::unlikely(
                                        listener.is_aborted()
                                            || results_count.load(Ordering::Relaxed) >= limit,
                                    ) {
                                        return Err(anyhow::anyhow!("walk stopped"));
                                    }

                                    if entry.path.to_string_lossy().contains(data.query.as_str()) {
                                        let mut directory_entry = walked_directory_entry(
                                            &entry,
                                            &*filesystem,
                                            None,
                                            &[],
                                            &handle,
                                        )?;
                                        directory_entry.name = match entry.path.strip_prefix(&*root)
                                        {
                                            Ok(path) => path.to_string_lossy().into(),
                                            Err(_) => return Ok(()),
                                        };

                                        if results_count.fetch_add(1, Ordering::Relaxed) < limit {
                                            results.lock().push(directory_entry, None);
                                        }
                                        return Ok(());
                                    }

                                    if !data.include_content || !filesystem.is_fast() {
                                        return Ok(());
                                    }

                                    let metadata = match entry.source_metadata() {
                                        Some(Ok(metadata)) => Some(metadata),
                                        Some(Err(_)) => return Ok(()),
                                        None => None,
                                    };
                                    let size = match &metadata {
                                        Some(metadata) => metadata.len(),
                                        None => match filesystem.symlink_metadata(&entry.path) {
                                            Ok(metadata) => metadata.size,
                                            Err(_) => return Ok(()),
                                        },
                                    };

                                    if size > max_size
                                        || (!needle.is_empty() && size < needle.len() as u64)
                                    {
                                        return Ok(());
                                    }

                                    let Some(mut reader) =
                                        open_walked_file(&entry, &*filesystem, &listener)
                                    else {
                                        return Ok(());
                                    };
                                    let mut head = [0; 64];
                                    let (scan, head_len) = search_in_stream(
                                        &mut (&mut reader).take(max_size),
                                        &needle,
                                        &mut head,
                                    )?;
                                    if !matches!(scan, Scan::Match(_)) {
                                        return Ok(());
                                    }

                                    let mut directory_entry = walked_directory_entry(
                                        &entry,
                                        &*filesystem,
                                        metadata,
                                        head.get_slice(..head_len)?,
                                        &handle,
                                    )?;
                                    directory_entry.name = match entry.path.strip_prefix(&*root) {
                                        Ok(path) => path.to_string_lossy().into(),
                                        Err(_) => return Ok(()),
                                    };

                                    if results_count.fetch_add(1, Ordering::Relaxed) < limit {
                                        results.lock().push(directory_entry, None);
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
                let ignored: IsIgnoredFn = ignore_builder.build()?.into();

                let needle = match &data.content_filter {
                    Some(cf) => match Needle::new(&cf.query, cf.case_insensitive) {
                        Ok(needle) => Some(Arc::new(needle)),
                        Err(_) => return ApiResponse::error("invalid content query").ok(),
                    },
                    None => None,
                };

                let per_page = data.per_page;

                tokio::task::spawn_blocking({
                    let root = Arc::new(root);
                    let results = Arc::clone(&results);
                    let listener = listener.clone();

                    move || {
                        let mut walker = filesystem.walk_dir(&*root, ignored)?;

                        let result = walker.run_parallel(
                            state.config.load().api.file_search_threads,
                            Some(DirectoryWalkFilterFn::from({
                                let path_includes = Arc::clone(&path_includes);

                                move |file_type: crate::server::filesystem::cap::FileType,
                                      path: &Path| {
                                    file_type.is_file()
                                        && (!has_path_includes
                                            || path_includes.matched(path, false).is_whitelist())
                                }
                            })),
                            DirectoryWalkFn::from({
                                let handle = tokio::runtime::Handle::current();
                                let filesystem = filesystem.clone();
                                let results_count = Arc::clone(&results_count);
                                let results = Arc::clone(&results);
                                let data = Arc::new(data);
                                let root = Arc::clone(&root);
                                let needle = needle.clone();
                                let listener = listener.clone();

                                move |entry: VirtualWalkEntry| {
                                    if crate::unlikely(
                                        listener.is_aborted()
                                            || results_count.load(Ordering::Relaxed)
                                                >= data.per_page,
                                    ) {
                                        return Err(anyhow::anyhow!("walk stopped"));
                                    }

                                    let mut metadata = None;
                                    let size = if data.size_filter.is_some()
                                        || data.content_filter.is_some()
                                    {
                                        match entry.source_metadata() {
                                            Some(Ok(source_metadata)) => {
                                                let size = source_metadata.len();
                                                metadata = Some(source_metadata);
                                                size
                                            }
                                            Some(Err(_)) => return Ok(()),
                                            None => {
                                                match filesystem.symlink_metadata(&entry.path) {
                                                    Ok(metadata) => metadata.size,
                                                    Err(_) => return Ok(()),
                                                }
                                            }
                                        }
                                    } else {
                                        0
                                    };

                                    if let Some(size_filter) = &data.size_filter
                                        && !(size_filter.min..size_filter.max).contains(&size)
                                    {
                                        return Ok(());
                                    }

                                    let mut content_matches = None;
                                    let mut head = [0; 128];
                                    let buffer = if let Some(content_filter) = &data.content_filter
                                        && let Some(needle) = &needle
                                        && filesystem.is_fast()
                                        && (size <= content_filter.max_search_size
                                            || content_filter.include_unmatched)
                                    {
                                        if size <= content_filter.max_search_size {
                                            if !needle.is_empty() && size < needle.len() as u64 {
                                                return Ok(());
                                            }

                                            let Some(mut reader) =
                                                open_walked_file(&entry, &*filesystem, &listener)
                                            else {
                                                return Ok(());
                                            };
                                            let (scan, head_len) = match &data.match_context {
                                                Some(context) => search_with_context(
                                                    &mut reader,
                                                    needle,
                                                    context,
                                                    content_filter.max_search_size,
                                                    size,
                                                    context_limits.max_response_size as usize,
                                                    &mut head,
                                                )?,
                                                None => search_in_stream(
                                                    &mut (&mut reader)
                                                        .take(content_filter.max_search_size),
                                                    needle,
                                                    &mut head,
                                                )?,
                                            };
                                            match scan {
                                                Scan::Match(matches) => content_matches = matches,
                                                Scan::Binary | Scan::NoMatch => return Ok(()),
                                            }

                                            head.get_slice(..head_len)?
                                        } else {
                                            let Some(mut reader) =
                                                open_walked_file(&entry, &*filesystem, &listener)
                                            else {
                                                return Ok(());
                                            };
                                            let head_len =
                                                match reader.read_uninterrupted(&mut head) {
                                                    Ok(head_len) => head_len,
                                                    Err(_) => return Ok(()),
                                                };

                                            head.get_slice(..head_len)?
                                        }
                                    } else if data
                                        .content_filter
                                        .as_ref()
                                        .is_some_and(|cf| !cf.include_unmatched)
                                    {
                                        return Ok(());
                                    } else if filesystem.is_fast() {
                                        let Some(mut reader) =
                                            open_walked_file(&entry, &*filesystem, &listener)
                                        else {
                                            return Ok(());
                                        };
                                        let head_len = match reader.read_uninterrupted(&mut head) {
                                            Ok(head_len) => head_len,
                                            Err(_) => return Ok(()),
                                        };

                                        head.get_slice(..head_len)?
                                    } else {
                                        &[]
                                    };

                                    let mut directory_entry = walked_directory_entry(
                                        &entry,
                                        &*filesystem,
                                        metadata,
                                        buffer,
                                        &handle,
                                    )?;
                                    directory_entry.name = match entry.path.strip_prefix(&*root) {
                                        Ok(path) => path.to_string_lossy().into(),
                                        Err(_) => return Ok(()),
                                    };

                                    if results_count.fetch_add(1, Ordering::Relaxed) < data.per_page
                                    {
                                        results.lock().push(directory_entry, content_matches);
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

        let results = results.lock();
        ApiResponse::new_serialized(Response {
            results: &results.entries,
            content_matches: results.content_matches.as_deref(),
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
