use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod ws;

fn log_file_path(state: &State, file: &str) -> Option<std::path::PathBuf> {
    if !crate::utils::is_single_component_file_name(file) {
        return None;
    }

    Some(
        state
            .config
            .resolve_as_path(|cfg| &cfg.system.log_directory)
            .join(file),
    )
}

mod get {
    use crate::{
        io::compression::{CompressionType, reader::AsyncCompressionReader},
        response::{ApiErrorExt, ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::{
        extract::{Path, Query},
        http::StatusCode,
    };
    use serde::Deserialize;
    use tokio::io::AsyncRead;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        lines: Option<usize>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = String),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        (
            "file" = String,
            description = "The log file name",
            example = "wings.log",
        ),
        (
            "lines" = Option<usize>, Query,
            description = "The number of lines to tail from the log file",
            example = "100",
        ),
    ))]
    pub async fn route(
        state: GetState,
        Path(file): Path<compact_str::CompactString>,
        Query(params): Query<Params>,
    ) -> ApiResponseResult {
        let opened = match super::log_file_path(&state, &file) {
            Some(path) => tokio::fs::File::open(path).await.ok(),
            None => None,
        };

        let mut opened = opened.or_api_error(StatusCode::NOT_FOUND, "log file not found")?;

        let lines = params.lines.map(|n| n.min(crate::io::tail::LINES_CAP));

        let reader: Box<dyn AsyncRead + Send + Unpin> = match CompressionType::from_file_name(&file)
        {
            CompressionType::None => {
                if let Some(lines) = lines {
                    opened = crate::io::tail::async_tail(opened, lines).await?;
                }

                Box::new(opened)
            }
            compression_type => {
                let reader = AsyncCompressionReader::new_mt(
                    opened.into_std().await,
                    compression_type,
                    state.config.load().api.file_decompression_threads,
                );

                if let Some(lines) = lines {
                    Box::new(crate::io::tail::async_tail_stream(reader, lines).await?)
                } else {
                    Box::new(reader)
                }
            }
        };

        ApiResponse::new_stream(reader)
            .with_header("Content-Type", "text/plain")
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .nest("/ws", ws::router(state))
        .with_state(state.clone())
}
