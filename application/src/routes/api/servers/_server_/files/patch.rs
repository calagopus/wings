use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
        server::filesystem::patch::{Patch, PatchError, PatchFormat},
    };
    use axum::http::StatusCode;
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use utoipa::ToSchema;

    fn strip_default() -> usize {
        1
    }

    #[derive(ToSchema, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "type")]
    pub enum Source {
        Inline { data: String },
        File { path: compact_str::CompactString },
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[serde(default)]
        root: compact_str::CompactString,
        format: PatchFormat,
        source: Source,
        file: Option<compact_str::CompactString>,
        #[serde(default = "strip_default")]
        strip: usize,
        user: Option<uuid::Uuid>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        patched: usize,
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
        server: GetServer,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        let ignored = crate::routes::token::ignored(&server, &data.ignored, "file not found")?;
        let root = Path::new(&data.root);

        let result = async {
            let contents = match data.source {
                Source::Inline { data: inline } if data.format == PatchFormat::Bsdiff => {
                    base64::engine::general_purpose::STANDARD
                        .decode(inline)
                        .map_err(|_| {
                            PatchError::Failed("inline bsdiff patches must be base64".into())
                        })?
                }
                Source::Inline { data: inline } => inline.into_bytes(),
                Source::File { path } => {
                    Patch::read_file(&server, root, Path::new(&path), &ignored).await?
                }
            };

            Patch::parse(data.format, &contents, data.file.as_deref(), data.strip)?
                .apply(&server, root, &ignored, data.user)
                .await
        }
        .await;

        match result {
            Ok(patched) => ApiResponse::new_serialized(Response { patched }).ok(),
            Err(PatchError::NotFound(message)) => ApiResponse::error(message)
                .with_status(StatusCode::NOT_FOUND)
                .ok(),
            Err(PatchError::Failed(message)) => ApiResponse::error(&message)
                .with_status(StatusCode::EXPECTATION_FAILED)
                .ok(),
            Err(PatchError::Internal(err)) => Err(err.into()),
        }
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
