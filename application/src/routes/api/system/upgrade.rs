use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        io::SafeDigestExt,
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, GetState},
    };
    use axum::http::{HeaderMap, HeaderName, StatusCode};
    use serde::{Deserialize, Serialize};
    use sha1::Digest;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        url: compact_str::CompactString,
        headers: HashMap<compact_str::CompactString, compact_str::CompactString>,
        sha256: compact_str::CompactString,

        restart_command: compact_str::CompactString,
        restart_command_args: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        applied: bool,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = ACCEPTED, body = inline(Response)),
        (status = CONFLICT, body = inline(ApiError)),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        if !matches!(state.container_type, crate::routes::AppContainerType::None) {
            return ApiResponse::error(
                "upgrades are not supported in containerized environments (yet)",
            )
            .with_status(StatusCode::BAD_REQUEST)
            .ok();
        }

        if state.config.load().ignore_panel_wings_upgrades {
            return ApiResponse::new_serialized(Response { applied: false }).ok();
        }

        let current_exe = std::env::current_exe()?;
        let current_exe_parent = match current_exe.parent() {
            Some(parent) => parent,
            None => {
                return ApiResponse::error("unable to find parent of current exe")
                    .with_status(StatusCode::BAD_REQUEST)
                    .ok();
            }
        };
        let current_exe_filename = match current_exe.file_name() {
            Some(filename) => filename,
            None => {
                return ApiResponse::error("unable to find file name of current exe")
                    .with_status(StatusCode::BAD_REQUEST)
                    .ok();
            }
        };

        let tmp_file =
            current_exe_parent.join(format!("{}.upgrade", current_exe_filename.display()));

        let mut headers = HeaderMap::new();
        headers.reserve(data.headers.len());

        for (key, value) in data.headers {
            headers.insert(
                match HeaderName::try_from(key.as_str()) {
                    Ok(v) => v,
                    Err(_) => continue,
                },
                match value.parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                },
            );
        }

        let client = reqwest::Client::builder()
            .user_agent("Pterodactyl Panel (https://pterodactyl.io)")
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()?;

        let mut response = client
            .get(data.url.as_str())
            .headers(headers)
            .send()
            .await
            .map_err(|err| err.without_url())?;
        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true).read(true);
        #[cfg(unix)]
        options.mode(0o766);
        let mut file = options.open(&tmp_file).await?;

        while let Some(chunk) = response.chunk().await.map_err(|err| err.without_url())? {
            file.write_all(&chunk).await?;
        }

        file.sync_all().await?;
        drop(response);

        file.seek(std::io::SeekFrom::Start(0)).await?;

        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0; crate::BUFFER_SIZE];

        loop {
            match file.read(&mut buffer).await? {
                0 => break,
                bytes_read => hasher.safe_update(&buffer, bytes_read)?,
            }
        }

        drop(file);

        if hex::encode(hasher.finalize()) != data.sha256 {
            tokio::fs::remove_file(tmp_file).await.ok();

            return ApiResponse::error("downloaded file does not match provided sha256")
                .with_status(StatusCode::CONFLICT)
                .ok();
        }

        tokio::spawn(async move {
            let run = async || -> Result<(), anyhow::Error> {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                tokio::fs::rename(tmp_file, current_exe).await?;

                #[allow(clippy::zombie_processes)]
                std::process::Command::new(data.restart_command)
                    .args(data.restart_command_args)
                    .spawn()?;

                Ok(())
            };

            if let Err(err) = run().await {
                tracing::error!("error while upgrading binary: {:?}", err)
            }
        });

        ApiResponse::new_serialized(Response { applied: true })
            .with_status(StatusCode::ACCEPTED)
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
