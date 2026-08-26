use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        io::{SafeDigestExt, SafeSliceExt, SafeWriteExt},
        response::{ApiResponse, ApiResponseResult},
        routes::api::servers::_server_::GetServer,
    };
    use axum::http::StatusCode;
    use axum_extra::extract::Query;
    use compact_str::ToCompactString;
    use serde::{Deserialize, Serialize};
    use sha1::Digest;
    use std::{collections::HashMap, path::Path};
    use tokio::io::{AsyncReadExt, BufReader};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    #[schema(rename_all = "lowercase")]
    pub enum Algorithm {
        Md5,
        Crc32,
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Curseforge,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct Params {
        algorithm: Algorithm,
        #[serde(default)]
        root: compact_str::CompactString,
        files: Vec<compact_str::CompactString>,

        #[serde(default)]
        ignored: Vec<compact_str::CompactString>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        fingerprints: HashMap<compact_str::CompactString, compact_str::CompactString>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
        (
            "algorithm" = Algorithm, Query,
            description = "The algorithm to use for the fingerprint",
        ),
        (
            "files" = Vec<String>, Query,
            description = "The list of files to fingerprint",
        ),
        (
            "ignored" = Vec<String>, Query,
            description = "Additional ignored files",
        ),
    ))]
    pub async fn route(server: GetServer, Query(data): Query<Params>) -> ApiResponseResult {
        let ignored = match crate::server::filesystem::RequestIgnored::compile(&data.ignored) {
            Ok(ignored) => ignored,
            Err(err) => {
                tracing::error!(
                    server = %server.uuid,
                    "rejecting request, subuser ignored files cannot be compiled: {:#?}",
                    err
                );

                return ApiResponse::error("file not found")
                    .with_status(StatusCode::NOT_FOUND)
                    .ok();
            }
        };

        let mut fingerprint_handles = Vec::new();
        fingerprint_handles.reserve_exact(data.files.len());

        for path_raw in data.files {
            let path = Path::new(&data.root).join(&path_raw);

            let parent = match path.parent() {
                Some(parent) => parent,
                None => continue,
            };

            let file_name = match path.file_name() {
                Some(name) => name,
                None => continue,
            };

            let (path, filesystem) = server
                .filesystem
                .resolve_readable_fs_ignoring(&server, parent, &ignored)
                .await;
            let path = path.join(file_name);

            let metadata = match filesystem.async_metadata(&path).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if !metadata.file_type.is_file() {
                continue;
            }

            let file_read = match filesystem.async_read_file(&path, None).await {
                Ok(file) => file,
                Err(_) => continue,
            };
            let mut file = BufReader::new(file_read.reader);

            let mut buffer = vec![0; crate::BUFFER_SIZE];

            fingerprint_handles.push(async move {
                Ok::<_, anyhow::Error>((
                    path_raw,
                    match data.algorithm {
                        Algorithm::Md5 => {
                            let mut hasher = md5::Context::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if bytes_read == 0 {
                                    break;
                                }

                                hasher.safe_write_all(&buffer, bytes_read)?;
                            }

                            compact_str::format_compact!("{:x}", hasher.finalize())
                        }
                        Algorithm::Crc32 => {
                            let mut hasher = crc32fast::Hasher::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                hasher.update(buffer.get_slice(..bytes_read)?);
                            }

                            compact_str::format_compact!("{:x}", hasher.finalize())
                        }
                        Algorithm::Sha1 => {
                            let mut hasher = sha1::Sha1::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                hasher.safe_update(&buffer, bytes_read)?;
                            }

                            hex::encode(hasher.finalize()).into()
                        }
                        Algorithm::Sha224 => {
                            let mut hasher = sha2::Sha224::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                hasher.safe_update(&buffer, bytes_read)?;
                            }

                            hex::encode(hasher.finalize()).into()
                        }
                        Algorithm::Sha256 => {
                            let mut hasher = sha2::Sha256::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                hasher.safe_update(&buffer, bytes_read)?;
                            }

                            hex::encode(hasher.finalize()).into()
                        }
                        Algorithm::Sha384 => {
                            let mut hasher = sha2::Sha384::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                hasher.safe_update(&buffer, bytes_read)?;
                            }

                            hex::encode(hasher.finalize()).into()
                        }
                        Algorithm::Sha512 => {
                            let mut hasher = sha2::Sha512::new();

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                hasher.safe_update(&buffer, bytes_read)?;
                            }

                            hex::encode(hasher.finalize()).into()
                        }
                        Algorithm::Curseforge => {
                            #[inline]
                            fn is_ignored_in_curseforge_fingerprint(b: u8) -> bool {
                                b == b'\t' || b == b'\n' || b == b'\r' || b == b' '
                            }

                            const MULTIPLEX: u32 = 1540483477;

                            let mut normalized_length: u32 = 0;

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                for &b in buffer.get_slice(..bytes_read)? {
                                    if !is_ignored_in_curseforge_fingerprint(b) {
                                        normalized_length = normalized_length.wrapping_add(1);
                                    }
                                }
                            }

                            drop(file);
                            let file_read = filesystem.async_read_file(&path, None).await?;
                            let mut file = BufReader::new(file_read.reader);

                            let mut num2: u32 = 1 ^ normalized_length;
                            let mut num3: u32 = 0;
                            let mut num4: u32 = 0;

                            loop {
                                let bytes_read = file.read(&mut buffer).await?;
                                if crate::unlikely(bytes_read == 0) {
                                    break;
                                }

                                for &b in buffer.get_slice(..bytes_read)? {
                                    if !is_ignored_in_curseforge_fingerprint(b) {
                                        num3 |= (b as u32) << num4;
                                        num4 = num4.wrapping_add(8);

                                        if num4 == 32 {
                                            let num6 = num3.wrapping_mul(MULTIPLEX);
                                            let num7 =
                                                (num6 ^ (num6 >> 24)).wrapping_mul(MULTIPLEX);

                                            num2 = num2.wrapping_mul(MULTIPLEX) ^ num7;
                                            num3 = 0;
                                            num4 = 0;
                                        }
                                    }
                                }
                            }

                            if num4 > 0 {
                                num2 = (num2 ^ num3).wrapping_mul(MULTIPLEX);
                            }

                            let num6 = (num2 ^ (num2 >> 13)).wrapping_mul(MULTIPLEX);
                            let result = num6 ^ (num6 >> 15);

                            result.to_compact_string()
                        }
                    },
                ))
            });
        }

        let joined_fingerprints = futures::future::join_all(fingerprint_handles).await;

        ApiResponse::new_serialized(Response {
            fingerprints: joined_fingerprints
                .into_iter()
                .filter_map(Result::ok)
                .collect(),
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
