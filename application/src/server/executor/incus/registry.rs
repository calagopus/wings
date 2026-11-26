//! A read-only client for the OCI distribution API.
//!
//! Wings downloads image layers itself so that it can report the same per-layer progress as the
//! docker runtime. Incus then converts the downloaded files into an instance image.

use anyhow::{Context, bail, ensure};
use futures::StreamExt;
use reqwest::{Response, StatusCode, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path, time::Duration};
use tokio::io::AsyncWriteExt;

const MAX_DOCUMENT: usize = 4 * 1024 * 1024;
const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

#[derive(Clone, Debug, Deserialize)]
pub(super) struct Descriptor {
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

impl Descriptor {
    /// The hexadecimal part of a validated digest, which names the downloaded file.
    pub(super) fn hex(&self) -> anyhow::Result<&str> {
        digest_hex(&self.digest)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    manifests: Option<Vec<Descriptor>>,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Option<Vec<Descriptor>>,
}

/// The manifest of one platform's image.
pub(super) struct Manifest {
    pub digest: String,
    pub bytes: Vec<u8>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

pub(super) fn digest_hex(digest: &str) -> anyhow::Result<&str> {
    digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .with_context(|| format!("unsupported OCI digest {digest}"))
}

/// Splits a repository such as `library/alpine:3` into its name and the tag or digest asked for.
pub(super) fn split_repository(repository: &str) -> (&str, &str) {
    if let Some((name, digest)) = repository.split_once('@') {
        let name = match name.rsplit_once(':') {
            Some((name, tag)) if !tag.contains('/') => name,
            _ => name,
        };
        return (name, digest);
    }
    match repository.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => (name, tag),
        _ => (repository, "latest"),
    }
}

/// The parameters of a `WWW-Authenticate` challenge.
fn challenge_parameters(value: &str) -> HashMap<&str, &str> {
    let mut result = HashMap::new();
    let mut rest = value;
    while let Some((key, after)) = rest.split_once('=') {
        let key = key.trim_start_matches([',', ' ']).trim();
        let (value, after) = match after.strip_prefix('"') {
            Some(quoted) => quoted.split_once('"').unwrap_or((quoted, "")),
            None => after.split_once(',').unwrap_or((after, "")),
        };
        result.insert(key, value);
        rest = after;
    }
    result
}

pub(super) struct Registry {
    http: reqwest::Client,
    base: String,
    repository: String,
    credentials: Option<(String, String)>,
    authorization: tokio::sync::RwLock<Option<String>>,
}

impl Registry {
    pub(super) fn new(
        host: &str,
        repository: &str,
        credentials: Option<(String, String)>,
    ) -> anyhow::Result<Self> {
        // Docker Hub serves its API from another name than the one images are known by.
        let host = if host == "docker.io" {
            "registry-1.docker.io"
        } else {
            host
        };
        Ok(Self {
            http: reqwest::Client::builder()
                .https_only(true)
                .connect_timeout(Duration::from_secs(30))
                .read_timeout(Duration::from_secs(120))
                .user_agent(concat!("calagopus-wings/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base: format!("https://{host}/v2/"),
            repository: repository.to_string(),
            credentials,
            authorization: tokio::sync::RwLock::new(None),
        })
    }

    async fn send(&self, url: &str, accept: Option<&str>) -> anyhow::Result<Response> {
        let mut request = self.http.get(url);
        if let Some(accept) = accept {
            request = request.header(header::ACCEPT, accept);
        }
        if let Some(authorization) = self.authorization.read().await.as_deref() {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        Ok(request.send().await?)
    }

    async fn authorize(&self, challenge: &str) -> anyhow::Result<()> {
        let (scheme, parameters) = challenge.split_once(' ').unwrap_or((challenge, ""));
        let authorization = if scheme.eq_ignore_ascii_case("basic") {
            let (username, password) = self
                .credentials
                .as_ref()
                .context("the registry requires credentials")?;
            use base64::Engine;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
            )
        } else if scheme.eq_ignore_ascii_case("bearer") {
            let parameters = challenge_parameters(parameters);
            let realm = parameters
                .get("realm")
                .context("registry token URL missing")?;
            let mut url = url::Url::parse(realm).context("invalid registry token URL")?;
            ensure!(url.scheme() == "https", "registry token URL must use HTTPS");
            {
                let mut query = url.query_pairs_mut();
                if let Some(service) = parameters.get("service") {
                    query.append_pair("service", service);
                }
                query.append_pair("scope", &format!("repository:{}:pull", self.repository));
            }
            let mut request = self.http.get(url);
            if let Some((username, password)) = &self.credentials {
                request = request.basic_auth(username, Some(password));
            }
            let response = request.send().await?;
            ensure!(
                response.status().is_success(),
                "the registry refused to authenticate: {}",
                response.status()
            );
            #[derive(Deserialize)]
            struct Token {
                #[serde(default)]
                token: String,
                #[serde(default)]
                access_token: String,
            }
            let token: Token = serde_json::from_slice(&bounded(response).await?)?;
            let token = if token.token.is_empty() {
                token.access_token
            } else {
                token.token
            };
            ensure!(!token.is_empty(), "the registry returned no token");
            format!("Bearer {token}")
        } else {
            bail!("unsupported registry authentication scheme {scheme}");
        };
        *self.authorization.write().await = Some(authorization);
        Ok(())
    }

    async fn get(&self, path: &str, accept: Option<&str>) -> anyhow::Result<Response> {
        let url = format!("{}{}/{path}", self.base, self.repository);
        let mut response = self.send(&url, accept).await?;
        if response.status() == StatusCode::UNAUTHORIZED
            && let Some(challenge) = response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        {
            self.authorize(&challenge).await?;
            response = self.send(&url, accept).await?;
        }
        ensure!(
            response.status().is_success(),
            "registry request for {} failed: {}",
            self.repository,
            response.status()
        );
        Ok(response)
    }

    async fn document(&self, reference: &str) -> anyhow::Result<(String, Vec<u8>, Document)> {
        let response = self
            .get(&format!("manifests/{reference}"), Some(MANIFEST_TYPES))
            .await?;
        let bytes = bounded(response).await?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if reference.starts_with("sha256:") {
            ensure!(
                digest == reference,
                "the registry returned a manifest that does not match its digest"
            );
        }
        let document = serde_json::from_slice(&bytes).context("decoding the image manifest")?;
        Ok((digest, bytes, document))
    }

    /// The manifest a tag or digest names for this architecture.
    pub(super) async fn manifest(
        &self,
        reference: &str,
        architecture: &str,
    ) -> anyhow::Result<Manifest> {
        let (mut digest, mut bytes, mut document) = self.document(reference).await?;
        if let Some(manifests) = document.manifests.take() {
            let entry = manifests
                .into_iter()
                .find(|entry| {
                    entry.platform.as_ref().is_some_and(|platform| {
                        platform.os == "linux" && platform.architecture == architecture
                    })
                })
                .with_context(|| format!("the image has no linux/{architecture} variant"))?;
            digest_hex(&entry.digest)?;
            (digest, bytes, document) = self.document(&entry.digest).await?;
        }
        let config = document.config.context("unsupported image manifest")?;
        let layers = document.layers.context("unsupported image manifest")?;
        config.hex()?;
        for layer in &layers {
            layer.hex()?;
        }
        Ok(Manifest {
            digest,
            bytes,
            config,
            layers,
        })
    }

    /// Downloads a blob to `destination`, verifying its size and digest.
    pub(super) async fn download(
        &self,
        blob: &Descriptor,
        destination: &Path,
        mut progress: impl FnMut(u64),
    ) -> anyhow::Result<()> {
        let response = self.get(&format!("blobs/{}", blob.digest), None).await?;
        let temporary = destination.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = async {
            let mut file = tokio::fs::File::create(&temporary).await?;
            let mut stream = response.bytes_stream();
            let mut hash = Sha256::new();
            let mut received = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                received += chunk.len() as u64;
                ensure!(
                    received <= blob.size,
                    "a layer is larger than its manifest says"
                );
                hash.update(&chunk);
                file.write_all(&chunk).await?;
                progress(received);
            }
            file.flush().await?;
            ensure!(
                received == blob.size && hex::encode(hash.finalize()) == blob.hex()?,
                "a downloaded layer does not match its digest"
            );
            tokio::fs::rename(&temporary, destination).await?;
            anyhow::Ok(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result
    }
}

/// Reads a response that is expected to be small.
async fn bounded(response: Response) -> anyhow::Result<Vec<u8>> {
    let mut stream = response.bytes_stream();
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            data.len() + chunk.len() <= MAX_DOCUMENT,
            "oversized registry response"
        );
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repositories_split_into_name_and_reference() {
        assert_eq!(
            split_repository("library/alpine"),
            ("library/alpine", "latest")
        );
        assert_eq!(split_repository("a/b:java_21"), ("a/b", "java_21"));
        assert_eq!(split_repository("a/b@sha256:00"), ("a/b", "sha256:00"));
        assert_eq!(split_repository("a/b:1@sha256:00"), ("a/b", "sha256:00"));
    }

    #[test]
    fn challenges_are_parsed() {
        let parameters = challenge_parameters(
            r#"realm="https://auth.example/token",service="registry.example",scope="repository:a/b:pull,push""#,
        );
        assert_eq!(parameters.get("realm"), Some(&"https://auth.example/token"));
        assert_eq!(parameters.get("service"), Some(&"registry.example"));
        assert_eq!(parameters.get("scope"), Some(&"repository:a/b:pull,push"));
    }

    #[test]
    fn only_sha256_digests_name_files() {
        assert!(digest_hex(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(digest_hex("sha256:../../etc").is_err());
        assert!(digest_hex("md5:abc").is_err());
    }
}
