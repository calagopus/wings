use crate::{
    remote::jwt::BasePayload,
    response::{ApiErrorExt, ApiResponse},
    server::filesystem::ignore_list::IgnoreList,
};
use axum::http::StatusCode;
use serde::{Deserialize, de::DeserializeOwned};

pub trait TokenPayload: DeserializeOwned {
    fn base(&self) -> &BasePayload;
}

impl TokenPayload for BasePayload {
    #[inline]
    fn base(&self) -> &BasePayload {
        self
    }
}

pub fn verify<P: TokenPayload>(
    state: &crate::routes::AppState,
    token: &str,
    scope: &str,
) -> Result<P, ApiResponse> {
    let payload: P = state
        .config
        .jwt
        .verify(token)
        .or_api_error(StatusCode::UNAUTHORIZED, "invalid token")?;

    if let Err(err) = payload.base().validate(&state.config.jwt, Some(scope)) {
        return Err(ApiResponse::error(&format!("invalid token: {err}"))
            .with_status(StatusCode::UNAUTHORIZED));
    }

    Ok(payload)
}

/// Records a use of a single-use token, rejecting it once it has been used up.
pub fn consume(state: &crate::routes::AppState, unique_id: &str) -> Result<(), ApiResponse> {
    if !state.config.jwt.limited_jwt_id(unique_id) {
        return Err(
            ApiResponse::error("token has already been used").with_status(StatusCode::UNAUTHORIZED)
        );
    }

    Ok(())
}

pub async fn server(
    state: &crate::routes::AppState,
    uuid: uuid::Uuid,
) -> Result<crate::server::Server, ApiResponse> {
    state
        .server_manager
        .get_server(uuid)
        .await
        .or_api_error(StatusCode::NOT_FOUND, "server not found")
}

pub fn subject_uuid(payload: &BasePayload) -> Result<uuid::Uuid, ApiResponse> {
    payload
        .subject
        .as_deref()
        .and_then(|subject| subject.parse().ok())
        .or_api_error(StatusCode::UNAUTHORIZED, "invalid token")
}

/// Subuser file restrictions carried by file tokens, meant to be `#[serde(flatten)]`ed.
#[derive(Deserialize)]
pub struct IgnoredFiles {
    #[serde(default)]
    ignored_files: Vec<compact_str::CompactString>,
}

impl IgnoredFiles {
    pub fn compile(&self) -> Result<Option<IgnoreList>, ignore::Error> {
        if self.ignored_files.is_empty() {
            return Ok(None);
        }

        IgnoreList::try_from_lines(self.ignored_files.iter()).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sign(state: &crate::routes::AppState, scope: &str) -> Result<String, anyhow::Error> {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "scope": scope,
            "iss": "panel",
            "aud": ["wings"],
            "exp": now + 60,
            "iat": now,
            "jti": uuid::Uuid::new_v4().to_string(),
        });

        Ok(jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(state.config.load().token.as_bytes()),
        )?)
    }

    // verify
    #[test]
    fn verify_accepts_matching_scope_and_rejects_others() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let token = sign(&state, "download")?;

            let payload = verify::<BasePayload>(&state, &token, "download")
                .map_err(|err| anyhow::anyhow!("valid token rejected: {}", err.status))?;
            assert_eq!(payload.scope, "download");

            let wrong_scope = verify::<BasePayload>(&state, &token, "upload")
                .err()
                .ok_or_else(|| anyhow::anyhow!("token accepted for a foreign scope"))?;
            assert_eq!(wrong_scope.status, StatusCode::UNAUTHORIZED);

            let garbage = verify::<BasePayload>(&state, "not.a.token", "download")
                .err()
                .ok_or_else(|| anyhow::anyhow!("garbage token accepted"))?;
            assert_eq!(garbage.status, StatusCode::UNAUTHORIZED);

            Ok(())
        })
    }

    #[derive(Deserialize)]
    struct FilePayload {
        file: String,
        #[serde(flatten)]
        ignored_files: IgnoredFiles,
    }

    // IgnoredFiles
    #[test]
    fn ignored_files_compile_from_flattened_payload() -> Result<(), anyhow::Error> {
        let absent: FilePayload = serde_json::from_str(r#"{"file":"a"}"#)?;
        assert_eq!(absent.file, "a");
        assert!(absent.ignored_files.compile()?.is_none());

        let present: FilePayload =
            serde_json::from_str(r#"{"file":"a","ignored_files":["*.log"]}"#)?;
        let list = present
            .ignored_files
            .compile()?
            .ok_or_else(|| anyhow::anyhow!("patterns compiled to no list"))?;
        let file = crate::server::filesystem::cap::FileType::File;
        assert!(list.is_ignored(Path::new("foo.log"), file));
        assert!(!list.is_ignored(Path::new("foo.txt"), file));

        let malformed: FilePayload =
            serde_json::from_str(r#"{"file":"a","ignored_files":["foo[.log"]}"#)?;
        assert!(malformed.ignored_files.compile().is_err());

        Ok(())
    }
}
