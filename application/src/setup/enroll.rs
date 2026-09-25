use crate::remote::ResponseExt;
use anyhow::Context;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Enrollment {
    pub uuid: uuid::Uuid,
    pub token_id: String,
    pub token: String,
    pub remote: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    pub api_port: u16,
    pub sftp_port: u16,
}

impl Enrollment {
    pub fn merge_allowed_origins(&self, existing: &[String]) -> Vec<String> {
        let mut origins = existing.to_vec();
        for origin in &self.allowed_origins {
            if !origins.contains(origin) {
                origins.push(origin.clone());
            }
        }

        origins
    }

    pub fn apply_identity(self, config: &mut crate::config::InnerConfig) {
        config.allowed_origins = self.merge_allowed_origins(&config.allowed_origins);
        config.uuid = self.uuid;
        config.token_id = self.token_id;
        config.token = self.token;
        config.remote = self.remote;
    }
}

pub async fn redeem(
    panel_url: &str,
    code: &str,
    allow_insecure: bool,
) -> Result<Enrollment, anyhow::Error> {
    let panel_url = reqwest::Url::parse(panel_url).context("invalid panel url")?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(format!("calagopus wings/v{}", crate::VERSION))
        .tls_danger_accept_invalid_certs(allow_insecure)
        .build()?;

    let response = client
        .post(format!(
            "{}/api/remote/enroll",
            panel_url.as_str().trim_end_matches('/')
        ))
        .json(&serde_json::json!({ "code": code.trim() }))
        .send()
        .await
        .with_context(|| format!("failed to reach the panel at {panel_url}"))?
        .error_for_remote_status()
        .await?;

    response
        .json()
        .await
        .context("failed to parse enrollment response from the panel")
}
