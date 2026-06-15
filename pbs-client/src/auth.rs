use super::config::PbsConfig;

pub fn authorization_header(config: &PbsConfig) -> String {
    format!(
        "PBSAPIToken={}!{}:{}",
        config.username, config.token_name, config.token_secret
    )
}
