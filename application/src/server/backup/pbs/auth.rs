use super::config::PbsConfig;

/// Builds the value for the `Authorization` header used on every PBS request.
///
/// PBS API tokens authenticate with the scheme:
/// `PBSAPIToken=USER@REALM!TOKENNAME:SECRET`
///
/// The `username` field already carries the realm (e.g. `root@pam`).
///
/// The returned string contains the token secret and must never be logged.
pub fn authorization_header(config: &PbsConfig) -> String {
    format!(
        "PBSAPIToken={}!{}:{}",
        config.username, config.token_name, config.token_secret
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PbsConfig {
        PbsConfig {
            url: "https://10.0.20.148:8007".into(),
            datastore: "daddy".into(),
            namespace: None,
            username: "root@pam".into(),
            token_name: "incus".into(),
            token_secret: "s3cr3t-value".into(),
            fingerprint: "ab".repeat(32).into(),
            backup_id_prefix: None,
        }
    }

    #[test]
    fn header_uses_pbsapitoken_scheme() {
        assert_eq!(
            authorization_header(&config()),
            "PBSAPIToken=root@pam!incus:s3cr3t-value"
        );
    }
}
