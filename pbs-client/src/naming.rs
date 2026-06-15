use compact_str::CompactString;

pub const BACKUP_TYPE: &str = "host";

pub fn backup_id(prefix: &str, server_uuid: uuid::Uuid) -> CompactString {
    compact_str::format_compact!("{prefix}-{server_uuid}")
}

pub fn is_calagopus_id(prefix: &str, backup_id: &str) -> bool {
    backup_id
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|rest| uuid::Uuid::parse_str(rest).is_ok())
}
