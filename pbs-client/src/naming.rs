use compact_str::CompactString;

pub const BACKUP_TYPE: &str = "host";

pub fn backup_id(prefix: &str, group_id: &str) -> CompactString {
    compact_str::format_compact!("{prefix}-{group_id}")
}

pub fn is_calagopus_id(prefix: &str, backup_id: &str) -> bool {
    backup_id
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .map(|rest| rest.strip_suffix("-db").unwrap_or(rest))
        .is_some_and(|rest| uuid::Uuid::parse_str(rest).is_ok())
}
