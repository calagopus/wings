use compact_str::CompactString;

/// PBS backup type used for Calagopus server backups.
///
/// PBS groups are identified by `(backup-type, backup-id)`. Game/host server
/// filesystems are not VMs or containers, so we use the generic `host` type.
pub const BACKUP_TYPE: &str = "host";

/// Builds the deterministic, collision-safe PBS backup-id for a server.
///
/// The id is `{prefix}-{server_uuid}` (prefix defaults to `calagopus`). The
/// server UUID guarantees global uniqueness, and the prefix namespaces
/// Calagopus-created groups so prune/delete can be scoped to them. This never
/// encodes restore-relevant metadata — that lives in a blob written alongside
/// the archive.
pub fn backup_id(prefix: &str, server_uuid: uuid::Uuid) -> CompactString {
    compact_str::format_compact!("{prefix}-{server_uuid}")
}

/// Returns `true` if a backup-id was created by Calagopus with the given prefix.
///
/// Used to scope destructive operations (delete/prune) so they can never touch
/// unrelated PBS backups.
pub fn is_calagopus_id(prefix: &str, backup_id: &str) -> bool {
    backup_id
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|rest| uuid::Uuid::parse_str(rest).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_uuid(value: &str) -> uuid::Uuid {
        uuid::Uuid::parse_str(value).expect("valid uuid literal")
    }

    #[test]
    fn backup_id_is_deterministic_and_scoped() {
        let server = server_uuid("11111111-2222-3333-4444-555555555555");

        let a = backup_id("calagopus", server);
        let b = backup_id("calagopus", server);
        assert_eq!(a, b, "naming must be deterministic for a given server");
        assert_eq!(a, "calagopus-11111111-2222-3333-4444-555555555555");

        assert!(is_calagopus_id("calagopus", &a));
        // Different prefix or non-UUID suffix must not be treated as ours.
        assert!(!is_calagopus_id("other", &a));
        assert!(!is_calagopus_id("calagopus", "calagopus-not-a-uuid"));
        assert!(!is_calagopus_id("calagopus", "vm-100"));
    }

    #[test]
    fn distinct_servers_get_distinct_ids() {
        let a = backup_id(
            "calagopus",
            server_uuid("11111111-2222-3333-4444-555555555555"),
        );
        let b = backup_id(
            "calagopus",
            server_uuid("99999999-2222-3333-4444-555555555555"),
        );
        assert_ne!(a, b);
    }
}
