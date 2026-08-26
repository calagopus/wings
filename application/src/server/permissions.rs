use crate::server::filesystem::cap::FileType;
use parking_lot::Mutex;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Permission {
    #[serde(rename = "*")]
    All,
    #[serde(rename = "meta.calagopus")]
    MetaCalagopus,

    #[serde(rename = "websocket.connect")]
    WebsocketConnect,
    #[serde(rename = "control.read-console")]
    ControlReadConsole,
    #[serde(rename = "control.console")]
    ControlConsole,
    #[serde(rename = "control.start")]
    ControlStart,
    #[serde(rename = "control.stop")]
    ControlStop,
    #[serde(rename = "control.restart")]
    ControlRestart,
    #[serde(rename = "admin.websocket.errors")]
    AdminWebsocketErrors,
    #[serde(rename = "admin.websocket.install")]
    AdminWebsocketInstall,
    #[serde(rename = "admin.websocket.transfer")]
    AdminWebsocketTransfer,
    #[serde(rename = "backup.read", alias = "backups.read")]
    BackupRead,
    #[serde(rename = "schedule.read", alias = "schedules.read")]
    ScheduleRead,

    #[serde(rename = "file.read", alias = "files.read")]
    FileRead,
    #[serde(rename = "file.read-content", alias = "files.read-content")]
    FileReadContent,
    #[serde(rename = "file.create", alias = "files.create")]
    FileCreate,
    #[serde(rename = "file.update", alias = "files.update")]
    FileUpdate,
    #[serde(rename = "file.delete", alias = "files.delete")]
    FileDelete,
    #[serde(rename = "file.archive", alias = "files.archive")]
    FileArchive,
    #[serde(rename = "file.sftp", alias = "files.sftp")]
    FileSftp,
}

impl Permission {
    #[inline]
    pub fn is_admin(self) -> bool {
        matches!(
            self,
            Permission::AdminWebsocketErrors
                | Permission::AdminWebsocketInstall
                | Permission::AdminWebsocketTransfer
        )
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Permission::All => "*",
            Permission::MetaCalagopus => "meta.calagopus",
            Permission::WebsocketConnect => "websocket.connect",
            Permission::ControlReadConsole => "control.read-console",
            Permission::ControlConsole => "control.console",
            Permission::ControlStart => "control.start",
            Permission::ControlStop => "control.stop",
            Permission::ControlRestart => "control.restart",
            Permission::AdminWebsocketErrors => "admin.websocket.errors",
            Permission::AdminWebsocketInstall => "admin.websocket.install",
            Permission::AdminWebsocketTransfer => "admin.websocket.transfer",
            Permission::BackupRead => "backup.read",
            Permission::ScheduleRead => "schedule.read",
            Permission::FileRead => "file.read",
            Permission::FileReadContent => "file.read-content",
            Permission::FileCreate => "file.create",
            Permission::FileUpdate => "file.update",
            Permission::FileDelete => "file.delete",
            Permission::FileArchive => "file.archive",
            Permission::FileSftp => "file.sftp",
        }
    }
}

/// A subuser's compiled deny-list.
///
/// `Unusable` is what keeps a malformed list from becoming a hole: a list that cannot
/// be compiled hides everything rather than nothing, since silently degrading to "no
/// path is hidden" hands the subuser exactly the files the list was written to hide.
enum IgnoredFiles {
    Unrestricted,
    Matcher(ignore::overrides::Override),
    Unusable,
}

impl IgnoredFiles {
    fn compile(patterns: &[impl AsRef<str>]) -> Self {
        if patterns.is_empty() {
            return Self::Unrestricted;
        }

        let mut builder = ignore::overrides::OverrideBuilder::new("");
        for pattern in patterns {
            if let Err(err) = builder.add(pattern.as_ref()) {
                tracing::error!(
                    "rejecting subuser ignored files, {} is not a valid pattern: {:#?}",
                    pattern.as_ref(),
                    err
                );

                return Self::Unusable;
            }
        }

        match builder.build() {
            Ok(overrides) => Self::Matcher(overrides),
            Err(err) => {
                tracing::error!(
                    "rejecting subuser ignored files, cannot compile: {:#?}",
                    err
                );

                Self::Unusable
            }
        }
    }

    fn matches(&self, path: std::path::PathBuf, is_dir: bool) -> bool {
        match self {
            Self::Unrestricted => false,
            Self::Matcher(overrides) => overrides.matched(path, is_dir).is_whitelist(),
            Self::Unusable => true,
        }
    }
}

type UserPermissions = (Permissions, IgnoredFiles, std::time::Instant);
pub struct UserPermissionsMap {
    map: Arc<Mutex<HashMap<uuid::Uuid, UserPermissions>>>,
    removal_sender: tokio::sync::broadcast::Sender<uuid::Uuid>,
    _removal_receiver: tokio::sync::broadcast::Receiver<uuid::Uuid>,

    task: tokio::task::JoinHandle<()>,
}

impl Default for UserPermissionsMap {
    fn default() -> Self {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = tokio::sync::broadcast::channel(32);

        Self {
            map: Arc::clone(&map),
            removal_sender: tx,
            _removal_receiver: rx,
            task: tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

                    let mut map = map.lock();
                    map.retain(|_, (_, _, last_access)| {
                        last_access.elapsed().as_secs() < 60 * 60 * 24
                    });
                }
            }),
        }
    }
}

impl UserPermissionsMap {
    pub async fn wait_for_removal(&self, user_uuid: uuid::Uuid) {
        let mut receiver = self.removal_sender.subscribe();

        loop {
            match receiver.recv().await {
                Ok(uuid) if uuid == user_uuid => break,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
                    if !self.map.lock().contains_key(&user_uuid) =>
                {
                    break;
                }
                _ => {}
            }
        }
    }

    pub fn has_permission(&self, user_uuid: uuid::Uuid, permission: Permission) -> bool {
        let mut map = self.map.lock();
        if let Some((permissions, _, last_access)) = map.get_mut(&user_uuid) {
            *last_access = std::time::Instant::now();

            permissions.has_permission(permission)
        } else {
            false
        }
    }

    pub fn has_calagopus_permission_or(
        &self,
        user_uuid: uuid::Uuid,
        permission: Permission,
        default: bool,
    ) -> bool {
        let mut map = self.map.lock();
        if let Some((permissions, _, last_access)) = map.get_mut(&user_uuid) {
            *last_access = std::time::Instant::now();

            permissions.has_calagopus_permission_or(permission, default)
        } else {
            default
        }
    }

    pub fn is_ignored(
        &self,
        server: &crate::server::Server,
        user_uuid: uuid::Uuid,
        path: impl AsRef<std::path::Path>,
        file_type: FileType,
    ) -> bool {
        let path = if file_type.is_symlink() {
            server
                .filesystem
                .canonicalize(path.as_ref())
                .unwrap_or_else(|_| server.filesystem.relative_path(path.as_ref()))
        } else {
            server.filesystem.relative_path(path.as_ref())
        };

        self.matches(user_uuid, path, file_type)
    }

    pub async fn async_is_ignored(
        &self,
        server: &crate::server::Server,
        user_uuid: uuid::Uuid,
        path: impl AsRef<std::path::Path>,
        file_type: FileType,
    ) -> bool {
        let path = if file_type.is_symlink() {
            server
                .filesystem
                .async_canonicalize(path.as_ref())
                .await
                .unwrap_or_else(|_| server.filesystem.relative_path(path.as_ref()))
        } else {
            server.filesystem.relative_path(path.as_ref())
        };

        self.matches(user_uuid, path, file_type)
    }

    fn matches(
        &self,
        user_uuid: uuid::Uuid,
        path: std::path::PathBuf,
        file_type: FileType,
    ) -> bool {
        let mut map = self.map.lock();
        if let Some((_, ignored, last_access)) = map.get_mut(&user_uuid) {
            *last_access = std::time::Instant::now();

            ignored.matches(path, file_type.is_dir())
        } else {
            false
        }
    }

    pub fn set_permissions(
        &self,
        user_uuid: uuid::Uuid,
        permissions: Permissions,
        ignored_files: Option<&[impl AsRef<str>]>,
    ) {
        if permissions.is_empty() {
            self.map.lock().remove(&user_uuid);
            self.removal_sender.send(user_uuid).ok();
            return;
        }

        let ignored_files = ignored_files.map(IgnoredFiles::compile);

        let mut map = self.map.lock();
        if let Some((current_permissions, current_ignored, _)) = map.get_mut(&user_uuid) {
            *current_permissions = permissions;
            if let Some(ignored_files) = ignored_files {
                *current_ignored = ignored_files;
            }
        } else {
            map.insert(
                user_uuid,
                (
                    permissions,
                    ignored_files.unwrap_or(IgnoredFiles::Unrestricted),
                    std::time::Instant::now(),
                ),
            );
        }
    }

    pub fn clear_permissions(&self) {
        let mut map = self.map.lock();
        for user_uuid in map.keys().copied().collect::<Vec<_>>() {
            map.remove(&user_uuid);
            self.removal_sender.send(user_uuid).ok();
        }
    }
}

impl Drop for UserPermissionsMap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Default, Clone, Serialize)]
#[repr(transparent)]
pub struct Permissions(HashSet<Permission>);

impl Permissions {
    #[inline]
    pub fn is_calagopus(&self) -> bool {
        self.0.contains(&Permission::MetaCalagopus)
    }

    #[inline]
    pub fn has_permission(&self, permission: Permission) -> bool {
        if (self.0.contains(&Permission::All) && !permission.is_admin())
            || self.0.contains(&permission)
        {
            return true;
        }

        false
    }

    #[inline]
    pub fn has_calagopus_permission_or(&self, permission: Permission, default: bool) -> bool {
        if !self.is_calagopus() {
            return default;
        }

        self.has_permission(permission)
    }
}

impl Deref for Permissions {
    type Target = HashSet<Permission>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Permissions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PermissionsVisitor(PhantomData<fn() -> Permissions>);

        impl<'de> Visitor<'de> for PermissionsVisitor {
            type Value = Permissions;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of permissions")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut permissions = HashSet::new();

                while let Ok(Some(result)) = seq.next_element::<serde_json::Value>() {
                    if let Ok(permission) = serde_json::from_value::<Permission>(result) {
                        permissions.insert(permission);
                    }
                }

                Ok(Permissions(permissions))
            }
        }

        deserializer.deserialize_seq(PermissionsVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    const ALL: &[Permission] = &[
        Permission::All,
        Permission::MetaCalagopus,
        Permission::WebsocketConnect,
        Permission::ControlReadConsole,
        Permission::ControlConsole,
        Permission::ControlStart,
        Permission::ControlStop,
        Permission::ControlRestart,
        Permission::AdminWebsocketErrors,
        Permission::AdminWebsocketInstall,
        Permission::AdminWebsocketTransfer,
        Permission::BackupRead,
        Permission::ScheduleRead,
        Permission::FileRead,
        Permission::FileReadContent,
        Permission::FileCreate,
        Permission::FileUpdate,
        Permission::FileDelete,
        Permission::FileArchive,
        Permission::FileSftp,
    ];

    fn perms(list: &[Permission]) -> Permissions {
        let mut p = Permissions::default();
        for &x in list {
            p.insert(x);
        }
        p
    }

    // Permission

    #[test]
    fn is_admin_only_for_admin_variants() {
        assert!(Permission::AdminWebsocketErrors.is_admin());
        assert!(Permission::AdminWebsocketInstall.is_admin());
        assert!(Permission::AdminWebsocketTransfer.is_admin());
        assert!(!Permission::All.is_admin());
        assert!(!Permission::FileRead.is_admin());
        assert!(!Permission::ControlStart.is_admin());
    }

    #[test]
    fn to_str_matches_serde_rename_and_round_trips() {
        for &p in ALL {
            assert_eq!(serde_json::to_value(p).unwrap(), json!(p.to_str()));
            let back: Permission = serde_json::from_value(json!(p.to_str())).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn deserialize_accepts_aliases() {
        assert_eq!(
            serde_json::from_value::<Permission>(json!("files.read")).unwrap(),
            Permission::FileRead
        );
        assert_eq!(
            serde_json::from_value::<Permission>(json!("backups.read")).unwrap(),
            Permission::BackupRead
        );
        assert_eq!(
            serde_json::from_value::<Permission>(json!("schedules.read")).unwrap(),
            Permission::ScheduleRead
        );
    }

    // Permissions

    #[test]
    fn wildcard_grants_everything_except_admin() {
        let p = perms(&[Permission::All]);
        assert!(p.has_permission(Permission::FileRead));
        assert!(p.has_permission(Permission::ControlStart));
        assert!(!p.has_permission(Permission::AdminWebsocketErrors));
    }

    #[test]
    fn admin_permission_requires_explicit_grant() {
        let p = perms(&[Permission::All, Permission::AdminWebsocketErrors]);
        assert!(p.has_permission(Permission::AdminWebsocketErrors));
        // a different admin permission is still not covered by the wildcard
        assert!(!p.has_permission(Permission::AdminWebsocketInstall));
    }

    #[test]
    fn explicit_and_missing_permissions() {
        let p = perms(&[Permission::FileRead]);
        assert!(p.has_permission(Permission::FileRead));
        assert!(!p.has_permission(Permission::FileDelete));
        assert!(!Permissions::default().has_permission(Permission::FileRead));
    }

    #[test]
    fn is_calagopus_checks_meta_marker() {
        assert!(perms(&[Permission::MetaCalagopus]).is_calagopus());
        assert!(!perms(&[Permission::FileRead]).is_calagopus());
    }

    #[test]
    fn calagopus_permission_or_uses_default_only_for_non_calagopus() {
        let plain = perms(&[Permission::FileRead]);
        // not a calagopus user: the default is returned, ignoring the actual grant
        assert!(!plain.has_calagopus_permission_or(Permission::FileRead, false));
        assert!(plain.has_calagopus_permission_or(Permission::FileRead, true));

        let calagopus = perms(&[Permission::MetaCalagopus, Permission::FileRead]);
        // calagopus user: the real grant decides, the default is ignored
        assert!(calagopus.has_calagopus_permission_or(Permission::FileRead, false));
        assert!(!calagopus.has_calagopus_permission_or(Permission::FileDelete, true));
    }

    #[test]
    fn deserialize_skips_unknown_permissions() {
        let permissions: Permissions =
            serde_json::from_value(json!(["file.read", "totally.bogus", "control.start"])).unwrap();
        assert!(permissions.has_permission(Permission::FileRead));
        assert!(permissions.has_permission(Permission::ControlStart));
        assert_eq!(permissions.len(), 2);
    }

    #[test]
    fn deserialize_collapses_aliases_and_duplicates() {
        let permissions: Permissions =
            serde_json::from_value(json!(["file.read", "files.read", "file.read"])).unwrap();
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains(&Permission::FileRead));
    }

    #[test]
    fn deserialize_empty_sequence() {
        let permissions: Permissions = serde_json::from_value(json!([])).unwrap();
        assert!(permissions.is_empty());
    }

    // UserPermissionsMap

    #[test]
    fn map_set_and_query() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            assert!(!permissions.has_permission(user, Permission::FileRead));
            permissions.set_permissions(user, perms(&[Permission::FileRead]), None::<&[&str]>);
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_empty_permissions_removes_user() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_permissions(user, perms(&[Permission::FileRead]), None::<&[&str]>);
            permissions.set_permissions(user, Permissions::default(), None::<&[&str]>);
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_update_replaces_permission_set() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_permissions(user, perms(&[Permission::FileRead]), None::<&[&str]>);
            permissions.set_permissions(user, perms(&[Permission::FileDelete]), None::<&[&str]>);
            assert!(!permissions.has_permission(user, Permission::FileRead));
            assert!(permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_calagopus_permission_or_defaults_for_absent_user() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            assert!(permissions.has_calagopus_permission_or(user, Permission::FileRead, true));
            assert!(!permissions.has_calagopus_permission_or(user, Permission::FileRead, false));
        });
    }

    #[test]
    fn map_is_ignored_matches_patterns() {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let ignored: &[&str] = &["*.log"];
            permissions.set_permissions(user, perms(&[Permission::FileRead]), Some(ignored));
            assert!(permissions.is_ignored(&server, user, "server.log", FileType::File));
            assert!(permissions.is_ignored(&server, user, "sub/server.log", FileType::File));
            assert!(!permissions.is_ignored(&server, user, "server.txt", FileType::File));
            // unknown user is never ignored
            assert!(!permissions.is_ignored(
                &server,
                uuid::Uuid::new_v4(),
                "server.log",
                FileType::File
            ));
        });
    }

    #[test]
    fn map_update_without_ignored_keeps_existing_overrides() {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let ignored: &[&str] = &["*.log"];
            permissions.set_permissions(user, perms(&[Permission::FileRead]), Some(ignored));
            assert!(permissions.is_ignored(&server, user, "x.log", FileType::File));
            permissions.set_permissions(user, perms(&[Permission::FileDelete]), None::<&[&str]>);
            assert!(permissions.is_ignored(&server, user, "x.log", FileType::File));
        });
    }

    #[test]
    fn map_uncompilable_ignored_files_hide_everything() {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();

            // an unclosed character class cannot be compiled - the whole list is then
            // unusable, and must hide everything rather than nothing
            let ignored: &[&str] = &["[abc", "*.log"];
            permissions.set_permissions(user, perms(&[Permission::FileRead]), Some(ignored));

            assert!(permissions.is_ignored(&server, user, "server.log", FileType::File));
            assert!(permissions.is_ignored(&server, user, "anything.txt", FileType::File));
            assert!(permissions.is_ignored(&server, user, "sub", FileType::Dir));
        });
    }

    #[test]
    fn map_wait_for_removal_resolves_when_cleared() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_permissions(user, perms(&[Permission::FileRead]), None::<&[&str]>);

            let done = tokio::time::timeout(Duration::from_secs(2), async {
                let removal = permissions.wait_for_removal(user);
                let trigger = async {
                    tokio::task::yield_now().await;
                    permissions.clear_permissions();
                };
                tokio::join!(removal, trigger);
            })
            .await;

            assert!(done.is_ok(), "wait_for_removal did not resolve");
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_wait_for_removal_resolves_despite_channel_overflow() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_permissions(user, perms(&[Permission::FileRead]), None::<&[&str]>);

            for _ in 0..64 {
                permissions.set_permissions(
                    uuid::Uuid::new_v4(),
                    perms(&[Permission::FileRead]),
                    None::<&[&str]>,
                );
            }

            let done = tokio::time::timeout(Duration::from_secs(2), async {
                let removal = permissions.wait_for_removal(user);
                let trigger = async {
                    tokio::task::yield_now().await;
                    permissions.clear_permissions();
                };
                tokio::join!(removal, trigger);
            })
            .await;

            assert!(done.is_ok(), "wait_for_removal did not resolve after lag");
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }
}
