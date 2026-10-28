use crate::server::filesystem::{cap::FileType, ignore_list::IgnoreList};
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
    Matcher(IgnoreList),
    Unusable,
}

impl IgnoredFiles {
    fn compile(patterns: &[impl AsRef<str>]) -> Self {
        if patterns.is_empty() {
            return Self::Unrestricted;
        }

        match IgnoreList::try_from_lines(patterns) {
            Ok(list) => Self::Matcher(list),
            Err(err) => {
                tracing::error!(
                    "rejecting subuser ignored files, cannot compile: {:#?}",
                    err
                );

                Self::Unusable
            }
        }
    }

    fn matches(&self, path: std::path::PathBuf, file_type: FileType) -> bool {
        match self {
            Self::Unrestricted => false,
            Self::Matcher(list) => list.is_ignored(&path, file_type),
            Self::Unusable => true,
        }
    }
}

struct UserPermissions {
    permissions: Permissions,
    ignored_files: IgnoredFiles,
    last_access: std::time::Instant,
    /// Panel time, in unix milliseconds, at which these permissions were evaluated.
    as_of: i64,
}

struct Inner {
    users: HashMap<uuid::Uuid, UserPermissions>,
    /// Panel times, in unix milliseconds, at or before which anything evaluated for a user
    /// is outdated.
    invalidated: HashMap<uuid::Uuid, i64>,
    invalidated_all: i64,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            invalidated: HashMap::new(),
            invalidated_all: i64::MIN,
        }
    }
}

impl Inner {
    fn invalidated_at(&self, user_uuid: uuid::Uuid) -> i64 {
        self.invalidated
            .get(&user_uuid)
            .copied()
            .unwrap_or(i64::MIN)
            .max(self.invalidated_all)
    }

    fn invalidate(&mut self, user_uuid: uuid::Uuid, as_of: i64) {
        let invalidated = self.invalidated.entry(user_uuid).or_insert(as_of);
        *invalidated = (*invalidated).max(as_of);
    }
}

/// Outcome of [`UserPermissionsMap::set_token_permissions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVerdict {
    Applied,
    /// The token predates the permissions already held, which are kept as the fresher state.
    Kept,
    /// The token predates an invalidation by the panel and must not be accepted.
    Stale,
}

/// Outcome of [`UserPermissionsMap::set_fetched_permissions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchVerdict {
    Applied,
    /// Permissions evaluated after this fetch are already held.
    Superseded,
    /// The fetch predates an invalidation by the panel and must not be used.
    Outdated,
}

#[inline]
pub fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The permissions wings holds for users of one server. These are always the full grants of
/// the account, never the narrowed list of a scoped credential, which stays with the
/// connection that presented it.
pub struct UserPermissionsMap {
    inner: Arc<Mutex<Inner>>,
    removal_sender: tokio::sync::broadcast::Sender<uuid::Uuid>,
    _removal_receiver: tokio::sync::broadcast::Receiver<uuid::Uuid>,

    task: tokio::task::JoinHandle<()>,
}

impl Default for UserPermissionsMap {
    fn default() -> Self {
        let inner = Arc::new(Mutex::new(Inner::default()));
        let (tx, rx) = tokio::sync::broadcast::channel(32);

        Self {
            inner: Arc::clone(&inner),
            removal_sender: tx.clone(),
            _removal_receiver: rx,
            task: tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

                    let now = now_millis();
                    let mut inner = inner.lock();
                    inner
                        .invalidated
                        .retain(|_, &mut stamp| now - stamp < 1000 * 60 * 60 * 24);

                    let mut expired = Vec::new();
                    inner.users.retain(|&user_uuid, user| {
                        let keep = user.last_access.elapsed().as_secs() < 60 * 60 * 24;
                        if !keep {
                            expired.push(user_uuid);
                        }

                        keep
                    });
                    drop(inner);

                    for user_uuid in expired {
                        tx.send(user_uuid).ok();
                    }
                }
            }),
        }
    }
}

impl UserPermissionsMap {
    pub async fn wait_for_removal(&self, user_uuid: uuid::Uuid) {
        let mut receiver = self.removal_sender.subscribe();

        while self.inner.lock().users.contains_key(&user_uuid) {
            match receiver.recv().await {
                Ok(uuid) if uuid == user_uuid => break,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                _ => {}
            }
        }
    }

    fn with_user<T>(
        &self,
        user_uuid: uuid::Uuid,
        f: impl FnOnce(&Permissions, &IgnoredFiles) -> T,
    ) -> Option<T> {
        let mut inner = self.inner.lock();
        let user = inner.users.get_mut(&user_uuid)?;
        user.last_access = std::time::Instant::now();

        Some(f(&user.permissions, &user.ignored_files))
    }

    pub fn has_user(&self, user_uuid: uuid::Uuid) -> bool {
        self.with_user(user_uuid, |_, _| ()).is_some()
    }

    pub fn has_permission(&self, user_uuid: uuid::Uuid, permission: Permission) -> bool {
        self.with_user(user_uuid, |permissions, _| {
            permissions.has_permission(permission)
        })
        .unwrap_or(false)
    }

    pub fn has_calagopus_permission_or(
        &self,
        user_uuid: uuid::Uuid,
        permission: Permission,
        default: bool,
    ) -> bool {
        self.with_user(user_uuid, |permissions, _| {
            permissions.has_calagopus_permission_or(permission, default)
        })
        .unwrap_or(default)
    }

    pub fn permissions(&self, user_uuid: uuid::Uuid) -> Option<Vec<Permission>> {
        self.with_user(user_uuid, |permissions, _| {
            permissions.iter().copied().collect()
        })
    }

    pub fn has_ignored_files(&self, user_uuid: uuid::Uuid) -> bool {
        self.with_user(user_uuid, |_, ignored| {
            !matches!(ignored, IgnoredFiles::Unrestricted)
        })
        .unwrap_or(false)
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
        self.with_user(user_uuid, |_, ignored| ignored.matches(path, file_type))
            .unwrap_or(false)
    }

    /// Applies permissions pushed by the panel through the legacy push routes, which carry no
    /// panel time, so wings' own clock stands in. Anything issued before the push is outdated.
    pub fn set_pushed_permissions(
        &self,
        user_uuid: uuid::Uuid,
        permissions: Permissions,
        ignored_files: Option<&[impl AsRef<str>]>,
    ) {
        let now = now_millis();

        let mut inner = self.inner.lock();
        inner.invalidate(user_uuid, now);
        self.apply_permissions(&mut inner, user_uuid, permissions, ignored_files, now);
    }

    /// Applies permissions the panel evaluated at `as_of`, unless permissions evaluated later
    /// are already held or the panel invalidated the user after `as_of`.
    pub fn set_fetched_permissions(
        &self,
        user_uuid: uuid::Uuid,
        permissions: Permissions,
        ignored_files: Option<&[impl AsRef<str>]>,
        as_of: i64,
    ) -> FetchVerdict {
        let mut inner = self.inner.lock();

        if as_of <= inner.invalidated_at(user_uuid) {
            return FetchVerdict::Outdated;
        }

        if inner
            .users
            .get(&user_uuid)
            .is_some_and(|user| user.as_of > as_of)
        {
            return FetchVerdict::Superseded;
        }

        self.apply_permissions(&mut inner, user_uuid, permissions, ignored_files, as_of);

        FetchVerdict::Applied
    }

    /// Applies the full permissions carried by a token issued at `issued_at` (unix seconds)
    /// unless the panel invalidated the user since, or fresher permissions are held.
    pub fn set_token_permissions(
        &self,
        user_uuid: uuid::Uuid,
        issued_at: Option<i64>,
        permissions: Permissions,
        ignored_files: Option<&[impl AsRef<str>]>,
    ) -> TokenVerdict {
        let issued_at = issued_at.map_or(i64::MIN, |issued_at| issued_at.saturating_mul(1000));

        let mut inner = self.inner.lock();

        if issued_at <= inner.invalidated_at(user_uuid) {
            return TokenVerdict::Stale;
        }

        if inner
            .users
            .get(&user_uuid)
            .is_some_and(|user| user.as_of >= issued_at)
        {
            return TokenVerdict::Kept;
        }

        self.apply_permissions(&mut inner, user_uuid, permissions, ignored_files, issued_at);

        TokenVerdict::Applied
    }

    /// Marks everything evaluated for the user at or before `as_of` as outdated, the held
    /// permissions stay in effect until fresh ones replace them. Returns whether any are held.
    pub fn invalidate(&self, user_uuid: uuid::Uuid, as_of: i64) -> bool {
        let mut inner = self.inner.lock();
        inner.invalidate(user_uuid, as_of);

        inner.users.contains_key(&user_uuid)
    }

    /// Like [`Self::invalidate`] for every user, returns the users whose permissions are held.
    pub fn invalidate_all(&self, as_of: i64) -> Vec<uuid::Uuid> {
        let mut inner = self.inner.lock();
        inner.invalidated_all = inner.invalidated_all.max(as_of);

        inner.users.keys().copied().collect()
    }

    /// Drops the user's permissions, ending their sessions, unless permissions evaluated
    /// after `as_of` are held.
    pub fn revoke(&self, user_uuid: uuid::Uuid, as_of: i64) {
        let mut inner = self.inner.lock();
        inner.invalidate(user_uuid, as_of);

        if inner
            .users
            .get(&user_uuid)
            .is_some_and(|user| user.as_of <= as_of)
        {
            inner.users.remove(&user_uuid);
            drop(inner);

            self.removal_sender.send(user_uuid).ok();
        }
    }

    fn apply_permissions(
        &self,
        inner: &mut Inner,
        user_uuid: uuid::Uuid,
        permissions: Permissions,
        ignored_files: Option<&[impl AsRef<str>]>,
        as_of: i64,
    ) {
        if permissions.is_empty() {
            if inner.users.remove(&user_uuid).is_some() {
                self.removal_sender.send(user_uuid).ok();
            }

            return;
        }

        let ignored_files = ignored_files.map(IgnoredFiles::compile);

        if let Some(user) = inner.users.get_mut(&user_uuid) {
            user.permissions = permissions;
            user.as_of = as_of;
            if let Some(ignored_files) = ignored_files {
                user.ignored_files = ignored_files;
            }
        } else {
            inner.users.insert(
                user_uuid,
                UserPermissions {
                    permissions,
                    ignored_files: ignored_files.unwrap_or(IgnoredFiles::Unrestricted),
                    last_access: std::time::Instant::now(),
                    as_of,
                },
            );
        }
    }

    pub fn clear_permissions(&self) {
        let removed: Vec<_> = self
            .inner
            .lock()
            .users
            .drain()
            .map(|(user_uuid, _)| user_uuid)
            .collect();
        for user_uuid in removed {
            self.removal_sender.send(user_uuid).ok();
        }
    }

    #[cfg(test)]
    pub fn grant(&self, user_uuid: uuid::Uuid, list: &[Permission]) {
        self.set_pushed_permissions(user_uuid, Permissions::from_list(list), None::<&[&str]>);
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

    #[cfg(test)]
    pub fn from_list(list: &[Permission]) -> Self {
        let mut permissions = Self::default();
        for &permission in list {
            permissions.insert(permission);
        }

        permissions
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

    fn read() -> Permissions {
        Permissions::from_list(&[Permission::FileRead])
    }

    fn delete() -> Permissions {
        Permissions::from_list(&[Permission::FileDelete])
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
        let p = Permissions::from_list(&[Permission::All]);
        assert!(p.has_permission(Permission::FileRead));
        assert!(p.has_permission(Permission::ControlStart));
        assert!(!p.has_permission(Permission::AdminWebsocketErrors));
    }

    #[test]
    fn admin_permission_requires_explicit_grant() {
        let p = Permissions::from_list(&[Permission::All, Permission::AdminWebsocketErrors]);
        assert!(p.has_permission(Permission::AdminWebsocketErrors));
        // a different admin permission is still not covered by the wildcard
        assert!(!p.has_permission(Permission::AdminWebsocketInstall));
    }

    #[test]
    fn explicit_and_missing_permissions() {
        let p = Permissions::from_list(&[Permission::FileRead]);
        assert!(p.has_permission(Permission::FileRead));
        assert!(!p.has_permission(Permission::FileDelete));
        assert!(!Permissions::default().has_permission(Permission::FileRead));
    }

    #[test]
    fn is_calagopus_checks_meta_marker() {
        assert!(Permissions::from_list(&[Permission::MetaCalagopus]).is_calagopus());
        assert!(!Permissions::from_list(&[Permission::FileRead]).is_calagopus());
    }

    #[test]
    fn calagopus_permission_or_uses_default_only_for_non_calagopus() {
        let plain = Permissions::from_list(&[Permission::FileRead]);
        // not a calagopus user: the default is returned, ignoring the actual grant
        assert!(!plain.has_calagopus_permission_or(Permission::FileRead, false));
        assert!(plain.has_calagopus_permission_or(Permission::FileRead, true));

        let calagopus = Permissions::from_list(&[Permission::MetaCalagopus, Permission::FileRead]);
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
            permissions.grant(user, &[Permission::FileRead]);
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_empty_permissions_removes_user() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.grant(user, &[Permission::FileRead]);
            permissions.grant(user, &[]);
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_update_replaces_permission_set() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.grant(user, &[Permission::FileRead]);
            permissions.grant(user, &[Permission::FileDelete]);
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
    fn map_has_user_follows_grants_and_removal() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let other = uuid::Uuid::new_v4();
            assert!(!permissions.has_user(user));

            permissions.grant(user, &[Permission::FileRead]);
            permissions.grant(other, &[Permission::FileRead]);
            assert!(permissions.has_user(user));

            permissions.grant(user, &[]);
            assert!(!permissions.has_user(user));
            assert!(permissions.has_user(other));

            permissions.clear_permissions();
            assert!(!permissions.has_user(other));
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
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                Some(ignored),
            );
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

    /// A staging file inherits the visibility of the file it will become, or a deny rule is
    /// dodged by reaching for `server.log.upload-part` over SFTP instead.
    #[test]
    fn map_is_ignored_matches_a_staging_file_as_its_target() {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let ignored: &[&str] = &["*.log"];
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                Some(ignored),
            );

            assert!(permissions.is_ignored(
                &server,
                user,
                "server.log.upload-part",
                FileType::File
            ));
            assert!(!permissions.is_ignored(
                &server,
                user,
                "server.txt.upload-part",
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
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                Some(ignored),
            );
            assert!(permissions.is_ignored(&server, user, "x.log", FileType::File));
            permissions.grant(user, &[Permission::FileDelete]);
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
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                Some(ignored),
            );

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
            permissions.grant(user, &[Permission::FileRead]);

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
            permissions.grant(user, &[Permission::FileRead]);

            for _ in 0..64 {
                permissions.set_pushed_permissions(
                    uuid::Uuid::new_v4(),
                    Permissions::from_list(&[Permission::FileRead]),
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

    #[test]
    fn map_token_applies_without_push() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let iat = chrono::Utc::now().timestamp() - 100;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::FileRead]),
                    None::<&[&str]>
                ),
                TokenVerdict::Applied
            );
            assert!(permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_stale_token_does_not_override_push() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let ignored: &[&str] = &["*.log"];
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                Some(ignored),
            );

            let iat = chrono::Utc::now().timestamp() - 100;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[
                        Permission::FileRead,
                        Permission::FileReadContent,
                        Permission::ControlConsole
                    ]),
                    Some(&[] as &[&str])
                ),
                TokenVerdict::Stale
            );
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileReadContent));
            assert!(!permissions.has_permission(user, Permission::ControlConsole));
            assert!(permissions.has_ignored_files(user));
        });
    }

    #[test]
    fn map_stale_token_does_not_restore_revoked_user() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_pushed_permissions(user, Permissions::default(), Some(&[] as &[&str]));

            let iat = chrono::Utc::now().timestamp() - 100;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::All, Permission::FileRead]),
                    None::<&[&str]>
                ),
                TokenVerdict::Stale
            );
            assert!(!permissions.has_permission(user, Permission::All));
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_token_issued_after_push_applies() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
            );

            let iat = chrono::Utc::now().timestamp() + 2;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Applied
            );
            assert!(permissions.has_permission(user, Permission::FileDelete));
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_token_issued_in_push_second_or_without_iat_is_refused() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
            );
            let pushed = permissions.inner.lock().invalidated[&user].div_euclid(1000);

            for issued_at in [Some(pushed), None] {
                assert_eq!(
                    permissions.set_token_permissions(
                        user,
                        issued_at,
                        Permissions::from_list(&[Permission::FileDelete]),
                        None::<&[&str]>
                    ),
                    TokenVerdict::Stale
                );
            }
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_token_older_than_fetch_is_kept() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_fetched_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
                now_millis(),
            );

            let iat = chrono::Utc::now().timestamp() - 100;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::FileRead, Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Kept
            );
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_token_issued_in_fetch_second_is_kept() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let fetched = now_millis();
            permissions.set_fetched_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
                fetched,
            );
            let fetched = fetched.div_euclid(1000);

            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(fetched),
                    Permissions::from_list(&[Permission::FileRead, Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Kept
            );
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    None,
                    Permissions::from_list(&[Permission::FileRead, Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Stale
            );
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_token_issued_after_fetch_applies() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_fetched_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
                now_millis(),
            );

            let iat = chrono::Utc::now().timestamp() + 2;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::FileRead, Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Applied
            );
            assert!(permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_push_after_fetch_makes_older_token_stale() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_fetched_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
                now_millis(),
            );
            permissions.set_pushed_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
            );

            let iat = chrono::Utc::now().timestamp() - 100;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::FileRead, Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Stale
            );
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_fetch_then_revoking_push_does_not_restore_user() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_fetched_permissions(
                user,
                Permissions::from_list(&[Permission::FileRead]),
                None::<&[&str]>,
                now_millis(),
            );
            permissions.set_pushed_permissions(user, Permissions::default(), Some(&[] as &[&str]));

            let iat = chrono::Utc::now().timestamp() - 100;
            assert_eq!(
                permissions.set_token_permissions(
                    user,
                    Some(iat),
                    Permissions::from_list(&[Permission::FileRead, Permission::FileDelete]),
                    None::<&[&str]>
                ),
                TokenVerdict::Stale
            );
            assert!(!permissions.has_user(user));
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_fetch_at_or_before_invalidation_is_outdated() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let t = now_millis();
            permissions.invalidate(user, t);

            for as_of in [t - 1, t] {
                assert_eq!(
                    permissions.set_fetched_permissions(user, read(), None::<&[&str]>, as_of),
                    FetchVerdict::Outdated
                );
                assert!(!permissions.has_user(user));
            }
            assert_eq!(
                permissions.set_fetched_permissions(user, read(), None::<&[&str]>, t + 1),
                FetchVerdict::Applied
            );
            assert!(permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_outdated_fetch_does_not_change_held_permissions() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let t = now_millis();
            permissions.set_fetched_permissions(user, read(), None::<&[&str]>, t);
            permissions.invalidate(user, t + 10);

            assert_eq!(
                permissions.set_fetched_permissions(user, delete(), None::<&[&str]>, t + 10),
                FetchVerdict::Outdated
            );
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_invalidate_all_outdates_fetches_and_tokens_for_unheld_users() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let fetched = uuid::Uuid::new_v4();
            let tokened = uuid::Uuid::new_v4();
            let t = now_millis();
            assert!(permissions.invalidate_all(t).is_empty());

            assert_eq!(
                permissions.set_fetched_permissions(fetched, read(), None::<&[&str]>, t),
                FetchVerdict::Outdated
            );
            assert_eq!(
                permissions.set_token_permissions(
                    tokened,
                    Some(t.div_euclid(1000)),
                    read(),
                    None::<&[&str]>
                ),
                TokenVerdict::Stale
            );
            assert!(!permissions.has_user(fetched));
            assert!(!permissions.has_user(tokened));

            assert_eq!(
                permissions.set_fetched_permissions(fetched, read(), None::<&[&str]>, t + 1),
                FetchVerdict::Applied
            );
        });
    }

    #[test]
    fn map_token_issued_at_or_before_invalidation_is_stale() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let iat = chrono::Utc::now().timestamp() - 100;
            permissions.set_token_permissions(user, Some(iat - 10), read(), None::<&[&str]>);
            // mid-second, so the token from that same second predates it
            permissions.invalidate(user, iat * 1000 + 500);

            for issued_at in [iat - 1, iat] {
                assert_eq!(
                    permissions.set_token_permissions(
                        user,
                        Some(issued_at),
                        delete(),
                        None::<&[&str]>
                    ),
                    TokenVerdict::Stale
                );
            }
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));

            assert_eq!(
                permissions.set_token_permissions(user, Some(iat + 1), delete(), None::<&[&str]>),
                TokenVerdict::Applied
            );
            assert!(permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_older_fetch_is_superseded_and_newer_replaces() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let t = now_millis();
            assert_eq!(
                permissions.set_fetched_permissions(user, delete(), None::<&[&str]>, t + 10),
                FetchVerdict::Applied
            );

            assert_eq!(
                permissions.set_fetched_permissions(user, read(), None::<&[&str]>, t),
                FetchVerdict::Superseded
            );
            assert!(permissions.has_permission(user, Permission::FileDelete));
            assert!(!permissions.has_permission(user, Permission::FileRead));

            assert_eq!(
                permissions.set_fetched_permissions(user, read(), None::<&[&str]>, t + 20),
                FetchVerdict::Applied
            );
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.has_permission(user, Permission::FileDelete));
        });
    }

    #[test]
    fn map_fetch_older_than_token_is_superseded() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let iat = chrono::Utc::now().timestamp() - 100;
            permissions.set_token_permissions(user, Some(iat), delete(), None::<&[&str]>);

            assert_eq!(
                permissions.set_fetched_permissions(
                    user,
                    read(),
                    None::<&[&str]>,
                    (iat - 1) * 1000
                ),
                FetchVerdict::Superseded
            );
            assert!(permissions.has_permission(user, Permission::FileDelete));
            assert!(!permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_invalidate_keeps_permissions_without_removal() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            permissions.set_fetched_permissions(user, read(), None::<&[&str]>, now_millis());

            let removed = tokio::time::timeout(Duration::from_millis(200), async {
                let removal = permissions.wait_for_removal(user);
                let trigger = async {
                    tokio::task::yield_now().await;
                    assert!(permissions.invalidate(user, now_millis()));
                };
                tokio::join!(removal, trigger);
            })
            .await;

            assert!(removed.is_err(), "invalidate broadcast a removal");
            assert!(permissions.has_permission(user, Permission::FileRead));
            assert!(!permissions.invalidate(uuid::Uuid::new_v4(), now_millis()));
        });
    }

    #[test]
    fn map_invalidate_all_reports_exactly_held_users() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let a = uuid::Uuid::new_v4();
            let b = uuid::Uuid::new_v4();
            let t = now_millis();
            permissions.set_fetched_permissions(a, read(), None::<&[&str]>, t);
            permissions.set_fetched_permissions(b, read(), None::<&[&str]>, t);
            // invalidated but never held
            permissions.invalidate(uuid::Uuid::new_v4(), t);

            let mut held = permissions.invalidate_all(t + 1);
            held.sort();
            let mut expected = vec![a, b];
            expected.sort();
            assert_eq!(held, expected);
            assert!(permissions.has_permission(a, Permission::FileRead));
            assert!(permissions.has_permission(b, Permission::FileRead));
        });
    }

    #[test]
    fn map_revoke_removes_user_and_wakes_waiter() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let t = now_millis();
            permissions.set_fetched_permissions(user, read(), None::<&[&str]>, t);

            let done = tokio::time::timeout(Duration::from_secs(2), async {
                let removal = permissions.wait_for_removal(user);
                let trigger = async {
                    tokio::task::yield_now().await;
                    permissions.revoke(user, t + 1);
                };
                tokio::join!(removal, trigger);
            })
            .await;

            assert!(done.is_ok(), "wait_for_removal did not resolve on revoke");
            assert!(!permissions.has_user(user));
        });
    }

    #[test]
    fn map_revoke_older_than_held_permissions_keeps_them() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let t = now_millis();
            permissions.set_fetched_permissions(user, read(), None::<&[&str]>, t + 10);

            permissions.revoke(user, t);
            assert!(permissions.has_permission(user, Permission::FileRead));
        });
    }

    #[test]
    fn map_revoke_without_held_user_makes_older_token_stale() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let iat = chrono::Utc::now().timestamp() - 100;
            permissions.revoke(user, iat * 1000);

            assert_eq!(
                permissions.set_token_permissions(user, Some(iat), read(), None::<&[&str]>),
                TokenVerdict::Stale
            );
            assert!(!permissions.has_user(user));
        });
    }

    #[test]
    fn map_older_invalidation_does_not_reopen_window() {
        tokio_test::block_on(async {
            let permissions = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let other = uuid::Uuid::new_v4();
            let t = now_millis();
            permissions.invalidate(user, t + 10_000);
            permissions.invalidate(user, t);
            permissions.revoke(user, t);
            permissions.invalidate_all(t + 10_000);
            permissions.invalidate_all(t);

            for target in [user, other] {
                assert_eq!(
                    permissions.set_fetched_permissions(target, read(), None::<&[&str]>, t + 5_000),
                    FetchVerdict::Outdated
                );
            }
            assert!(!permissions.has_user(user));
            assert!(!permissions.has_user(other));
        });
    }
}
