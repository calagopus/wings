use super::permissions::{Permission, Permissions, UserPermissionsMap};
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use base64::Engine;
use compact_str::ToCompactString;
use futures::{SinkExt, stream::SplitSink};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
};
use std::{
    borrow::Cow,
    collections::HashSet,
    error::Error,
    marker::PhantomData,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use tokio::sync::{Mutex, RwLock};
use utoipa::ToSchema;

pub mod handler;
mod jwt;
pub mod limiter;
mod message_handler;

#[derive(Deserialize)]
pub struct WebsocketJwtPayload {
    #[serde(flatten)]
    pub base: crate::remote::jwt::BasePayload,

    pub user_uuid: uuid::Uuid,
    pub user_name: Option<compact_str::CompactString>,
    pub user_avatar: Option<String>,
    pub server_uuid: uuid::Uuid,
    /// What this connection may do, narrowed by the credential the token was issued through.
    pub permissions: Permissions,
    /// The account's grants on the server. Panels that predate it only send `permissions`,
    /// which then stands in for both.
    pub full_permissions: Option<Permissions>,
    pub ignored_files: Option<Vec<compact_str::CompactString>>,
}

impl WebsocketJwtPayload {
    fn has_live_permission(
        &self,
        user_permissions: &UserPermissionsMap,
        permission: Permission,
    ) -> bool {
        user_permissions.has_permission(self.user_uuid, permission)
            && self.permissions.has_permission(permission)
    }

    fn has_live_calagopus_permission_or(
        &self,
        user_permissions: &UserPermissionsMap,
        permission: Permission,
        default: bool,
    ) -> bool {
        user_permissions.has_calagopus_permission_or(self.user_uuid, permission, default)
            && self
                .permissions
                .has_calagopus_permission_or(permission, default)
    }
}

#[derive(Debug, Clone, Copy, ToSchema, Deserialize, Serialize)]
pub enum WebsocketEvent {
    #[serde(rename = "auth success")]
    AuthenticationSuccess,
    #[serde(rename = "token expiring")]
    TokenExpiring,
    #[serde(rename = "token expired")]
    TokenExpired,
    #[serde(rename = "auth")]
    Authentication,

    #[serde(rename = "configure socket")]
    ConfigureSocket,
    #[serde(rename = "socket configured")]
    SocketConfigured,
    #[serde(rename = "set state")]
    SetState,
    #[serde(rename = "send logs")]
    SendServerLogs,
    #[serde(rename = "send command")]
    SendCommand,
    #[serde(rename = "send stats")]
    SendStats,
    #[serde(rename = "send status")]
    SendStatus,
    #[serde(rename = "daemon error")]
    Error,
    #[serde(rename = "jwt error")]
    JwtError,

    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,

    #[serde(rename = "stats")]
    ServerStats,
    #[serde(rename = "status")]
    ServerStatus,
    #[serde(rename = "pending restart")]
    ServerPendingRestart,
    #[serde(rename = "custom event")]
    ServerCustomEvent,
    #[serde(rename = "console output")]
    ServerConsoleOutput,
    #[serde(rename = "install output")]
    ServerInstallOutput,
    #[serde(rename = "image pull progress")]
    ServerImagePullProgress,
    #[serde(rename = "image pull completed")]
    ServerImagePullCompleted,
    #[serde(rename = "install started")]
    ServerInstallStarted,
    #[serde(rename = "install progress")]
    ServerInstallProgress,
    #[serde(rename = "install completed")]
    ServerInstallCompleted,
    #[serde(rename = "daemon message")]
    ServerDaemonMessage,
    #[serde(rename = "backup started")]
    ServerBackupStarted,
    #[serde(rename = "backup progress")]
    ServerBackupProgress,
    #[serde(rename = "backup completed")]
    ServerBackupCompleted,
    #[serde(rename = "backup deleted")]
    ServerBackupDeleted,
    #[serde(rename = "backup restore started")]
    ServerBackupRestoreStarted,
    #[serde(rename = "backup restore progress")]
    ServerBackupRestoreProgress,
    #[serde(rename = "backup restore completed")]
    ServerBackupRestoreCompleted,
    #[serde(rename = "database backup restore started")]
    ServerDatabaseBackupRestoreStarted,
    #[serde(rename = "database backup restore progress")]
    ServerDatabaseBackupRestoreProgress,
    #[serde(rename = "database backup restore completed")]
    ServerDatabaseBackupRestoreCompleted,
    #[serde(rename = "transfer logs")]
    ServerTransferLogs,
    #[serde(rename = "transfer status")]
    ServerTransferStatus,
    #[serde(rename = "transfer progress")]
    ServerTransferProgress,
    #[serde(rename = "schedule started")]
    ServerScheduleStarted,
    #[serde(rename = "schedule step status")]
    ServerScheduleStepStatus,
    #[serde(rename = "schedule step error")]
    ServerScheduleStepError,
    #[serde(rename = "schedule completed")]
    ServerScheduleCompleted,
    #[serde(rename = "operation progress")]
    ServerOperationProgress,
    #[serde(rename = "operation error")]
    ServerOperationError,
    #[serde(rename = "operation completed")]
    ServerOperationCompleted,
    #[serde(rename = "operation aborted")]
    ServerOperationAborted,
    #[serde(rename = "file uploads")]
    ServerFileUploads,

    #[serde(rename = "file collab subscribe")]
    FileCollabSubscribe,
    #[serde(rename = "file collab unsubscribe")]
    FileCollabUnsubscribe,
    #[serde(rename = "file collab update")]
    FileCollabUpdate,
    #[serde(rename = "file collab awareness")]
    FileCollabAwareness,
    #[serde(rename = "file collab save")]
    FileCollabSave,
    #[serde(rename = "file collab sync")]
    FileCollabSync,
    #[serde(rename = "file collab participants")]
    FileCollabParticipants,
    #[serde(rename = "file collab saved")]
    FileCollabSaved,
    #[serde(rename = "file collab reload")]
    FileCollabReload,
    #[serde(rename = "file collab conflict")]
    FileCollabConflict,
    #[serde(rename = "file collab error")]
    FileCollabError,
}

pub enum BroadcastPermission {
    Denied,
    Authenticated,
    Required(Permission),
    CalagopusOr(Permission, bool),
}

impl WebsocketEvent {
    pub fn broadcast_permission(self) -> BroadcastPermission {
        match self {
            Self::ServerStats
            | Self::ServerStatus
            | Self::ServerPendingRestart
            | Self::ServerImagePullProgress
            | Self::ServerImagePullCompleted
            | Self::ServerInstallStarted
            | Self::ServerInstallProgress
            | Self::ServerInstallCompleted
            | Self::ServerTransferStatus => BroadcastPermission::Authenticated,

            Self::ServerConsoleOutput | Self::ServerDaemonMessage => {
                BroadcastPermission::CalagopusOr(Permission::ControlReadConsole, true)
            }

            Self::ServerInstallOutput => {
                BroadcastPermission::Required(Permission::AdminWebsocketInstall)
            }
            Self::ServerTransferLogs | Self::ServerTransferProgress => {
                BroadcastPermission::Required(Permission::AdminWebsocketTransfer)
            }
            Self::ServerBackupStarted
            | Self::ServerBackupProgress
            | Self::ServerBackupCompleted
            | Self::ServerBackupDeleted
            | Self::ServerBackupRestoreStarted
            | Self::ServerBackupRestoreProgress
            | Self::ServerBackupRestoreCompleted
            | Self::ServerDatabaseBackupRestoreStarted
            | Self::ServerDatabaseBackupRestoreProgress
            | Self::ServerDatabaseBackupRestoreCompleted => {
                BroadcastPermission::Required(Permission::BackupRead)
            }
            Self::ServerScheduleStarted
            | Self::ServerScheduleStepStatus
            | Self::ServerScheduleStepError
            | Self::ServerScheduleCompleted => {
                BroadcastPermission::Required(Permission::ScheduleRead)
            }
            Self::ServerOperationProgress
            | Self::ServerOperationError
            | Self::ServerOperationCompleted
            | Self::ServerOperationAborted
            | Self::ServerFileUploads => BroadcastPermission::Required(Permission::FileRead),

            Self::AuthenticationSuccess
            | Self::TokenExpiring
            | Self::TokenExpired
            | Self::Authentication
            | Self::ConfigureSocket
            | Self::SocketConfigured
            | Self::SetState
            | Self::SendServerLogs
            | Self::SendCommand
            | Self::SendStats
            | Self::SendStatus
            | Self::Error
            | Self::JwtError
            | Self::Ping
            | Self::Pong
            | Self::ServerCustomEvent
            | Self::FileCollabSubscribe
            | Self::FileCollabUnsubscribe
            | Self::FileCollabUpdate
            | Self::FileCollabAwareness
            | Self::FileCollabSave
            | Self::FileCollabSync
            | Self::FileCollabParticipants
            | Self::FileCollabSaved
            | Self::FileCollabReload
            | Self::FileCollabConflict
            | Self::FileCollabError => BroadcastPermission::Denied,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetedWebsocketMessage {
    user_uuids: Arc<HashSet<uuid::Uuid>>,
    connection_uuids: Arc<HashSet<uuid::Uuid>>,
    permissions: Arc<Permissions>,
    message: WebsocketMessage,
}

impl TargetedWebsocketMessage {
    pub fn new(
        user_uuids: HashSet<uuid::Uuid>,
        permissions: Permissions,
        message: WebsocketMessage,
    ) -> Self {
        Self {
            user_uuids: Arc::new(user_uuids),
            connection_uuids: Arc::new(HashSet::new()),
            permissions: Arc::new(permissions),
            message,
        }
    }

    pub fn new_connections(
        connection_uuids: HashSet<uuid::Uuid>,
        permissions: Permissions,
        message: WebsocketMessage,
    ) -> Self {
        Self {
            user_uuids: Arc::new(HashSet::new()),
            connection_uuids: Arc::new(connection_uuids),
            permissions: Arc::new(permissions),
            message,
        }
    }

    pub fn matches(
        &self,
        connection_id: &uuid::Uuid,
        user_uuid: &uuid::Uuid,
        has_permission: impl Fn(Permission) -> bool,
    ) -> bool {
        (self.user_uuids.is_empty() || self.user_uuids.contains(user_uuid))
            && (self.connection_uuids.is_empty() || self.connection_uuids.contains(connection_id))
            && self.permissions.iter().all(|perm| has_permission(*perm))
    }

    pub fn matches_user(
        &self,
        user_uuid: &uuid::Uuid,
        has_permission: impl Fn(Permission) -> bool,
    ) -> bool {
        self.connection_uuids.is_empty()
            && (self.user_uuids.is_empty() || self.user_uuids.contains(user_uuid))
            && self.permissions.iter().all(|perm| has_permission(*perm))
    }

    #[inline]
    pub fn into_message(self) -> WebsocketMessage {
        self.message
    }
}

/// A single websocket message argument.
///
/// Structured and binary arguments keep their raw form so `msgpack` transmission can embed them
/// natively, while every other consumer sees the string they would have received before: compact
/// JSON for structured arguments, standard base64 for binary ones.
#[derive(Debug, Clone)]
pub enum WebsocketArg {
    Text(compact_str::CompactString),
    Structured(Arc<StructuredArg>),
    Binary(Arc<BinaryArg>),
}

#[derive(Debug)]
pub struct StructuredArg {
    value: serde_json::Value,
    json: OnceLock<compact_str::CompactString>,
}

#[derive(Debug)]
pub struct BinaryArg {
    bytes: Vec<u8>,
    base64: OnceLock<compact_str::CompactString>,
}

impl WebsocketArg {
    pub fn binary(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Binary(Arc::new(BinaryArg {
            bytes: bytes.into(),
            base64: OnceLock::new(),
        }))
    }

    pub fn structured(value: impl Serialize) -> Result<Self, serde_json::Error> {
        Ok(Self::Structured(Arc::new(StructuredArg {
            value: serde_json::to_value(value)?,
            json: OnceLock::new(),
        })))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Text(text) => text,
            Self::Structured(arg) => arg.json.get_or_init(|| arg.value.to_compact_string()),
            Self::Binary(arg) => arg.base64.get_or_init(|| {
                base64::engine::general_purpose::STANDARD
                    .encode(&arg.bytes)
                    .into()
            }),
        }
    }
}

impl std::ops::Deref for WebsocketArg {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl std::borrow::Borrow<str> for WebsocketArg {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for WebsocketArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<T: Into<compact_str::CompactString>> From<T> for WebsocketArg {
    #[inline]
    fn from(value: T) -> Self {
        Self::Text(value.into())
    }
}

impl Serialize for WebsocketArg {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WebsocketArg {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ArgVisitor;

        impl Visitor<'_> for ArgVisitor {
            type Value = WebsocketArg;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or binary")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(WebsocketArg::Text(value.into()))
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(WebsocketArg::binary(value))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(WebsocketArg::binary(value))
            }
        }

        deserializer.deserialize_any(ArgVisitor)
    }
}

struct NativeArg<'a>(&'a WebsocketArg);

impl Serialize for NativeArg<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            WebsocketArg::Text(text) => serializer.serialize_str(text),
            WebsocketArg::Structured(arg) => arg.value.serialize(serializer),
            WebsocketArg::Binary(arg) => serializer.serialize_bytes(&arg.bytes),
        }
    }
}

#[derive(Debug, Clone, ToSchema, Deserialize, Serialize)]
pub struct WebsocketMessage {
    pub event: WebsocketEvent,

    #[serde(deserialize_with = "string_vec_or_empty")]
    #[serde(serialize_with = "arc_vec")]
    #[schema(value_type = Vec<String>)]
    pub args: Arc<[WebsocketArg]>,
}

impl WebsocketMessage {
    #[inline]
    pub fn builder(event: WebsocketEvent) -> WebsocketMessageBuilder {
        WebsocketMessageBuilder::new(event)
    }

    /// The same outer shape as [`WebsocketMessage`]'s own `Serialize`, but with structured
    /// arguments embedded as values instead of JSON strings.
    fn native(&self) -> NativeWebsocketMessage<'_> {
        NativeWebsocketMessage {
            event: self.event,
            args: &self.args,
        }
    }
}

#[derive(Serialize)]
struct NativeWebsocketMessage<'a> {
    event: WebsocketEvent,
    #[serde(serialize_with = "native_args")]
    args: &'a [WebsocketArg],
}

pub struct WebsocketMessageBuilder {
    event: WebsocketEvent,
    args: Vec<WebsocketArg>,
}

impl WebsocketMessageBuilder {
    pub fn new(event: WebsocketEvent) -> Self {
        Self {
            event,
            args: Vec::new(),
        }
    }

    pub fn structured_arg(mut self, arg: impl Serialize) -> Self {
        match WebsocketArg::structured(arg) {
            Ok(arg) => self.args.push(arg),
            Err(err) => tracing::warn!("failed to serialize websocket message argument: {:?}", err),
        }
        self
    }

    pub fn binary_arg(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.args.push(WebsocketArg::binary(bytes));
        self
    }

    pub fn arg(mut self, arg: impl Into<WebsocketArg>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<WebsocketArg>>) -> Self {
        self.args.extend(args.into_iter().map(|arg| arg.into()));
        self
    }

    pub fn build(self) -> WebsocketMessage {
        WebsocketMessage {
            event: self.event,
            args: Arc::from(self.args),
        }
    }
}

fn string_vec_or_empty<'de, D>(deserializer: D) -> Result<Arc<[WebsocketArg]>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVecVisitor(PhantomData<[WebsocketArg]>);

    impl<'de> Visitor<'de> for StringVecVisitor {
        type Value = Arc<[WebsocketArg]>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or binary array or null")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(element) = seq.next_element::<Option<WebsocketArg>>()? {
                if let Some(value) = element {
                    vec.push(value);
                }
            }
            Ok(Arc::from(vec))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Arc::new([]))
        }
    }

    deserializer.deserialize_any(StringVecVisitor(PhantomData))
}

fn arc_vec<S>(vec: &Arc<[WebsocketArg]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut seq = serializer.serialize_seq(Some(vec.len()))?;
    for item in vec.iter() {
        seq.serialize_element(item)?;
    }

    seq.end()
}

fn native_args<S>(args: &&[WebsocketArg], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut seq = serializer.serialize_seq(Some(args.len()))?;
    for item in args.iter() {
        seq.serialize_element(&NativeArg(item))?;
    }

    seq.end()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransmissionMode {
    /// JSON text frames.
    Text,
    /// Msgpack binary frames, structured arguments as JSON strings.
    Binary,
    /// Msgpack binary frames, structured and binary arguments embedded as msgpack values.
    Msgpack,
}

impl TransmissionMode {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Binary,
            2 => Self::Msgpack,
            _ => Self::Text,
        }
    }

    /// Decodes an incoming binary argument the way this mode sends them: msgpack bin in
    /// `msgpack` mode, standard base64 strings otherwise.
    fn binary_arg(self, arg: &WebsocketArg) -> Option<Cow<'_, [u8]>> {
        match (self, arg) {
            (Self::Msgpack, WebsocketArg::Binary(arg)) => Some(Cow::Borrowed(&arg.bytes)),
            (Self::Text | Self::Binary, WebsocketArg::Text(text)) => {
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .ok()
                    .map(Cow::Owned)
            }
            _ => None,
        }
    }
}

pub type SocketJwt = Arc<RwLock<Option<Arc<WebsocketJwtPayload>>>>;

pub struct ServerWebsocketHandler {
    pub connection_id: uuid::Uuid,
    sender: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    state: crate::routes::State,
    server: crate::server::Server,
    socket_jwt: SocketJwt,
    closed: AtomicBool,
    transmission_mode: AtomicU8,
    missed_targeted: AtomicBool,
}

impl ServerWebsocketHandler {
    fn new(
        sender: Arc<Mutex<SplitSink<WebSocket, Message>>>,
        state: crate::routes::State,
        server: crate::server::Server,
        socket_jwt: SocketJwt,
    ) -> Self {
        Self {
            connection_id: uuid::Uuid::new_v4(),
            sender,
            state,
            server,
            socket_jwt,
            closed: AtomicBool::new(false),
            transmission_mode: AtomicU8::new(TransmissionMode::Text as u8),
            missed_targeted: AtomicBool::new(false),
        }
    }

    fn set_transmission_mode(&self, mode: TransmissionMode) {
        self.transmission_mode.store(mode as u8, Ordering::Relaxed);
    }

    fn binary_arg<'a>(&self, arg: &'a WebsocketArg) -> Option<Cow<'a, [u8]>> {
        TransmissionMode::from_u8(self.transmission_mode.load(Ordering::Relaxed)).binary_arg(arg)
    }

    async fn get_jwt(&self) -> Result<Arc<WebsocketJwtPayload>, anyhow::Error> {
        if let Some(socket_jwt) = &*self.socket_jwt.read().await {
            Ok(Arc::clone(socket_jwt))
        } else {
            Err(anyhow::anyhow!("unable to acquire socket jwt"))
        }
    }

    async fn get_validated_jwt(&self) -> Result<Arc<WebsocketJwtPayload>, anyhow::Error> {
        let jwt = self.get_jwt().await?;

        if let Err(err) = jwt.base.validate(&self.state.config.jwt, Some("websocket")) {
            return Err(anyhow::anyhow!("invalid token: {err}"));
        }

        Ok(jwt)
    }

    async fn has_permission(&self, permission: Permission) -> Result<bool, anyhow::Error> {
        let jwt = self.get_validated_jwt().await?;

        Ok(jwt.has_live_permission(&self.server.user_permissions, permission))
    }

    async fn has_calagopus_permission_or(
        &self,
        permission: Permission,
        default: bool,
    ) -> Result<bool, anyhow::Error> {
        let jwt = self.get_validated_jwt().await?;

        Ok(
            jwt.has_live_calagopus_permission_or(
                &self.server.user_permissions,
                permission,
                default,
            ),
        )
    }

    async fn filter_upload_entries(
        &self,
        message: WebsocketMessage,
    ) -> Result<WebsocketMessage, anyhow::Error> {
        let user_uuid = self.get_validated_jwt().await?.user_uuid;

        if !self.server.user_permissions.has_ignored_files(user_uuid) {
            return Ok(message);
        }

        let entries: Vec<_> = self
            .server
            .filesystem
            .uploads
            .entries(&self.server.filesystem)
            .await
            .into_iter()
            .filter(|entry| {
                !self.server.user_permissions.is_ignored(
                    &self.server,
                    user_uuid,
                    std::path::Path::new(entry.directory.as_str()).join(entry.target_name.as_str()),
                    crate::server::filesystem::cap::FileType::File,
                )
            })
            .collect();

        Ok(WebsocketMessage::builder(message.event)
            .structured_arg(&entries)
            .build())
    }

    async fn close(&self, reason: &str) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        self.closed.store(true, Ordering::Relaxed);

        if let Err(err) = self
            .sender
            .lock()
            .await
            .send(Message::Close(Some(CloseFrame {
                code: axum::extract::ws::close_code::NORMAL,
                reason: reason.into(),
            })))
            .await
            && err.source().is_none_or(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_none_or(|i| i.kind() != std::io::ErrorKind::BrokenPipe)
            })
        {
            tracing::error!("failed to close websocket: {:?}", err);
        }
    }

    pub async fn send_message(&self, message: WebsocketMessage) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }

        let mode = TransmissionMode::from_u8(self.transmission_mode.load(Ordering::Relaxed));
        let message = match mode {
            TransmissionMode::Text => match serde_json::to_string(&message) {
                Ok(message) => Message::Text(message.into()),
                Err(err) => {
                    tracing::error!("failed to serialize websocket message: {:?}", err);
                    return;
                }
            },
            TransmissionMode::Binary | TransmissionMode::Msgpack => {
                let encoded = if mode == TransmissionMode::Msgpack {
                    rmp_serde::to_vec(&message.native())
                } else {
                    rmp_serde::to_vec(&message)
                };

                match encoded {
                    Ok(message) => Message::Binary(message.into()),
                    Err(err) => {
                        tracing::error!("failed to serialize websocket message: {:?}", err);
                        return;
                    }
                }
            }
        };

        if let Err(err) = self.sender.lock().await.send(message).await
            && err.source().is_none_or(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_none_or(|i| i.kind() != std::io::ErrorKind::BrokenPipe)
            })
        {
            tracing::error!("failed to send websocket message: {:?}", err);
        }
    }

    async fn send_error(&self, message: impl Into<Cow<'_, str>>) {
        self.send_message(
            WebsocketMessage::builder(WebsocketEvent::ServerDaemonMessage)
                .arg(
                    nu_ansi_term::Style::new()
                        .bold()
                        .on(nu_ansi_term::Color::Red)
                        .paint(message.into())
                        .to_compact_string(),
                )
                .build(),
        )
        .await;
    }

    async fn send_admin_error(&self, message: impl Into<anyhow::Error>) {
        let show_error = self.socket_jwt.read().await.as_ref().is_some_and(|j| {
            j.permissions
                .has_permission(super::permissions::Permission::AdminWebsocketErrors)
        });

        if show_error {
            self.send_error(message.into().to_string()).await;
        } else {
            self.send_error("An unexpected error occurred. Please contact an Administrator.")
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token(user: uuid::Uuid, permissions: &[&str]) -> WebsocketJwtPayload {
        serde_json::from_value(json!({
            "iss": "panel",
            "aud": ["wings"],
            "jti": "test",
            "user_uuid": user,
            "server_uuid": uuid::Uuid::new_v4(),
            "permissions": permissions,
        }))
        .unwrap()
    }

    // WebsocketJwtPayload

    #[test]
    fn broader_map_entry_from_another_session_does_not_widen_token() {
        tokio_test::block_on(async {
            let map = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            map.grant(
                user,
                &[
                    Permission::All,
                    Permission::MetaCalagopus,
                    Permission::WebsocketConnect,
                ],
            );
            let jwt = token(
                user,
                &["meta.calagopus", "websocket.connect", "control.console"],
            );

            assert!(!jwt.has_live_permission(&map, Permission::FileReadContent));
            assert!(!jwt.has_live_calagopus_permission_or(
                &map,
                Permission::ControlReadConsole,
                true
            ));
            assert!(jwt.has_live_permission(&map, Permission::ControlConsole));
        });
    }

    #[test]
    fn token_and_map_agreeing_grant_normally() {
        tokio_test::block_on(async {
            let map = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            map.grant(
                user,
                &[
                    Permission::All,
                    Permission::MetaCalagopus,
                    Permission::WebsocketConnect,
                ],
            );
            let jwt = token(user, &["*", "meta.calagopus", "websocket.connect"]);

            assert!(jwt.has_live_permission(&map, Permission::FileReadContent));
            assert!(jwt.has_live_permission(&map, Permission::FileUpdate));
            assert!(jwt.has_live_calagopus_permission_or(
                &map,
                Permission::ControlReadConsole,
                false
            ));
        });
    }

    #[test]
    fn panel_downgrade_in_map_narrows_token() {
        tokio_test::block_on(async {
            let map = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            let jwt = token(user, &["*", "meta.calagopus", "websocket.connect"]);
            map.grant(
                user,
                &[
                    Permission::All,
                    Permission::MetaCalagopus,
                    Permission::WebsocketConnect,
                ],
            );
            assert!(jwt.has_live_permission(&map, Permission::FileUpdate));

            map.grant(
                user,
                &[Permission::MetaCalagopus, Permission::WebsocketConnect],
            );

            assert!(!jwt.has_live_permission(&map, Permission::FileUpdate));
            assert!(!jwt.has_live_calagopus_permission_or(
                &map,
                Permission::ControlReadConsole,
                true
            ));
            assert!(jwt.has_live_permission(&map, Permission::WebsocketConnect));
        });
    }

    #[test]
    fn map_entry_of_another_user_does_not_count() {
        tokio_test::block_on(async {
            let map = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            map.grant(
                uuid::Uuid::new_v4(),
                &[Permission::All, Permission::MetaCalagopus],
            );
            let jwt = token(user, &["*", "meta.calagopus"]);

            assert!(!jwt.has_live_permission(&map, Permission::FileRead));
        });
    }

    #[test]
    fn pterodactyl_token_falls_back_to_default_for_console() {
        tokio_test::block_on(async {
            let map = UserPermissionsMap::default();
            let user = uuid::Uuid::new_v4();
            map.grant(
                user,
                &[Permission::WebsocketConnect, Permission::ControlConsole],
            );
            let jwt = token(user, &["websocket.connect", "control.console"]);

            assert!(jwt.has_live_calagopus_permission_or(
                &map,
                Permission::ControlReadConsole,
                true
            ));
            assert!(!jwt.has_live_calagopus_permission_or(
                &map,
                Permission::ControlReadConsole,
                false
            ));
        });
    }

    #[derive(Serialize)]
    struct Nested {
        label: &'static str,
        count: u32,
    }

    #[derive(Serialize)]
    struct Sample {
        id: uuid::Uuid,
        nested: Nested,
        missing: Option<u8>,
        big: u64,
        ratio: f64,
    }

    fn sample() -> Sample {
        Sample {
            id: uuid::Uuid::new_v4(),
            nested: Nested {
                label: "quote \" and ünïcode",
                count: 7,
            },
            missing: None,
            big: u64::MAX - 1,
            ratio: 0.1,
        }
    }

    fn mixed_message(value: &Sample) -> WebsocketMessage {
        WebsocketMessage::builder(WebsocketEvent::SendStats)
            .arg("text")
            .structured_arg(value)
            .build()
    }

    // WebsocketMessage

    #[test]
    fn structured_arg_matches_serde_json_string() {
        let value = sample();
        let frame: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&mixed_message(&value)).unwrap()).unwrap();

        assert_eq!(
            frame["args"][1],
            serde_json::Value::String(serde_json::to_string(&value).unwrap())
        );
    }

    #[test]
    fn binary_frame_matches_text_frame() {
        let message = mixed_message(&sample());
        let text: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&message).unwrap()).unwrap();
        let binary: serde_json::Value =
            rmp_serde::from_slice(&rmp_serde::to_vec(&message).unwrap()).unwrap();

        assert_eq!(binary, json!([text["event"], text["args"]]));
    }

    #[test]
    fn msgpack_frame_embeds_structured_args_natively() {
        let value = sample();
        let message = mixed_message(&value);
        let decoded: serde_json::Value =
            rmp_serde::from_slice(&rmp_serde::to_vec(&message.native()).unwrap()).unwrap();

        assert_eq!(
            decoded,
            json!([
                "send stats",
                ["text", serde_json::to_value(&value).unwrap()]
            ])
        );

        let none = WebsocketMessage::builder(WebsocketEvent::SendStats)
            .structured_arg(None::<u8>)
            .build();
        let decoded: serde_json::Value =
            rmp_serde::from_slice(&rmp_serde::to_vec(&none.native()).unwrap()).unwrap();

        assert_eq!(decoded, json!(["send stats", [null]]));
    }

    const BINARY: [u8; 5] = [0, 1, 0xfe, 0xff, b'a'];

    fn binary_message() -> WebsocketMessage {
        WebsocketMessage::builder(WebsocketEvent::SendStats)
            .arg("text")
            .binary_arg(BINARY.to_vec())
            .binary_arg(Vec::new())
            .build()
    }

    #[test]
    fn binary_arg_is_standard_base64_in_text_and_binary_frames() {
        use base64::Engine;

        let message = binary_message();
        let text: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&message).unwrap()).unwrap();

        assert_eq!(
            text["args"],
            json!([
                "text",
                base64::engine::general_purpose::STANDARD.encode(BINARY),
                ""
            ])
        );

        let binary: serde_json::Value =
            rmp_serde::from_slice(&rmp_serde::to_vec(&message).unwrap()).unwrap();

        assert_eq!(binary, json!([text["event"], text["args"]]));
    }

    #[test]
    fn msgpack_frame_embeds_binary_args_as_bin() {
        use base64::Engine;

        let encoded = rmp_serde::to_vec(&binary_message().native()).unwrap();
        let mut bin = vec![0xc4, BINARY.len() as u8];
        bin.extend_from_slice(&BINARY);
        let base64 = base64::engine::general_purpose::STANDARD.encode(BINARY);

        assert!(encoded.windows(bin.len()).any(|w| w == bin.as_slice()));
        assert!(encoded.ends_with(&[0xc4, 0]));
        assert!(
            !encoded
                .windows(base64.len())
                .any(|w| w == base64.as_bytes())
        );
    }

    #[test]
    fn incoming_null_args_are_empty_or_dropped() {
        let message: WebsocketMessage =
            serde_json::from_str(r#"{"event":"send command","args":null}"#).unwrap();
        assert!(message.args.is_empty());

        let message: WebsocketMessage =
            serde_json::from_str(r#"{"event":"send command","args":["a",null,"b"]}"#).unwrap();
        let args: Vec<&str> = message.args.iter().map(WebsocketArg::as_str).collect();
        assert_eq!(args, ["a", "b"]);
        assert!(
            message
                .args
                .iter()
                .all(|arg| matches!(arg, WebsocketArg::Text(_)))
        );
    }

    #[test]
    fn incoming_msgpack_bin_args_are_binary() {
        let event = b"file collab update";
        let mut frame = vec![0x92, 0xa0 | event.len() as u8];
        frame.extend_from_slice(event);
        frame.extend_from_slice(&[0x93, 0xa4]);
        frame.extend_from_slice(b"path");
        frame.extend_from_slice(&[0xa1, b'1', 0xc4, BINARY.len() as u8]);
        frame.extend_from_slice(&BINARY);

        let message: WebsocketMessage = rmp_serde::from_slice(&frame).unwrap();

        assert!(matches!(message.event, WebsocketEvent::FileCollabUpdate));
        assert_eq!(message.args.len(), 3);
        assert!(matches!(&message.args[0], WebsocketArg::Text(text) if text == "path"));
        assert!(matches!(&message.args[1], WebsocketArg::Text(text) if text == "1"));
        assert!(matches!(&message.args[2], WebsocketArg::Binary(binary) if binary.bytes == BINARY));
    }

    #[test]
    fn incoming_non_string_args_are_rejected() {
        assert!(
            serde_json::from_str::<WebsocketMessage>(r#"{"event":"send command","args":["a",1]}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<WebsocketMessage>(
                r#"{"event":"send command","args":["a",{"b":1}]}"#
            )
            .is_err()
        );
    }

    // TransmissionMode

    #[test]
    fn binary_arg_matches_mode() {
        use base64::Engine;

        let binary = WebsocketArg::binary(BINARY.to_vec());
        let base64 = WebsocketArg::from(base64::engine::general_purpose::STANDARD.encode(BINARY));

        assert_eq!(
            TransmissionMode::Msgpack.binary_arg(&binary).as_deref(),
            Some(&BINARY[..])
        );
        assert!(TransmissionMode::Msgpack.binary_arg(&base64).is_none());

        for mode in [TransmissionMode::Text, TransmissionMode::Binary] {
            assert_eq!(mode.binary_arg(&base64).as_deref(), Some(&BINARY[..]));
            assert!(mode.binary_arg(&binary).is_none());
            assert!(
                mode.binary_arg(&WebsocketArg::from("not base64!"))
                    .is_none()
            );
        }
    }
}
