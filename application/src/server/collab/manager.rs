use super::{CollabConflict, CollabError, CollabParticipant, CollabSaved, CollabSyncMeta};
use crate::server::{
    activity::{Activity, ActivityEvent},
    filesystem::{cap::FileType, virtualfs::VirtualWritableFilesystem},
    permissions::{Permission, Permissions},
    websocket::{
        ServerWebsocketHandler, TargetedWebsocketMessage, WebsocketEvent, WebsocketMessage,
    },
};
use base64::Engine;
use compact_str::ToCompactString;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yrs::{
    Doc, GetString, ReadTxn, StateVector, Text, TextRef, Transact, Update,
    encoding::{
        read::{Cursor, Read},
        write::Write,
    },
    updates::decoder::Decode,
};

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

const MAX_AWARENESS_INT: u64 = (1 << 53) - 1;

struct AwarenessEntry {
    client: u64,
    clock: u64,
    removed: bool,
}

fn decode_awareness(update: &[u8]) -> Option<Vec<AwarenessEntry>> {
    let mut cursor = Cursor::new(update);
    let count: u64 = cursor.read_var().ok()?;

    let mut entries = Vec::with_capacity((count as usize).min(64));
    for _ in 0..count {
        let client: u64 = cursor.read_var().ok()?;
        let clock: u64 = cursor.read_var().ok()?;
        let state = cursor.read_buf().ok()?;

        entries.push(AwarenessEntry {
            client,
            clock,
            removed: state == b"null",
        });
    }

    Some(entries)
}

fn encode_awareness_removal(clients: &HashMap<u64, u64>) -> Vec<u8> {
    let mut update = Vec::new();
    update.write_var(clients.len() as u64);

    for (&client, &clock) in clients {
        update.write_var(client);
        update.write_var(clock);
        Write::write_buf(&mut update, b"null");
    }

    update
}

const MAX_EDITOR_ID_LEN: usize = 64;

fn editor_id(editor: Option<&str>) -> Result<compact_str::CompactString, CollabError> {
    match editor {
        None => Ok(compact_str::CompactString::const_new("")),
        Some(editor) if editor.len() <= MAX_EDITOR_ID_LEN => Ok(editor.to_compact_string()),
        Some(_) => Err(CollabError::User("editor id is too long")),
    }
}

#[derive(Default)]
struct ConnectionState {
    subscriptions: HashMap<compact_str::CompactString, HashSet<compact_str::CompactString>>,
    keys: HashMap<compact_str::CompactString, compact_str::CompactString>,
    pending_resync: bool,
}

impl ConnectionState {
    fn subscribe(
        &mut self,
        raw_path: &str,
        key: &compact_str::CompactString,
        editor: compact_str::CompactString,
    ) {
        self.subscriptions
            .entry(key.clone())
            .or_default()
            .insert(editor);
        self.keys.insert(raw_path.to_compact_string(), key.clone());
        self.pending_resync = false;
    }

    fn unsubscribe(
        &mut self,
        raw_path: &str,
        resolved: Option<compact_str::CompactString>,
        editor: &str,
    ) -> Option<Unsubscribed> {
        let key = self.keys.get(raw_path).cloned().or(resolved)?;
        let editors = self.subscriptions.get_mut(&key)?;

        editors.remove(editor);
        if !editors.is_empty() {
            return Some(Unsubscribed { key, last: false });
        }

        self.subscriptions.remove(&key);
        self.keys.retain(|_, resolved| resolved != &key);

        Some(Unsubscribed { key, last: true })
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Unsubscribed {
    key: compact_str::CompactString,
    last: bool,
}

fn track_awareness_clients(
    clients: &mut HashMap<u64, u64>,
    entries: &[AwarenessEntry],
    max_cursors: usize,
) {
    for entry in entries {
        if entry.client > MAX_AWARENESS_INT || entry.clock > MAX_AWARENESS_INT {
            continue;
        }

        if entry.removed {
            clients.remove(&entry.client);
        } else if clients.len() < max_cursors || clients.contains_key(&entry.client) {
            let clock = clients.entry(entry.client).or_default();
            *clock = (*clock).max(entry.clock);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ConflictState {
    hash: Option<blake3::Hash>,
    deleted: bool,
}

impl From<ConflictState> for CollabConflict {
    fn from(state: ConflictState) -> Self {
        Self {
            hash: state.hash.map(|hash| hash.to_hex().to_string()),
            deleted: state.deleted,
        }
    }
}

struct Participant {
    user_uuid: uuid::Uuid,
    user_name: compact_str::CompactString,
    user_avatar: Option<String>,
}

fn broadcast_permissions() -> Permissions {
    let mut permissions = Permissions::default();
    permissions.insert(Permission::FileReadContent);

    permissions
}

struct CollabDoc {
    doc: Doc,
    text: TextRef,
    applied_update_bytes: u64,
    disk_hash: blake3::Hash,
}

impl CollabDoc {
    fn new(content: &str) -> Self {
        let doc = Doc::new();
        let text = doc.get_or_insert_text("content");

        {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, content);
        }

        Self {
            doc,
            text,
            applied_update_bytes: 0,
            disk_hash: blake3::hash(content.as_bytes()),
        }
    }

    fn encode_full_state(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    fn content(&self) -> String {
        self.text.get_string(&self.doc.transact())
    }
}

pub struct CollabSession {
    path: compact_str::CompactString,
    abs_path: PathBuf,
    filesystem: Arc<dyn VirtualWritableFilesystem>,
    websocket: tokio::sync::broadcast::Sender<TargetedWebsocketMessage>,
    doc: parking_lot::Mutex<CollabDoc>,
    dirty: AtomicBool,
    conflict: parking_lot::Mutex<Option<ConflictState>>,
    participants: tokio::sync::Mutex<HashMap<uuid::Uuid, Participant>>,
    awareness: parking_lot::Mutex<HashMap<uuid::Uuid, HashMap<u64, u64>>>,
    save_lock: tokio::sync::Mutex<()>,
}

impl CollabSession {
    async fn broadcast(&self, except: Option<uuid::Uuid>, message: WebsocketMessage) {
        let connections: HashSet<uuid::Uuid> = {
            let participants = self.participants.lock().await;
            participants
                .keys()
                .copied()
                .filter(|connection| Some(*connection) != except)
                .collect()
        };

        if connections.is_empty() {
            return;
        }

        self.websocket
            .send(TargetedWebsocketMessage::new_connections(
                connections,
                broadcast_permissions(),
                message,
            ))
            .ok();
    }

    async fn broadcast_conflict(&self, state: Option<ConflictState>) {
        self.broadcast(
            None,
            WebsocketMessage::builder(WebsocketEvent::FileCollabConflict)
                .arg(self.path.clone())
                .structured_arg(state.map(CollabConflict::from))
                .build(),
        )
        .await;
    }

    async fn broadcast_resync(&self) {
        self.broadcast(
            None,
            WebsocketMessage::builder(WebsocketEvent::FileCollabError)
                .arg(self.path.clone())
                .arg("resync")
                .build(),
        )
        .await;
    }

    fn set_conflict(&self, state: Option<ConflictState>) -> bool {
        let mut conflict = self.conflict.lock();
        if *conflict != state {
            *conflict = state;
            true
        } else {
            false
        }
    }

    fn current_conflict(&self) -> Option<ConflictState> {
        *self.conflict.lock()
    }

    fn track_awareness(
        &self,
        connection_id: uuid::Uuid,
        entries: &[AwarenessEntry],
        max_cursors: usize,
    ) {
        let mut awareness = self.awareness.lock();
        let clients = awareness.entry(connection_id).or_default();

        track_awareness_clients(clients, entries, max_cursors);

        if clients.is_empty() {
            awareness.remove(&connection_id);
        }
    }

    fn awareness_removal_message(&self, connection_id: uuid::Uuid) -> Option<WebsocketMessage> {
        let clients = self.awareness.lock().remove(&connection_id)?;
        if clients.is_empty() {
            return None;
        }

        Some(
            WebsocketMessage::builder(WebsocketEvent::FileCollabAwareness)
                .arg(self.path.clone())
                .arg(BASE64.encode(encode_awareness_removal(&clients)))
                .build(),
        )
    }

    async fn participants_message(&self) -> WebsocketMessage {
        let participants: Vec<CollabParticipant> = {
            let participants = self.participants.lock().await;
            let mut seen = HashSet::new();
            participants
                .values()
                .filter(|p| seen.insert(p.user_uuid))
                .map(|p| CollabParticipant {
                    user: p.user_uuid,
                    name: p.user_name.clone(),
                    avatar: p.user_avatar.clone(),
                })
                .collect()
        };

        WebsocketMessage::builder(WebsocketEvent::FileCollabParticipants)
            .arg(self.path.clone())
            .structured_arg(participants)
            .build()
    }
}

pub struct CollabManager {
    server: uuid::Uuid,
    websocket: tokio::sync::broadcast::Sender<TargetedWebsocketMessage>,
    config: Arc<crate::config::Config>,
    sessions: Arc<tokio::sync::Mutex<HashMap<compact_str::CompactString, Arc<CollabSession>>>>,
    connections: tokio::sync::Mutex<HashMap<uuid::Uuid, ConnectionState>>,
    pending_updates: parking_lot::Mutex<
        HashMap<
            (
                uuid::Uuid,
                compact_str::CompactString,
                compact_str::CompactString,
            ),
            Vec<u8>,
        >,
    >,
    pending_teardowns:
        Arc<parking_lot::Mutex<HashMap<compact_str::CompactString, tokio::task::AbortHandle>>>,
}

impl CollabManager {
    pub fn new(
        server: uuid::Uuid,
        websocket: tokio::sync::broadcast::Sender<TargetedWebsocketMessage>,
        config: &Arc<crate::config::Config>,
    ) -> Self {
        Self {
            server,
            websocket,
            config: Arc::clone(config),
            sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            connections: tokio::sync::Mutex::new(HashMap::new()),
            pending_updates: parking_lot::Mutex::new(HashMap::new()),
            pending_teardowns: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    async fn resolve(
        &self,
        server: &crate::server::Server,
        user_uuid: uuid::Uuid,
        raw_path: &str,
    ) -> Result<
        (
            PathBuf,
            compact_str::CompactString,
            Arc<dyn VirtualWritableFilesystem>,
        ),
        CollabError,
    > {
        use compact_str::ToCompactString;

        if !self.config.load().system.file_collaboration.enabled {
            return Err(CollabError::User("collaborative editing is disabled"));
        }

        let parent = Path::new(raw_path)
            .parent()
            .ok_or(CollabError::User("file has no parent"))?;
        let file_name = Path::new(raw_path)
            .file_name()
            .ok_or(CollabError::User("invalid file name"))?;

        let (root, filesystem) = server.filesystem.resolve_writable_fs(server, parent).await;
        if !filesystem.is_primary_server_fs() {
            return Err(CollabError::User(
                "collaborative editing is only available on the primary filesystem",
            ));
        }

        let path = root.join(file_name);
        if server
            .filesystem
            .async_is_ignored(&path, FileType::File)
            .await
            || server
                .user_permissions
                .async_is_ignored(server, user_uuid, &path, FileType::File)
                .await
        {
            return Err(CollabError::User("file not found"));
        }

        let key = server.filesystem.diff_key(&path).await;

        Ok((path, key.to_string_lossy().to_compact_string(), filesystem))
    }

    async fn read_content(
        filesystem: &Arc<dyn VirtualWritableFilesystem>,
        path: &Path,
        size_cap: u64,
    ) -> Result<String, CollabError> {
        let metadata = filesystem
            .async_metadata(&path)
            .await
            .map_err(|_| CollabError::User("file not found"))?;
        if !metadata.file_type.is_file() {
            return Err(CollabError::User("file is not a file"));
        }
        if metadata.size > size_cap {
            return Err(CollabError::User(
                "file is too large for collaborative editing",
            ));
        }

        let mut handle = filesystem
            .async_read_file(&path, None)
            .await
            .map_err(|_| CollabError::User("file not found"))?;
        if handle.size > size_cap {
            return Err(CollabError::User(
                "file is too large for collaborative editing",
            ));
        }

        let mut buf = Vec::with_capacity(handle.size as usize);
        (&mut handle.reader)
            .take(size_cap.saturating_add(1))
            .read_to_end(&mut buf)
            .await
            .map_err(|err| CollabError::Internal(err.into()))?;
        if buf.len() as u64 > size_cap {
            return Err(CollabError::User(
                "file is too large for collaborative editing",
            ));
        }

        String::from_utf8(buf).map_err(|_| CollabError::User("file is not editable as text"))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe(
        &self,
        server: &crate::server::Server,
        handler: &Arc<ServerWebsocketHandler>,
        user_uuid: uuid::Uuid,
        user_name: compact_str::CompactString,
        user_avatar: Option<String>,
        raw_path: &str,
        editor: Option<&str>,
    ) -> Result<(), CollabError> {
        let editor = editor_id(editor)?;
        let (path, key, filesystem) = self.resolve(server, user_uuid, raw_path).await?;

        let config = self.config.load();
        let size_cap = config.system.file_collaboration.file_size_cap;
        let max_sessions = config.system.file_collaboration.max_sessions_per_server as usize;
        let max_subscriptions =
            config.system.file_collaboration.max_sessions_per_connection as usize;
        let max_editors = config.system.file_collaboration.max_editors_per_session as usize;
        drop(config);

        {
            let connections = self.connections.lock().await;
            if let Some(connection) = connections.get(&handler.connection_id) {
                if !connection.subscriptions.contains_key(&key)
                    && connection.subscriptions.len() >= max_subscriptions
                {
                    return Err(CollabError::User(
                        "too many collaborative sessions open on this connection",
                    ));
                }

                if let Some(editors) = connection.subscriptions.get(&key)
                    && !editors.contains(&editor)
                    && editors.len() >= max_editors
                {
                    return Err(CollabError::User(
                        "too many editors open for this file on this connection",
                    ));
                }
            }
        }

        if let Some(abort) = self.pending_teardowns.lock().remove(&key) {
            abort.abort();
        }

        let session = {
            let mut sessions = self.sessions.lock().await;

            let session = match sessions.get(&key) {
                Some(session) => {
                    let session = Arc::clone(session);

                    if session.participants.lock().await.is_empty()
                        && !session.dirty.load(Ordering::Relaxed)
                    {
                        let content = match Self::read_content(&filesystem, &path, size_cap).await {
                            Ok(content) => content,
                            Err(err) => {
                                sessions.remove(&key);
                                tracing::debug!(
                                    server = %self.server,
                                    path = %key,
                                    "closed empty collaborative editing session after refresh failure"
                                );

                                return Err(err);
                            }
                        };
                        {
                            let mut doc = session.doc.lock();
                            if doc.disk_hash != blake3::hash(content.as_bytes()) {
                                *doc = CollabDoc::new(&content);
                            }
                        }
                        session.set_conflict(None);
                        session.awareness.lock().clear();
                    }

                    session
                }
                None => {
                    if sessions.len() >= max_sessions {
                        return Err(CollabError::User(
                            "too many collaborative sessions open on this server",
                        ));
                    }

                    let content = Self::read_content(&filesystem, &path, size_cap).await?;
                    let session = Arc::new(CollabSession {
                        path: key.clone(),
                        abs_path: path.clone(),
                        filesystem: Arc::clone(&filesystem),
                        websocket: self.websocket.clone(),
                        doc: parking_lot::Mutex::new(CollabDoc::new(&content)),
                        dirty: AtomicBool::new(false),
                        conflict: parking_lot::Mutex::new(None),
                        participants: tokio::sync::Mutex::new(HashMap::new()),
                        awareness: parking_lot::Mutex::new(HashMap::new()),
                        save_lock: tokio::sync::Mutex::new(()),
                    });

                    sessions.insert(key.clone(), Arc::clone(&session));
                    self.spawn_reconciler(&session);
                    tracing::debug!(
                        server = %self.server,
                        path = %key,
                        "opened collaborative editing session"
                    );

                    session
                }
            };

            session.participants.lock().await.insert(
                handler.connection_id,
                Participant {
                    user_uuid,
                    user_name,
                    user_avatar,
                },
            );

            session
        };
        self.connections
            .lock()
            .await
            .entry(handler.connection_id)
            .or_default()
            .subscribe(raw_path, &key, editor);

        let (state, dirty) = {
            let doc = session.doc.lock();
            (
                doc.encode_full_state(),
                session.dirty.load(Ordering::Relaxed),
            )
        };
        let conflict = session.current_conflict().map(CollabConflict::from);

        handler
            .send_message(
                WebsocketMessage::builder(WebsocketEvent::FileCollabSync)
                    .arg(key)
                    .arg(BASE64.encode(state))
                    .structured_arg(CollabSyncMeta { dirty, conflict })
                    .arg(raw_path)
                    .build(),
            )
            .await;

        let participants = session.participants_message().await;
        session.broadcast(None, participants).await;

        Ok(())
    }

    fn spawn_reconciler(&self, session: &Arc<CollabSession>) {
        let weak = Arc::downgrade(session);
        let config = Arc::clone(&self.config);
        let server = self.server;

        tokio::spawn(async move {
            let mut last_mtime: Option<std::time::SystemTime> = None;
            let mut reported_unreadable = false;

            loop {
                tokio::time::sleep(RECONCILE_INTERVAL).await;

                let Some(session) = weak.upgrade() else { break };
                let Ok(_save_guard) = session.save_lock.try_lock() else {
                    continue;
                };

                if session.dirty.load(Ordering::Relaxed) {
                    let converged = {
                        let doc = session.doc.lock();
                        blake3::hash(doc.content().as_bytes()) == doc.disk_hash
                    };
                    if converged {
                        session.dirty.store(false, Ordering::Relaxed);
                    }
                }

                let size_cap = config.load().system.file_collaboration.file_size_cap;

                let content = match session.filesystem.async_metadata(&session.abs_path).await {
                    Ok(metadata) if metadata.file_type.is_file() && metadata.size <= size_cap => {
                        if metadata.modified.is_some() && metadata.modified == last_mtime {
                            continue;
                        }

                        match Self::read_content(&session.filesystem, &session.abs_path, size_cap)
                            .await
                        {
                            Ok(content) => {
                                last_mtime = metadata.modified;
                                Ok(content)
                            }
                            Err(_) => Err(false),
                        }
                    }
                    Ok(metadata) if metadata.file_type.is_file() => Err(false),
                    _ => Err(true),
                };

                match content {
                    Ok(content) => {
                        reported_unreadable = false;

                        let disk_hash = blake3::hash(content.as_bytes());
                        let matches = {
                            let doc = session.doc.lock();
                            doc.disk_hash == disk_hash
                        };

                        if matches {
                            if session.set_conflict(None) {
                                session.broadcast_conflict(None).await;
                            }
                        } else if session.dirty.load(Ordering::Relaxed) {
                            let state = ConflictState {
                                hash: Some(disk_hash),
                                deleted: false,
                            };
                            if session.set_conflict(Some(state)) {
                                tracing::debug!(
                                    server = %server,
                                    path = %session.path,
                                    "collab: file changed on disk while session has unsaved changes"
                                );
                                session.broadcast_conflict(Some(state)).await;
                            }
                        } else {
                            let reloaded = {
                                let mut doc = session.doc.lock();
                                if !session.dirty.load(Ordering::Relaxed)
                                    && doc.disk_hash != disk_hash
                                {
                                    *doc = CollabDoc::new(&content);
                                    true
                                } else {
                                    false
                                }
                            };

                            if reloaded {
                                session.set_conflict(None);
                                tracing::debug!(
                                    server = %server,
                                    path = %session.path,
                                    "collab: reloaded clean session from external file change"
                                );
                                session.broadcast_resync().await;
                            }
                        }
                    }
                    Err(deleted) => {
                        if session.dirty.load(Ordering::Relaxed) {
                            let state = ConflictState {
                                hash: None,
                                deleted,
                            };
                            if session.set_conflict(Some(state)) {
                                session.broadcast_conflict(Some(state)).await;
                            }
                        } else if !reported_unreadable {
                            reported_unreadable = true;
                            session.broadcast_resync().await;
                        }
                    }
                }
            }
        });
    }

    async fn subscribed_session(
        &self,
        server: &crate::server::Server,
        connection_id: uuid::Uuid,
        user_uuid: uuid::Uuid,
        raw_path: &str,
    ) -> Result<(compact_str::CompactString, Arc<CollabSession>), CollabError> {
        let (_, resolved, _) = self.resolve(server, user_uuid, raw_path).await?;

        let key = {
            let connections = self.connections.lock().await;
            let Some(connection) = connections.get(&connection_id) else {
                return Err(CollabError::User("not subscribed to this file"));
            };

            let key = connection.keys.get(raw_path).cloned().unwrap_or(resolved);
            if !connection.subscriptions.contains_key(&key) {
                return Err(CollabError::User("not subscribed to this file"));
            }

            key
        };

        let session = self
            .sessions
            .lock()
            .await
            .get(&key)
            .map(Arc::clone)
            .ok_or(CollabError::User("not subscribed to this file"))?;

        Ok((key, session))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn apply_update(
        &self,
        server: &crate::server::Server,
        connection_id: uuid::Uuid,
        user_uuid: uuid::Uuid,
        raw_path: &str,
        finished: bool,
        chunk: &str,
        editor: Option<&str>,
    ) -> Result<(), CollabError> {
        let editor = editor_id(editor)?;
        let (key, session) = self
            .subscribed_session(server, connection_id, user_uuid, raw_path)
            .await?;

        let size_cap = self.config.load().system.file_collaboration.file_size_cap;

        let chunk = BASE64
            .decode(chunk)
            .map_err(|_| CollabError::User("invalid update encoding"))?;

        let update = {
            let mut pending = self.pending_updates.lock();
            let pending_key = (connection_id, editor, key.clone());

            match pending.get_mut(&pending_key) {
                Some(buffer) => {
                    if buffer.len() + chunk.len() > size_cap as usize {
                        pending.remove(&pending_key);
                        return Err(CollabError::User("update is too large"));
                    }
                    buffer.extend_from_slice(&chunk);

                    if !finished {
                        return Ok(());
                    }
                    pending.remove(&pending_key).unwrap_or_default()
                }
                None => {
                    if chunk.len() > size_cap as usize {
                        return Err(CollabError::User("update is too large"));
                    }
                    if !finished {
                        pending.insert(pending_key, chunk);
                        return Ok(());
                    }
                    chunk
                }
            }
        };

        let decoded =
            Update::decode_v1(&update).map_err(|_| CollabError::User("invalid update encoding"))?;

        let needs_resync = {
            let mut guard = session.doc.lock();

            let overflow = {
                let doc = &mut *guard;
                let mut txn = doc.doc.transact_mut();
                txn.apply_update(decoded)
                    .map_err(|_| CollabError::User("invalid update"))?;

                doc.text.len(&txn) as u64 > size_cap
            };
            session.dirty.store(true, Ordering::Relaxed);

            if overflow {
                let mut content = guard.content();
                let mut cap = (size_cap as usize).min(content.len());
                while cap > 0 && !content.is_char_boundary(cap) {
                    cap -= 1;
                }
                content.truncate(cap);
                *guard = CollabDoc::new(&content);

                true
            } else {
                guard.applied_update_bytes += update.len() as u64;

                if guard.applied_update_bytes > size_cap.saturating_mul(8) {
                    let content = guard.content();
                    *guard = CollabDoc::new(&content);
                    true
                } else {
                    false
                }
            }
        };

        if needs_resync {
            session.broadcast_resync().await;

            return Ok(());
        }

        session
            .broadcast(
                Some(connection_id),
                WebsocketMessage::builder(WebsocketEvent::FileCollabUpdate)
                    .arg(key)
                    .arg(BASE64.encode(&update))
                    .build(),
            )
            .await;

        Ok(())
    }

    pub async fn relay_awareness(
        &self,
        server: &crate::server::Server,
        connection_id: uuid::Uuid,
        user_uuid: uuid::Uuid,
        raw_path: &str,
        payload: &str,
    ) -> Result<(), CollabError> {
        let (key, session) = self
            .subscribed_session(server, connection_id, user_uuid, raw_path)
            .await?;

        match BASE64
            .decode(payload)
            .ok()
            .as_deref()
            .and_then(decode_awareness)
        {
            Some(entries) => {
                let max_cursors = self
                    .config
                    .load()
                    .system
                    .file_collaboration
                    .max_cursors_per_connection as usize;

                session.track_awareness(connection_id, &entries, max_cursors)
            }
            None => tracing::debug!(
                server = %self.server,
                path = %key,
                "received an unparseable collaborative editing awareness update"
            ),
        }

        session
            .broadcast(
                Some(connection_id),
                WebsocketMessage::builder(WebsocketEvent::FileCollabAwareness)
                    .arg(key)
                    .arg(payload)
                    .build(),
            )
            .await;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn save(
        &self,
        server: &crate::server::Server,
        connection_id: uuid::Uuid,
        user_uuid: uuid::Uuid,
        user_ip: Option<std::net::IpAddr>,
        raw_path: &str,
        force: bool,
        expected_hash: Option<&str>,
    ) -> Result<(), CollabError> {
        let (key, session) = self
            .subscribed_session(server, connection_id, user_uuid, raw_path)
            .await?;
        let path = session.abs_path.clone();
        let filesystem = Arc::clone(&session.filesystem);

        let _save_guard = session.save_lock.lock().await;

        let (content, doc_disk_hash) = {
            let doc = session.doc.lock();
            (doc.content(), doc.disk_hash)
        };

        let config = self.config.load();
        let history = &config.system.file_history;
        let history_enabled = history.enabled;
        let history_size_cap = history.file_size_cap;
        let size_cap = config.system.file_collaboration.file_size_cap;
        drop(config);

        let (file_exists, old_content_size) = match filesystem.async_metadata(&path).await {
            Ok(metadata) if metadata.file_type.is_file() => (true, metadata.size as i64),
            Ok(_) => return Err(CollabError::User("file is not a file")),
            Err(_) => (false, 0),
        };

        let read_cap = history_size_cap.max(size_cap);
        let old_bytes: Option<Vec<u8>> =
            if file_exists && old_content_size > 0 && old_content_size as u64 <= read_cap {
                match filesystem.async_read_file(&path, None).await {
                    Ok(mut handle) if handle.size <= read_cap => {
                        let mut buf = Vec::with_capacity(handle.size as usize);
                        match (&mut handle.reader)
                            .take(read_cap.saturating_add(1))
                            .read_to_end(&mut buf)
                            .await
                        {
                            Ok(_) if buf.len() as u64 <= read_cap => Some(buf),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            } else {
                None
            };

        let current_hash: Option<blake3::Hash> = if !file_exists {
            None
        } else if old_content_size == 0 {
            Some(blake3::hash(b""))
        } else {
            old_bytes.as_deref().map(blake3::hash)
        };

        if !current_hash.is_some_and(|hash| hash == doc_disk_hash) {
            let force_applies = force
                && expected_hash.is_none_or(|expected| {
                    current_hash.is_some_and(|hash| hash.to_hex().as_str() == expected)
                });

            if !force_applies {
                let state = ConflictState {
                    hash: current_hash,
                    deleted: !file_exists,
                };
                session.set_conflict(Some(state));
                session.broadcast_conflict(Some(state)).await;

                return Ok(());
            }
        }

        if !server
            .filesystem
            .has_headroom(content.len() as i64 - old_content_size)
        {
            return Err(CollabError::User("failed to allocate space"));
        }

        let captured_before: Option<Vec<u8>> = if history_enabled
            && old_content_size > 0
            && old_content_size as u64 <= history_size_cap
        {
            old_bytes
                .as_ref()
                .filter(|buf| buf.len() as u64 <= history_size_cap)
                .cloned()
        } else {
            None
        };

        let mut file = filesystem.async_create_file(&path).await?;
        file.write_all(content.as_bytes())
            .await
            .map_err(|err| CollabError::Internal(anyhow::anyhow!("failed to write file: {err}")))?;
        file.shutdown()
            .await
            .map_err(|err| CollabError::Internal(anyhow::anyhow!("failed to write file: {err}")))?;

        let mut revision_id = None;
        if history_enabled && content.len() as u64 <= history_size_cap {
            match server
                .diff
                .record_edit(
                    &key,
                    captured_before,
                    content.clone().into_bytes(),
                    Some(user_uuid),
                )
                .await
            {
                Ok(id) => {
                    if id != 0 {
                        revision_id = Some(id);
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        server = %self.server,
                        path = %key,
                        "collab: record_edit failed: {err:#}"
                    );
                }
            }
        }

        {
            let mut doc = session.doc.lock();
            doc.disk_hash = blake3::hash(content.as_bytes());
            session
                .dirty
                .store(doc.content() != content, Ordering::Relaxed);
        }
        session.set_conflict(None);

        server.activity.log_activity(Activity {
            event: ActivityEvent::FileWrite,
            user: Some(user_uuid),
            ip: user_ip,
            metadata: Some(serde_json::json!({
                "file": key,
                "revision_id": revision_id,
            })),
            schedule: None,
            timestamp: chrono::Utc::now(),
        });

        session
            .broadcast(
                None,
                WebsocketMessage::builder(WebsocketEvent::FileCollabSaved)
                    .arg(key)
                    .structured_arg(CollabSaved {
                        user: user_uuid,
                        revision_id,
                    })
                    .build(),
            )
            .await;

        Ok(())
    }

    pub async fn reload(
        &self,
        server: &crate::server::Server,
        connection_id: uuid::Uuid,
        user_uuid: uuid::Uuid,
        raw_path: &str,
    ) -> Result<(), CollabError> {
        let (key, session) = self
            .subscribed_session(server, connection_id, user_uuid, raw_path)
            .await?;
        let size_cap = self.config.load().system.file_collaboration.file_size_cap;

        let _save_guard = session.save_lock.lock().await;

        let content = Self::read_content(&session.filesystem, &session.abs_path, size_cap).await?;
        {
            let mut doc = session.doc.lock();
            *doc = CollabDoc::new(&content);
        }
        session.dirty.store(false, Ordering::Relaxed);
        session.set_conflict(None);

        tracing::debug!(
            server = %self.server,
            path = %key,
            "collab: session reloaded from disk"
        );

        session.broadcast_resync().await;

        Ok(())
    }

    pub async fn unsubscribe(
        &self,
        server: &crate::server::Server,
        connection_id: uuid::Uuid,
        user_uuid: uuid::Uuid,
        raw_path: &str,
        editor: Option<&str>,
    ) -> Result<(), CollabError> {
        let editor = editor_id(editor)?;

        let resolved = self
            .resolve(server, user_uuid, raw_path)
            .await
            .ok()
            .map(|(_, key, _)| key);

        let unsubscribed = {
            let mut connections = self.connections.lock().await;
            let Some(connection) = connections.get_mut(&connection_id) else {
                return Ok(());
            };

            let unsubscribed = connection.unsubscribe(raw_path, resolved, &editor);
            if connection.subscriptions.is_empty() {
                connections.remove(&connection_id);
            }

            unsubscribed
        };

        let Some(Unsubscribed { key, last }) = unsubscribed else {
            return Ok(());
        };

        self.pending_updates
            .lock()
            .remove(&(connection_id, editor, key.clone()));

        if last {
            self.leave_session(connection_id, &key).await;
        }

        Ok(())
    }

    /// Asks a connection to resubscribe to all of its collaborative sessions after
    /// targeted websocket messages were dropped (channel lag or an expired jwt), since
    /// a missed update leaves the client's document permanently stalled. Debounced per
    /// connection until the client resubscribes. The resync errors are stamped with the
    /// raw paths the connection subscribed with, not the canonical session keys — a
    /// client that never received its sync ack only recognizes the former.
    pub async fn resync_connection(&self, handler: &ServerWebsocketHandler) {
        let paths: Vec<compact_str::CompactString> = {
            let mut connections = self.connections.lock().await;
            let Some(connection) = connections.get_mut(&handler.connection_id) else {
                return;
            };

            if connection.pending_resync {
                return;
            }
            connection.pending_resync = true;

            connection.keys.keys().cloned().collect()
        };

        for key in paths {
            handler
                .send_message(
                    WebsocketMessage::builder(WebsocketEvent::FileCollabError)
                        .arg(key)
                        .arg("resync")
                        .build(),
                )
                .await;
        }
    }

    pub async fn disconnect(&self, connection_id: uuid::Uuid) {
        let connection = self.connections.lock().await.remove(&connection_id);
        self.pending_updates
            .lock()
            .retain(|(connection, _, _), _| *connection != connection_id);

        if let Some(connection) = connection {
            for key in connection.subscriptions.into_keys() {
                self.leave_session(connection_id, &key).await;
            }
        }
    }

    async fn leave_session(&self, connection_id: uuid::Uuid, key: &compact_str::CompactString) {
        let session = match self.sessions.lock().await.get(key) {
            Some(session) => Arc::clone(session),
            None => return,
        };

        let empty = {
            let mut participants = session.participants.lock().await;
            participants.remove(&connection_id);
            participants.is_empty()
        };

        let removal = session.awareness_removal_message(connection_id);

        if empty {
            self.schedule_teardown(key.clone());
        } else {
            if let Some(removal) = removal {
                session.broadcast(None, removal).await;
            }

            let participants = session.participants_message().await;
            session.broadcast(None, participants).await;
        }
    }

    fn schedule_teardown(&self, key: compact_str::CompactString) {
        let grace = std::time::Duration::from_secs(
            self.config
                .load()
                .system
                .file_collaboration
                .session_grace_period,
        );

        let task = tokio::spawn({
            let key = key.clone();
            let server = self.server;
            let sessions = Arc::clone(&self.sessions);
            let pending_teardowns = Arc::clone(&self.pending_teardowns);

            async move {
                tokio::time::sleep(grace).await;

                let mut sessions = sessions.lock().await;
                if let Some(session) = sessions.get(&key)
                    && session.participants.lock().await.is_empty()
                {
                    if session.dirty.load(Ordering::Relaxed) {
                        tracing::warn!(
                            server = %server,
                            path = %key,
                            "discarding collaborative editing session with unsaved changes"
                        );
                    }
                    sessions.remove(&key);
                }

                pending_teardowns.lock().remove(&key);
            }
        });

        let mut pending_teardowns = self.pending_teardowns.lock();
        if let Some(old) = pending_teardowns.insert(key, task.abort_handle()) {
            old.abort();
        }
    }
}
