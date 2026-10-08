use crate::{
    remote::AuthenticationType,
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        permissions::Permission,
    },
};
use russh::{
    Channel, ChannelId, Disconnect, MethodSet, Pty,
    server::{Auth, Msg, Session},
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

fn validate_username(username: &str) -> bool {
    let mut last = "";
    let mut segments = 0;

    for segment in username.split('.') {
        last = segment;
        segments += 1;
    }

    segments >= 2 && last.len() == 8 && last.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn auth_methods(config: &crate::config::InnerConfig) -> MethodSet {
    let mut methods = MethodSet::empty();
    if !config.system.sftp.disable_password_auth {
        methods.push(russh::MethodKind::Password);
    }
    methods.push(russh::MethodKind::PublicKey);

    methods
}

pub struct SshSession {
    pub limiter: Arc<super::limiter::SshLimiter>,
    pub state: State,
    pub server: Option<crate::server::Server>,

    pub user_ip: IpAddr,
    pub user_uuid: Option<uuid::Uuid>,
    pub open_channels: usize,

    pub clients: HashMap<ChannelId, Channel<Msg>>,
    pub shell_clients: HashSet<ChannelId>,

    pub removal_task: Option<tokio::task::AbortHandle>,
}

impl SshSession {
    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(auth_methods(&self.state.config.load())),
            partial_success: false,
        }
    }

    pub fn get_channel(&mut self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        self.clients.remove(&channel_id)
    }

    fn authenticated(&self) -> Option<(uuid::Uuid, crate::server::Server)> {
        self.user_uuid.zip(self.server.clone())
    }

    fn shell_user(&self) -> Option<(uuid::Uuid, crate::server::Server)> {
        if !self.state.config.load().system.sftp.shell.enabled {
            return None;
        }

        let (user_uuid, server) = self.authenticated()?;

        server
            .user_permissions
            .has_permission(user_uuid, Permission::WebsocketConnect)
            .then_some((user_uuid, server))
    }

    async fn authenticate(
        &mut self,
        authentication_type: AuthenticationType,
        username: &str,
        credential: &str,
    ) -> Result<Auth, russh::Error> {
        if !validate_username(username) {
            return Ok(self.reject());
        }

        self.limiter
            .check_attempt(self.user_ip, authentication_type)
            .await?;

        let (user, server, permissions, ignored_files) = match self
            .state
            .config
            .client
            .get_sftp_auth(authentication_type, username, credential)
            .await
        {
            Ok(data) => data,
            Err(err) => {
                tracing::debug!(
                    username = username,
                    method = ?authentication_type,
                    "failed to authenticate: {:#?}",
                    err
                );

                return Ok(self.reject());
            }
        };

        if !permissions.has_permission(Permission::FileSftp) {
            return Ok(self.reject());
        }

        self.limiter
            .finish_attempt(&self.user_ip, authentication_type)
            .await;

        let Some(server) = self.state.server_manager.get_server(server).await else {
            return Ok(self.reject());
        };

        if server.locked_state().is_some() {
            return Ok(self.reject());
        }

        self.limiter.increment_sessions(user)?;
        self.user_uuid = Some(user);

        tracing::debug!(
            server = %server.uuid,
            %user,
            method = ?authentication_type,
            "user authenticated"
        );

        server
            .user_permissions
            .set_fetched_permissions(user, permissions, Some(&ignored_files));
        if self.state.config.load().system.sftp.activity.log_logins {
            server.activity.log_activity(Activity {
                event: ActivityEvent::SftpLogin,
                user: Some(user),
                ip: Some(self.user_ip),
                metadata: Some(json!({
                    "method": authentication_type,
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }
        self.server = Some(server);

        Ok(Auth::Accept)
    }
}

impl russh::server::Handler for SshSession {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(self.reject())
    }

    async fn auth_password(&mut self, username: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.state.config.load().system.sftp.disable_password_auth {
            return Ok(Auth::UnsupportedMethod);
        }

        self.authenticate(AuthenticationType::Password, username, password)
            .await
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.authenticate(
            AuthenticationType::PublicKey,
            username,
            &public_key.to_openssh()?,
        )
        .await
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let Some((user_uuid, server)) = self.authenticated() else {
            return Ok(());
        };

        let handle = session.handle();
        let task = tokio::spawn(async move {
            server.user_permissions.wait_for_removal(user_uuid).await;

            tracing::debug!(
                server = %server.uuid,
                "closing ssh session due to user permissions removal"
            );

            handle
                .disconnect(
                    Disconnect::ByApplication,
                    "permission revoked".to_string(),
                    String::new(),
                )
                .await
                .ok();
        });

        self.removal_task = Some(task.abort_handle());

        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.open_channels
            >= self
                .state
                .config
                .load()
                .system
                .sftp
                .limits
                .max_channels_per_connection
        {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }

        reply.accept().await;

        tracing::debug!("opening new channel: {}", channel.id());
        self.clients.insert(channel.id(), channel);
        self.open_channels += 1;

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.open_channels = self.open_channels.saturating_sub(1);

        tracing::debug!("channel eof: {}", channel);
        session.close(channel)?;

        self.clients.remove(&channel);
        self.shell_clients.retain(|&id| id != channel);

        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.shell_user().is_some() {
            session.channel_success(channel_id)?;
        } else {
            session.channel_failure(channel_id)?;
        }

        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel_id: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel_id)?;

        Ok(())
    }

    async fn env_request(
        &mut self,
        channel_id: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel_id)?;

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::debug!("channel shell request: {}", channel_id);

        let Some((user_uuid, server)) = self.shell_user() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        let channel = match self.get_channel(channel_id) {
            Some(channel) => channel,
            None => return Err(russh::Error::WrongChannel),
        };

        self.shell_clients.insert(channel_id);

        session.channel_success(channel_id)?;
        let ssh = super::shell::ShellSession {
            state: Arc::clone(&self.state),
            server,

            user_ip: self.user_ip,
            user_uuid,
            mode: super::shell::ShellMode::Normal,
        };
        ssh.run(channel);

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);

        let Some((user_uuid, server)) = self.shell_user() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        let channel = match self.get_channel(channel_id) {
            Some(channel) => channel,
            None => return Err(russh::Error::WrongChannel),
        };

        tracing::debug!("received command from exec: {}", command);

        session.channel_success(channel_id)?;
        let exec = super::exec::ExecSession {
            server,

            user_ip: self.user_ip,
            user_uuid,
        };
        exec.run(command.to_string(), channel);

        Ok(())
    }

    async fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data == [3] && self.shell_clients.contains(&channel_id) {
            return Err(russh::Error::Disconnect);
        }

        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some((user_uuid, server)) = self.authenticated() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        if name == "sftp" {
            let channel = match self.get_channel(channel_id) {
                Some(channel) => channel,
                None => return Err(russh::Error::WrongChannel),
            };
            let sftp = super::sftp::SftpSession {
                limiter: Arc::clone(&self.limiter),
                state: Arc::clone(&self.state),
                server,

                user_ip: self.user_ip,
                user_uuid,

                handle_id: 0,
                handles: HashMap::new(),
            };

            session.channel_success(channel_id)?;
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id)?;
        }

        Ok(())
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        if let Some(task) = self.removal_task.take() {
            task.abort();
        }

        if let Some(user) = self.user_uuid {
            self.limiter.decrement_sessions(user);
        }
    }
}
