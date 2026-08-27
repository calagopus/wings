use crate::{
    remote::AuthenticationType,
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        permissions::Permission,
    },
};
use russh::{
    Channel, ChannelId, MethodSet,
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

pub struct SshSession {
    pub limiter: Arc<super::limiter::SshLimiter>,
    pub state: State,
    pub server: Option<crate::server::Server>,

    pub user_ip: IpAddr,
    pub user_uuid: Option<uuid::Uuid>,
    pub open_channels: usize,

    pub clients: HashMap<ChannelId, Channel<Msg>>,
    pub shell_clients: HashSet<ChannelId>,
}

impl SshSession {
    fn get_auth_methods(&self) -> MethodSet {
        let mut methods = MethodSet::empty();
        if !self.state.config.load().system.sftp.disable_password_auth {
            methods.push(russh::MethodKind::Password);
        }
        methods.push(russh::MethodKind::PublicKey);

        methods
    }

    pub fn get_channel(&mut self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        self.clients.remove(&channel_id)
    }
}

impl russh::server::Handler for SshSession {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(self.get_auth_methods()),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, username: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.state.config.load().system.sftp.disable_password_auth {
            return Ok(Auth::UnsupportedMethod);
        }

        if !validate_username(username) {
            return Ok(Auth::Reject {
                proceed_with_methods: Some(self.get_auth_methods()),
                partial_success: false,
            });
        }

        self.limiter
            .check_attempt(self.user_ip, AuthenticationType::Password)
            .await?;

        let (user, server, permissions, ignored_files) = match self
            .state
            .config
            .client
            .get_sftp_auth(AuthenticationType::Password, username, password)
            .await
        {
            Ok(data) => data,
            Err(err) => {
                tracing::debug!(
                    username = username,
                    "failed to authenticate (password): {:#?}",
                    err
                );

                return Ok(Auth::reject());
            }
        };

        if !permissions.has_permission(Permission::FileSftp) {
            return Ok(Auth::reject());
        }

        self.limiter
            .finish_attempt(&self.user_ip, AuthenticationType::Password)
            .await;

        let server = match self.state.server_manager.get_server(server).await {
            Some(server) => server,
            None => {
                return Ok(Auth::Reject {
                    proceed_with_methods: Some(self.get_auth_methods()),
                    partial_success: false,
                });
            }
        };

        if server.locked_state().is_some() {
            return Ok(Auth::reject());
        }

        self.limiter.increment_sessions(user)?;
        self.user_uuid = Some(user);

        tracing::debug!(server = %server.uuid, %user, "user authenticated with password");

        server
            .user_permissions
            .set_permissions(user, permissions, Some(&ignored_files));
        if self.state.config.load().system.sftp.activity.log_logins {
            server.activity.log_activity(Activity {
                event: ActivityEvent::SftpLogin,
                user: Some(user),
                ip: Some(self.user_ip),
                metadata: Some(json!({
                    "method": "password",
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }
        self.server = Some(server);

        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if !validate_username(username) {
            return Ok(Auth::Reject {
                proceed_with_methods: Some(self.get_auth_methods()),
                partial_success: false,
            });
        }

        self.limiter
            .check_attempt(self.user_ip, AuthenticationType::PublicKey)
            .await?;

        let (user, server, permissions, ignored_files) = match self
            .state
            .config
            .client
            .get_sftp_auth(
                AuthenticationType::PublicKey,
                username,
                &public_key.to_openssh()?,
            )
            .await
        {
            Ok(data) => data,
            Err(err) => {
                tracing::debug!(
                    username = username,
                    "failed to authenticate (public_key): {:#?}",
                    err
                );

                return Ok(Auth::Reject {
                    proceed_with_methods: Some(self.get_auth_methods()),
                    partial_success: false,
                });
            }
        };

        if !permissions.has_permission(Permission::FileSftp) {
            return Ok(Auth::reject());
        }

        self.limiter
            .finish_attempt(&self.user_ip, AuthenticationType::PublicKey)
            .await;

        let server = match self.state.server_manager.get_server(server).await {
            Some(server) => server,
            None => return Ok(Auth::reject()),
        };

        if server.locked_state().is_some() {
            return Ok(Auth::reject());
        }

        self.limiter.increment_sessions(user)?;
        self.user_uuid = Some(user);

        tracing::debug!(server = %server.uuid, %user, "user authenticated with public key");

        server
            .user_permissions
            .set_permissions(user, permissions, Some(&ignored_files));
        if self.state.config.load().system.sftp.activity.log_logins {
            server.activity.log_activity(Activity {
                event: ActivityEvent::SftpLogin,
                user: Some(user),
                ip: Some(self.user_ip),
                metadata: Some(json!({
                    "method": "public_key",
                })),
                schedule: None,
                timestamp: chrono::Utc::now(),
            });
        }
        self.server = Some(server);

        Ok(Auth::Accept)
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

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::debug!("channel shell request: {}", channel_id);

        if !self.state.config.load().system.sftp.shell.enabled {
            return Err(russh::Error::RequestDenied);
        }

        let user_uuid = match self.user_uuid {
            Some(uuid) => uuid,
            None => return Err(russh::Error::RequestDenied),
        };

        let server = match &self.server {
            Some(server) => server.clone(),
            None => return Err(russh::Error::UnsupportedAuthMethod),
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

        let user_uuid = match self.user_uuid {
            Some(uuid) => uuid,
            None => return Err(russh::Error::RequestDenied),
        };

        let server = match &self.server {
            Some(server) => server.clone(),
            None => return Err(russh::Error::UnsupportedAuthMethod),
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
        let user_uuid = match self.user_uuid {
            Some(uuid) => uuid,
            None => return Err(russh::Error::RequestDenied),
        };

        let server = match &self.server {
            Some(server) => server.clone(),
            None => return Err(russh::Error::UnsupportedAuthMethod),
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
        if let Some(user) = self.user_uuid {
            self.limiter.decrement_sessions(user);
        }
    }
}
