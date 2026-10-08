use crate::routes::State;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

mod auth;
mod exec;
mod limiter;
mod sftp;
mod shell;

pub use auth::auth_methods;

pub struct Server {
    ratelimiter: Arc<limiter::SshLimiter>,
    state: State,
}

impl Server {
    pub fn new(state: Arc<crate::routes::AppState>) -> Self {
        Self {
            ratelimiter: Arc::new(limiter::SshLimiter::new(state.config.clone())),
            state,
        }
    }
}

impl russh::server::Server for Server {
    type Handler = auth::SshSession;

    fn new_client(&mut self, client: Option<SocketAddr>) -> Self::Handler {
        auth::SshSession {
            limiter: Arc::clone(&self.ratelimiter),
            state: Arc::clone(&self.state),
            server: None,

            user_ip: client.map_or_else(
                || std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                |s| s.ip(),
            ),
            user_uuid: None,
            open_channels: 0,

            clients: HashMap::new(),
            shell_clients: HashSet::new(),

            removal_task: None,
        }
    }
}
