use super::{Server, state::ServerState};
use anyhow::Context;
use std::{
    collections::HashMap,
    io::Write,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{RwLock, Semaphore};

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), anyhow::Error> {
    let parent = path.parent().context("state file has no parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path)?;

    Ok(())
}

#[derive(Clone, Copy)]
pub enum ServerCreation {
    /// Run the installation script, then report the result to the panel.
    Install,
    /// Skip the installation script, but still report a successful install to the panel.
    SkipInstall,
    /// The server is the destination of a transfer, its contents arrive over the wire and
    /// the panel is notified through the transfer endpoints instead.
    Transferred,
}

pub struct ServerManager {
    servers: Arc<RwLock<Vec<Server>>>,
    booted: AtomicBool,
}

impl ServerManager {
    pub fn new(raw_servers: &[crate::remote::servers::RawServer]) -> Self {
        let servers = Vec::with_capacity(raw_servers.len());

        Self {
            servers: Arc::new(RwLock::new(servers)),
            booted: AtomicBool::new(false),
        }
    }

    pub async fn boot(
        &self,
        app_state: &crate::routes::State,
        raw_servers: Vec<crate::remote::servers::RawServer>,
    ) {
        let root_directory = app_state
            .config
            .resolve_as_path(|cfg| &cfg.system.root_directory);

        let states_path = root_directory.join("states.json");
        let mut states: HashMap<uuid::Uuid, ServerState> = serde_json::from_str(
            tokio::fs::read_to_string(&states_path)
                .await
                .unwrap_or_default()
                .as_str(),
        )
        .unwrap_or_default();

        let installing_path = root_directory.join("installing.json");
        let mut installing: HashMap<uuid::Uuid, (bool, super::installation::InstallationScript)> =
            serde_json::from_str(
                tokio::fs::read_to_string(&installing_path)
                    .await
                    .unwrap_or_default()
                    .as_str(),
            )
            .unwrap_or_default();

        let mut servers = self.servers.write().await;
        let semaphore = Arc::new(Semaphore::new(
            app_state.config.load().remote_query.boot_servers_per_page as usize,
        ));

        for server in raw_servers {
            let server = Server::new(
                server.settings,
                server.process_configuration,
                app_state.clone(),
            );
            let state = states.remove(&server.uuid).unwrap_or_default();

            server.initialize_schedules().await;
            server.filesystem.attach().await;

            let spawn_start_task = {
                let semaphore = Arc::clone(&semaphore);
                let server = server.clone();

                move || {
                    tokio::spawn(async move {
                        tracing::info!(
                            server = %server.uuid,
                            "restoring server state {:?}",
                            state
                        );

                        match server.attach_container().await {
                            Ok(_) => {
                                tracing::debug!(server = %server.uuid, "server attached successfully");
                            }
                            Err(err) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    error = %err,
                                    "failed to attach server container"
                                );
                            }
                        }

                        let do_autostart =
                            match server.configuration.read().await.auto_start_behavior {
                                crate::models::ServerAutoStartBehavior::Always => true,
                                crate::models::ServerAutoStartBehavior::UnlessStopped => {
                                    matches!(state, ServerState::Running | ServerState::Starting)
                                }
                                crate::models::ServerAutoStartBehavior::Never => false,
                            };

                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        if do_autostart
                            && !matches!(
                                server.state.get_state(),
                                ServerState::Running | ServerState::Starting
                            )
                        {
                            let _permit = match semaphore.acquire().await {
                                Ok(p) => p,
                                Err(_) => return,
                            };

                            server.start(None, false).await.ok();
                        }
                    });
                }
            };

            if let Some((reinstall, container_script)) = installing.remove(&server.uuid) {
                let boot_servers_per_page =
                    app_state.config.load().remote_query.boot_servers_per_page;

                tokio::spawn({
                    let server = server.clone();

                    async move {
                        tracing::info!(
                            server = %server.uuid,
                            "restoring installing state {:?}",
                            state
                        );

                        let installer = Arc::new(
                            super::installation::ServerInstaller::new(
                                &server,
                                reinstall,
                                false,
                                Some(container_script),
                            )
                            .await,
                        );

                        if let Err(err) = installer.attach().await {
                            tracing::warn!(
                                server = %server.uuid,
                                "failed to attach installation container: {:#?}",
                                err
                            );
                            if boot_servers_per_page > 0 {
                                spawn_start_task();
                            }
                            return;
                        }

                        tracing::info!(server = %server.uuid, "installation container attached successfully");

                        server.installer.write().await.replace(installer);
                    }
                });
            } else if app_state.config.load().remote_query.boot_servers_per_page > 0 {
                spawn_start_task();
            } else {
                match server.attach_container().await {
                    Ok(_) => {
                        tracing::info!(server = %server.uuid, "server attached successfully");
                    }
                    Err(err) => {
                        tracing::warn!(
                            server = %server.uuid,
                            error = %err,
                            "failed to attach server container"
                        );
                    }
                }
            }

            servers.push(server);
        }

        self.booted.store(true, Ordering::SeqCst);

        tokio::spawn({
            let servers = Arc::clone(&self.servers);

            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                    if let Err(err) = Self::persist_into(&servers, &root_directory).await {
                        tracing::error!("failed to persist server states: {:?}", err);
                    }
                }
            }
        });
    }

    #[inline]
    pub fn booted(&self) -> bool {
        self.booted.load(Ordering::SeqCst)
    }

    pub async fn persist(&self, config: &crate::config::Config) -> Result<(), anyhow::Error> {
        if !self.booted() {
            return Err(anyhow::anyhow!("servers are still booting"));
        }

        let root_directory = config.resolve_as_path(|cfg| &cfg.system.root_directory);

        Self::persist_into(&self.servers, &root_directory).await
    }

    async fn persist_into(
        servers: &RwLock<Vec<Server>>,
        root_directory: &Path,
    ) -> Result<(), anyhow::Error> {
        let servers = servers.read().await;

        let states: HashMap<_, _> = servers
            .iter()
            .map(|s| (s.uuid, s.state.get_state()))
            .collect();

        let mut installing = HashMap::new();
        for server in servers.iter() {
            if let Some(installer) = server.installer.read().await.as_ref()
                && let Ok(installation_script) = installer.get_installation_script()
            {
                installing.insert(
                    server.uuid,
                    (installer.reinstall, (*installation_script).clone()),
                );
            }
        }
        drop(servers);

        let states = serde_json::to_vec(&states)?;
        let installing = serde_json::to_vec(&installing)?;
        let root_directory = root_directory.to_path_buf();

        tokio::task::spawn_blocking(move || {
            write_atomic(&root_directory.join("states.json"), &states)?;
            write_atomic(&root_directory.join("installing.json"), &installing)
        })
        .await?
    }

    #[inline]
    pub async fn get_servers(&self) -> tokio::sync::RwLockReadGuard<'_, Vec<Server>> {
        self.servers.read().await
    }

    #[inline]
    pub async fn get_server(&self, server: uuid::Uuid) -> Option<Server> {
        let servers = self.servers.read().await;

        servers.iter().find(|s| s.uuid == server).cloned()
    }

    pub async fn create_server(
        &self,
        app_state: &crate::routes::State,
        raw_server: crate::remote::servers::RawServer,
        creation: ServerCreation,
    ) -> Server {
        let server = Server::new(
            raw_server.settings,
            raw_server.process_configuration,
            app_state.clone(),
        );

        server.filesystem.setup().await;

        match creation {
            ServerCreation::Install => {
                tokio::spawn({
                    let server = server.clone();

                    async move {
                        let mut installer = Arc::new(
                            super::installation::ServerInstaller::new(&server, false, false, None)
                                .await,
                        );

                        if let Err(err) = installer.start(false).await {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to install server: {:#?}",
                                err
                            );
                        }

                        server.installer.write().await.replace(installer);
                    }
                });
            }
            ServerCreation::SkipInstall => {
                tokio::spawn({
                    let server = server.clone();

                    async move {
                        let installer =
                            super::installation::ServerInstaller::new(&server, false, false, None)
                                .await;

                        installer.unset_installing(true).await.ok();
                    }
                });
            }
            ServerCreation::Transferred => {}
        }

        self.servers.write().await.push(server.clone());

        server
    }

    pub async fn delete_server(&self, server: &Server) {
        let mut servers = self.servers.write().await;

        if let Some(pos) = servers.iter().position(|s| s.uuid == server.uuid) {
            let server = servers.remove(pos);
            server.set_suspended(true).await;

            tokio::spawn(async move { server.destroy().await });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // write_atomic
    #[test]
    fn write_atomic_replaces_content_without_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("states.json");
        std::fs::write(&path, b"old content that is longer").unwrap();

        write_atomic(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("states.json")]);
    }
}
