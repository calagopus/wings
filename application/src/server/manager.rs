use super::{Server, state::ServerState};
use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};
use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::{RwLock, Semaphore},
};

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
}

impl ServerManager {
    pub fn new(raw_servers: &[crate::remote::servers::RawServer]) -> Self {
        let servers = Vec::with_capacity(raw_servers.len());

        Self {
            servers: Arc::new(RwLock::new(servers)),
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

        tokio::spawn({
            let servers = Arc::clone(&self.servers);

            async move {
                let mut states_file = match File::create(&states_path).await {
                    Ok(file) => file,
                    Err(err) => {
                        tracing::error!("failed to create states.json file: {:?}", err);
                        return;
                    }
                };

                let mut run_inner = async || -> Result<(), anyhow::Error> {
                    let servers = servers.read().await;
                    let states: HashMap<_, _> = servers
                        .iter()
                        .map(|s| (s.uuid, s.state.get_state()))
                        .collect();

                    states_file.set_len(0).await?;
                    states_file.seek(std::io::SeekFrom::Start(0)).await?;
                    states_file
                        .write_all(serde_json::to_string(&states)?.as_bytes())
                        .await?;
                    states_file.flush().await?;
                    states_file.sync_all().await?;

                    Ok(())
                };

                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                    match run_inner().await {
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("failed to write states.json file: {:?}", err);
                            continue;
                        }
                    }
                }
            }
        });

        tokio::spawn({
            let servers = Arc::clone(&self.servers);

            async move {
                let mut installing_file = match File::create(&installing_path).await {
                    Ok(file) => file,
                    Err(err) => {
                        tracing::error!("failed to create installing.json file: {:?}", err);
                        return;
                    }
                };

                let mut run_inner = async || -> Result<(), anyhow::Error> {
                    let mut installing = HashMap::new();
                    for server in servers.read().await.iter() {
                        if let Some(installer) = server.installer.read().await.as_ref()
                            && let Ok(installation_script) = installer.get_installation_script()
                        {
                            installing.insert(
                                server.uuid,
                                (installer.reinstall, (*installation_script).clone()),
                            );
                        }
                    }

                    installing_file.set_len(0).await?;
                    installing_file.seek(std::io::SeekFrom::Start(0)).await?;
                    installing_file
                        .write_all(serde_json::to_string(&installing)?.as_bytes())
                        .await?;
                    installing_file.flush().await?;
                    installing_file.sync_all().await?;

                    Ok(())
                };

                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                    match run_inner().await {
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("failed to write installing.json file: {:?}", err);
                            continue;
                        }
                    }
                }
            }
        });
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
            server.suspended.store(true, Ordering::SeqCst);

            tokio::spawn(async move { server.destroy().await });
        }
    }
}
