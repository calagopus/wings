use anyhow::Context;
use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};
use utoipa::ToSchema;

#[derive(ToSchema, Deserialize, Serialize, Clone)]
pub struct InstallationScript {
    pub container_image: compact_str::CompactString,
    pub entrypoint: compact_str::CompactString,

    #[serde(deserialize_with = "crate::deserialize::deserialize_defaultable")]
    pub script: String,
    #[serde(default)]
    pub environment: HashMap<compact_str::CompactString, serde_json::Value>,
}

pub const INSTALL_STATUS_FILE_NAME: &str = "status";
pub const INSTALL_PROGRESS_FILE_NAME: &str = "progress";

const INSTALL_FILE_READ_LIMIT: u64 = 4096;
const INSTALL_PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

pub struct ServerInstaller {
    pub reinstall: bool,
    environment: Vec<String>,
    server: super::Server,
    installation_script: Option<Arc<InstallationScript>>,

    process_handle: Arc<Mutex<Option<Arc<dyn super::executor::ProcessHandle>>>>,

    abort_notify: Arc<tokio::sync::Notify>,
    failure_reason: Mutex<Option<compact_str::CompactString>>,
}

impl ServerInstaller {
    pub async fn new(
        server: &super::Server,
        reinstall: bool,
        installation_script: Option<InstallationScript>,
    ) -> Self {
        Self {
            reinstall,
            environment: server
                .configuration
                .read()
                .await
                .environment(&server.app_state.config),
            server: server.clone(),
            installation_script: installation_script.map(Arc::new),
            process_handle: Arc::new(Mutex::new(None)),
            abort_notify: Arc::new(tokio::sync::Notify::new()),
            failure_reason: Mutex::new(None),
        }
    }

    pub fn get_install_status_path(server: &super::Server) -> std::path::PathBuf {
        server
            .app_state
            .config
            .tmp_data_path(server.uuid)
            .join(INSTALL_STATUS_FILE_NAME)
    }

    pub fn get_install_progress_path(server: &super::Server) -> std::path::PathBuf {
        server
            .app_state
            .config
            .tmp_data_path(server.uuid)
            .join(INSTALL_PROGRESS_FILE_NAME)
    }

    async fn open_install_file(path: &std::path::Path) -> Option<tokio::fs::File> {
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            );
        }

        let file = options.open(path).await.ok()?;
        if !file.metadata().await.ok()?.is_file() {
            return None;
        }

        Some(file)
    }

    async fn read_install_status(path: &std::path::Path) -> Option<compact_str::CompactString> {
        let file = Self::open_install_file(path).await?;

        let mut content = Vec::new();
        file.take(INSTALL_FILE_READ_LIMIT)
            .read_to_end(&mut content)
            .await
            .ok()?;

        let content = String::from_utf8_lossy(&content);
        let line = content.lines().next()?.trim();
        if line.is_empty() {
            return None;
        }

        let reason: compact_str::CompactString =
            line.chars().filter(|c| !c.is_control()).take(255).collect();

        match reason.parse::<i64>() {
            Ok(0) => return None,
            Ok(code) => {
                return Some(compact_str::format_compact!(
                    "installation script reported exit code {code}"
                ));
            }
            Err(_) => {}
        }

        if reason.is_empty() {
            return Some(compact_str::CompactString::const_new(
                "installation script reported a failure",
            ));
        }

        Some(reason)
    }

    async fn read_install_progress(
        path: &std::path::Path,
    ) -> Option<crate::models::InstallProgress> {
        let mut file = Self::open_install_file(path).await?;

        let length = file.metadata().await.ok()?.len();
        if length > INSTALL_FILE_READ_LIMIT {
            file.seek(std::io::SeekFrom::Start(length - INSTALL_FILE_READ_LIMIT))
                .await
                .ok()?;
        }

        let mut content = Vec::new();
        file.take(INSTALL_FILE_READ_LIMIT)
            .read_to_end(&mut content)
            .await
            .ok()?;

        let content = String::from_utf8_lossy(&content);
        let line = content
            .lines()
            .map(|line| line.trim())
            .rfind(|line| !line.is_empty())?;

        let (progress, label) = match line.split_once(char::is_whitespace) {
            Some((progress, label)) => (progress, label.trim()),
            None => (line, ""),
        };

        let (progress, total) = match progress.split_once('/') {
            Some((progress, total)) => (progress, total.parse::<i64>().ok()?),
            None => (progress, 100),
        };
        if total <= 0 {
            return None;
        }

        let progress = progress.parse::<i64>().ok()?.clamp(0, total);
        let label: compact_str::CompactString = label
            .chars()
            .filter(|c| !c.is_control())
            .take(255)
            .collect();

        Some(crate::models::InstallProgress {
            progress: progress as u64,
            total: total as u64,
            label: if label.is_empty() { None } else { Some(label) },
        })
    }

    async fn send_install_progress(&self) {
        let progress =
            match Self::read_install_progress(&Self::get_install_progress_path(&self.server)).await
            {
                Some(progress) => progress,
                None => return,
            };

        self.server
            .websocket
            .send(
                super::websocket::WebsocketMessage::builder(
                    super::websocket::WebsocketEvent::ServerInstallProgress,
                )
                .structured_arg(progress)
                .build(),
            )
            .ok();
    }

    fn install_progress_interval() -> tokio::time::Interval {
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + INSTALL_PROGRESS_INTERVAL,
            INSTALL_PROGRESS_INTERVAL,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        interval
    }

    async fn evaluate_install_result(&self, oom_killed: bool) {
        let reason = if oom_killed {
            Some(compact_str::CompactString::const_new(
                "installation container ran out of memory",
            ))
        } else {
            Self::read_install_status(&Self::get_install_status_path(&self.server)).await
        };

        if let Some(reason) = reason {
            tracing::warn!(
                server = %self.server.uuid,
                "installation process reported failure: {}",
                reason
            );

            self.server.log_daemon_install(compact_str::format_compact!(
                "Installation failed: {reason}"
            ));
            *self.failure_reason.lock().await = Some(reason);
        }
    }

    pub fn get_install_logs_path(server: &super::Server) -> std::path::PathBuf {
        server
            .app_state
            .config
            .resolve_as_path(|cfg| &cfg.system.log_directory)
            .join(server.uuid.to_string())
            .join("install.log")
    }

    pub async fn get_install_logs(
        server: &super::Server,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let log_path = Self::get_install_logs_path(server);

        tokio::fs::File::open(&log_path).await
    }

    pub async fn create_install_logs(
        server: &super::Server,
    ) -> Result<tokio::fs::File, std::io::Error> {
        let log_path = Self::get_install_logs_path(server);

        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::File::create(&log_path).await
    }

    pub async fn delete_install_logs(server: &super::Server) {
        let log_path = Self::get_install_logs_path(server);

        tokio::fs::remove_file(&log_path).await.ok();

        if let Some(parent) = log_path.parent() {
            tokio::fs::remove_dir(parent).await.ok();
        }
    }

    pub fn get_installation_script(&self) -> Result<Arc<InstallationScript>, anyhow::Error> {
        match &self.installation_script {
            Some(installation_script) => Ok(Arc::clone(installation_script)),
            None => Err(anyhow::anyhow!(
                "server install process has not been started"
            )),
        }
    }

    #[inline]
    pub fn abort(&self) {
        self.abort_notify.notify_one();
    }

    pub async fn unset_installing(&self, successful: bool) -> Result<(), anyhow::Error> {
        self.server.installing.store(false, Ordering::SeqCst);
        self.server.installer.write().await.take();

        if let Err(err) = self.cleanup_container().await {
            tracing::error!(
                server = %self.server.uuid,
                "failed to cleanup installation container: {}",
                err
            );
        }

        tokio::fs::remove_dir_all(self.server.app_state.config.tmp_data_path(self.server.uuid))
            .await
            .ok();
        if let Err(err) = self
            .server
            .app_state
            .config
            .client
            .set_server_install(self.server.uuid, successful, self.reinstall)
            .await
        {
            tracing::error!(
                server = %self.server.uuid,
                "failed to set server install status: {}",
                err
            );
        }

        self.server.websocket.send(
            super::websocket::WebsocketMessage::builder(
                super::websocket::WebsocketEvent::ServerInstallCompleted,
            )
            .arg(successful.to_compact_string())
            .build(),
        )?;

        if successful
            && !self.reinstall
            && self
                .server
                .configuration
                .read()
                .await
                .start_on_completion
                .is_some_and(|s| s)
            && let Err(err) = self.server.start(None, false).await
        {
            tracing::error!(
                server = %self.server.uuid,
                "failed to start server after initial install: {}",
                err
            );
        }

        self.server.filesystem.rerun_disk_checker();

        Ok(())
    }

    pub async fn start(self: &mut Arc<Self>, force: bool) -> Result<(), anyhow::Error> {
        if let Some(state) = self.server.locked_state() {
            return Err(anyhow::anyhow!(
                "server is in a locked state ({state}), cannot start installation process"
            ));
        }

        self.server.installing.store(true, Ordering::SeqCst);
        self.server.websocket.send(
            super::websocket::WebsocketMessage::builder(
                super::websocket::WebsocketEvent::ServerInstallStarted,
            )
            .build(),
        )?;

        tracing::info!(
            server = %self.server.uuid,
            "starting installation process"
        );

        self.server
            .log_daemon("Starting installation process, this could take a few minutes...".into());

        if self.server.configuration.read().await.skip_egg_scripts && !force {
            self.unset_installing(true).await?;
            tracing::info!(
                server = %self.server.uuid,
                "skipping installation script execution as per configuration"
            );

            return Ok(());
        }

        let container_script = match &self.installation_script {
            Some(container_script) => container_script.clone(),
            None => {
                let container_script = match self
                    .server
                    .app_state
                    .config
                    .client
                    .server_install_script(self.server.uuid)
                    .await
                    .context("Failed to fetch installation script")
                {
                    Ok(container_script) => Arc::new(container_script),
                    Err(err) => {
                        self.unset_installing(false).await?;
                        return Err(err);
                    }
                };

                match Arc::get_mut(self) {
                    Some(installer) => {
                        installer
                            .installation_script
                            .replace(Arc::clone(&container_script));
                    }
                    None => {
                        self.unset_installing(false).await?;
                        return Err(anyhow::anyhow!(
                            "unable to get mutable reference to server installer"
                        ));
                    }
                }

                container_script
            }
        };

        if container_script.script.trim().is_empty() {
            tracing::info!(
                server = %self.server.uuid,
                "no installation script provided, marking server as installed"
            );

            self.unset_installing(true).await?;
            return Ok(());
        }

        tokio::spawn({
            let installer = Arc::clone(self);

            async move {
                let run = async || {
                    let (handle, mut status_rx) = match installer
                        .server
                        .app_state
                        .executor
                        .setup_installation_process(&installer.server, &container_script)
                        .await
                        .context("Failed to setup installation process")
                    {
                        Ok(r) => r,
                        Err(err) => {
                            installer.unset_installing(false).await?;
                            return Err(err);
                        }
                    };

                    *installer.process_handle.lock().await = Some(Arc::clone(&handle));

                    let mut stdout_rx = match handle
                        .subscribe_stdout_lines_ratelimited()
                        .await
                        .context("Failed to subscribe to stdout")
                    {
                        Ok(rx) => rx,
                        Err(err) => {
                            installer.unset_installing(false).await?;
                            return Err(err);
                        }
                    };

                    tokio::select! {
                        result = tokio::time::timeout(
                            if installer
                                .server
                                .app_state
                                .config
                                .load()
                                .docker
                                .installer_limits
                                .timeout
                                > 0
                            {
                                std::time::Duration::from_secs(
                                    installer
                                        .server
                                        .app_state
                                        .config
                                        .load()
                                        .docker
                                        .installer_limits
                                        .timeout,
                                )
                            } else {
                                std::time::Duration::MAX
                            },
                            {
                                let installer = Arc::clone(&installer);

                                async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    handle.start().await.context("Failed to start installation container")?;

                                    let mut progress_tick = Self::install_progress_interval();
                                    let mut seen_running = false;
                                    let mut stdout_open = true;
                                    loop {
                                        tokio::select! {
                                            _ = progress_tick.tick() => {
                                                installer.send_install_progress().await;
                                            }
                                            result = stdout_rx.recv(), if stdout_open => {
                                                match result {
                                                    Ok(line) => {
                                                        installer
                                                            .server
                                                            .websocket
                                                            .send(
                                                                super::websocket::WebsocketMessage::builder(
                                                                    super::websocket::WebsocketEvent::ServerInstallOutput,
                                                                )
                                                                .arg(line.to_compact_string())
                                                                .build(),
                                                            )
                                                            .ok();
                                                    }
                                                    Err(tokio::sync::broadcast::error::RecvError::Closed) => stdout_open = false,
                                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                                }
                                            }
                                            result = status_rx.recv() => {
                                                match result {
                                                    Some(super::executor::ProcessStatus::Running) => {
                                                        seen_running = true;
                                                    }
                                                    Some(super::executor::ProcessStatus::Stopped { exit_code, oom_killed }) if seen_running || !stdout_open => {
                                                        tracing::info!(server = ?installer.server.uuid, exit_code, oom_killed, "ending server installation process by container exit");

                                                        installer.evaluate_install_result(oom_killed).await;
                                                        break;
                                                    }
                                                    None => break,
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }

                                    Ok::<_, anyhow::Error>(())
                                }
                            }
                        ) => match result {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "failed to start installation container: {}",
                                    err
                                ));
                            }
                            Err(err) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "timeout while waiting for installation: {:#?}",
                                    err
                                ));
                            }
                        },
                        _ = installer.abort_notify.notified() => {
                            tracing::info!(
                                server = %installer.server.uuid,
                                "installation script aborted"
                            );
                        }
                    }

                    let successful = installer.failure_reason.lock().await.is_none();
                    installer.unset_installing(successful).await?;

                    Ok(())
                };

                if let Err(err) = run().await {
                    tracing::error!(
                        server = %installer.server.uuid,
                        "generic installation script error: {:#?}",
                        err
                    );
                }
            }
        });

        Ok(())
    }

    pub async fn attach(self: &Arc<Self>) -> Result<(), anyhow::Error> {
        self.server.installing.store(true, Ordering::SeqCst);
        self.server.websocket.send(
            super::websocket::WebsocketMessage::builder(
                super::websocket::WebsocketEvent::ServerInstallStarted,
            )
            .build(),
        )?;

        let (handle, mut status_rx) = match self
            .server
            .app_state
            .executor
            .attach_installation_process(&self.server)
            .await
            .context("Failed to attach to installation process")
        {
            Ok(r) => r,
            Err(err) => {
                self.unset_installing(true).await?;
                return Err(err);
            }
        };

        *self.process_handle.lock().await = Some(Arc::clone(&handle));

        let mut stdout_rx = match handle
            .subscribe_stdout_lines_ratelimited()
            .await
            .context("Failed to subscribe to stdout")
        {
            Ok(rx) => rx,
            Err(err) => {
                self.unset_installing(false).await?;
                return Err(err);
            }
        };

        tokio::spawn({
            let installer = Arc::clone(self);

            async move {
                let run = async || {
                    tokio::select! {
                        result = tokio::time::timeout(
                            if installer
                                .server
                                .app_state
                                .config
                                .load()
                                .docker
                                .installer_limits
                                .timeout
                                > 0
                            {
                                std::time::Duration::from_secs(
                                    installer
                                        .server
                                        .app_state
                                        .config
                                        .load()
                                        .docker
                                        .installer_limits
                                        .timeout,
                                )
                            } else {
                                std::time::Duration::MAX
                            },
                            {
                                let installer = Arc::clone(&installer);

                                async move {
                                    let mut progress_tick = Self::install_progress_interval();
                                    let mut stdout_open = true;

                                    loop {
                                        tokio::select! {
                                            _ = progress_tick.tick() => {
                                                installer.send_install_progress().await;
                                            }
                                            result = stdout_rx.recv(), if stdout_open => {
                                                match result {
                                                    Ok(line) => {
                                                    installer
                                                        .server
                                                        .websocket
                                                        .send(
                                                            super::websocket::WebsocketMessage::builder(
                                                                super::websocket::WebsocketEvent::ServerInstallOutput,
                                                            )
                                                            .arg(line.to_compact_string())
                                                            .build(),
                                                        )
                                                        .ok();
                                                    }
                                                    Err(tokio::sync::broadcast::error::RecvError::Closed) => stdout_open = false,
                                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                                }
                                            }
                                            result = status_rx.recv() => {
                                                match result {
                                                    Some(super::executor::ProcessStatus::Stopped { exit_code, oom_killed }) => {
                                                        tracing::info!(server = ?installer.server.uuid, exit_code, oom_killed, "ending server installation process by container exit");

                                                        installer.evaluate_install_result(oom_killed).await;
                                                        break;
                                                    }
                                                    None => {
                                                        tracing::info!(server = ?installer.server.uuid, "ending server installation process by container exit");
                                                        break;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }

                                    Ok::<_, anyhow::Error>(())
                                }
                            }
                        ) => match result {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "failed during installation container streaming: {}",
                                    err
                                ));
                            }
                            Err(err) => {
                                installer.unset_installing(false).await?;
                                return Err(anyhow::anyhow!(
                                    "timeout while waiting for installation: {:#?}",
                                    err
                                ));
                            }
                        },
                        _ = installer.abort_notify.notified() => {
                            tracing::info!(
                                server = %installer.server.uuid,
                                "installation script aborted"
                            );
                        }
                    }

                    let successful = installer.failure_reason.lock().await.is_none();
                    installer.unset_installing(successful).await?;

                    Ok(())
                };

                if let Err(err) = run().await {
                    tracing::error!(
                        server = %installer.server.uuid,
                        "generic installation script error: {:#?}",
                        err
                    );
                }
            }
        });

        Ok(())
    }

    async fn cleanup_container(&self) -> Result<(), anyhow::Error> {
        let handle = match self.process_handle.lock().await.clone() {
            Some(h) => h,
            None => return Ok(()),
        };
        let container_script = self.get_installation_script()?;

        if let Err(err) = handle.kill().await {
            tracing::warn!(
                server = %self.server.uuid,
                "failed to kill installation container, ignoring: {}",
                err
            );
        }

        let mut env = String::new();
        for var in &self.environment {
            env.push_str(&format!("  {var}\n"));
        }

        let failure = match self.failure_reason.lock().await.as_ref() {
            Some(reason) => format!("\n  Failure Reason:       {reason}"),
            None => String::new(),
        };

        let mut file = ServerInstaller::create_install_logs(&self.server).await?;
        file.write_all(
            format!(
                r"Server Installation Log

|
| Details
| ------------------------------
  Server UUID:          {}
  Container Image:      {}
  Container Entrypoint: {}{failure}

|
| Environment Variables
| ------------------------------
{env}

|
| Script Output
| ------------------------------
",
                self.server.uuid, container_script.container_image, container_script.entrypoint,
            )
            .as_bytes(),
        )
        .await?;

        match handle.logs(None).await {
            Ok(mut reader) => {
                tokio::io::copy(&mut reader, &mut file).await?;
            }
            Err(err) => {
                tracing::warn!(
                    server = %self.server.uuid,
                    "could not collect installation logs: {}",
                    err
                );
            }
        }

        file.shutdown().await?;

        self.server
            .app_state
            .executor
            .cleanup_installation_process(&self.server)
            .await?;

        Ok(())
    }
}

impl Drop for ServerInstaller {
    fn drop(&mut self) {
        self.abort_notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(content: &str) -> Option<(u64, u64, Option<String>)> {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(INSTALL_PROGRESS_FILE_NAME);
            tokio::fs::write(&path, content).await.unwrap();

            ServerInstaller::read_install_progress(&path)
                .await
                .map(|p| (p.progress, p.total, p.label.map(|l| l.to_string())))
        })
    }

    // ServerInstaller::read_install_progress

    #[test]
    fn reads_a_bare_percentage_as_a_total_of_100() {
        assert_eq!(progress("42\n"), Some((42, 100, None)));
    }

    #[test]
    fn reads_a_percentage_with_a_label() {
        assert_eq!(
            progress("42 Downloading server files\n"),
            Some((42, 100, Some("Downloading server files".to_string())))
        );
    }

    #[test]
    fn reads_an_explicit_progress_and_total() {
        assert_eq!(progress("1234/5678\n"), Some((1234, 5678, None)));
    }

    #[test]
    fn reads_an_explicit_progress_and_total_with_a_label() {
        assert_eq!(
            progress("512/2048 Downloading\n"),
            Some((512, 2048, Some("Downloading".to_string())))
        );
    }

    #[test]
    fn uses_the_last_written_line_so_appending_scripts_still_report() {
        assert_eq!(progress("10\n20\n30\n"), Some((30, 100, None)));
    }

    #[test]
    fn reads_the_tail_of_a_file_larger_than_the_read_limit() {
        let mut content = "0 padding\n".repeat(1024);
        content.push_str("77 done padding\n");

        assert!(content.len() as u64 > INSTALL_FILE_READ_LIMIT);
        assert_eq!(
            progress(&content),
            Some((77, 100, Some("done padding".into())))
        );
    }

    #[test]
    fn clamps_progress_to_the_total() {
        assert_eq!(progress("500"), Some((100, 100, None)));
        assert_eq!(progress("-5"), Some((0, 100, None)));
        assert_eq!(progress("9000/1024"), Some((1024, 1024, None)));
    }

    #[test]
    fn ignores_empty_and_unparseable_content() {
        assert_eq!(progress(""), None);
        assert_eq!(progress("\n  \n"), None);
        assert_eq!(progress("not a number"), None);
        assert_eq!(progress("50%"), None);
    }

    #[test]
    fn ignores_malformed_and_zero_totals() {
        assert_eq!(progress("42/"), None);
        assert_eq!(progress("/100"), None);
        assert_eq!(progress("42/0"), None);
        assert_eq!(progress("42/-1"), None);
        assert_eq!(progress("42/abc"), None);
    }

    #[test]
    fn strips_control_characters_from_labels() {
        assert_eq!(
            progress("42 clean\x07label"),
            Some((42, 100, Some("cleanlabel".to_string())))
        );
    }

    #[test]
    fn ignores_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INSTALL_PROGRESS_FILE_NAME);

        assert_eq!(
            tokio_test::block_on(ServerInstaller::read_install_progress(&path)).map(|p| p.progress),
            None
        );
    }

    #[test]
    fn ignores_a_symlinked_file() {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            tokio::fs::write(&target, "42").await.unwrap();

            let path = dir.path().join(INSTALL_PROGRESS_FILE_NAME);
            tokio::fs::symlink(&target, &path).await.unwrap();

            assert!(
                ServerInstaller::read_install_progress(&path)
                    .await
                    .is_none()
            );
        });
    }
}
