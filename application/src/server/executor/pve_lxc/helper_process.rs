use super::*;

pub(super) struct PveHelperProcessHandle {
    vmid: u32,
    cli: PveCli,
    log_path: PathBuf,
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    stdout_ratelimited_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
    stdout_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
}

impl PveHelperProcessHandle {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn new(
        vmid: u32,
        cli: PveCli,
        server: &crate::server::Server,
        app_config: Arc<crate::config::Config>,
        log_path: PathBuf,
        status_tx: tokio::sync::mpsc::Sender<super::ProcessStatus>,
        already_started: bool,
        start_at_end: bool,
        auto_cleanup: bool,
        cleanup_path: Option<PathBuf>,
    ) -> Result<Self, anyhow::Error> {
        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await?;

        let websocket_log_count = app_config.load().system.websocket_log_count;
        let (stdout_ratelimited_tx, stdout_ratelimited_rx) =
            tokio::sync::broadcast::channel::<Arc<compact_str::CompactString>>(websocket_log_count);
        let (stdout_tx, stdout_rx) = tokio::sync::broadcast::channel::<
            Arc<compact_str::CompactString>,
        >(websocket_log_count * 2);

        let started = Arc::new(AtomicBool::new(already_started));
        let cancelled = Arc::new(AtomicBool::new(false));

        let status_cli = cli.clone();
        let status_started = Arc::clone(&started);
        let status_cancelled = Arc::clone(&cancelled);
        let status_server = server.uuid;
        tokio::spawn(async move {
            let mut sent_running = false;
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tick.tick().await;
                if status_cancelled.load(Ordering::Acquire) {
                    break;
                }

                match status_cli.status(vmid).await {
                    Ok(cli::ContainerStatus::Running) => {
                        if !sent_running {
                            sent_running = true;
                            if status_tx.send(super::ProcessStatus::Running).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(cli::ContainerStatus::Stopped) if status_started.load(Ordering::Acquire) => {
                        if !sent_running
                            && status_tx.send(super::ProcessStatus::Running).await.is_err()
                        {
                            break;
                        }
                        let _ = status_tx
                            .send(super::ProcessStatus::Stopped {
                                exit_code: -1,
                                oom_killed: false,
                            })
                            .await;
                        break;
                    }
                    Ok(cli::ContainerStatus::Stopped) => {}
                    Err(error) => {
                        tracing::warn!(
                            server = %status_server,
                            vmid,
                            "failed to read Proxmox helper LXC process state: {error:#}"
                        );
                    }
                }
            }
        });

        let output_cli = cli.clone();
        let output_started = Arc::clone(&started);
        let output_cancelled = Arc::clone(&cancelled);
        let output_server = Arc::downgrade(&**server);
        let output_log_path = log_path.clone();
        tokio::spawn(async move {
            let mut file = match tokio::fs::OpenOptions::new()
                .read(true)
                .open(&output_log_path)
                .await
            {
                Ok(file) => file,
                Err(error) => {
                    tracing::error!(vmid, "failed to open Proxmox helper log: {error:#}");
                    return;
                }
            };
            if start_at_end
                && let Ok(metadata) = file.metadata().await
                && let Err(error) = file.seek(std::io::SeekFrom::Start(metadata.len())).await
            {
                tracing::warn!(vmid, "failed to seek Proxmox helper log: {error:#}");
            }

            let mut line_buffer = LineBuffer::new();
            let mut ratelimit_counter = 0;
            let mut ratelimit_start = std::time::Instant::now();

            loop {
                if output_cancelled.load(Ordering::Acquire) {
                    break;
                }

                if let (Ok(position), Ok(metadata)) =
                    (file.stream_position().await, file.metadata().await)
                    && metadata.len() < position
                {
                    if let Err(error) = file.seek(std::io::SeekFrom::Start(0)).await {
                        tracing::warn!(
                            vmid,
                            "failed to rewind truncated Proxmox helper log: {error:#}"
                        );
                    }
                    line_buffer = LineBuffer::new();
                }

                let mut data = Vec::new();
                match file.read_to_end(&mut data).await {
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(vmid, "failed to read Proxmox helper log: {error:#}");
                    }
                }

                if !data.is_empty() {
                    line_buffer.extend(&data);
                    while let Some(line) = line_buffer.next_line() {
                        let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
                        let allow_ratelimit = {
                            ratelimit_counter += 1;
                            let config = app_config.load();
                            if config.throttles.enabled
                                && config.throttles.line_reset_interval > 0
                                && ratelimit_counter >= config.throttles.lines
                            {
                                if ratelimit_start.elapsed()
                                    < std::time::Duration::from_millis(
                                        config.throttles.line_reset_interval,
                                    )
                                {
                                    if ratelimit_counter == config.throttles.lines
                                        && let Some(server) = output_server.upgrade()
                                    {
                                        server.log_daemon_with_prelude(
                                            "Server is outputting console data too quickly -- throttling...",
                                        );
                                    }
                                    false
                                } else {
                                    ratelimit_counter = 0;
                                    ratelimit_start = std::time::Instant::now();
                                    true
                                }
                            } else {
                                true
                            }
                        };

                        if allow_ratelimit {
                            stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                        }
                        stdout_tx.send(line).ok();
                    }
                    line_buffer.compact();
                }

                let stopped = output_started.load(Ordering::Acquire)
                    && matches!(
                        output_cli.status(vmid).await,
                        Ok(cli::ContainerStatus::Stopped)
                    );
                if stopped {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    let mut final_data = Vec::new();
                    if file.read_to_end(&mut final_data).await.is_ok() && !final_data.is_empty() {
                        line_buffer.extend(&final_data);
                        while let Some(line) = line_buffer.next_line() {
                            let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
                            stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                            stdout_tx.send(line).ok();
                        }
                    }
                    if let Some(line) = line_buffer.flush() {
                        let line = Arc::new(compact_str::CompactString::from_utf8_lossy(line));
                        stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                        stdout_tx.send(line).ok();
                    }
                    break;
                }

                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }

            if auto_cleanup {
                output_cancelled.store(true, Ordering::Release);
                if let Err(error) = output_cli.destroy(vmid).await {
                    tracing::warn!(
                        vmid,
                        "failed to destroy completed Proxmox helper LXC: {error:#}"
                    );
                }
                if let Some(path) = cleanup_path
                    && let Err(error) = tokio::fs::remove_dir_all(&path).await
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(
                        path = %path.display(),
                        "failed to remove Proxmox helper staging directory: {error:#}"
                    );
                }
            }
        });

        Ok(Self {
            vmid,
            cli,
            log_path,
            started,
            cancelled,
            stdout_ratelimited_rx,
            stdout_rx,
        })
    }
}

impl Drop for PveHelperProcessHandle {
    fn drop(&mut self) {
        if !self.started.load(Ordering::Acquire) {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

#[async_trait::async_trait]
impl ProcessHandle for PveHelperProcessHandle {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, anyhow::Error> {
        if let Some(lines) = lines {
            let file = tokio::fs::File::open(&self.log_path).await?;
            Ok(Box::new(crate::io::tail::async_tail(file, lines).await?))
        } else {
            Ok(Box::new(tokio::fs::File::open(&self.log_path).await?))
        }
    }

    async fn send_stdin(&self, _data: Vec<u8>) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "stdin is not supported for Proxmox helper containers"
        ))
    }

    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>
    {
        Ok(self.stdout_ratelimited_rx.resubscribe())
    }

    async fn subscribe_stdout_lines(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>, anyhow::Error>
    {
        Ok(self.stdout_rx.resubscribe())
    }

    async fn sync_configuration(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        self.cli.start(self.vmid).await?;
        self.started.store(true, Ordering::Release);
        Ok(())
    }

    async fn stop(&self) -> Result<(), anyhow::Error> {
        self.cli.stop(self.vmid).await
    }

    async fn kill(&self) -> Result<(), anyhow::Error> {
        self.cli.stop(self.vmid).await
    }
}
