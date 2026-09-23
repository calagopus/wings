use crate::{
    models::ServerPowerAction,
    routes::State,
    server::{
        PowerActionError,
        activity::{Activity, ActivityEvent},
        permissions::Permission,
        websocket::WebsocketEvent,
    },
};
use russh::{Channel, ChannelWriteHalf, server::Msg};
use serde_json::json;
use std::{pin::Pin, str::FromStr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast::error::RecvError,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum ShellMode {
    Normal,
    WinScp,
}

pub struct ShellSession {
    pub state: State,
    pub server: crate::server::Server,

    pub user_ip: std::net::IpAddr,
    pub user_uuid: uuid::Uuid,
    pub mode: ShellMode,
}

impl ShellSession {
    #[inline]
    fn has_permission(&self, permission: Permission) -> bool {
        self.server
            .user_permissions
            .has_permission(self.user_uuid, permission)
    }

    async fn handle_cli_command(
        &mut self,
        line: &str,
        writer: &mut Pin<Box<impl tokio::io::AsyncWrite>>,
    ) {
        writer.write_all(b"\r\n").await.unwrap_or_default();

        let prelude = self.state.config.daemon_prelude();

        let mut writeln = async |line: &str| {
            writer
                .write_all(format!("{prelude} {line}\r\n\x1b[2K").as_bytes())
                .await
                .unwrap_or_default();
        };

        let mut segments = line.split_whitespace();
        segments.next();

        match segments.next() {
            Some("help") => {
                writeln("Available commands:").await;
                writeln("  help    - Show this help message").await;
                writeln("  version - Show the current version").await;
                writeln("  power   - Send a power action to the server").await;
                writeln("  stats   - Show server statistics").await;
            }
            Some("version") => {
                writeln(&format!("Current version: {}", crate::VERSION)).await;
            }
            Some("power") => {
                let Some(action) = segments
                    .next()
                    .and_then(|action| ServerPowerAction::from_str(action).ok())
                else {
                    let config = self.state.config.load();
                    let prefix = &config.system.sftp.shell.cli.name;
                    writeln(&format!("Usage: {prefix} power <start|restart|stop|kill>")).await;
                    return;
                };

                let permission = action.required_permission();
                if !self.has_permission(permission) {
                    writeln(&format!(
                        "You are missing the `{}` permission to do this.",
                        permission.to_str()
                    ))
                    .await;
                    return;
                }

                match self.server.checked_power_action(action).await {
                    Ok(()) => {
                        self.server.activity.log_activity(Activity {
                            event: action.activity_event(),
                            user: Some(self.user_uuid),
                            ip: Some(self.user_ip),
                            metadata: None,
                            schedule: None,
                            timestamp: chrono::Utc::now(),
                        });
                    }
                    Err(PowerActionError::User(message)) => writeln(&message).await,
                    Err(PowerActionError::Internal(_)) => {
                        writeln(&format!(
                            "An unexpected error occurred while trying to {} the server. Please contact an Administrator.",
                            action.to_str()
                        ))
                        .await;
                    }
                }
            }
            Some("stats") => {
                let resource_usage = self.server.resource_usage();

                writeln("Server Statistics:").await;
                writeln(&format!(
                    "  CPU Usage: {:.2}% / {}",
                    resource_usage.cpu_absolute,
                    if self.server.configuration.read().await.build.cpu_limit == 0 {
                        "Unlimited".to_string()
                    } else {
                        format!(
                            "{}%",
                            self.server.configuration.read().await.build.cpu_limit
                        )
                    }
                ))
                .await;
                writeln(&format!(
                    "  Memory Usage: {} / {} ({:.2}%)",
                    human_bytes::human_bytes(resource_usage.memory_bytes as f64),
                    if self.server.configuration.read().await.build.memory_limit == 0 {
                        "Unlimited".to_string()
                    } else {
                        human_bytes::human_bytes(
                            (self.server.configuration.read().await.build.memory_limit
                                * 1024
                                * 1024) as f64,
                        )
                    },
                    (resource_usage.memory_bytes as f64 / resource_usage.memory_limit_bytes as f64
                        * 100.0)
                        .min(100.0)
                ))
                .await;
                writeln(&format!(
                    "  Disk Usage: {} / {} ({:.2}%)",
                    human_bytes::human_bytes(resource_usage.disk_bytes as f64),
                    if self.server.filesystem.disk_limit() == 0 {
                        "Unlimited".to_string()
                    } else {
                        human_bytes::human_bytes(self.server.filesystem.disk_limit() as f64)
                    },
                    (resource_usage.disk_bytes as f64 / self.server.filesystem.disk_limit() as f64
                        * 100.0)
                        .min(100.0)
                ))
                .await;
                writeln("  Network Usage:").await;
                writeln(&format!(
                    "    Received: {}",
                    human_bytes::human_bytes(resource_usage.network.rx_bytes as f64)
                ))
                .await;
                writeln(&format!(
                    "    Sent: {}",
                    human_bytes::human_bytes(resource_usage.network.tx_bytes as f64)
                ))
                .await;
            }
            _ => {
                writeln("Unknown command. Type '.wings help' for a list of commands.").await;
            }
        }
    }

    async fn handle_special_keys(
        &mut self,
        byte: u8,
        current_line: &mut Vec<u8>,
        cursor_pos: &mut usize,
        command_history: &mut Vec<Vec<u8>>,
        history_index: &mut Option<usize>,
        data_writer: &mut Pin<Box<impl tokio::io::AsyncWrite>>,
    ) {
        match byte {
            b'A' => {
                if !command_history.is_empty() {
                    let history_index = if let Some(history_index) = history_index
                        && *history_index > 0
                    {
                        *history_index -= 1;

                        *history_index
                    } else if history_index.is_none() {
                        if !current_line.is_empty() {
                            if command_history.len() >= 20 {
                                command_history.remove(0);
                            }
                            command_history.push(current_line.clone());
                        }
                        let new_history_index = command_history.len() - 1;
                        *history_index = Some(new_history_index);

                        new_history_index
                    } else {
                        data_writer.write_all(b"\x07").await.unwrap_or_default();
                        data_writer.flush().await.unwrap_or_default();
                        return;
                    };

                    let Some(history_cmd) = command_history.get(history_index) else {
                        return;
                    };

                    data_writer.write_all(b"\r").await.unwrap_or_default();
                    let mut output = Vec::with_capacity(history_cmd.len() + 3);
                    output.extend_from_slice(b"\x1b[2K");
                    output.extend_from_slice(history_cmd);
                    data_writer.write_all(&output).await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();

                    current_line.clear();
                    current_line.extend_from_slice(history_cmd);
                    *cursor_pos = current_line.len();
                } else {
                    data_writer.write_all(b"\x07").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                }
            }
            b'B' => {
                if let Some(inner_history_index) = history_index {
                    if let Some(history_cmd) = command_history.get(*inner_history_index + 1) {
                        *inner_history_index += 1;

                        data_writer.write_all(b"\r").await.unwrap_or_default();
                        let mut output = Vec::with_capacity(history_cmd.len() + 3);
                        output.extend_from_slice(b"\x1b[2K");
                        output.extend_from_slice(history_cmd);
                        data_writer.write_all(&output).await.unwrap_or_default();
                        data_writer.flush().await.unwrap_or_default();

                        current_line.clear();
                        current_line.extend_from_slice(history_cmd);
                        *cursor_pos = current_line.len();
                    } else {
                        *history_index = None;
                        data_writer
                            .write_all(b"\r\x1b[2K")
                            .await
                            .unwrap_or_default();
                        data_writer.flush().await.unwrap_or_default();
                        current_line.clear();
                        *cursor_pos = 0;
                    }
                } else {
                    data_writer.write_all(b"\x07").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                }
            }
            b'C' => {
                if *cursor_pos < current_line.len() {
                    *cursor_pos += 1;
                    data_writer.write_all(b"\x1b[C").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                } else {
                    data_writer.write_all(b"\x07").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                }
            }
            b'D' => {
                if *cursor_pos > 0 {
                    *cursor_pos -= 1;
                    data_writer.write_all(b"\x1b[D").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                } else {
                    data_writer.write_all(b"\x07").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                }
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_input_byte(
        &mut self,
        byte: u8,
        current_line: &mut Vec<u8>,
        cursor_pos: &mut usize,
        command_history: &mut Vec<Vec<u8>>,
        history_index: &mut Option<usize>,
        data_writer: &mut Pin<Box<impl tokio::io::AsyncWrite>>,
        writer: &ChannelWriteHalf<Msg>,
    ) {
        match byte {
            b'\r' | b'\n' => {
                if !current_line.is_empty() {
                    let line = String::from_utf8_lossy(current_line);

                    if !command_history.is_empty() && command_history.last() != Some(current_line) {
                        if command_history.len() >= 16 {
                            command_history.remove(0);
                        }
                        command_history.push(current_line.clone());
                    } else if command_history.is_empty() {
                        command_history.push(current_line.clone());
                    }
                    *history_index = None;

                    tracing::debug!(
                        server = %self.server.uuid,
                        "received command from shell: {}",
                        line
                    );

                    if line.starts_with("echo \"WinSCP: this is end-of-file:0\"") {
                        tracing::debug!(
                            server = %self.server.uuid,
                            "received WinSCP end-of-file command, switching to WinSCP mode"
                        );
                        self.mode = ShellMode::WinScp;
                    }

                    match self.mode {
                        ShellMode::Normal => {
                            if line
                                .starts_with(&self.state.config.load().system.sftp.shell.cli.name)
                            {
                                self.handle_cli_command(&line, data_writer).await;
                            } else if self.has_permission(Permission::ControlConsole) {
                                if self.server.state.get_state()
                                    != crate::server::state::ServerState::Offline
                                {
                                    if let Err(err) =
                                        self.server.send_stdin(format!("{line}\n").into()).await
                                    {
                                        data_writer.write_all(b"\r\n").await.unwrap_or_default();

                                        tracing::error!(
                                            server = %self.server.uuid,
                                            "failed to send command to server: {}",
                                            err
                                        );
                                    } else {
                                        data_writer.write_all(b"\r").await.unwrap_or_default();

                                        self.server.activity.log_activity(Activity {
                                            event: ActivityEvent::ConsoleCommand,
                                            user: Some(self.user_uuid),
                                            ip: Some(self.user_ip),
                                            metadata: Some(json!({
                                                "command": line,
                                            })),
                                            schedule: None,
                                            timestamp: chrono::Utc::now(),
                                        });
                                    }
                                } else {
                                    let prelude = self.state.config.daemon_prelude();

                                    data_writer.write_all(b"\r\n").await.unwrap_or_default();
                                    data_writer
                                        .write_all(
                                            format!(
                                                "{prelude} The server is currently offline.\r\n\x1b[2K"
                                            )
                                            .as_bytes(),
                                        )
                                        .await
                                        .unwrap_or_default();
                                }
                            } else {
                                let prelude = self.state.config.daemon_prelude();

                                data_writer.write_all(b"\r\n").await.unwrap_or_default();
                                data_writer
                                    .write_all(format!("{prelude} You are missing the `control.console` permission to do this.\r\n\x1b[2K").as_bytes())
                                    .await
                                    .unwrap_or_default();
                            }
                        }
                        ShellMode::WinScp => {
                            let mut segments = line.split_whitespace();

                            if let Some("echo") = segments.next() {
                                let content = segments.collect::<Vec<&str>>().join(" ");

                                data_writer.write_all(b"\r\n").await.unwrap_or_default();
                                data_writer
                                    .write_all(content.trim_matches('"').as_bytes())
                                    .await
                                    .unwrap_or_default();
                                writer.exit_status(0).await.unwrap_or_default();
                            }
                        }
                    }

                    current_line.clear();
                    *cursor_pos = 0;
                }

                data_writer.flush().await.unwrap_or_default();
            }
            8 | 127 => {
                if *cursor_pos > 0 {
                    if *cursor_pos < current_line.len() {
                        current_line.remove(*cursor_pos - 1);
                        *cursor_pos -= 1;

                        let Some(line_slice) = current_line.get(*cursor_pos..) else {
                            return;
                        };

                        data_writer.write_all(b"\x08").await.unwrap_or_default();
                        data_writer.write_all(b"\x1b[K").await.unwrap_or_default();
                        data_writer.write_all(line_slice).await.unwrap_or_default();

                        if *cursor_pos < current_line.len() {
                            let move_back = current_line.len() - *cursor_pos;
                            data_writer
                                .write_all(format!("\x1b[{move_back}D").as_bytes())
                                .await
                                .unwrap_or_default();
                        }
                    } else {
                        current_line.pop();
                        *cursor_pos -= 1;
                        data_writer
                            .write_all(b"\x08 \x08")
                            .await
                            .unwrap_or_default();
                    }

                    data_writer.flush().await.unwrap_or_default();
                } else {
                    data_writer.write_all(b"\x07").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                }
            }
            _ => {
                if current_line.len() < 1024 {
                    if *cursor_pos < current_line.len() {
                        current_line.insert(*cursor_pos, byte);
                        *cursor_pos += 1;

                        let Some(line_slice) = current_line.get(*cursor_pos..) else {
                            return;
                        };

                        data_writer.write_all(&[byte]).await.unwrap_or_default();
                        data_writer.write_all(line_slice).await.unwrap_or_default();

                        if *cursor_pos < current_line.len() {
                            let move_back = current_line.len() - *cursor_pos;
                            data_writer
                                .write_all(format!("\x1b[{move_back}D").as_bytes())
                                .await
                                .unwrap_or_default();
                        }
                    } else {
                        data_writer.write_all(&[byte]).await.unwrap_or_default();
                        current_line.push(byte);
                        *cursor_pos += 1;
                    }
                    data_writer.flush().await.unwrap_or_default();
                } else {
                    data_writer.write_all(b"\x07").await.unwrap_or_default();
                    data_writer.flush().await.unwrap_or_default();
                }
            }
        }
    }

    pub fn run(mut self, channel: Channel<Msg>) {
        tokio::spawn(async move {
            let (mut reader, writer) = channel.split();
            let mut reader = reader.make_reader();

            writer
                .make_writer()
                .write_all(
                    format!(
                        "\x1b]0;{} - {}\x07",
                        self.state.config.load().app_name,
                        self.server.configuration.read().await.meta.name
                    )
                    .as_bytes(),
                )
                .await
                .unwrap_or_default();

            if self.server.user_permissions.has_calagopus_permission_or(
                self.user_uuid,
                Permission::ControlReadConsole,
                true,
            ) {
                let mut log_stream = self
                    .server
                    .logs(Some(self.state.config.load().system.websocket_log_count))
                    .await;

                {
                    let prelude = self.state.config.daemon_prelude();

                    writer
                        .make_writer()
                        .write_all(
                            format!(
                                "{prelude} Server marked as {}...\r\n\x1b[2K",
                                self.server.state.get_state().to_str()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap_or_default();
                }

                if self.server.state.get_state() != crate::server::state::ServerState::Offline
                    || self.state.config.load().api.send_offline_server_logs
                {
                    tokio::io::copy(&mut log_stream, &mut writer.make_writer())
                        .await
                        .unwrap_or_default();
                }
            } else {
                let prelude = self.state.config.daemon_prelude();

                writer
                    .make_writer()
                    .write_all(
                        format!(
                            "{prelude} You are missing the `control.read-console` permission to view server logs and console output.\r\n\x1b[2K"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap_or_default();
            }

            let futures: [Pin<Box<dyn Future<Output = ()> + Send>>; 2] = [
                {
                    let mut receiver = self.server.websocket.subscribe();
                    let state = Arc::clone(&self.state);
                    let server = self.server.clone();
                    let user_uuid = self.user_uuid;
                    let mut writer = writer.make_writer();

                    Box::pin(async move {
                        loop {
                            match receiver.recv().await {
                                Ok(message) => match message.event {
                                    WebsocketEvent::ServerInstallOutput
                                        if server.user_permissions.has_permission(
                                            user_uuid,
                                            Permission::AdminWebsocketInstall,
                                        ) =>
                                    {
                                        writer
                                            .write_all(
                                                format!("{}\r\n\x1b[2K", message.args.join(" "))
                                                    .as_bytes(),
                                            )
                                            .await
                                            .unwrap_or_default();
                                    }
                                    WebsocketEvent::ServerTransferLogs
                                        if server.user_permissions.has_permission(
                                            user_uuid,
                                            Permission::AdminWebsocketTransfer,
                                        ) =>
                                    {
                                        writer
                                            .write_all(
                                                format!("{}\r\n\x1b[2K", message.args.join(" "))
                                                    .as_bytes(),
                                            )
                                            .await
                                            .unwrap_or_default();
                                    }
                                    WebsocketEvent::ServerConsoleOutput => {
                                        writer
                                            .write_all(
                                                format!("{}\r\n\x1b[2K", message.args.join(" "))
                                                    .as_bytes(),
                                            )
                                            .await
                                            .unwrap_or_default();
                                    }
                                    WebsocketEvent::ServerDaemonMessage => {
                                        writer
                                            .write_all(
                                                format!("{}\r\n\x1b[2K", message.args.join(" "))
                                                    .as_bytes(),
                                            )
                                            .await
                                            .unwrap_or_default();
                                    }
                                    WebsocketEvent::ServerStatus => {
                                        let prelude = state.config.daemon_prelude();
                                        let Some(status) = message.args.first() else {
                                            return;
                                        };

                                        writer
                                            .write_all(
                                                format!(
                                                    "{prelude} Server marked as {}...\r\n\x1b[2K",
                                                    status
                                                )
                                                .as_bytes(),
                                            )
                                            .await
                                            .unwrap_or_default();
                                    }
                                    _ => {}
                                },
                                Err(RecvError::Closed) => {
                                    tracing::debug!(
                                        server = %server.uuid,
                                        "websocket channel closed, stopping listener"
                                    );
                                    break;
                                }
                                Err(RecvError::Lagged(_)) => {
                                    tracing::debug!(
                                        server = %server.uuid,
                                        "websocket lagged behind, messages dropped"
                                    );
                                }
                            }
                        }
                    })
                },
                {
                    let config = self.state.config.clone();
                    let server = self.server.clone();
                    let user_uuid = self.user_uuid;
                    let mut writer = writer.make_writer();

                    Box::pin(async move {
                        'outer: loop {
                            if !server.user_permissions.has_calagopus_permission_or(
                                user_uuid,
                                Permission::ControlReadConsole,
                                true,
                            ) {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                continue;
                            }

                            if let Some(mut stdout) = server.get_stdout_lines_ratelimited().await {
                                loop {
                                    if !server.user_permissions.has_calagopus_permission_or(
                                        user_uuid,
                                        Permission::ControlReadConsole,
                                        true,
                                    ) {
                                        let prelude = config.daemon_prelude();

                                        writer
                                            .write_all(
                                                format!(
                                                    "{prelude} You are missing the `control.read-console` permission to view server logs and console output.\r\n\x1b[2K"
                                                )
                                                .as_bytes(),
                                            )
                                            .await
                                            .unwrap_or_default();

                                        continue 'outer;
                                    }

                                    match stdout.recv().await {
                                        Ok(stdout) => {
                                            if let Err(err) = writer
                                                .write_all(
                                                    format!("{stdout}\r\n\x1b[2K").as_bytes(),
                                                )
                                                .await
                                            {
                                                tracing::error!(error = %err, "failed to write stdout");
                                            }
                                        }
                                        Err(RecvError::Closed) => {
                                            break;
                                        }
                                        Err(RecvError::Lagged(_)) => {
                                            tracing::debug!(
                                                server = %server.uuid,
                                                "stdout lagged behind, messages dropped"
                                            );
                                        }
                                    }
                                }
                            }

                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    })
                },
            ];

            let stdin_task = {
                let mut data_writer = writer.make_writer();

                Box::pin(async move {
                    let mut buffer = [0; 1024];
                    let mut current_line = Vec::with_capacity(1024);
                    let mut command_history: Vec<Vec<u8>> = Vec::with_capacity(16);
                    let mut history_index: Option<usize> = None;
                    let mut escape_sequence = false;
                    let mut cursor_sequence = false;
                    let mut sequence_buffer = Vec::with_capacity(3);
                    let mut cursor_pos = 0;

                    loop {
                        match reader.read(&mut buffer).await {
                            Ok(0) => break,
                            Ok(bytes_read) => {
                                let Some(buffer_slice) = buffer.get(..bytes_read) else {
                                    continue;
                                };

                                for &byte in buffer_slice {
                                    if escape_sequence {
                                        sequence_buffer.push(byte);

                                        if byte == b'[' && sequence_buffer.len() == 1 {
                                            cursor_sequence = true;
                                        } else if cursor_sequence && sequence_buffer.len() == 2 {
                                            self.handle_special_keys(
                                                byte,
                                                &mut current_line,
                                                &mut cursor_pos,
                                                &mut command_history,
                                                &mut history_index,
                                                &mut Box::pin(&mut data_writer),
                                            )
                                            .await;

                                            escape_sequence = false;
                                            cursor_sequence = false;
                                            sequence_buffer.clear();
                                        } else if sequence_buffer.len() >= 3
                                            || (!cursor_sequence && sequence_buffer.len() >= 2)
                                        {
                                            data_writer
                                                .write_all(b"\x1b")
                                                .await
                                                .unwrap_or_default();
                                            data_writer
                                                .write_all(&sequence_buffer)
                                                .await
                                                .unwrap_or_default();
                                            data_writer.flush().await.unwrap_or_default();
                                            escape_sequence = false;
                                            cursor_sequence = false;
                                            sequence_buffer.clear();
                                        }
                                    } else if byte == 0x1b {
                                        escape_sequence = true;
                                        sequence_buffer.clear();
                                    } else {
                                        self.handle_input_byte(
                                            byte,
                                            &mut current_line,
                                            &mut cursor_pos,
                                            &mut command_history,
                                            &mut history_index,
                                            &mut Box::pin(&mut data_writer),
                                            &writer,
                                        )
                                        .await;
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::debug!("error reading from SSH session: {:?}", err);
                                break;
                            }
                        }
                    }
                })
            };

            tokio::select! {
                _ = stdin_task => {
                    tracing::debug!("shell stdin task finished");
                }
                _ = futures::future::join_all(futures) => {
                    tracing::debug!("shell handles finished");
                }
            }
        });
    }
}
