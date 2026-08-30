use crate::{
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        filesystem::{RenameParents, archive::ArchiveFormat},
    },
};
use cap_std::fs::OpenOptions;
use compact_str::{CompactStringExt, ToCompactString};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScheduleVariable {
    pub variable: compact_str::CompactString,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScheduleDynamicParameter {
    Raw(compact_str::CompactString),
    Variable(ScheduleVariable),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ScheduleAction {
    Sleep {
        duration: u64,
    },
    Ensure {
        condition: super::conditions::ScheduleCondition,
    },
    Format {
        format: String,
        output_into: ScheduleVariable,
    },
    MatchRegex {
        input: ScheduleDynamicParameter,

        #[serde(with = "serde_regex")]
        regex: regex::Regex,

        output_into: Vec<Option<ScheduleVariable>>,
    },
    WaitForConsoleLine {
        ignore_failure: bool,

        contains: ScheduleDynamicParameter,
        #[serde(default)]
        case_insensitive: bool,
        timeout: u64,

        output_into: Option<ScheduleVariable>,
    },
    SendPower {
        ignore_failure: bool,

        action: crate::models::ServerPowerAction,
    },
    SendCommand {
        ignore_failure: bool,

        command: ScheduleDynamicParameter,
    },
    CreateBackup {
        ignore_failure: bool,
        foreground: bool,

        name: Option<ScheduleDynamicParameter>,
        ignored_files: Vec<compact_str::CompactString>,
    },
    CreateDirectory {
        ignore_failure: bool,

        root: ScheduleDynamicParameter,
        name: ScheduleDynamicParameter,
    },
    WriteFile {
        ignore_failure: bool,
        append: bool,

        file: ScheduleDynamicParameter,
        content: ScheduleDynamicParameter,
    },
    CopyFile {
        ignore_failure: bool,
        foreground: bool,

        file: ScheduleDynamicParameter,
        destination: ScheduleDynamicParameter,
    },
    DeleteFiles {
        root: ScheduleDynamicParameter,
        files: Vec<compact_str::CompactString>,
    },
    RenameFiles {
        root: ScheduleDynamicParameter,
        files: Vec<crate::models::RenameFile>,
    },
    CompressFiles {
        ignore_failure: bool,
        foreground: bool,

        root: ScheduleDynamicParameter,
        files: Vec<compact_str::CompactString>,
        format: ArchiveFormat,
        name: ScheduleDynamicParameter,
    },
    DecompressFile {
        ignore_failure: bool,
        foreground: bool,

        root: ScheduleDynamicParameter,
        file: ScheduleDynamicParameter,
    },
    UpdateStartupVariable {
        ignore_failure: bool,

        env_variable: ScheduleDynamicParameter,
        value: ScheduleDynamicParameter,
    },
    UpdateStartupCommand {
        ignore_failure: bool,

        command: ScheduleDynamicParameter,
    },
    UpdateStartupDockerImage {
        ignore_failure: bool,

        image: ScheduleDynamicParameter,
    },
}

impl ScheduleAction {
    #[inline]
    pub fn ignore_failure(&self) -> bool {
        match self {
            ScheduleAction::Sleep { .. } => false,
            ScheduleAction::Ensure { .. } => false,
            ScheduleAction::Format { .. } => false,
            ScheduleAction::MatchRegex { .. } => false,
            ScheduleAction::WaitForConsoleLine { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::SendPower { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::SendCommand { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CreateBackup { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CreateDirectory { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::WriteFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CopyFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::DeleteFiles { .. } => false,
            ScheduleAction::RenameFiles { .. } => false,
            ScheduleAction::CompressFiles { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::DecompressFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::UpdateStartupVariable { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::UpdateStartupCommand { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::UpdateStartupDockerImage { ignore_failure, .. } => *ignore_failure,
        }
    }

    pub async fn execute(
        &self,
        state: &State,
        server: &crate::server::Server,
        execution_context: &mut super::ScheduleExecutionContext,
    ) -> Result<(), Cow<'static, str>> {
        if let Some(state) = server.locked_state() {
            return Err(format!(
                "server is in a locked state ({state}), cannot execute schedule action"
            )
            .into());
        }

        match self {
            ScheduleAction::Sleep { duration } => {
                tokio::time::sleep(std::time::Duration::from_millis(*duration)).await;
            }
            ScheduleAction::Ensure { condition } => {
                if !condition.evaluate(server, execution_context).await {
                    return Err("condition did not evaluate with success.".into());
                }
            }
            ScheduleAction::Format {
                format,
                output_into,
            } => {
                let mut result = compact_str::CompactString::default();
                let mut chars = format.chars().peekable();

                while let Some(ch) = chars.next() {
                    if ch == '{' {
                        if chars.peek() == Some(&'{') {
                            chars.next();
                            result.push('{');
                        } else {
                            let mut var_name = String::new();
                            let mut found_closing = false;

                            for inner_ch in chars.by_ref() {
                                if inner_ch == '}' {
                                    found_closing = true;
                                    break;
                                }
                                var_name.push(inner_ch);
                            }

                            if found_closing {
                                if let Some(value) =
                                    execution_context.get_variable_by_str(&var_name)
                                {
                                    result.push_str(value.as_str());
                                } else {
                                    result.push('{');
                                    result.push_str(&var_name);
                                    result.push('}');
                                }
                            } else {
                                result.push('{');
                                result.push_str(&var_name);
                            }
                        }
                    } else if ch == '}' {
                        if chars.peek() == Some(&'}') {
                            chars.next();
                            result.push('}');
                        } else {
                            result.push(ch);
                        }
                    } else {
                        result.push(ch);
                    }
                }

                execution_context.store_variable(output_into.clone(), result);
            }
            ScheduleAction::MatchRegex {
                input,
                regex,
                output_into,
            } => {
                let input = match execution_context.resolve_parameter(input) {
                    Some(input) => input.to_string(),
                    None => {
                        return Err("unable to resolve parameter `input` into a string.".into());
                    }
                };

                let Some(matches) = regex.captures(&input) else {
                    return Ok(());
                };

                for (group_match, output_into) in matches.iter().skip(1).zip(output_into.iter()) {
                    let (Some(group_match), Some(output_into)) = (group_match, output_into) else {
                        continue;
                    };

                    execution_context.store_variable(
                        output_into.clone(),
                        group_match.as_str().to_compact_string(),
                    );
                }
            }
            ScheduleAction::WaitForConsoleLine {
                contains,
                case_insensitive,
                timeout,
                output_into,
                ..
            } => {
                let mut stdout = match server.get_stdout_lines().await {
                    Some(stdout) => stdout,
                    None => {
                        return Err("unable to get server stdout, is the server offline?".into());
                    }
                };

                let contains = match execution_context.resolve_parameter(contains) {
                    Some(contains) => contains,
                    None => {
                        return Err("unable to resolve parameter `contains` into a string.".into());
                    }
                };

                let line_finder = async {
                    if *case_insensitive {
                        let contains = contains.to_lowercase();

                        while let Ok(line) = stdout.recv().await {
                            if line.to_lowercase().contains(&*contains) {
                                return Some(line.to_compact_string());
                            }
                        }
                    } else {
                        while let Ok(line) = stdout.recv().await {
                            if line.contains(&**contains) {
                                return Some(line.to_compact_string());
                            }
                        }
                    }

                    None
                };

                if let Ok(line) =
                    tokio::time::timeout(std::time::Duration::from_millis(*timeout), line_finder)
                        .await
                {
                    if let Some(output_into) = output_into
                        && let Some(line) = line
                    {
                        execution_context.store_variable(output_into.clone(), line);
                    }

                    return Ok(());
                }

                return Err("timeout while waiting for matching console output.".into());
            }
            ScheduleAction::SendPower { action, .. } => match action {
                crate::models::ServerPowerAction::Start => {
                    if server.state.get_state() != crate::server::state::ServerState::Offline {
                        return Err("server is already running or starting.".into());
                    }

                    if let Err(err) = server.start(None, false).await {
                        match err.downcast::<&str>() {
                            Ok(message) => {
                                return Err(message.into());
                            }
                            Err(err) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to start server: {:#?}",
                                    err,
                                );

                                return Err(
                                    "an unexpected error occurred while starting the server."
                                        .into(),
                                );
                            }
                        }
                    } else {
                        server.activity.log_activity(Activity {
                            event: ActivityEvent::PowerStart,
                            user: None,
                            ip: None,
                            metadata: None,
                            schedule: Some(execution_context.schedule_uuid),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
                crate::models::ServerPowerAction::Restart => {
                    if server.restarting.load(std::sync::atomic::Ordering::SeqCst) {
                        return Err("server is already restarting.".into());
                    }

                    let auto_kill = server.configuration.read().await.auto_kill;
                    if let Err(err) = if auto_kill.enabled && auto_kill.seconds > 0 {
                        server
                            .restart_with_kill_timeout(
                                None,
                                std::time::Duration::from_secs(auto_kill.seconds),
                            )
                            .await
                    } else {
                        server.restart(None).await
                    } {
                        match err.downcast::<&str>() {
                            Ok(message) => {
                                return Err(message.into());
                            }
                            Err(err) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to restart server: {:#?}",
                                    err
                                );

                                return Err(
                                    "an unexpected error occurred while restarting the server."
                                        .into(),
                                );
                            }
                        }
                    } else {
                        server.activity.log_activity(Activity {
                            event: ActivityEvent::PowerRestart,
                            user: None,
                            ip: None,
                            metadata: None,
                            schedule: Some(execution_context.schedule_uuid),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
                crate::models::ServerPowerAction::Stop => {
                    if matches!(
                        server.state.get_state(),
                        crate::server::state::ServerState::Offline
                            | crate::server::state::ServerState::Stopping
                    ) {
                        return Err("server is already offline or stopping.".into());
                    }

                    let auto_kill = server.configuration.read().await.auto_kill;
                    if let Err(err) = if auto_kill.enabled && auto_kill.seconds > 0 {
                        server
                            .stop_with_kill_timeout(
                                std::time::Duration::from_secs(auto_kill.seconds),
                                false,
                            )
                            .await
                    } else {
                        server.stop(None, false).await
                    } {
                        match err.downcast::<&str>() {
                            Ok(message) => {
                                return Err(message.into());
                            }
                            Err(err) => {
                                tracing::error!(
                                    server = %server.uuid,
                                    "failed to stop server: {:#?}",
                                    err
                                );

                                return Err(
                                    "an unexpected error occurred while stopping the server."
                                        .into(),
                                );
                            }
                        }
                    } else {
                        server.activity.log_activity(Activity {
                            event: ActivityEvent::PowerStop,
                            user: None,
                            ip: None,
                            metadata: None,
                            schedule: Some(execution_context.schedule_uuid),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
                crate::models::ServerPowerAction::Kill => {
                    if server.state.get_state() == crate::server::state::ServerState::Offline {
                        return Err("server is already offline.".into());
                    }

                    if let Err(err) = server.kill(false).await {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to kill server: {:#?}",
                            err
                        );

                        return Err("an unexpected error occurred while killing the server.".into());
                    } else {
                        server.activity.log_activity(Activity {
                            event: ActivityEvent::PowerKill,
                            user: None,
                            ip: None,
                            metadata: None,
                            schedule: Some(execution_context.schedule_uuid),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
            },
            ScheduleAction::SendCommand { command, .. } => {
                if server.state.get_state() == crate::server::state::ServerState::Offline {
                    return Err("server is not running.".into());
                }

                let command = match execution_context.resolve_parameter(command) {
                    Some(command) => command,
                    None => {
                        return Err("unable to resolve parameter `command` into a string.".into());
                    }
                };

                if server
                    .send_stdin(format!("{command}\n").into())
                    .await
                    .is_ok()
                {
                    server.activity.log_activity(Activity {
                        event: ActivityEvent::ConsoleCommand,
                        user: None,
                        ip: None,
                        metadata: Some(serde_json::json!({
                            "command": command,
                        })),
                        schedule: Some(execution_context.schedule_uuid),
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
            ScheduleAction::CreateBackup {
                foreground,
                name,
                ignored_files,
                ..
            } => {
                let name = match name {
                    Some(name) => match execution_context.resolve_parameter(name) {
                        Some(name) => Some(name.as_str()),
                        None => {
                            return Err("unable to resolve parameter `name` into a string.".into());
                        }
                    },
                    None => None,
                };

                let (adapter, uuid) = match state
                    .config
                    .client
                    .create_backup(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        name,
                        ignored_files,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to create backup: {:#?}",
                            err
                        );

                        return Err("failed to create backup".into());
                    }
                };

                if state.backup_manager.fast_contains(server, uuid).await {
                    return Err("backup already exists".into());
                }

                let thread = tokio::spawn({
                    let state = Arc::clone(state);
                    let ignored_files = ignored_files.join_compact("\n");
                    let server = server.clone();

                    async move {
                        if let Err(err) = state
                            .backup_manager
                            .create(adapter, &server, uuid, ignored_files)
                            .await
                        {
                            tracing::error!(
                                "failed to create backup {} (adapter = {:?}) for {}: {}",
                                uuid,
                                adapter,
                                server.uuid,
                                err
                            );

                            return Err("failed to create backup".into());
                        }

                        Ok::<_, Cow<'static, str>>(())
                    }
                });

                if *foreground && let Ok(Err(err)) = thread.await {
                    return Err(err);
                }
            }
            ScheduleAction::CreateDirectory { root, name, .. } => {
                let raw_root = match execution_context.resolve_parameter(root) {
                    Some(root) => root,
                    None => {
                        return Err("unable to resolve parameter `root` into a string.".into());
                    }
                };
                let name = match execution_context.resolve_parameter(name) {
                    Some(name) => name,
                    None => {
                        return Err("unable to resolve parameter `name` into a string.".into());
                    }
                };

                let (root, filesystem) = server
                    .filesystem
                    .resolve_writable_fs(server, raw_root)
                    .await;

                let metadata = filesystem.async_metadata(&root).await;
                if !metadata.map_or(true, |m| m.file_type.is_dir()) {
                    return Err("path is not a directory".into());
                }

                if filesystem.is_primary_server_fs() && server.filesystem.is_ignored(&root, true) {
                    return Err("path not found".into());
                }

                let destination = root.join(name);

                if filesystem.is_primary_server_fs()
                    && server.filesystem.is_ignored(&destination, true)
                {
                    return Err("destination not found".into());
                }

                if let Err(err) = filesystem.async_create_dir_all(&destination).await {
                    tracing::error!(path = %destination.display(), "failed to create directory: {:?}", err);

                    return Err("failed to create directory".into());
                }

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileCreateDirectory,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "directory": raw_root,
                        "name": name,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });
            }
            ScheduleAction::WriteFile {
                file: file_path,
                content,
                append,
                ..
            } => {
                let file_path = match execution_context.resolve_parameter(file_path) {
                    Some(file_path) => file_path,
                    None => {
                        return Err("unable to resolve parameter `file` into a string.".into());
                    }
                };
                let content = match execution_context.resolve_parameter(content) {
                    Some(content) => content,
                    None => {
                        return Err("unable to resolve parameter `content` into a string.".into());
                    }
                };

                let parent = match Path::new(&file_path).parent() {
                    Some(parent) => parent,
                    None => {
                        return Err("file has no parent".into());
                    }
                };

                let file_name = match Path::new(&file_path).file_name() {
                    Some(name) => name,
                    None => {
                        return Err("invalid file name".into());
                    }
                };

                let (root, filesystem) =
                    server.filesystem.resolve_writable_fs(server, &parent).await;
                let path = root.join(file_name);

                let metadata = filesystem.async_metadata(&path).await;

                if filesystem.is_primary_server_fs() && server.filesystem.is_ignored(parent, true) {
                    return Err("file not found".into());
                }

                let old_content_size = if let Ok(metadata) = metadata {
                    if !metadata.file_type.is_file() {
                        return Err("file is not a file".into());
                    }

                    metadata.size as i64
                } else {
                    0
                };

                if filesystem.is_primary_server_fs() && server.filesystem.is_ignored(parent, true) {
                    return Err("parent directory not found".into());
                }

                if let Err(err) = server.filesystem.async_create_dir_all(parent).await {
                    tracing::error!(path = %parent.display(), "failed to create parent directory: {:?}", err);

                    return Err("failed to create parent directory".into());
                }

                let added_content_size = if *append {
                    content.len() as i64
                } else {
                    content.len() as i64 - old_content_size
                };
                if filesystem.is_primary_server_fs()
                    && !server
                        .filesystem
                        .async_allocate_in_path(parent, added_content_size, false)
                        .await
                {
                    return Err("failed to allocate space".into());
                }

                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create(true)
                    .truncate(!*append)
                    .append(*append);

                let mut file = match filesystem
                    .async_open_file_with_options(&path, options)
                    .await
                {
                    Ok(file) => file,
                    Err(err) => {
                        tracing::error!(path = %path.display(), "failed to open file: {:?}", err);
                        return Err("failed to open file".into());
                    }
                };

                if let Err(err) = file.write_all(content.as_bytes()).await {
                    tracing::error!(path = %path.display(), "failed to write file: {:?}", err);
                    return Err("failed to write file".into());
                }
                if let Err(err) = file.shutdown().await {
                    tracing::error!(path = %path.display(), "failed to shutdown file: {:?}", err);
                    return Err("failed to shutdown file".into());
                }

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileWrite,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "file": file_path,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });
            }
            ScheduleAction::CopyFile {
                foreground,
                file,
                destination,
                ..
            } => {
                let file = match execution_context.resolve_parameter(file) {
                    Some(file) => file,
                    None => {
                        return Err("unable to resolve parameter `file` into a string.".into());
                    }
                };
                let destination = match execution_context.resolve_parameter(destination) {
                    Some(destination) => destination,
                    None => {
                        return Err(
                            "unable to resolve parameter `destination` into a string.".into()
                        );
                    }
                };

                let parent = match Path::new(file).parent() {
                    Some(parent) => parent,
                    None => {
                        return Err("file has no parent".into());
                    }
                };

                let file_name = match Path::new(file).file_name() {
                    Some(name) => name,
                    None => {
                        return Err("invalid file name".into());
                    }
                };

                let (root, filesystem) =
                    server.filesystem.resolve_readable_fs(server, parent).await;
                let path = root.join(file_name);

                let metadata = match filesystem.async_metadata(&path).await {
                    Ok(metadata) => {
                        if !metadata.file_type.is_file()
                            || (filesystem.is_primary_server_fs()
                                && server
                                    .filesystem
                                    .is_ignored(&path, metadata.file_type.is_dir()))
                        {
                            return Err("file not found".into());
                        } else {
                            metadata
                        }
                    }
                    Err(_) => {
                        return Err("file not found".into());
                    }
                };

                if filesystem.is_primary_server_fs() && server.filesystem.is_ignored(parent, true) {
                    return Err("parent directory not found".into());
                }

                let file_name = parent.join(destination);
                let destination_parent = match file_name.parent() {
                    Some(parent) => parent,
                    None => {
                        return Err("destination has no parent".into());
                    }
                };
                let destination_file_name = match file_name.file_name() {
                    Some(name) => name,
                    None => {
                        return Err("invalid destination file name".into());
                    }
                };

                let (destination_path, destination_filesystem) = server
                    .filesystem
                    .resolve_writable_fs(server, destination_parent)
                    .await;
                let destination_path = server
                    .filesystem
                    .relative_path(&destination_path.join(destination_file_name));

                let progress = Arc::new(AtomicU64::new(0));
                let total = Arc::new(AtomicU64::new(metadata.size));

                let (_, task) = server
                    .filesystem
                    .operations
                    .add_operation(
                        crate::server::filesystem::operations::FilesystemOperation::Copy {
                            path: path.clone(),
                            destination_path: file_name,
                            start_time: chrono::Utc::now(),
                            progress: progress.clone(),
                            total: total.clone(),
                        },
                        {
                            let server = server.clone();
                            let destination_path = destination_path.clone();
                            let destination_filesystem = destination_filesystem.clone();

                            async move {
                                server
                                    .filesystem
                                    .copy_path(
                                        progress,
                                        &server,
                                        metadata,
                                        path,
                                        filesystem.clone(),
                                        destination_path,
                                        destination_filesystem,
                                    )
                                    .await?;

                                Ok(())
                            }
                        },
                    )
                    .await;

                if *foreground {
                    match task.await {
                        Ok(Some(Ok(()))) => {}
                        Ok(None) => {
                            return Err("file copy aborted by another source".into());
                        }
                        Ok(Some(Err(err))) => {
                            tracing::error!(
                                server = %server.uuid,
                                root = %root.display(),
                                "failed to copy file: {:#?}",
                                err,
                            );

                            return Err(format!("failed to copy file: {err}").into());
                        }
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                root = %root.display(),
                                "failed to copy file: {:#?}",
                                err,
                            );

                            return Err("failed to copy file".into());
                        }
                    }
                }

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileCopy,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "file": file,
                        "name": destination,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });
            }
            ScheduleAction::DeleteFiles { root, files } => {
                let raw_root = match execution_context.resolve_parameter(root) {
                    Some(root) => root,
                    None => {
                        return Err("unable to resolve parameter `root` into a string.".into());
                    }
                };

                for file in files {
                    let (source, filesystem) = server
                        .filesystem
                        .resolve_writable_fs(server, Path::new(&raw_root).join(file))
                        .await;
                    if source == Path::new(&raw_root) {
                        continue;
                    }

                    let metadata = match filesystem.async_symlink_metadata(&source).await {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };

                    if filesystem.is_primary_server_fs()
                        && server
                            .filesystem
                            .is_ignored(&source, metadata.file_type.is_dir())
                    {
                        continue;
                    }

                    if filesystem.is_primary_server_fs() {
                        server.filesystem.truncate_path(&source).await.ok();
                    } else if metadata.file_type.is_dir() {
                        filesystem.async_remove_dir_all(&source).await.ok();
                    } else {
                        filesystem.async_remove_file(&source).await.ok();
                    }
                }

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileDelete,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "directory": raw_root,
                        "files": files,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });
            }
            ScheduleAction::RenameFiles { root, files } => {
                let raw_root = match execution_context.resolve_parameter(root) {
                    Some(root) => Path::new(root),
                    None => {
                        return Err("unable to resolve parameter `root` into a string.".into());
                    }
                };

                let (root, filesystem) = server
                    .filesystem
                    .resolve_writable_fs(server, &raw_root)
                    .await;

                for file in files {
                    let from = root.join(&file.from);
                    if from == root {
                        continue;
                    }

                    let to = root.join(&file.to);
                    if to == root {
                        continue;
                    }

                    if from == to {
                        continue;
                    }

                    let from_metadata = match filesystem.async_metadata(&from).await {
                        Ok(metadata) => metadata,
                        Err(_) => continue,
                    };

                    if filesystem.async_metadata(&to).await.is_ok()
                        || (filesystem.is_primary_server_fs()
                            && (server
                                .filesystem
                                .is_ignored(&from, from_metadata.file_type.is_dir())
                                || server
                                    .filesystem
                                    .is_ignored(&to, from_metadata.file_type.is_dir())))
                    {
                        continue;
                    }

                    if filesystem.is_primary_server_fs() {
                        if let Err(err) = server
                            .filesystem
                            .rename_path(from, to, RenameParents::Create)
                            .await
                        {
                            tracing::debug!(
                                server = %server.uuid,
                                "failed to rename file: {:#?}",
                                err
                            );
                        }
                    } else {
                        filesystem.async_rename(&from, &to).await.ok();
                    }
                }

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileRename,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "directory": raw_root,
                        "files": files,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });
            }
            ScheduleAction::CompressFiles {
                foreground,
                root,
                files,
                format,
                name,
                ..
            } => {
                let raw_root = match execution_context.resolve_parameter(root) {
                    Some(root) => root,
                    None => {
                        return Err("unable to resolve parameter `root` into a string.".into());
                    }
                };
                let name = match execution_context.resolve_parameter(name) {
                    Some(name) => name,
                    None => {
                        return Err("unable to resolve parameter `name` into a string.".into());
                    }
                };

                let (root, filesystem) = server
                    .filesystem
                    .resolve_readable_fs(server, Path::new(&raw_root))
                    .await;

                let metadata = filesystem.async_symlink_metadata(&root).await;
                if !metadata.map_or(true, |m| m.file_type.is_dir()) {
                    return Err("root is not a directory".into());
                }

                let file_name = root.join(name);

                let parent = match file_name.parent() {
                    Some(parent) => parent,
                    None => {
                        return Err("file has no parent".into());
                    }
                };

                let file_name = match file_name.file_name() {
                    Some(name) => name,
                    None => {
                        return Err("invalid file name".into());
                    }
                };

                let (destination_root, destination_filesystem) =
                    server.filesystem.resolve_writable_fs(server, parent).await;
                let destination_path = destination_root.join(file_name);

                if destination_filesystem.is_primary_server_fs()
                    && server.filesystem.is_ignored(&destination_path, false)
                {
                    return Err("file not found".into());
                }

                let progress = Arc::new(AtomicU64::new(0));
                let total = Arc::new(AtomicU64::new(0));

                let (_, task) = server
                    .filesystem
                    .operations
                    .add_operation(
                        crate::server::filesystem::operations::FilesystemOperation::Compress {
                            path: PathBuf::from(&raw_root),
                            files: files.iter().map(PathBuf::from).collect(),
                            destination_path: PathBuf::from(&raw_root).join(file_name),
                            start_time: chrono::Utc::now(),
                            progress: progress.clone(),
                            total: total.clone(),
                        },
                        {
                            let state = state.clone();
                            let root = root.clone();
                            let files = files.clone();
                            let format = *format;
                            let server = server.clone();
                            let filesystem = filesystem.clone();
                            let destination_path = destination_path.clone();
                            let destination_filesystem = destination_filesystem.clone();

                            async move {
                                let ignored = server.filesystem.get_ignored();
                                let writer = tokio::task::spawn_blocking(move || {
                                    destination_filesystem.create_seekable_file(&destination_path)
                                })
                                .await??;

                                let mut total_size = 0;
                                for file in &files {
                                    let directory_entry = match filesystem
                                        .async_directory_entry_buffer(&root.join(file), &[])
                                        .await
                                    {
                                        Ok(entry) => entry,
                                        Err(_) => continue,
                                    };

                                    total_size += directory_entry.size;
                                }

                                total.store(total_size, std::sync::atomic::Ordering::Relaxed);

                                match format {
                                    ArchiveFormat::Tar
                                    | ArchiveFormat::TarGz
                                    | ArchiveFormat::TarXz
                                    | ArchiveFormat::TarLzip
                                    | ArchiveFormat::TarBz2
                                    | ArchiveFormat::TarLz4
                                    | ArchiveFormat::TarZstd => {
                                        crate::server::filesystem::archive::create::create_tar(
                                            server.filesystem.clone(),
                                            writer,
                                            &root,
                                            files,
                                            Some(progress),
                                            ignored.into(),
                                            crate::server::filesystem::archive::create::CreateTarOptions {
                                                compression_type: format.compression_format(),
                                                compression_level: state
                                                    .config.load()
                                                    .system
                                                    .backups
                                                    .compression_level,
                                                threads: state.config.load().api.file_compression_threads,
                                            },
                                        )
                                        .await
                                    }
                                    ArchiveFormat::Zip => {
                                        crate::server::filesystem::archive::create::create_zip(
                                            server.filesystem.clone(),
                                            writer,
                                            &root,
                                            files,
                                            Some(progress),
                                            ignored.into(),
                                            crate::server::filesystem::archive::create::CreateZipOptions {
                                                compression_level: state
                                                    .config.load()
                                                    .system
                                                    .backups
                                                    .compression_level,
                                            },
                                        )
                                        .await
                                    }
                                    ArchiveFormat::SevenZip => {
                                        crate::server::filesystem::archive::create::create_7z(
                                            server.filesystem.clone(),
                                            writer,
                                            &root,
                                            files,
                                            Some(progress),
                                            ignored.into(),
                                            crate::server::filesystem::archive::create::Create7zOptions {
                                                compression_level: state
                                                    .config.load()
                                                    .system
                                                    .backups
                                                    .compression_level,
                                                threads: state.config.load().api.file_compression_threads,
                                            },
                                        )
                                        .await
                                    }
                                }?;

                                Ok(())
                            }
                        },
                    )
                    .await;

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileCompress,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "directory": raw_root,
                        "name": name,
                        "files": files,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });

                if *foreground {
                    match task.await {
                        Ok(Some(Ok(()))) => {}
                        Ok(None) => {
                            return Err("archive compression aborted by another source".into());
                        }
                        Ok(Some(Err(err))) => {
                            tracing::error!(
                                server = %server.uuid,
                                root = %root.display(),
                                "failed to compress files: {:#?}",
                                err,
                            );

                            return Err(format!("failed to compress files: {err}").into());
                        }
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                root = %root.display(),
                                "failed to compress files: {:#?}",
                                err,
                            );

                            return Err("failed to compress files".into());
                        }
                    }
                }
            }
            ScheduleAction::DecompressFile {
                foreground,
                root,
                file,
                ..
            } => {
                let root = match execution_context.resolve_parameter(root) {
                    Some(root) => root,
                    None => {
                        return Err("unable to resolve parameter `root` into a string.".into());
                    }
                };
                let file = match execution_context.resolve_parameter(file) {
                    Some(file) => file,
                    None => {
                        return Err("unable to resolve parameter `file` into a string.".into());
                    }
                };

                let root = match server.filesystem.async_canonicalize(root).await {
                    Ok(path) => path,
                    Err(_) => {
                        return Err("root not found".into());
                    }
                };

                let metadata = server.filesystem.async_metadata(&root).await;
                if !metadata.map(|m| m.is_dir()).unwrap_or(true) {
                    return Err("root is not a directory".into());
                }

                let source = root.join(file);

                if server.filesystem.is_ignored(
                    &source,
                    server
                        .filesystem
                        .async_metadata(&source)
                        .await
                        .is_ok_and(|m| m.is_dir()),
                ) {
                    return Err("file not found".into());
                }

                let archive = match crate::server::filesystem::archive::Archive::open(
                    server.clone(),
                    source.clone(),
                )
                .await
                {
                    Ok(archive) => archive,
                    Err(err) => {
                        return Err(format!("failed to open archive: {err}").into());
                    }
                };

                let thread = tokio::spawn(archive.extract(root.clone(), None, None));

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FileDecompress,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "directory": root.display().to_string(),
                        "file": file,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });

                if *foreground && let Ok(Err(err)) = thread.await {
                    tracing::error!(path = %source.display(), "failed to decompress file: {:?}", err);

                    return Err("failed to decompress file".into());
                }
            }
            ScheduleAction::UpdateStartupVariable {
                env_variable,
                value,
                ..
            } => {
                let env_variable = match execution_context.resolve_parameter(env_variable) {
                    Some(env_variable) => env_variable,
                    None => {
                        return Err(
                            "unable to resolve parameter `env_variable` into a string.".into()
                        );
                    }
                };
                let value = match execution_context.resolve_parameter(value) {
                    Some(value) => value,
                    None => {
                        return Err("unable to resolve parameter `value` into a string.".into());
                    }
                };

                match state
                    .config
                    .client
                    .set_server_startup_variable(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        env_variable,
                        value,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to set server startup variable: {:#?}",
                            err
                        );

                        return Err("failed to set server startup variable".into());
                    }
                };
            }
            ScheduleAction::UpdateStartupCommand { command, .. } => {
                let command = match execution_context.resolve_parameter(command) {
                    Some(command) => command,
                    None => {
                        return Err("unable to resolve parameter `command` into a string.".into());
                    }
                };

                match state
                    .config
                    .client
                    .set_server_startup_command(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        command,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to set server startup command: {:#?}",
                            err
                        );

                        return Err("failed to set server startup command".into());
                    }
                };
            }
            ScheduleAction::UpdateStartupDockerImage { image, .. } => {
                let image = match execution_context.resolve_parameter(image) {
                    Some(image) => image,
                    None => {
                        return Err("unable to resolve parameter `image` into a string.".into());
                    }
                };

                match state
                    .config
                    .client
                    .set_server_startup_docker_image(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        image,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to set server startup docker image: {:#?}",
                            err
                        );

                        return Err("failed to set server startup docker image".into());
                    }
                };
            }
        }

        Ok(())
    }
}
