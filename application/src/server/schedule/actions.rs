use crate::{
    routes::State,
    server::{
        activity::{Activity, ActivityEvent},
        filesystem::{
            RenameParents, archive::ArchiveFormat, cap::FileType, virtualfs::IsIgnoredFn,
        },
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

impl<'a> From<&'a ScheduleVariable> for Cow<'a, ScheduleVariable> {
    fn from(value: &'a ScheduleVariable) -> Self {
        Cow::Borrowed(value)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScheduleDynamicParameter {
    Raw(compact_str::CompactString),
    Variable(ScheduleVariable),
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
}

impl From<ScheduleHttpMethod> for reqwest::Method {
    fn from(value: ScheduleHttpMethod) -> Self {
        match value {
            ScheduleHttpMethod::Get => reqwest::Method::GET,
            ScheduleHttpMethod::Post => reqwest::Method::POST,
            ScheduleHttpMethod::Put => reqwest::Method::PUT,
            ScheduleHttpMethod::Patch => reqwest::Method::PATCH,
            ScheduleHttpMethod::Delete => reqwest::Method::DELETE,
            ScheduleHttpMethod::Head => reqwest::Method::HEAD,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ScheduleHttpHeader {
    pub name: compact_str::CompactString,
    pub value: ScheduleDynamicParameter,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum ScheduleBackupSelector {
    Latest {
        #[serde(default)]
        backup_group_uuid: Option<uuid::Uuid>,
    },
    Oldest {
        #[serde(default)]
        backup_group_uuid: Option<uuid::Uuid>,
    },
    Uuid {
        uuid: ScheduleDynamicParameter,
    },
    Name {
        name: ScheduleDynamicParameter,
        #[serde(default)]
        backup_group_uuid: Option<uuid::Uuid>,
        #[serde(default)]
        oldest: bool,
    },
}

#[derive(Default)]
pub struct ResolvedBackupSelector {
    pub backup_uuid: Option<uuid::Uuid>,
    pub backup_name: Option<compact_str::CompactString>,
    pub backup_group_uuid: Option<uuid::Uuid>,
    pub oldest: bool,
}

impl ScheduleBackupSelector {
    pub fn resolve(
        &self,
        execution_context: &super::ScheduleExecutionContext,
    ) -> Result<ResolvedBackupSelector, Cow<'static, str>> {
        match self {
            ScheduleBackupSelector::Latest { backup_group_uuid } => Ok(ResolvedBackupSelector {
                backup_group_uuid: *backup_group_uuid,
                ..Default::default()
            }),
            ScheduleBackupSelector::Oldest { backup_group_uuid } => Ok(ResolvedBackupSelector {
                backup_group_uuid: *backup_group_uuid,
                oldest: true,
                ..Default::default()
            }),
            ScheduleBackupSelector::Uuid { uuid } => {
                let uuid = match execution_context.resolve_parameter(uuid) {
                    Some(uuid) => uuid,
                    None => {
                        return Err("unable to resolve parameter `uuid` into a string.".into());
                    }
                };

                match uuid::Uuid::parse_str(uuid) {
                    Ok(uuid) => Ok(ResolvedBackupSelector {
                        backup_uuid: Some(uuid),
                        ..Default::default()
                    }),
                    Err(_) => Err("unable to parse parameter `uuid` into a uuid.".into()),
                }
            }
            ScheduleBackupSelector::Name {
                name,
                backup_group_uuid,
                oldest,
            } => match execution_context.resolve_parameter(name) {
                Some(name) => Ok(ResolvedBackupSelector {
                    backup_name: Some(name.to_compact_string()),
                    backup_group_uuid: *backup_group_uuid,
                    oldest: *oldest,
                    ..Default::default()
                }),
                None => Err("unable to resolve parameter `name` into a string.".into()),
            },
        }
    }
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
    If {
        condition: super::conditions::ScheduleCondition,
    },
    ElseIf {
        condition: super::conditions::ScheduleCondition,
    },
    Else,
    EndIf,
    Exit {
        successful: bool,
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
    WaitForState {
        ignore_failure: bool,

        state: crate::server::state::ServerState,
        timeout: u64,
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
        #[serde(default)]
        backup_group_uuid: Option<uuid::Uuid>,
        ignored_files: Vec<compact_str::CompactString>,

        #[serde(default)]
        output_into: Option<ScheduleVariable>,
    },
    RestoreBackup {
        ignore_failure: bool,
        truncate_directory: bool,
        #[serde(default)]
        restore_startup: bool,

        backup: ScheduleBackupSelector,
    },
    DeleteBackup {
        #[serde(default)]
        ignore_failure: bool,

        backup: ScheduleBackupSelector,
    },
    MoveBackup {
        #[serde(default)]
        ignore_failure: bool,

        backup: ScheduleBackupSelector,
        #[serde(default)]
        backup_group_uuid: Option<uuid::Uuid>,
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
        #[serde(default)]
        ignore_failure: bool,

        root: ScheduleDynamicParameter,
        files: Vec<compact_str::CompactString>,
    },
    RenameFiles {
        #[serde(default)]
        ignore_failure: bool,

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
    PullFile {
        ignore_failure: bool,
        foreground: bool,

        root: ScheduleDynamicParameter,
        url: ScheduleDynamicParameter,
        #[serde(default)]
        file_name: Option<ScheduleDynamicParameter>,
        #[serde(default)]
        use_header: bool,
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
    HttpRequest {
        ignore_failure: bool,

        method: ScheduleHttpMethod,
        url: reqwest::Url,
        #[serde(default)]
        headers: Vec<ScheduleHttpHeader>,
        #[serde(default)]
        body: Option<ScheduleDynamicParameter>,
        timeout: u64,
        #[serde(default)]
        ignore_error_status: bool,

        #[serde(default)]
        output_status_into: Option<ScheduleVariable>,
        #[serde(default)]
        output_body_into: Option<ScheduleVariable>,
    },
}

impl ScheduleAction {
    #[inline]
    pub fn ignore_failure(&self) -> bool {
        match self {
            ScheduleAction::Sleep { .. } => false,
            ScheduleAction::Ensure { .. } => false,
            ScheduleAction::If { .. } => false,
            ScheduleAction::ElseIf { .. } => false,
            ScheduleAction::Else => false,
            ScheduleAction::EndIf => false,
            ScheduleAction::Exit { .. } => false,
            ScheduleAction::Format { .. } => false,
            ScheduleAction::MatchRegex { .. } => false,
            ScheduleAction::WaitForConsoleLine { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::WaitForState { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::SendPower { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::SendCommand { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CreateBackup { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::RestoreBackup { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::DeleteBackup { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::MoveBackup { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CreateDirectory { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::WriteFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CopyFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::DeleteFiles { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::RenameFiles { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::CompressFiles { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::DecompressFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::PullFile { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::UpdateStartupVariable { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::UpdateStartupCommand { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::UpdateStartupDockerImage { ignore_failure, .. } => *ignore_failure,
            ScheduleAction::HttpRequest { ignore_failure, .. } => *ignore_failure,
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
            ScheduleAction::If { .. }
            | ScheduleAction::ElseIf { .. }
            | ScheduleAction::Else
            | ScheduleAction::EndIf
            | ScheduleAction::Exit { .. } => {}

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
                fn format_value(
                    format: &str,
                    execution_context: &super::ScheduleExecutionContext,
                ) -> Result<compact_str::CompactString, Cow<'static, str>> {
                    let mut result = compact_str::CompactString::default();
                    let mut chars = format.chars().peekable();

                    fn push_str_within_limit(
                        result: &mut compact_str::CompactString,
                        value: &str,
                    ) -> Result<(), Cow<'static, str>> {
                        if result.len() + value.len() > super::MAX_VARIABLE_SIZE {
                            return Err(format!(
                                "formatted value exceeds the maximum size of {} bytes.",
                                super::MAX_VARIABLE_SIZE
                            )
                            .into());
                        }

                        result.push_str(value);

                        Ok(())
                    }

                    fn push_within_limit(
                        result: &mut compact_str::CompactString,
                        value: char,
                    ) -> Result<(), Cow<'static, str>> {
                        let mut buffer = [0u8; 4];

                        push_str_within_limit(result, value.encode_utf8(&mut buffer))
                    }

                    while let Some(ch) = chars.next() {
                        if ch != '{' || chars.peek() != Some(&'{') {
                            push_within_limit(&mut result, ch)?;
                            continue;
                        }

                        chars.next();

                        let mut var_name = String::new();
                        let mut found_closing = false;

                        while let Some(inner_ch) = chars.next() {
                            if inner_ch == '}' && chars.peek() == Some(&'}') {
                                chars.next();
                                found_closing = true;
                                break;
                            }

                            var_name.push(inner_ch);
                        }

                        match execution_context
                            .get_variable_by_str(var_name.trim())
                            .filter(|_| found_closing)
                        {
                            Some(value) => push_str_within_limit(&mut result, value.as_str())?,
                            None => {
                                push_str_within_limit(&mut result, "{{")?;
                                push_str_within_limit(&mut result, &var_name)?;

                                if found_closing {
                                    push_str_within_limit(&mut result, "}}")?;
                                }
                            }
                        }
                    }

                    Ok(result)
                }

                let result = format_value(format, execution_context)?;

                execution_context.store_variable(output_into, result)?;
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

                    execution_context
                        .store_variable(output_into, group_match.as_str().to_compact_string())?;
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
                        execution_context.store_variable(output_into, line)?;
                    }

                    return Ok(());
                }

                return Err("timeout while waiting for matching console output.".into());
            }
            ScheduleAction::WaitForState {
                state: target_state,
                timeout,
                ..
            } => {
                if !server
                    .state
                    .wait_for_state(*target_state, std::time::Duration::from_millis(*timeout))
                    .await
                {
                    return Err(format!(
                        "timeout while waiting for server state `{}`.",
                        target_state.to_str()
                    )
                    .into());
                }
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
                backup_group_uuid,
                ignored_files,
                output_into,
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
                        *backup_group_uuid,
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

                        return Err(crate::remote::ApiError::message_or(
                            &err,
                            "failed to create backup",
                        ));
                    }
                };

                if state.backup_manager.fast_contains(server, uuid).await {
                    return Err("backup already exists".into());
                }

                if let Some(output_into) = output_into {
                    execution_context.store_variable(output_into, uuid.to_compact_string())?;
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
            ScheduleAction::RestoreBackup {
                truncate_directory,
                restore_startup,
                backup,
                ..
            } => {
                let selector = backup.resolve(execution_context)?;

                let (adapter, uuid, download_url) = match state
                    .config
                    .client
                    .restore_backup(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        selector.backup_uuid,
                        selector.backup_name.as_deref(),
                        selector.backup_group_uuid,
                        selector.oldest,
                        *truncate_directory,
                        *restore_startup,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to request backup restore: {:#?}",
                            err
                        );

                        return Err(crate::remote::ApiError::message_or(
                            &err,
                            "failed to request backup restore",
                        ));
                    }
                };

                let backup = match state
                    .backup_manager
                    .find_adapter(state, adapter, uuid)
                    .await
                {
                    Ok(backup) => backup,
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            backup = %uuid,
                            "failed to find backup: {:#?}",
                            err
                        );

                        None
                    }
                };

                let backup = match backup {
                    Some(backup) => backup,
                    None => {
                        if let Err(err) = state
                            .config
                            .client
                            .set_backup_restore_status(server.uuid, uuid, false)
                            .await
                        {
                            tracing::error!(
                                server = %server.uuid,
                                backup = %uuid,
                                "failed to reset backup restore status: {:#?}",
                                err
                            );
                        }

                        return Err("backup not found".into());
                    }
                };

                let truncate_directory = *truncate_directory;
                let thread = tokio::spawn({
                    let state = Arc::clone(state);
                    let server = server.clone();

                    async move {
                        if let Err(err) = state
                            .backup_manager
                            .restore(&backup, &server, truncate_directory, download_url)
                            .await
                        {
                            tracing::error!(
                                "failed to restore backup {} (adapter = {:?}) for {}: {}",
                                uuid,
                                adapter,
                                server.uuid,
                                err
                            );

                            return Err("failed to restore backup".into());
                        }

                        Ok::<_, Cow<'static, str>>(())
                    }
                });

                match thread.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            backup = %uuid,
                            "failed to restore backup: {:#?}",
                            err
                        );

                        return Err("failed to restore backup".into());
                    }
                }
            }
            ScheduleAction::DeleteBackup { backup, .. } => {
                let selector = backup.resolve(execution_context)?;

                if let Err(err) = state
                    .config
                    .client
                    .delete_backup(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        selector.backup_uuid,
                        selector.backup_name.as_deref(),
                        selector.backup_group_uuid,
                        selector.oldest,
                    )
                    .await
                {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to delete backup: {:#?}",
                        err
                    );

                    return Err(crate::remote::ApiError::message_or(
                        &err,
                        "failed to delete backup",
                    ));
                }
            }
            ScheduleAction::MoveBackup {
                backup,
                backup_group_uuid,
                ..
            } => {
                let selector = backup.resolve(execution_context)?;

                if let Err(err) = state
                    .config
                    .client
                    .move_backup(
                        server.uuid,
                        Some(execution_context.schedule_uuid),
                        selector.backup_uuid,
                        selector.backup_name.as_deref(),
                        selector.backup_group_uuid,
                        selector.oldest,
                        *backup_group_uuid,
                    )
                    .await
                {
                    tracing::error!(
                        server = %server.uuid,
                        "failed to move backup: {:#?}",
                        err
                    );

                    return Err(crate::remote::ApiError::message_or(
                        &err,
                        "failed to move backup",
                    ));
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

                if filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(&root, FileType::Dir)
                        .await
                {
                    return Err("path not found".into());
                }

                let destination = root.join(name);

                if filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(&destination, FileType::Dir)
                        .await
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

                if filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(parent, FileType::Dir)
                        .await
                {
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

                if filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(parent, FileType::Dir)
                        .await
                {
                    return Err("parent directory not found".into());
                }

                if let Err(err) = server.filesystem.async_create_dir_all(parent).await {
                    tracing::error!(path = %parent.display(), "failed to create parent directory: {:?}", err);

                    return Err("failed to create parent directory".into());
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

                if filesystem.is_primary_server_fs() && !*append && old_content_size > 0 {
                    server
                        .filesystem
                        .async_allocate_in_path(parent, -old_content_size, true)
                        .await;
                }

                if let Err(err) = file.write_all(content.as_bytes()).await {
                    if err.kind() == std::io::ErrorKind::StorageFull {
                        return Err("failed to allocate space".into());
                    }

                    tracing::error!(path = %path.display(), "failed to write file: {:?}", err);
                    return Err("failed to write file".into());
                }
                if let Err(err) = file.shutdown().await {
                    if err.kind() == std::io::ErrorKind::StorageFull {
                        return Err("failed to allocate space".into());
                    }

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
                        if !metadata.file_type.is_file() {
                            return Err("file not found".into());
                        } else {
                            metadata
                        }
                    }
                    Err(_) => {
                        return Err("file not found".into());
                    }
                };

                if filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(parent, FileType::Dir)
                        .await
                {
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

                if destination_filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(&destination_path, metadata.file_type)
                        .await
                {
                    return Err("destination file not found".into());
                }

                let bytes_processed = Arc::new(AtomicU64::new(0));
                let bytes_total = Arc::new(AtomicU64::new(metadata.size));
                let files_processed = Arc::new(AtomicU64::new(0));

                let (_, task) = server
                    .filesystem
                    .operations
                    .add_operation(
                        crate::server::filesystem::operations::FilesystemOperation::Copy {
                            path: path.clone(),
                            destination_path: file_name,
                            start_time: chrono::Utc::now(),
                            bytes_processed: bytes_processed.clone(),
                            bytes_total: bytes_total.clone(),
                            files_processed: files_processed.clone(),
                        },
                        {
                            let server = server.clone();
                            let destination_path = destination_path.clone();
                            let destination_filesystem = destination_filesystem.clone();

                            async move {
                                server
                                    .filesystem
                                    .copy_path(
                                        crate::server::filesystem::archive::create::ArchiveProgress::new(
                                            bytes_processed,
                                            files_processed,
                                        ),
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
            ScheduleAction::DeleteFiles { root, files, .. } => {
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

                    let result = if filesystem.is_primary_server_fs() {
                        server.filesystem.truncate_path(&source).await
                    } else if metadata.file_type.is_dir() {
                        filesystem.async_remove_dir_all(&source).await
                    } else {
                        filesystem.async_remove_file(&source).await
                    };

                    if let Err(err) = result {
                        tracing::error!(
                            server = %server.uuid,
                            path = %source.display(),
                            "failed to delete file: {:#?}",
                            err
                        );

                        return Err(format!("failed to delete `{file}`").into());
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
            ScheduleAction::RenameFiles { root, files, .. } => {
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
                                .async_is_ignored(&from, from_metadata.file_type)
                                .await
                                || server
                                    .filesystem
                                    .async_is_ignored(&to, from_metadata.file_type)
                                    .await))
                    {
                        continue;
                    }

                    let result = if filesystem.is_primary_server_fs() {
                        server
                            .filesystem
                            .rename_path(from, to, RenameParents::Create)
                            .await
                    } else {
                        filesystem
                            .async_rename(&from, &to, from_metadata.file_type)
                            .await
                    };

                    if let Err(err) = result {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to rename file: {:#?}",
                            err
                        );

                        return Err(
                            format!("failed to rename `{}` to `{}`", file.from, file.to).into()
                        );
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
                    && server
                        .filesystem
                        .async_is_ignored(&destination_path, FileType::File)
                        .await
                {
                    return Err("file not found".into());
                }

                let excluded_destination = destination_filesystem
                    .is_primary_server_fs()
                    .then(|| destination_path.clone());

                let bytes_processed = Arc::new(AtomicU64::new(0));
                let bytes_total = Arc::new(AtomicU64::new(0));
                let files_processed = Arc::new(AtomicU64::new(0));

                let (_, task) = server
                    .filesystem
                    .operations
                    .add_operation(
                        crate::server::filesystem::operations::FilesystemOperation::Compress {
                            path: PathBuf::from(&raw_root),
                            files: files.iter().map(PathBuf::from).collect(),
                            destination_path: PathBuf::from(&raw_root).join(file_name),
                            start_time: chrono::Utc::now(),
                            bytes_processed: bytes_processed.clone(),
                            bytes_total: bytes_total.clone(),
                            files_processed: files_processed.clone(),
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
                                let mut ignored: IsIgnoredFn =
                                    server.filesystem.get_ignored().into();
                                if let Some(excluded_destination) = excluded_destination {
                                    ignored = ignored.excluding(excluded_destination);
                                }

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

                                bytes_total.store(total_size, std::sync::atomic::Ordering::Relaxed);

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
                                            crate::server::filesystem::archive::create::ArchiveProgress::new(bytes_processed.clone(), files_processed.clone()),
                                            ignored,
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
                                            crate::server::filesystem::archive::create::ArchiveProgress::new(bytes_processed.clone(), files_processed.clone()),
                                            ignored,
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
                                            crate::server::filesystem::archive::create::ArchiveProgress::new(bytes_processed.clone(), files_processed.clone()),
                                            ignored,
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

                if server
                    .filesystem
                    .async_is_ignored(&source, server.filesystem.probe_file_type(&source).await)
                    .await
                {
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

                let (destination_root, destination_filesystem) =
                    server.filesystem.resolve_writable_fs(server, &root).await;

                let bytes_processed = Arc::new(AtomicU64::new(0));
                let bytes_total = Arc::new(AtomicU64::new(0));
                let files_processed = Arc::new(AtomicU64::new(0));

                let (_, task) = server
                    .filesystem
                    .operations
                    .add_operation(
                        crate::server::filesystem::operations::FilesystemOperation::Decompress {
                            path: source.clone(),
                            destination_path: root.clone(),
                            start_time: chrono::Utc::now(),
                            bytes_processed: bytes_processed.clone(),
                            bytes_total: bytes_total.clone(),
                            files_processed: files_processed.clone(),
                        },
                        async move {
                            archive
                                .extract(
                                    destination_root,
                                    destination_filesystem,
                                    crate::server::filesystem::archive::create::ArchiveProgress::new(
                                        bytes_processed,
                                        files_processed,
                                    ),
                                    Some(bytes_total),
                                )
                                .await
                        },
                    )
                    .await;

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

                if *foreground {
                    match task.await {
                        Ok(Some(Ok(()))) => {}
                        Ok(None) => {
                            return Err("archive decompression aborted by another source".into());
                        }
                        Ok(Some(Err(err))) => {
                            tracing::error!(
                                server = %server.uuid,
                                path = %source.display(),
                                "failed to decompress file: {:#?}",
                                err,
                            );

                            return Err(format!("failed to decompress file: {err}").into());
                        }
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                path = %source.display(),
                                "failed to decompress file: {:#?}",
                                err,
                            );

                            return Err("failed to decompress file".into());
                        }
                    }
                }
            }
            ScheduleAction::PullFile {
                foreground,
                root,
                url,
                file_name,
                use_header,
                ..
            } => {
                let raw_root = match execution_context.resolve_parameter(root) {
                    Some(root) => root,
                    None => {
                        return Err("unable to resolve parameter `root` into a string.".into());
                    }
                };
                let url = match execution_context.resolve_parameter(url) {
                    Some(url) => url.to_compact_string(),
                    None => {
                        return Err("unable to resolve parameter `url` into a string.".into());
                    }
                };
                let file_name = match file_name {
                    Some(file_name) => match execution_context.resolve_parameter(file_name) {
                        Some(file_name) => Some(file_name.to_compact_string()),
                        None => {
                            return Err(
                                "unable to resolve parameter `file_name` into a string.".into()
                            );
                        }
                    },
                    None => None,
                };

                if state.config.load().api.disable_remote_download {
                    return Err("remote pulling is disabled".into());
                }

                let (root, filesystem) = server
                    .filesystem
                    .resolve_writable_fs(server, raw_root)
                    .await;

                let metadata = filesystem.async_symlink_metadata(&root).await;
                if !metadata.map_or(true, |m| m.file_type.is_dir()) {
                    return Err("root is not a directory".into());
                }

                if filesystem.is_primary_server_fs()
                    && server
                        .filesystem
                        .async_is_ignored(&root, FileType::Dir)
                        .await
                {
                    return Err("root not found".into());
                }

                if let Err(err) = filesystem.async_create_dir_all(&root).await {
                    tracing::error!(path = %root.display(), "failed to create directory: {:?}", err);

                    return Err("failed to create directory".into());
                }

                let download = match crate::server::filesystem::pull::Download::new(
                    server.clone(),
                    filesystem,
                    &root,
                    file_name,
                    url.clone(),
                    *use_header,
                )
                .await
                {
                    Ok(download) => Arc::new(tokio::sync::RwLock::new(download)),
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to create pull: {:?}",
                            err,
                        );

                        return Err(format!("failed to create pull: {err}").into());
                    }
                };

                let mut pulls = server.filesystem.pulls.write().await;
                {
                    let operations = server.filesystem.operations.operations().await;
                    pulls.retain(|key, _| operations.contains_key(key));
                }

                if pulls.len() >= state.config.load().api.server_remote_download_limit {
                    return Err("too many concurrent pulls".into());
                }

                let (identifier, task) = match download.write().await.start().await {
                    Ok(started) => started,
                    Err(err) => {
                        tracing::error!(
                            server = %server.uuid,
                            "failed to start pull: {:?}",
                            err,
                        );

                        return Err(format!("failed to start pull: {err}").into());
                    }
                };
                pulls.insert(identifier, Arc::clone(&download));
                drop(pulls);

                server.activity.log_activity(Activity {
                    event: ActivityEvent::FilePull,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "directory": raw_root,
                        "url": url,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });

                if *foreground {
                    match task.await {
                        Ok(Some(Ok(()))) => {}
                        Ok(None) => {
                            return Err("pull aborted by another source".into());
                        }
                        Ok(Some(Err(err))) => {
                            tracing::error!(
                                server = %server.uuid,
                                root = %root.display(),
                                "failed to pull file: {:#?}",
                                err,
                            );

                            return Err(format!("failed to pull file: {err}").into());
                        }
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                root = %root.display(),
                                "failed to pull file: {:#?}",
                                err,
                            );

                            return Err("failed to pull file".into());
                        }
                    }
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

                        return Err(crate::remote::ApiError::message_or(
                            &err,
                            "failed to set server startup variable",
                        ));
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

                        return Err(crate::remote::ApiError::message_or(
                            &err,
                            "failed to set server startup command",
                        ));
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

                        return Err(crate::remote::ApiError::message_or(
                            &err,
                            "failed to set server startup docker image",
                        ));
                    }
                };
            }
            ScheduleAction::HttpRequest {
                method,
                url,
                headers,
                body,
                timeout,
                ignore_error_status,
                output_status_into,
                output_body_into,
                ..
            } => {
                let mut resolved_headers = Vec::with_capacity(headers.len());
                for header in headers {
                    match execution_context.resolve_parameter(&header.value) {
                        Some(value) => {
                            resolved_headers.push((header.name.clone(), value.clone()));
                        }
                        None => {
                            return Err(format!(
                                "unable to resolve parameter `{}` into a string.",
                                header.name
                            )
                            .into());
                        }
                    }
                }

                let resolved_body = match body {
                    Some(body) => match execution_context.resolve_parameter(body) {
                        Some(body) => Some(body.as_str()),
                        None => {
                            return Err("unable to resolve parameter `body` into a string.".into());
                        }
                    },
                    None => None,
                };

                let outcome = super::http::execute(
                    &state.config,
                    server.uuid,
                    super::http::HttpRequestOptions {
                        method: (*method).into(),
                        url,
                        headers: resolved_headers
                            .iter()
                            .map(|(name, value)| (name.as_str(), value.as_str()))
                            .collect(),
                        body: resolved_body,
                        timeout: std::time::Duration::from_millis(*timeout),
                        capture_body: output_body_into.is_some(),
                    },
                )
                .await?;

                server.activity.log_activity(Activity {
                    event: ActivityEvent::ScheduleHttpRequest,
                    user: None,
                    ip: None,
                    metadata: Some(serde_json::json!({
                        "method": method,
                        "host": outcome.host,
                        "status": outcome.status,
                    })),
                    schedule: Some(execution_context.schedule_uuid),
                    timestamp: chrono::Utc::now(),
                });

                if let Some(output_into) = output_status_into {
                    execution_context
                        .store_variable(output_into, outcome.status.to_compact_string())?;
                }

                if let Some(output_into) = output_body_into
                    && let Some(body) = outcome.body
                {
                    execution_context.store_variable(output_into, body)?;
                }

                if !ignore_error_status && !(200..400).contains(&outcome.status) {
                    return Err(
                        format!("the http request returned status {}.", outcome.status).into(),
                    );
                }
            }
        }

        Ok(())
    }
}
