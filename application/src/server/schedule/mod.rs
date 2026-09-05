use crate::server::websocket::{WebsocketEvent, WebsocketMessage};
use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, str::FromStr, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use utoipa::ToSchema;

pub mod actions;
pub mod conditions;
pub mod http;
pub mod manager;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleResourceMetric {
    Cpu,
    Memory,
    Disk,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ScheduleTrigger {
    Cron {
        schedule: Box<croner::Cron>,
    },
    PowerAction {
        action: crate::models::ServerPowerAction,
    },
    ServerState {
        state: crate::server::state::ServerState,
    },
    BackupStatus {
        status: crate::models::ServerBackupStatus,
    },
    DatabaseBackupStatus {
        status: crate::models::ServerBackupStatus,
    },
    ScheduleCompletion {
        schedule: uuid::Uuid,
        successful: bool,
    },
    ResourceUsage {
        metric: ScheduleResourceMetric,
        comparator: conditions::ScheduleConditionComparator,
        value: f64,
        #[serde(default)]
        for_seconds: u64,
    },
    ConsoleLine {
        contains: compact_str::CompactString,
        #[serde(default)]
        case_insensitive: bool,
        output_into: Option<actions::ScheduleVariable>,
    },
    Crash,
}

impl PartialEq for ScheduleTrigger {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ScheduleTrigger::Cron { schedule: s1 }, ScheduleTrigger::Cron { schedule: s2 }) => {
                s1 == s2
            }
            (
                ScheduleTrigger::PowerAction { action: a1 },
                ScheduleTrigger::PowerAction { action: a2 },
            ) => a1 == a2,
            (
                ScheduleTrigger::ServerState { state: s1 },
                ScheduleTrigger::ServerState { state: s2 },
            ) => s1 == s2,
            (
                ScheduleTrigger::BackupStatus { status: s1 },
                ScheduleTrigger::BackupStatus { status: s2 },
            ) => s1 == s2,
            (
                ScheduleTrigger::DatabaseBackupStatus { status: s1 },
                ScheduleTrigger::DatabaseBackupStatus { status: s2 },
            ) => s1 == s2,
            (
                ScheduleTrigger::ScheduleCompletion {
                    schedule: s1,
                    successful: su1,
                },
                ScheduleTrigger::ScheduleCompletion {
                    schedule: s2,
                    successful: su2,
                },
            ) => s1 == s2 && su1 == su2,
            (
                ScheduleTrigger::ResourceUsage {
                    metric: m1,
                    comparator: c1,
                    value: v1,
                    for_seconds: f1,
                },
                ScheduleTrigger::ResourceUsage {
                    metric: m2,
                    comparator: c2,
                    value: v2,
                    for_seconds: f2,
                },
            ) => m1 == m2 && c1 == c2 && v1 == v2 && f1 == f2,
            (
                ScheduleTrigger::ConsoleLine {
                    contains: c1,
                    case_insensitive: ci1,
                    output_into: o1,
                },
                ScheduleTrigger::ConsoleLine {
                    contains: c2,
                    case_insensitive: ci2,
                    output_into: o2,
                },
            ) => c1 == c2 && ci1 == ci2 && o1 == o2,
            (ScheduleTrigger::Crash, ScheduleTrigger::Crash) => true,
            _ => false,
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct ApiScheduleCompletionStatus {
    pub uuid: uuid::Uuid,
    pub successful: bool,
    pub errors: HashMap<uuid::Uuid, Cow<'static, str>>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(ToSchema, Serialize)]
pub struct ScheduleStatus {
    pub running: bool,
    pub errors: HashMap<uuid::Uuid, Cow<'static, str>>,
    pub step: Option<uuid::Uuid>,
}

pub struct ScheduleExecutionContext {
    schedule_uuid: uuid::Uuid,
    variables: HashMap<compact_str::CompactString, compact_str::CompactString>,
}

impl ScheduleExecutionContext {
    pub fn new(schedule_uuid: uuid::Uuid) -> Self {
        Self {
            schedule_uuid,
            variables: HashMap::new(),
        }
    }

    pub fn resolve_parameter<'a>(
        &'a self,
        parameter: &'a actions::ScheduleDynamicParameter,
    ) -> Option<&'a compact_str::CompactString> {
        match parameter {
            actions::ScheduleDynamicParameter::Raw(value) => Some(value),
            actions::ScheduleDynamicParameter::Variable(variable) => {
                self.variables.get(&variable.variable)
            }
        }
    }

    pub fn get_variable_by_str(&self, variable: &str) -> Option<&compact_str::CompactString> {
        self.variables.get(variable)
    }

    pub fn store_variable<'a>(
        &mut self,
        variable: impl Into<Cow<'a, actions::ScheduleVariable>>,
        value: compact_str::CompactString,
    ) -> Result<(), Cow<'static, str>> {
        let variable = variable.into();

        if value.len() > MAX_VARIABLE_SIZE {
            return Err(format!(
                "variable `{}` exceeds the maximum size of {} bytes.",
                variable.variable, MAX_VARIABLE_SIZE
            )
            .into());
        }

        if !self.variables.contains_key(&variable.variable) && self.variables.len() >= MAX_VARIABLES
        {
            return Err(
                format!("a schedule may not store more than {MAX_VARIABLES} variables.").into(),
            );
        }

        self.variables.insert(variable.into_owned().variable, value);

        Ok(())
    }
}

struct ConditionFrame {
    parent_active: bool,
    active: bool,
    branch_taken: bool,
}

pub const MAX_IF_DEPTH: usize = 8;
pub const MAX_VARIABLES: usize = 64;
pub const MAX_VARIABLE_SIZE: usize = 16 * 1024;

fn validate_action_structure(
    actions: &[super::configuration::ScheduleAction],
) -> Result<(), (uuid::Uuid, Cow<'static, str>)> {
    let mut stack: Vec<(uuid::Uuid, bool)> = Vec::new();

    for action in actions {
        match &action.action {
            actions::ScheduleAction::If { .. } => {
                if stack.len() >= MAX_IF_DEPTH {
                    return Err((action.uuid, "maximum `if` nesting depth exceeded".into()));
                }

                stack.push((action.uuid, false));
            }
            actions::ScheduleAction::ElseIf { .. } => match stack.last() {
                None => {
                    return Err((action.uuid, "`else_if` without a matching `if`".into()));
                }
                Some((_, true)) => {
                    return Err((
                        action.uuid,
                        "`else_if` after `else` in the same block".into(),
                    ));
                }
                Some((_, false)) => {}
            },
            actions::ScheduleAction::Else => match stack.last_mut() {
                None => {
                    return Err((action.uuid, "`else` without a matching `if`".into()));
                }
                Some((_, else_seen)) => {
                    if *else_seen {
                        return Err((action.uuid, "multiple `else` in the same block".into()));
                    }

                    *else_seen = true;
                }
            },
            actions::ScheduleAction::EndIf if stack.pop().is_none() => {
                return Err((action.uuid, "`end_if` without a matching `if`".into()));
            }
            _ => {}
        }
    }

    if let Some((uuid, _)) = stack.pop() {
        return Err((uuid, "`if` block is never closed with `end_if`".into()));
    }

    Ok(())
}

pub struct Schedule {
    pub uuid: uuid::Uuid,
    pub triggers: Vec<ScheduleTrigger>,
    pub condition: Arc<RwLock<conditions::ScheduleCondition>>,
    pub raw_actions: Arc<RwLock<Arc<Vec<super::configuration::ScheduleAction>>>>,
    pub status: Arc<RwLock<ScheduleStatus>>,
    pub completion_status: Arc<Mutex<Option<ApiScheduleCompletionStatus>>>,

    trigger_tasks: Vec<tokio::task::JoinHandle<()>>,

    next_execution_context: Arc<Mutex<Option<ScheduleExecutionContext>>>,
    executor_task: tokio::task::JoinHandle<()>,
    executor_notifier: Arc<tokio::sync::Notify>,
    executor_skip_notifier: Arc<tokio::sync::Notify>,
}

impl Schedule {
    pub fn new(
        server: crate::server::Server,
        raw_schedule: super::configuration::Schedule,
    ) -> Self {
        let executor_notifier = Arc::new(tokio::sync::Notify::new());
        let executor_skip_notifier = Arc::new(tokio::sync::Notify::new());

        let condition = Arc::new(RwLock::new(raw_schedule.condition));
        let raw_actions = Arc::new(RwLock::new(Arc::new(raw_schedule.actions)));
        let status = Arc::new(RwLock::new(ScheduleStatus {
            running: false,
            errors: HashMap::new(),
            step: None,
        }));
        let completion_status = Arc::new(Mutex::new(None));
        let next_execution_context = Arc::new(Mutex::new(None));

        let (triggers, trigger_tasks) = Self::create_trigger_tasks(
            raw_schedule.uuid,
            server.clone(),
            raw_schedule.triggers,
            Arc::clone(&next_execution_context),
            Arc::clone(&executor_notifier),
        );

        Self {
            uuid: raw_schedule.uuid,
            triggers,
            condition: Arc::clone(&condition),
            raw_actions: Arc::clone(&raw_actions),
            status: Arc::clone(&status),
            completion_status: Arc::clone(&completion_status),
            trigger_tasks,
            next_execution_context: Arc::clone(&next_execution_context),
            executor_task: Self::create_executor_task(
                server,
                raw_schedule.uuid,
                condition,
                raw_actions,
                next_execution_context,
                Arc::clone(&executor_notifier),
                Arc::clone(&executor_skip_notifier),
                status,
                completion_status,
            ),
            executor_notifier,
            executor_skip_notifier,
        }
    }

    #[inline]
    pub fn trigger(&self, skip_condition: bool) {
        if skip_condition {
            self.executor_skip_notifier.notify_one();
        } else {
            self.executor_notifier.notify_one();
        }
    }

    pub async fn update(&self, raw_schedule: &super::configuration::Schedule) {
        *self.condition.write().await = raw_schedule.condition.clone();
        *self.raw_actions.write().await = Arc::new(raw_schedule.actions.clone());
    }

    pub fn recreate_triggers(
        &mut self,
        server: crate::server::Server,
        triggers: Vec<ScheduleTrigger>,
    ) {
        tracing::debug!(schedule = %self.uuid, "recreating triggers");

        for task in self.trigger_tasks.drain(..) {
            task.abort();
        }

        let (triggers, tasks) = Self::create_trigger_tasks(
            self.uuid,
            server,
            triggers,
            Arc::clone(&self.next_execution_context),
            Arc::clone(&self.executor_notifier),
        );

        self.triggers = triggers;
        self.trigger_tasks = tasks;
    }

    pub async fn recreate_executor(&mut self, server: crate::server::Server) {
        tracing::debug!(server = %server.uuid, schedule = %self.uuid, "recreating executor task");

        self.executor_task.abort();
        self.executor_task = Self::create_executor_task(
            server,
            self.uuid,
            Arc::clone(&self.condition),
            Arc::clone(&self.raw_actions),
            Arc::clone(&self.next_execution_context),
            Arc::clone(&self.executor_notifier),
            Arc::clone(&self.executor_skip_notifier),
            Arc::clone(&self.status),
            Arc::clone(&self.completion_status),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn create_executor_task(
        server: crate::server::Server,
        uuid: uuid::Uuid,
        condition: Arc<RwLock<conditions::ScheduleCondition>>,
        raw_actions: Arc<RwLock<Arc<Vec<super::configuration::ScheduleAction>>>>,
        next_execution_context: Arc<Mutex<Option<ScheduleExecutionContext>>>,
        executor_notifier: Arc<tokio::sync::Notify>,
        executor_skip_notifier: Arc<tokio::sync::Notify>,
        status: Arc<RwLock<ScheduleStatus>>,
        completion_status: Arc<Mutex<Option<ApiScheduleCompletionStatus>>>,
    ) -> tokio::task::JoinHandle<()> {
        tracing::debug!(server = %server.uuid, schedule = %uuid, "creating executor task");

        tokio::task::spawn(async move {
            loop {
                let skip_condition = tokio::select! {
                    _ = executor_skip_notifier.notified() => true,
                    _ = executor_notifier.notified() => false,
                };

                let mut execution_context = match next_execution_context.lock().await.take() {
                    Some(context) => context,
                    None => ScheduleExecutionContext::new(uuid),
                };

                if !skip_condition
                    && !condition
                        .read()
                        .await
                        .evaluate(&server, &execution_context)
                        .await
                {
                    continue;
                }

                tracing::debug!(server = %server.uuid, schedule = %uuid, skip_condition, "schedule condition met, executing actions");

                let raw_actions_lock = raw_actions.read().await;
                let raw_actions = Arc::clone(&*raw_actions_lock);
                drop(raw_actions_lock);

                let mut errors = HashMap::new();
                let mut successful = true;

                server
                    .websocket
                    .send(
                        WebsocketMessage::builder(WebsocketEvent::ServerScheduleStarted)
                            .arg(uuid.to_compact_string())
                            .build(),
                    )
                    .ok();

                let send_step_status = |step: uuid::Uuid, skipped: bool| {
                    let mut builder =
                        WebsocketMessage::builder(WebsocketEvent::ServerScheduleStepStatus)
                            .arg(uuid.to_compact_string())
                            .arg(step.to_compact_string());
                    if skipped {
                        builder = builder.arg("skipped");
                    }

                    server.websocket.send(builder.build()).ok();
                };

                if let Err((action_uuid, err)) = validate_action_structure(&raw_actions) {
                    successful = false;
                    errors.insert(action_uuid, err.clone());
                    status.write().await.errors.insert(action_uuid, err.clone());

                    server
                        .websocket
                        .send(
                            WebsocketMessage::builder(WebsocketEvent::ServerScheduleStepError)
                                .arg(uuid.to_compact_string())
                                .arg(action_uuid.to_compact_string())
                                .arg(err.to_compact_string())
                                .build(),
                        )
                        .ok();
                } else {
                    let mut condition_stack: Vec<ConditionFrame> = Vec::new();

                    for raw_action in raw_actions.iter() {
                        let mut status_lock = status.write().await;
                        status_lock.running = true;
                        status_lock.step = Some(raw_action.uuid);
                        drop(status_lock);

                        match &raw_action.action {
                            actions::ScheduleAction::If { condition } => {
                                send_step_status(raw_action.uuid, false);

                                let parent_active =
                                    condition_stack.iter().all(|frame| frame.active);
                                let active = parent_active
                                    && condition.evaluate(&server, &execution_context).await;

                                condition_stack.push(ConditionFrame {
                                    parent_active,
                                    active,
                                    branch_taken: active,
                                });

                                continue;
                            }
                            actions::ScheduleAction::ElseIf { condition } => {
                                send_step_status(raw_action.uuid, false);

                                if let Some(frame) = condition_stack.last() {
                                    let active = frame.parent_active
                                        && !frame.branch_taken
                                        && condition.evaluate(&server, &execution_context).await;

                                    if let Some(frame) = condition_stack.last_mut() {
                                        frame.active = active;
                                        frame.branch_taken |= active;
                                    }
                                }

                                continue;
                            }
                            actions::ScheduleAction::Else => {
                                send_step_status(raw_action.uuid, false);

                                if let Some(frame) = condition_stack.last_mut() {
                                    frame.active = frame.parent_active && !frame.branch_taken;
                                    frame.branch_taken = true;
                                }

                                continue;
                            }
                            actions::ScheduleAction::EndIf => {
                                send_step_status(raw_action.uuid, false);
                                condition_stack.pop();

                                continue;
                            }
                            actions::ScheduleAction::Exit {
                                successful: exit_successful,
                            } => {
                                if !condition_stack.iter().all(|frame| frame.active) {
                                    send_step_status(raw_action.uuid, true);
                                    continue;
                                }

                                send_step_status(raw_action.uuid, false);
                                successful = *exit_successful;

                                break;
                            }
                            _ => {}
                        }

                        if !condition_stack.iter().all(|frame| frame.active) {
                            send_step_status(raw_action.uuid, true);
                            continue;
                        }

                        send_step_status(raw_action.uuid, false);

                        match raw_action
                            .action
                            .execute(&server.app_state, &server, &mut execution_context)
                            .await
                        {
                            Ok(()) => {}
                            Err(err) => {
                                errors.insert(raw_action.uuid, err.clone());
                                status
                                    .write()
                                    .await
                                    .errors
                                    .insert(raw_action.uuid, err.clone());

                                server
                                    .websocket
                                    .send(
                                        WebsocketMessage::builder(
                                            WebsocketEvent::ServerScheduleStepError,
                                        )
                                        .arg(uuid.to_compact_string())
                                        .arg(raw_action.uuid.to_compact_string())
                                        .arg(err.to_compact_string())
                                        .build(),
                                    )
                                    .ok();

                                if !raw_action.action.ignore_failure() {
                                    successful = false;
                                    break;
                                }
                            }
                        }
                    }
                }

                tracing::debug!(server = %server.uuid, schedule = %uuid, errors = ?errors, "schedule actions executed");

                let mut status_lock = status.write().await;
                status_lock.running = false;
                status_lock.step = None;
                drop(status_lock);

                server
                    .websocket
                    .send(
                        WebsocketMessage::builder(WebsocketEvent::ServerScheduleCompleted)
                            .arg(uuid.to_compact_string())
                            .build(),
                    )
                    .ok();

                *completion_status.lock().await = Some(ApiScheduleCompletionStatus {
                    uuid,
                    successful,
                    errors,
                    timestamp: chrono::Utc::now(),
                });

                server
                    .schedules
                    .execute_schedule_completion_trigger(uuid, successful)
                    .await;
            }
        })
    }

    fn create_trigger_tasks(
        schedule_uuid: uuid::Uuid,
        server: crate::server::Server,
        raw_triggers: Vec<ScheduleTrigger>,
        nest_execution_context: Arc<Mutex<Option<ScheduleExecutionContext>>>,
        executor_notifier: Arc<tokio::sync::Notify>,
    ) -> (Vec<ScheduleTrigger>, Vec<tokio::task::JoinHandle<()>>) {
        let taskable_triggers_count = raw_triggers
            .iter()
            .filter(|t| {
                matches!(
                    t,
                    ScheduleTrigger::Cron { .. }
                        | ScheduleTrigger::ConsoleLine { .. }
                        | ScheduleTrigger::ResourceUsage { .. }
                )
            })
            .count();
        let mut triggers = Vec::new();
        triggers.reserve_exact(raw_triggers.len() - taskable_triggers_count);
        let mut tasks = Vec::new();
        tasks.reserve_exact(taskable_triggers_count);

        for trigger in raw_triggers {
            match trigger {
                ScheduleTrigger::Cron { schedule } => {
                    tasks.push(tokio::task::spawn({
                        let executor_notifier = Arc::clone(&executor_notifier);
                        let server = server.clone();

                        async move {
                            loop {
                                let timezone_lock = server.configuration.read().await;
                                let timezone = timezone_lock
                                    .container
                                    .timezone
                                    .as_deref()
                                    .map_or_else(
                                        || {
                                            chrono_tz::Tz::from_str(
                                                &server.app_state.config.load().system.timezone,
                                            )
                                        },
                                        chrono_tz::Tz::from_str,
                                    )
                                    .unwrap_or(chrono_tz::UTC);
                                drop(timezone_lock);

                                let now_datetime = chrono::Utc::now().with_timezone(&timezone);
                                let target_datetime = match schedule.iter_after(now_datetime).next()
                                {
                                    Some(dt) => dt,
                                    None => break,
                                };

                                let target_timestamp = target_datetime.timestamp();
                                let now_timestamp = now_datetime.timestamp();
                                let sleep_duration = target_timestamp - now_timestamp;
                                if sleep_duration <= 0 {
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    continue;
                                }

                                tokio::time::sleep(std::time::Duration::from_secs(
                                    sleep_duration as u64,
                                ))
                                .await;
                                executor_notifier.notify_one();
                            }
                        }
                    }));
                }
                ScheduleTrigger::ResourceUsage {
                    metric,
                    comparator,
                    value,
                    for_seconds,
                } => {
                    tasks.push(tokio::task::spawn({
                        let executor_notifier = Arc::clone(&executor_notifier);
                        let server = server.clone();

                        async move {
                            let for_duration = std::time::Duration::from_secs(for_seconds);
                            let mut met_since: Option<tokio::time::Instant> = None;
                            let mut fired = false;
                            let mut usage_rx = server.subscribe_resource_usage();

                            loop {
                                let usage = *usage_rx.borrow_and_update();

                                let evaluable = !matches!(
                                    metric,
                                    ScheduleResourceMetric::Cpu | ScheduleResourceMetric::Memory
                                ) || usage.state
                                    == crate::server::state::ServerState::Running;
                                let current = match metric {
                                    ScheduleResourceMetric::Cpu => usage.cpu_absolute,
                                    ScheduleResourceMetric::Memory => usage.memory_bytes as f64,
                                    ScheduleResourceMetric::Disk => usage.disk_bytes as f64,
                                };

                                if evaluable && comparator.compare_f64(current, value) {
                                    let since =
                                        *met_since.get_or_insert_with(tokio::time::Instant::now);

                                    if !fired && since.elapsed() >= for_duration {
                                        fired = true;
                                        executor_notifier.notify_one();
                                    }
                                } else {
                                    met_since = None;
                                    fired = false;
                                }

                                if !fired && let Some(since) = met_since {
                                    tokio::select! {
                                        changed = usage_rx.changed() => {
                                            if changed.is_err() {
                                                break;
                                            }
                                        }
                                        _ = tokio::time::sleep_until(since + for_duration) => {
                                            fired = true;
                                            executor_notifier.notify_one();
                                        }
                                    }
                                } else if usage_rx.changed().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }));
                }
                ScheduleTrigger::ConsoleLine {
                    contains,
                    case_insensitive,
                    output_into,
                } => {
                    tasks.push(tokio::task::spawn({
                        let nest_execution_context = Arc::clone(&nest_execution_context);
                        let executor_notifier = Arc::clone(&executor_notifier);
                        let server = server.clone();

                        async move {
                            loop {
                                let mut stdout = match server.get_stdout_lines().await {
                                    Some(stdout) => stdout,
                                    None => {
                                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                        continue;
                                    }
                                };

                                if case_insensitive {
                                    let contains = contains.to_lowercase();

                                    while let Ok(line) = stdout.recv().await {
                                        if line.to_lowercase().contains(&*contains) {
                                            if let Some(output_into) = &output_into {
                                                let mut execution_context =
                                                    ScheduleExecutionContext::new(schedule_uuid);
                                                if let Err(err) = execution_context
                                                    .store_variable(
                                                        output_into,
                                                        line.to_compact_string(),
                                                    )
                                                {
                                                    tracing::warn!(
                                                        server = %server.uuid,
                                                        "failed to store console line trigger variable: {}",
                                                        err
                                                    );
                                                }
                                                nest_execution_context
                                                    .lock()
                                                    .await
                                                    .replace(execution_context);
                                            }

                                            executor_notifier.notify_one();
                                        }
                                    }
                                } else {
                                    while let Ok(line) = stdout.recv().await {
                                        if line.contains(&*contains) {
                                            if let Some(output_into) = &output_into {
                                                let mut execution_context =
                                                    ScheduleExecutionContext::new(schedule_uuid);
                                                if let Err(err) = execution_context
                                                    .store_variable(
                                                        output_into,
                                                        line.to_compact_string(),
                                                    )
                                                {
                                                    tracing::warn!(
                                                        server = %server.uuid,
                                                        "failed to store console line trigger variable: {}",
                                                        err
                                                    );
                                                }
                                                nest_execution_context
                                                    .lock()
                                                    .await
                                                    .replace(execution_context);
                                            }

                                            executor_notifier.notify_one();
                                        }
                                    }
                                }
                            }
                        }
                    }));
                }
                _ => triggers.push(trigger),
            }
        }

        (triggers, tasks)
    }
}

impl Drop for Schedule {
    fn drop(&mut self) {
        for task in self.trigger_tasks.drain(..) {
            task.abort();
        }
        self.executor_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::configuration::ScheduleAction as RawAction;

    fn raw(action: actions::ScheduleAction) -> RawAction {
        RawAction {
            uuid: uuid::Uuid::new_v4(),
            action,
        }
    }

    fn r#if() -> RawAction {
        raw(actions::ScheduleAction::If {
            condition: conditions::ScheduleCondition::None,
        })
    }

    fn else_if() -> RawAction {
        raw(actions::ScheduleAction::ElseIf {
            condition: conditions::ScheduleCondition::None,
        })
    }

    fn r#else() -> RawAction {
        raw(actions::ScheduleAction::Else)
    }

    fn end_if() -> RawAction {
        raw(actions::ScheduleAction::EndIf)
    }

    fn sleep() -> RawAction {
        raw(actions::ScheduleAction::Sleep { duration: 1 })
    }

    #[test]
    fn empty_and_marker_free_lists_are_valid() {
        assert!(validate_action_structure(&[]).is_ok());
        assert!(validate_action_structure(&[sleep(), sleep()]).is_ok());
    }

    #[test]
    fn balanced_blocks_are_valid() {
        assert!(validate_action_structure(&[r#if(), sleep(), end_if()]).is_ok());
        assert!(
            validate_action_structure(&[
                r#if(),
                sleep(),
                else_if(),
                sleep(),
                r#else(),
                sleep(),
                end_if(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn nested_blocks_are_valid() {
        assert!(
            validate_action_structure(&[
                r#if(),
                r#if(),
                sleep(),
                r#else(),
                sleep(),
                end_if(),
                end_if(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn unclosed_if_reports_the_if_step() {
        let opening = r#if();
        let opening_uuid = opening.uuid;
        let err = validate_action_structure(&[opening, sleep()]).unwrap_err();
        assert_eq!(err.0, opening_uuid);
    }

    #[test]
    fn orphaned_markers_are_rejected() {
        assert!(validate_action_structure(&[end_if()]).is_err());
        assert!(validate_action_structure(&[r#else()]).is_err());
        assert!(validate_action_structure(&[else_if()]).is_err());
    }

    #[test]
    fn else_if_after_else_is_rejected() {
        assert!(validate_action_structure(&[r#if(), r#else(), else_if(), end_if()]).is_err());
    }

    #[test]
    fn multiple_else_in_one_block_is_rejected() {
        assert!(validate_action_structure(&[r#if(), r#else(), r#else(), end_if()]).is_err());
    }

    #[test]
    fn nesting_deeper_than_cap_is_rejected() {
        let mut steps = Vec::new();
        for _ in 0..=MAX_IF_DEPTH {
            steps.push(r#if());
        }
        for _ in 0..=MAX_IF_DEPTH {
            steps.push(end_if());
        }

        assert!(validate_action_structure(&steps).is_err());
    }
}
