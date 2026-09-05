use crate::server::schedule::ScheduleTrigger;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub struct ScheduleManager {
    schedules: Arc<RwLock<Vec<super::Schedule>>>,
    schedule_task: tokio::task::JoinHandle<()>,
}

impl ScheduleManager {
    #[inline]
    pub fn new(config: Arc<crate::config::Config>) -> Self {
        let schedules = Arc::new(RwLock::new(Vec::new()));

        Self {
            schedules: Arc::clone(&schedules),
            schedule_task: tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                    let mut schedule_completions = Vec::new();
                    for schedule in schedules.read().await.iter() {
                        if let Some(completion_status) =
                            schedule.completion_status.lock().await.take()
                        {
                            schedule_completions.push(completion_status);
                        }
                    }

                    if !schedule_completions.is_empty()
                        && let Err(err) = config
                            .client
                            .send_schedule_status(schedule_completions)
                            .await
                    {
                        tracing::error!("failed to send schedule completion statuses: {:?}", err);
                    }
                }
            }),
        }
    }

    #[inline]
    pub async fn get_schedules(&self) -> RwLockReadGuard<'_, Vec<super::Schedule>> {
        self.schedules.read().await
    }

    #[inline]
    pub async fn get_mut_schedules(&self) -> RwLockWriteGuard<'_, Vec<super::Schedule>> {
        self.schedules.write().await
    }

    pub async fn update_schedules(&self, server: crate::server::Server) {
        let mut schedules = self.schedules.write().await;
        let raw_schedules = &server.configuration.read().await.schedules;

        schedules.retain(|s| {
            raw_schedules
                .iter()
                .any(|raw_schedule| raw_schedule.uuid == s.uuid)
        });

        for raw_schedule in raw_schedules.iter() {
            let schedule = schedules.iter_mut().find(|s| s.uuid == raw_schedule.uuid);

            if let Some(schedule) = schedule {
                if schedule.triggers != raw_schedule.triggers {
                    schedule.recreate_triggers(server.clone(), raw_schedule.triggers.clone());
                }

                schedule.update(raw_schedule).await;
            } else {
                let new_schedule = super::Schedule::new(server.clone(), raw_schedule.clone());
                schedules.push(new_schedule);
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn execute_server_state_trigger(&self, state: crate::server::state::ServerState) {
        tracing::debug!("executing server state schedule trigger");

        let schedules = self.schedules.read().await;

        for schedule in schedules.iter() {
            for trigger in schedule.triggers.iter() {
                if let ScheduleTrigger::ServerState {
                    state: trigger_state,
                } = trigger
                    && *trigger_state == state
                {
                    schedule.trigger(false);
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn execute_power_action_trigger(&self, action: crate::models::ServerPowerAction) {
        tracing::debug!("executing power action schedule trigger");

        let schedules = self.schedules.read().await;

        for schedule in schedules.iter() {
            for trigger in schedule.triggers.iter() {
                if let ScheduleTrigger::PowerAction {
                    action: trigger_action,
                } = trigger
                    && *trigger_action == action
                {
                    schedule.trigger(false);
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn execute_backup_status_trigger(&self, status: crate::models::ServerBackupStatus) {
        tracing::debug!("executing backup status schedule trigger");

        let schedules = self.schedules.read().await;

        for schedule in schedules.iter() {
            for trigger in schedule.triggers.iter() {
                if let ScheduleTrigger::BackupStatus {
                    status: trigger_status,
                } = trigger
                    && *trigger_status == status
                {
                    schedule.trigger(false);
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn execute_database_backup_status_trigger(
        &self,
        status: crate::models::ServerBackupStatus,
    ) {
        tracing::debug!("executing database backup status schedule trigger");

        let schedules = self.schedules.read().await;

        for schedule in schedules.iter() {
            for trigger in schedule.triggers.iter() {
                if let ScheduleTrigger::DatabaseBackupStatus {
                    status: trigger_status,
                } = trigger
                    && *trigger_status == status
                {
                    schedule.trigger(false);
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn execute_schedule_completion_trigger(
        &self,
        completed_schedule: uuid::Uuid,
        successful: bool,
    ) {
        tracing::debug!("executing schedule completion trigger");

        let schedules = self.schedules.read().await;

        for schedule in schedules.iter() {
            if schedule.uuid == completed_schedule {
                continue;
            }

            for trigger in schedule.triggers.iter() {
                if let ScheduleTrigger::ScheduleCompletion {
                    schedule: trigger_schedule,
                    successful: trigger_successful,
                } = trigger
                    && *trigger_schedule == completed_schedule
                    && *trigger_successful == successful
                {
                    schedule.trigger(false);
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn execute_crash_trigger(&self) {
        tracing::debug!("executing crash schedule trigger");

        let schedules = self.schedules.read().await;

        for schedule in schedules.iter() {
            for trigger in schedule.triggers.iter() {
                if let ScheduleTrigger::Crash = trigger {
                    schedule.trigger(false);
                }
            }
        }
    }
}

impl Drop for ScheduleManager {
    fn drop(&mut self) {
        self.schedule_task.abort();
    }
}
