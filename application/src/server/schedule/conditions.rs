use super::actions::{ScheduleDynamicParameter, ScheduleVariable};
use serde::{Deserialize, Serialize};
use std::pin::Pin;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleConditionComparator {
    SmallerThan,
    SmallerThanOrEquals,
    Equal,
    GreaterThan,
    GreaterThanOrEquals,
}

impl ScheduleConditionComparator {
    #[inline]
    pub fn compare_f64(self, lhs: f64, rhs: f64) -> bool {
        match self {
            ScheduleConditionComparator::SmallerThan => lhs < rhs,
            ScheduleConditionComparator::SmallerThanOrEquals => lhs <= rhs,
            ScheduleConditionComparator::Equal => lhs == rhs,
            ScheduleConditionComparator::GreaterThan => lhs > rhs,
            ScheduleConditionComparator::GreaterThanOrEquals => lhs >= rhs,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ScheduleCondition {
    None,
    And {
        conditions: Vec<ScheduleCondition>,
    },
    Or {
        conditions: Vec<ScheduleCondition>,
    },
    Not {
        condition: Box<ScheduleCondition>,
    },
    ServerState {
        state: crate::server::state::ServerState,
    },
    Uptime {
        comparator: ScheduleConditionComparator,
        value: u64,
    },
    ResourceUsage {
        metric: super::ScheduleResourceMetric,
        comparator: ScheduleConditionComparator,
        value: f64,
        #[serde(default)]
        percentage: bool,
    },
    FileExists {
        file: compact_str::CompactString,
    },
    VariableExists {
        variable: ScheduleVariable,
    },
    VariableEquals {
        variable: ScheduleVariable,
        equals: ScheduleDynamicParameter,
    },
    VariableContains {
        variable: ScheduleVariable,
        contains: ScheduleDynamicParameter,
    },
    VariableStartsWith {
        variable: ScheduleVariable,
        starts_with: ScheduleDynamicParameter,
    },
    VariableEndsWith {
        variable: ScheduleVariable,
        ends_with: ScheduleDynamicParameter,
    },
}

impl ScheduleCondition {
    pub fn evaluate<'a>(
        &'a self,
        server: &'a crate::server::Server,
        execution_context: &'a super::ScheduleExecutionContext,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self {
                ScheduleCondition::None => true,
                ScheduleCondition::And { conditions } => {
                    for condition in conditions {
                        if !condition.evaluate(server, execution_context).await {
                            return false;
                        }
                    }

                    true
                }
                ScheduleCondition::Or { conditions } => {
                    for condition in conditions {
                        if condition.evaluate(server, execution_context).await {
                            return true;
                        }
                    }

                    false
                }
                ScheduleCondition::Not { condition } => {
                    !condition.evaluate(server, execution_context).await
                }
                ScheduleCondition::ServerState { state: cond_state } => {
                    server.state.get_state() == *cond_state
                }
                ScheduleCondition::Uptime { comparator, value } => {
                    let resource_usage = server.resource_usage();

                    comparator.compare_f64(resource_usage.uptime as f64, *value as f64)
                }
                ScheduleCondition::ResourceUsage {
                    metric,
                    comparator,
                    value,
                    percentage,
                } => metric
                    .current_value(server, &server.resource_usage(), *percentage)
                    .await
                    .is_some_and(|current| comparator.compare_f64(current, *value)),
                ScheduleCondition::FileExists { file } => {
                    server.filesystem.async_symlink_metadata(file).await.is_ok()
                }
                ScheduleCondition::VariableExists { variable } => execution_context
                    .get_variable_by_str(&variable.variable)
                    .is_some(),
                ScheduleCondition::VariableEquals { variable, equals } => {
                    let Some(value) = execution_context.get_variable_by_str(&variable.variable)
                    else {
                        return false;
                    };

                    Some(value) == execution_context.resolve_parameter(equals)
                }
                ScheduleCondition::VariableContains { variable, contains } => {
                    let Some(value) = execution_context.get_variable_by_str(&variable.variable)
                    else {
                        return false;
                    };
                    let Some(contains) = execution_context.resolve_parameter(contains) else {
                        return false;
                    };

                    value.contains(&**contains)
                }
                ScheduleCondition::VariableStartsWith {
                    variable,
                    starts_with,
                } => {
                    let Some(value) = execution_context.get_variable_by_str(&variable.variable)
                    else {
                        return false;
                    };
                    let Some(starts_with) = execution_context.resolve_parameter(starts_with) else {
                        return false;
                    };

                    value.starts_with(&**starts_with)
                }
                ScheduleCondition::VariableEndsWith {
                    variable,
                    ends_with,
                } => {
                    let Some(value) = execution_context.get_variable_by_str(&variable.variable)
                    else {
                        return false;
                    };
                    let Some(ends_with) = execution_context.resolve_parameter(ends_with) else {
                        return false;
                    };

                    value.ends_with(&**ends_with)
                }
            }
        })
    }
}
