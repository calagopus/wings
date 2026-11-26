use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

const RAW_BASE_SECCOMP: &str = include_str!("../../../seccomp.min.json");
static BASE_SECCOMP: LazyLock<Seccomp> = LazyLock::new(|| {
    serde_json::from_str(RAW_BASE_SECCOMP)
        .expect("unable to deserialize base seccomp... how did you achieve this?")
});

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    #[serde(rename = "SCMP_ACT_KILL")]
    Kill,
    #[serde(rename = "SCMP_ACT_KILL_PROCESS")]
    KillProcess,
    #[serde(rename = "SCMP_ACT_KILL_THREAD")]
    KillThread,
    #[serde(rename = "SCMP_ACT_TRAP")]
    Trap,
    #[serde(rename = "SCMP_ACT_ERRNO")]
    Errno,
    #[serde(rename = "SCMP_ACT_TRACE")]
    Trace,
    #[serde(rename = "SCMP_ACT_ALLOW")]
    Allow,
    #[serde(rename = "SCMP_ACT_LOG")]
    Log,
    #[serde(rename = "SCMP_ACT_NOTIFY")]
    Notify,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    #[serde(rename = "SCMP_CMP_NE")]
    NotEqual,
    #[serde(rename = "SCMP_CMP_LT")]
    LessThan,
    #[serde(rename = "SCMP_CMP_LE")]
    LessThanEqual,
    #[serde(rename = "SCMP_CMP_EQ")]
    Equal,
    #[serde(rename = "SCMP_CMP_GE")]
    GreaterThan,
    #[serde(rename = "SCMP_CMP_GT")]
    GreaterThanEqual,
    #[serde(rename = "SCMP_CMP_MASKED_EQ")]
    MaskedEqual,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Arg {
    index: u32,
    value: u64,
    value_two: u64,
    op: Operator,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Filter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    caps: Vec<compact_str::CompactString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    arches: Vec<compact_str::CompactString>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Arch {
    architecture: compact_str::CompactString,
    #[serde(default)]
    sub_architectures: Vec<compact_str::CompactString>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Syscall {
    #[serde(default, skip_serializing_if = "compact_str::CompactString::is_empty")]
    name: compact_str::CompactString,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    names: Vec<compact_str::CompactString>,
    action: Action,
    args: Option<Vec<Arg>>,
    comment: compact_str::CompactString,
    includes: Filter,
    excludes: Filter,
    #[serde(default)]
    errno_ret: u32,
    #[serde(default, skip_serializing_if = "compact_str::CompactString::is_empty")]
    errno: compact_str::CompactString,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Seccomp {
    default_action: Action,
    default_errno_ret: u32,
    default_errno: compact_str::CompactString,
    arch_map: Vec<Arch>,
    syscalls: Vec<Syscall>,
}

impl Default for Seccomp {
    fn default() -> Self {
        BASE_SECCOMP.clone()
    }
}

impl Seccomp {
    pub fn remove_names(
        &mut self,
        names: &[compact_str::CompactString],
        action: Action,
    ) -> &mut Self {
        for syscall in self.syscalls.iter_mut() {
            if syscall.action == action {
                syscall.names.retain(|n| !names.contains(n));
            }
        }

        self
    }

    /// Renders the profile in liblxc's version 2 format, for a container whose capability
    /// bounding set is `capabilities` on the architecture `arch` (docker naming, e.g. `amd64`).
    #[cfg(target_os = "linux")]
    pub fn to_lxc(&self, capabilities: &[&str], arch: &str) -> String {
        let has = |name: &compact_str::CompactString| capabilities.contains(&name.as_str());
        let mut result = format!("2\nallowlist errno {}\n[all]\n", self.default_errno_ret);

        for rule in &self.syscalls {
            let included = (rule.includes.caps.is_empty() || rule.includes.caps.iter().any(has))
                && (rule.includes.arches.is_empty()
                    || rule.includes.arches.iter().any(|a| a == arch));
            if !included
                || rule.excludes.caps.iter().any(has)
                || rule.excludes.arches.iter().any(|a| a == arch)
            {
                continue;
            }

            let action = match rule.action {
                Action::Allow => compact_str::CompactString::const_new("allow"),
                Action::Errno => compact_str::format_compact!("errno {}", rule.errno_ret),
                // The base profile only allows or denies with an error number.
                _ => continue,
            };
            let conditions: String = rule
                .args
                .iter()
                .flatten()
                .map(|arg| {
                    let op = match arg.op {
                        Operator::NotEqual => "SCMP_CMP_NE",
                        Operator::LessThan => "SCMP_CMP_LT",
                        Operator::LessThanEqual => "SCMP_CMP_LE",
                        Operator::Equal => "SCMP_CMP_EQ",
                        Operator::GreaterThan => "SCMP_CMP_GE",
                        Operator::GreaterThanEqual => "SCMP_CMP_GT",
                        Operator::MaskedEqual => "SCMP_CMP_MASKED_EQ",
                    };
                    match arg.op {
                        Operator::MaskedEqual => {
                            format!(" [{},{},{op},{}]", arg.index, arg.value, arg.value_two)
                        }
                        _ => format!(" [{},{},{op}]", arg.index, arg.value),
                    }
                })
                .collect();

            for name in &rule.names {
                result.push_str(name);
                result.push(' ');
                result.push_str(&action);
                result.push_str(&conditions);
                result.push('\n');
            }
        }

        result
    }

    pub fn to_string(&self) -> Result<String, serde_json::Error> {
        let mut string = Vec::new();
        string.reserve_exact(8 + RAW_BASE_SECCOMP.len());
        string.extend_from_slice(b"seccomp=");
        serde_json::to_writer(&mut string, &self)?;

        Ok(unsafe { String::from_utf8_unchecked(string) })
    }
}
