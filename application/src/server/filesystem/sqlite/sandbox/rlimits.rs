use super::{Outcome, SandboxLayer, SandboxState};
use crate::server::filesystem::sqlite::{QUERY_DEADLINE, QUERY_MEMORY_LIMIT};
use anyhow::Context;
use rustix::process::{Resource, Rlimit, setrlimit};

const DATA_LIMIT: u64 = 2 * QUERY_MEMORY_LIMIT;
const CPU_LIMIT_SECONDS: u64 = 2 * QUERY_DEADLINE.as_secs();
const OPEN_FILES: u64 = 32;

pub struct Rlimits;

impl SandboxLayer for Rlimits {
    fn name(&self) -> &'static str {
        "resource limits"
    }

    fn apply(&self, _state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        for (resource, limit) in [
            (Resource::Data, DATA_LIMIT),
            (Resource::Cpu, CPU_LIMIT_SECONDS),
            (Resource::Core, 0),
            (Resource::Nofile, OPEN_FILES),
        ] {
            setrlimit(
                resource,
                Rlimit {
                    current: Some(limit),
                    maximum: Some(limit),
                },
            )
            .with_context(|| format!("failed to set the {resource:?} limit"))?;
        }

        Ok(Outcome::Applied)
    }
}
