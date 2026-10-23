use super::{Outcome, SandboxLayer, SandboxState};
use anyhow::Context;
use rustix::thread::{CapabilitySet, CapabilitySets, set_capabilities, set_no_new_privs};

pub struct PrivilegeLock;

impl SandboxLayer for PrivilegeLock {
    fn name(&self) -> &'static str {
        "privilege lock"
    }

    fn apply(&self, _state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        set_capabilities(
            None,
            CapabilitySets {
                effective: CapabilitySet::empty(),
                permitted: CapabilitySet::empty(),
                inheritable: CapabilitySet::empty(),
            },
        )
        .context("failed to clear capabilities")?;
        set_no_new_privs(true).context("failed to set no_new_privs")?;

        Ok(Outcome::Applied)
    }
}
