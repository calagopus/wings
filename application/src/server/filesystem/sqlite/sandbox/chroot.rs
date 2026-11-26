use super::{Outcome, SandboxLayer, SandboxState};
use anyhow::Context;
use rustix::thread::{CapabilitySet, capabilities};

pub struct Chroot;

impl SandboxLayer for Chroot {
    fn name(&self) -> &'static str {
        "chroot"
    }

    fn apply(&self, state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        let effective = capabilities(None)
            .context("failed to read capabilities")?
            .effective;
        if !effective.contains(CapabilitySet::SYS_CHROOT) {
            return Ok(Outcome::Skipped(
                "CAP_SYS_CHROOT is not available".to_string(),
            ));
        }

        rustix::process::chroot(".").context("failed to chroot into the database directory")?;
        rustix::process::chdir("/").context("failed to enter the new root")?;
        state.confined = true;

        Ok(Outcome::Applied)
    }
}
