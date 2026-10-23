use super::{Outcome, SandboxLayer, SandboxState};
use anyhow::Context;
use rustix::thread::{
    CapabilitySet, capabilities, capability_is_in_bounding_set, remove_capability_from_bounding_set,
};

pub struct BoundingSet;

impl SandboxLayer for BoundingSet {
    fn name(&self) -> &'static str {
        "capability bounding set"
    }

    fn apply(&self, _state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        let effective = capabilities(None)
            .context("failed to read capabilities")?
            .effective;
        if !effective.contains(CapabilitySet::SETPCAP) {
            return Ok(Outcome::Skipped("CAP_SETPCAP is not available".to_string()));
        }

        for capability in CapabilitySet::all().iter() {
            if capability_is_in_bounding_set(capability).unwrap_or(false) {
                remove_capability_from_bounding_set(capability)
                    .with_context(|| format!("failed to drop {capability:?}"))?;
            }
        }

        Ok(Outcome::Applied)
    }
}
