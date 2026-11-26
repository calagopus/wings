use super::{Outcome, SandboxLayer, SandboxState};
use anyhow::{Context, ensure};
use landlock::{
    ABI, Access, AccessFs, LandlockStatus, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

const ABI_VERSION: ABI = ABI::V5;

pub struct Landlock;

impl SandboxLayer for Landlock {
    fn name(&self) -> &'static str {
        "landlock"
    }

    fn apply(&self, state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        let access = AccessFs::from_all(ABI_VERSION);
        let directory = PathFd::new(".").context("failed to open the database directory")?;
        let status = Ruleset::default()
            .handle_access(access)?
            .create()?
            .add_rule(PathBeneath::new(directory, access))?
            .restrict_self()?;

        match status.landlock {
            LandlockStatus::NotEnabled => Ok(Outcome::Skipped(
                "landlock is not in the kernel's lsm list".to_string(),
            )),
            LandlockStatus::NotImplemented => Ok(Outcome::Skipped(
                "the kernel was built without landlock".to_string(),
            )),
            LandlockStatus::Available { .. } => {
                ensure!(
                    !matches!(status.ruleset, RulesetStatus::NotEnforced),
                    "landlock accepted the ruleset without enforcing it"
                );
                state.confined = true;

                Ok(Outcome::Applied)
            }
        }
    }
}
