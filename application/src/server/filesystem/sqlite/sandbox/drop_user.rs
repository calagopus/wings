use super::{Outcome, SandboxLayer, SandboxState};
use anyhow::{Context, ensure};
use rustix::{
    process::{Gid, Uid, getegid, geteuid},
    thread::{set_thread_groups, set_thread_res_gid, set_thread_res_uid},
};

pub struct DropUser;

impl SandboxLayer for DropUser {
    fn name(&self) -> &'static str {
        "server user"
    }

    fn apply(&self, state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        if state.user_namespace {
            return Ok(Outcome::Skipped(
                "the process is already mapped into a private user namespace".to_string(),
            ));
        }
        if !geteuid().is_root() {
            return Ok(Outcome::Skipped("not running as root".to_string()));
        }

        enter_server_user(state)?;

        Ok(Outcome::Applied)
    }
}

pub(super) fn enter_server_user(state: &SandboxState) -> Result<(), anyhow::Error> {
    ensure!(
        state.user.uid != 0 && state.user.gid != 0,
        "refusing to run queries as root"
    );
    let uid = Uid::from_raw_unchecked(state.user.uid);
    let gid = Gid::from_raw_unchecked(state.user.gid);

    set_thread_groups(&[]).context("failed to clear supplementary groups")?;
    set_thread_res_gid(gid, gid, gid).context("failed to switch to the server group")?;
    set_thread_res_uid(uid, uid, uid).context("failed to switch to the server user")?;
    ensure!(
        geteuid() == uid && getegid() == gid,
        "the server user did not take effect"
    );

    Ok(())
}
