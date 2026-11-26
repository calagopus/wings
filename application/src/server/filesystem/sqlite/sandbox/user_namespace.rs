use super::{Outcome, SandboxLayer, SandboxState};
use anyhow::Context;
use rustix::thread::{UnshareFlags, unshare_unsafe};

pub struct UserNamespace;

impl SandboxLayer for UserNamespace {
    fn name(&self) -> &'static str {
        "user namespace"
    }

    fn apply(&self, state: &mut SandboxState) -> Result<Outcome, anyhow::Error> {
        if state.confined {
            return Ok(Outcome::Skipped("already confined by chroot".to_string()));
        }

        if rustix::process::geteuid().is_root() {
            super::drop_user::enter_server_user(state)?;
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
                .context("failed to restore dumpability")?;
        }
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        // SAFETY: the helper is single-threaded and holds no resources tied to the namespace
        // it leaves.
        if let Err(err) = unsafe { unshare_unsafe(UnshareFlags::NEWUSER) } {
            return Ok(Outcome::Skipped(format!(
                "user namespaces are not available: {err}"
            )));
        }
        state.user_namespace = true;

        let mapped = std::fs::write("/proc/self/setgroups", "deny")
            .and_then(|()| std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")))
            .and_then(|()| std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")));
        if let Err(err) = mapped {
            return Ok(Outcome::Skipped(format!(
                "the user namespace grants no capabilities: {err}"
            )));
        }

        rustix::process::chroot(".")
            .context("failed to chroot into the database directory inside the user namespace")?;
        rustix::process::chdir("/").context("failed to enter the new root")?;
        state.confined = true;

        Ok(Outcome::Applied)
    }
}
