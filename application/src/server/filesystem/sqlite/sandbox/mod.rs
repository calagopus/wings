mod bounding_set;
mod chroot;
mod drop_user;
mod landlock;
mod privilege_lock;
mod rlimits;
mod user_namespace;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct SandboxUser {
    pub uid: u32,
    pub gid: u32,
}

pub enum Outcome {
    Applied,
    Skipped(String),
}

pub struct SandboxState {
    pub user: SandboxUser,
    pub confined: bool,
    pub user_namespace: bool,
}

pub trait SandboxLayer {
    fn name(&self) -> &'static str;
    fn apply(&self, state: &mut SandboxState) -> Result<Outcome, anyhow::Error>;
}

const LAYERS: &[&dyn SandboxLayer] = &[
    &rlimits::Rlimits,
    &chroot::Chroot,
    &user_namespace::UserNamespace,
    &landlock::Landlock,
    &bounding_set::BoundingSet,
    &drop_user::DropUser,
    &privilege_lock::PrivilegeLock,
];

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct SandboxReport {
    pub applied: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

impl SandboxReport {
    pub fn confined(&self) -> bool {
        let confining: [&dyn SandboxLayer; 3] = [
            &chroot::Chroot,
            &user_namespace::UserNamespace,
            &landlock::Landlock,
        ];

        self.applied
            .iter()
            .any(|layer| confining.iter().any(|confining| confining.name() == layer))
    }
}

pub fn apply(user: SandboxUser) -> Result<SandboxReport, anyhow::Error> {
    let mut state = SandboxState {
        user,
        confined: false,
        user_namespace: false,
    };
    let mut report = SandboxReport::default();

    for layer in LAYERS {
        match layer
            .apply(&mut state)
            .with_context(|| format!("failed to apply the {} sandbox layer", layer.name()))?
        {
            Outcome::Applied => report.applied.push(layer.name().to_owned()),
            Outcome::Skipped(reason) => report.skipped.push((layer.name().to_owned(), reason)),
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::filesystem::sqlite::reexec_supported;
    use rustix::{
        process::{Resource, getegid, geteuid, getgid, getgroups, getrlimit, getuid},
        thread::{CapabilitySet, capabilities, capability_is_in_bounding_set},
    };
    use std::{path::Path, process::Command};

    const DIRECTORY_ENV: &str = "WINGS_SQLITE_SANDBOX_TEST_DIRECTORY";
    const USER_ENV: &str = "WINGS_SQLITE_SANDBOX_TEST_USER";
    const MARKER: &str = "sandbox-marker";
    const LAYERS: [&str; 7] = [
        "resource limits",
        "chroot",
        "user namespace",
        "landlock",
        "capability bounding set",
        "server user",
        "privilege lock",
    ];

    // securityfs is not mounted in containers, so the expectation is unknown there
    fn landlock_enabled() -> Option<bool> {
        std::fs::read_to_string("/sys/kernel/security/lsm")
            .ok()
            .map(|lsm| lsm.split(',').any(|name| name.trim() == "landlock"))
    }

    fn reason<'a>(report: &'a SandboxReport, layer: &str) -> Option<&'a str> {
        report
            .skipped
            .iter()
            .find(|(name, _)| name == layer)
            .map(|(_, reason)| reason.as_str())
    }

    fn check_applied(user: SandboxUser) {
        let root = geteuid().is_root();
        let effective = capabilities(None).unwrap().effective;
        let landlock = landlock_enabled();
        let outside = std::fs::canonicalize(".")
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let report = apply(user).unwrap();

        let mut seen: Vec<&str> = report
            .applied
            .iter()
            .map(String::as_str)
            .chain(report.skipped.iter().map(|(name, _)| name.as_str()))
            .collect();
        seen.sort_unstable();
        let mut expected = LAYERS.to_vec();
        expected.sort_unstable();
        assert_eq!(seen, expected, "{report:?}");
        for names in [
            report
                .applied
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            report
                .skipped
                .iter()
                .map(|(name, _)| name.as_str())
                .collect(),
        ] {
            let positions: Vec<usize> = names
                .iter()
                .map(|name| LAYERS.iter().position(|layer| layer == name).unwrap())
                .collect();
            assert!(positions.is_sorted(), "{report:?}");
        }
        for (_, reason) in &report.skipped {
            assert!(!reason.is_empty(), "{report:?}");
        }

        let applied = |layer: &str| report.applied.iter().any(|name| name == layer);
        assert!(applied("resource limits"));
        assert!(applied("privilege lock"));
        assert_eq!(
            report.confined(),
            applied("chroot") || applied("user namespace") || applied("landlock")
        );

        for (resource, limit) in [
            (Resource::Data, 256 * 1024 * 1024),
            (Resource::Cpu, 30),
            (Resource::Core, 0),
            (Resource::Nofile, 32),
        ] {
            let rlimit = getrlimit(resource);
            assert_eq!(rlimit.current, Some(limit), "{resource:?}");
            assert_eq!(rlimit.maximum, Some(limit), "{resource:?}");
        }

        let chrooted = applied("chroot") || applied("user namespace");
        assert_eq!(
            applied("chroot"),
            effective.contains(CapabilitySet::SYS_CHROOT)
        );
        if applied("chroot") {
            assert_eq!(
                reason(&report, "user namespace"),
                Some("already confined by chroot")
            );
        }
        if chrooted {
            assert_eq!(std::env::current_dir().unwrap(), Path::new("/"));
            assert!(Path::new("/").join(MARKER).exists());
        }
        if let Some(landlock) = landlock {
            assert_eq!(applied("landlock"), landlock);
        }
        if report.confined() {
            assert!(std::fs::read_dir(&outside).is_err());
            assert!(std::fs::read("/etc/passwd").is_err());
        }

        assert_eq!(
            applied("capability bounding set"),
            effective.contains(CapabilitySet::SETPCAP)
        );
        if applied("capability bounding set") {
            for (name, capability) in CapabilitySet::all().iter_names() {
                assert!(
                    !capability_is_in_bounding_set(capability).unwrap(),
                    "{name}"
                );
            }
        }

        if root && !applied("user namespace") {
            assert!(applied("server user"));
            assert_eq!(getuid().as_raw(), user.uid);
            assert_eq!(geteuid().as_raw(), user.uid);
            assert_eq!(getgid().as_raw(), user.gid);
            assert_eq!(getegid().as_raw(), user.gid);
            assert!(getgroups().unwrap().is_empty());
        }
        if !root {
            assert!(!applied("server user"));
        }
        if applied("user namespace") {
            assert_eq!(
                reason(&report, "server user"),
                Some("the process is already mapped into a private user namespace")
            );
        }

        let sets = capabilities(None).unwrap();
        assert!(sets.effective.is_empty());
        assert!(sets.permitted.is_empty());
        assert!(sets.inheritable.is_empty());
        assert!(rustix::thread::no_new_privs().unwrap());
        assert!(rustix::thread::set_thread_uid(rustix::process::Uid::ROOT).is_err());
    }

    fn check_refused(user: SandboxUser) {
        let error = apply(user).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("failed to apply the server user sandbox layer"),
            "{message}"
        );
        assert!(
            message.contains("refusing to run queries as root"),
            "{message}"
        );
    }

    #[test]
    #[ignore = "entry point for the sandbox tests"]
    fn apply_entry() {
        let (Ok(directory), Ok(user)) = (std::env::var(DIRECTORY_ENV), std::env::var(USER_ENV))
        else {
            return;
        };
        let (uid, gid) = user.split_once(':').unwrap();
        let user = SandboxUser {
            uid: uid.parse().unwrap(),
            gid: gid.parse().unwrap(),
        };
        std::env::set_current_dir(directory).unwrap();

        if user.uid == 0 || user.gid == 0 {
            check_refused(user);
        } else {
            check_applied(user);
        }
    }

    fn apply_in_child(directory: &Path, user: SandboxUser) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "server::filesystem::sqlite::sandbox::tests::apply_entry",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(DIRECTORY_ENV, directory)
            .env(USER_ENV, format!("{}:{}", user.uid, user.gid))
            .env("_RJEM_MALLOC_CONF", "background_thread:false")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    // apply

    #[test]
    fn applies_every_layer_the_host_allows() {
        if !reexec_supported() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MARKER), "").unwrap();
        let user = match geteuid().is_root() {
            true => SandboxUser {
                uid: 65534,
                gid: 65534,
            },
            false => SandboxUser {
                uid: getuid().as_raw(),
                gid: getgid().as_raw(),
            },
        };

        apply_in_child(dir.path(), user);
    }

    #[test]
    fn refuses_to_keep_root() {
        if !geteuid().is_root() || !reexec_supported() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();

        apply_in_child(dir.path(), SandboxUser { uid: 0, gid: 65534 });
        apply_in_child(dir.path(), SandboxUser { uid: 65534, gid: 0 });
    }
}
