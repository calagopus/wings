//! The docker seccomp profile Wings applies, expressed for liblxc.

use crate::server::configuration::seccomp::{Action, Seccomp};

pub(super) fn profile(removed: &[compact_str::CompactString], capabilities: &[&str]) -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "powerpc64" => "ppc64le",
        other => other,
    };

    Seccomp::default()
        .remove_names(removed, Action::Allow)
        .to_lxc(capabilities, arch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_an_allowlist_honouring_capabilities_and_removals() {
        let profile = profile(&["ptrace".into()], &["CAP_CHOWN"]);
        let lines: Vec<&str> = profile.lines().collect();
        assert_eq!(
            lines.get(..3),
            Some(&["2", "allowlist errno 38", "[all]"][..])
        );
        assert!(lines.contains(&"read allow"));
        assert!(!lines.contains(&"ptrace allow"));
        // Gated behind a capability the container does not have.
        assert!(!lines.contains(&"bpf allow"));
        assert!(lines.contains(&"bpf errno 1"));
        // Netlink audit sockets stay denied without CAP_AUDIT_WRITE.
        assert!(
            lines.contains(&"socket errno 22 [0,16,SCMP_CMP_EQ] [2,9,SCMP_CMP_EQ]"),
            "{profile}"
        );
    }
}
