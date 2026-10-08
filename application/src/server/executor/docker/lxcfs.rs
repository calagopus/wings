use anyhow::Context;
use std::path::Path;

const FILES: &[&str] = &[
    "proc/cpuinfo",
    "proc/diskstats",
    "proc/meminfo",
    "proc/stat",
    "proc/swaps",
    "proc/uptime",
    "sys/devices/system/cpu",
];

pub fn mounts(directory: &Path, probe: bool) -> Result<Vec<bollard::models::Mount>, anyhow::Error> {
    let files: Vec<&str> = if probe {
        let stat = tokio::task::block_in_place(|| rustix::fs::statfs(directory))
            .with_context(|| format!("failed to statfs {}", directory.display()))?;
        if stat.f_type != 0x6573_5546 {
            return Err(anyhow::anyhow!(
                "{} is not a fuse mount, is lxcfs running?",
                directory.display()
            ));
        }

        tokio::task::block_in_place(|| {
            FILES
                .iter()
                .copied()
                .filter(|file| directory.join(file).exists())
                .collect()
        })
    } else {
        FILES.to_vec()
    };

    if files.is_empty() {
        return Err(anyhow::anyhow!(
            "{} does not contain any lxcfs files",
            directory.display()
        ));
    }

    Ok(files
        .into_iter()
        .map(|file| bollard::models::Mount {
            typ: Some(bollard::plugin::MountType::BIND),
            target: Some(format!("/{file}")),
            source: Some(directory.join(file).to_string_lossy().into_owned()),
            read_only: Some(true),
            ..Default::default()
        })
        .collect())
}

pub fn is_mounted(mounts: &[bollard::models::MountPoint]) -> bool {
    mounts
        .iter()
        .any(|mount| mount.destination.as_deref() == Some("/proc/meminfo"))
}

pub fn is_stale(pid: i64) -> bool {
    tokio::task::block_in_place(|| {
        std::fs::metadata(format!("/proc/{pid}/root/proc/meminfo"))
            .is_err_and(|err| err.raw_os_error() == Some(rustix::io::Errno::NOTCONN.raw_os_error()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("creating runtime failed")
    }

    // mounts
    #[test]
    fn unprobed_mounts_bind_every_virtualized_file_read_only() {
        let directory = Path::new("/var/lib/lxcfs");
        let mounts = mounts(directory, false).expect("unprobed mounts should not fail");

        let mut targets: Vec<&str> = mounts
            .iter()
            .map(|mount| mount.target.as_deref().expect("mount should have a target"))
            .collect();
        targets.sort_unstable();
        assert_eq!(
            targets,
            [
                "/proc/cpuinfo",
                "/proc/diskstats",
                "/proc/meminfo",
                "/proc/stat",
                "/proc/swaps",
                "/proc/uptime",
                "/sys/devices/system/cpu",
            ]
        );

        for mount in &mounts {
            let target = mount.target.as_deref().expect("mount should have a target");
            let expected_source = directory.join(target.trim_start_matches('/'));
            assert_eq!(mount.typ, Some(bollard::plugin::MountType::BIND));
            assert_eq!(mount.read_only, Some(true), "{target} must be read-only");
            assert_eq!(
                mount.source.as_deref().map(Path::new),
                Some(expected_source.as_path())
            );
        }
    }

    #[test]
    fn probing_rejects_a_plain_directory_shaped_like_lxcfs() {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let stat = rustix::fs::statfs(temp.path()).expect("statfs on temp dir failed");
        assert_ne!(
            stat.f_type as u64, FUSE_SUPER_MAGIC,
            "temp dir must not be on FUSE"
        );

        for file in ["proc/meminfo", "proc/cpuinfo", "proc/stat", "proc/uptime"] {
            let path = temp.path().join(file);
            std::fs::create_dir_all(path.parent().expect("file should have a parent"))
                .expect("failed to create fixture dir");
            std::fs::write(&path, "fake").expect("failed to write fixture");
        }
        std::fs::create_dir_all(temp.path().join("sys/devices/system/cpu"))
            .expect("failed to create fixture dir");

        let result = runtime().block_on(async { mounts(temp.path(), true) });
        assert!(result.is_err());
    }

    #[test]
    fn probing_rejects_a_missing_directory() {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let missing = temp.path().join("missing");

        let result = runtime().block_on(async { mounts(&missing, true) });
        assert!(result.is_err());
    }

    // is_stale
    #[test]
    fn live_and_missing_pids_are_not_stale() {
        let runtime = runtime();
        assert!(!runtime.block_on(async { is_stale(i64::from(std::process::id())) }));
        assert!(!runtime.block_on(async { is_stale(i64::from(i32::MAX)) }));
    }
}
