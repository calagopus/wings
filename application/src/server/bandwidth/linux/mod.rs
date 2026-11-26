mod netlink;

use super::limits::{BandwidthLimits, MAXIMUM_RATE, MINIMUM_RATE};
use anyhow::{Context, bail, ensure};
use netlink::{Link, Route, Shaping};
use rustix::{
    io::Errno,
    ioctl::{Ioctl, IoctlOutput, Opcode, opcode},
    thread::{CapabilitySet, LinkNameSpaceType},
};
use std::{
    ffi::OsString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    process::Stdio,
    time::Duration,
};

pub const HELPER_ARG: &str = "__wings-bandwidth";

const HANDLE: u16 = 0x5742;
const IFB: &str = super::IFB_DEVICE;
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_USERNS_DEPTH: usize = 32;

const NS_GET_USERNS: Opcode = opcode::none(0xb7, 0x1);
const NS_GET_PARENT: Opcode = opcode::none(0xb7, 0x2);

pub async fn ready(rootless: bool) -> Result<(), anyhow::Error> {
    if rootless {
        let limit = tokio::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .await
            .context("failed to read the user namespace limit")?;
        ensure!(
            limit.trim().parse::<u64>().unwrap_or(0) > 0,
            "rootless bandwidth limits require user namespaces"
        );

        return Ok(());
    }

    let status = tokio::fs::read_to_string("/proc/self/status").await?;
    let capabilities = CapabilitySet::from_bits_retain(super::capability_mask(&status, "CapEff")?);

    for (capability, name) in [
        (CapabilitySet::NET_ADMIN, "CAP_NET_ADMIN"),
        (CapabilitySet::SYS_ADMIN, "CAP_SYS_ADMIN"),
    ] {
        ensure!(
            capabilities.contains(capability),
            "bandwidth limits require {name}"
        );
    }

    Ok(())
}

pub async fn apply(pid: u32, limits: BandwidthLimits, rootless: bool) -> Result<(), anyhow::Error> {
    validate_rate(limits.upload)?;
    validate_rate(limits.download)?;

    if !limits.is_limited() && ready(rootless).await.is_err() {
        return Ok(());
    }

    let mut command = tokio::process::Command::new("/proc/self/exe");
    command
        .arg(HELPER_ARG)
        .arg(limits.upload.to_string())
        .arg(limits.download.to_string())
        .arg(rootless.to_string());

    if !run_in_namespace(pid, command).await? {
        ensure!(
            !limits.is_limited(),
            "bandwidth limits require a separate container network namespace"
        );
    }

    Ok(())
}

pub fn helper_main(args: &[OsString]) -> i32 {
    let result = (|| {
        let [upload, download, relayed] = args else {
            bail!("expected upload and download rates and the relay mode");
        };
        let limits = BandwidthLimits {
            upload: upload.to_str().context("invalid upload rate")?.parse()?,
            download: download
                .to_str()
                .context("invalid download rate")?
                .parse()?,
        };
        validate_rate(limits.upload)?;
        validate_rate(limits.download)?;

        apply_here(
            limits,
            relayed.to_str().context("invalid relay mode")?.parse()?,
        )
    })();

    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err:#}");
            1
        }
    }
}

fn validate_rate(rate: u64) -> Result<(), anyhow::Error> {
    ensure!(
        rate == 0 || (MINIMUM_RATE..=MAXIMUM_RATE).contains(&rate),
        "bandwidth rate {rate} bit/s is outside {MINIMUM_RATE}..={MAXIMUM_RATE}"
    );

    Ok(())
}

struct NamespaceIoctl<const OPCODE: Opcode>;

// SAFETY: NS_GET_USERNS and NS_GET_PARENT take no argument and return a new owned fd
// on success, so a null pointer and taking ownership of the return value are correct.
unsafe impl<const OPCODE: Opcode> Ioctl for NamespaceIoctl<OPCODE> {
    type Output = OwnedFd;

    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        OPCODE
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        std::ptr::null_mut()
    }

    unsafe fn output_from_ptr(
        out: IoctlOutput,
        _: *mut std::ffi::c_void,
    ) -> rustix::io::Result<OwnedFd> {
        // SAFETY: on success both ioctls return a freshly opened fd owned by the caller.
        Ok(unsafe { OwnedFd::from_raw_fd(out) })
    }
}

fn identity(fd: impl AsFd) -> Result<(u64, u64), anyhow::Error> {
    let stat = rustix::fs::fstat(fd)?;

    Ok((stat.st_dev, stat.st_ino))
}

fn user_namespaces(netns: &File) -> Result<Vec<OwnedFd>, anyhow::Error> {
    let own = std::fs::metadata("/proc/self/ns/user")?;
    let own = (own.dev(), own.ino());
    // SAFETY: netns is an open nsfs fd and NamespaceIoctl matches the ioctl's contract.
    let mut user = unsafe { rustix::ioctl::ioctl(netns, NamespaceIoctl::<NS_GET_USERNS>) }
        .context("failed to resolve the container's user namespace")?;
    let mut chain = Vec::new();

    while identity(&user)? != own {
        ensure!(
            chain.len() < MAX_USERNS_DEPTH,
            "container user namespace is nested too deeply"
        );
        // SAFETY: user is an open user namespace fd returned by a previous NS_GET_* ioctl.
        let parent = unsafe { rustix::ioctl::ioctl(&user, NamespaceIoctl::<NS_GET_PARENT>) }
            .context("container user namespace is not owned by wings' user namespace")?;
        chain.push(user);
        user = parent;
    }

    chain.reverse();

    Ok(chain)
}

fn enter(users: &[RawFd], netns: RawFd) -> Result<(), Errno> {
    for user in users {
        rustix::thread::move_into_link_name_space(
            // SAFETY: the parent keeps every fd in users open until the child has exec'd.
            unsafe { BorrowedFd::borrow_raw(*user) },
            Some(LinkNameSpaceType::User),
        )?;
    }

    if !users.is_empty() {
        let mut capabilities = rustix::thread::capabilities(None)?;
        capabilities.inheritable |= CapabilitySet::NET_ADMIN;
        rustix::thread::set_capabilities(None, capabilities)?;
        rustix::thread::configure_capability_in_ambient_set(CapabilitySet::NET_ADMIN, true)?;
    }

    rustix::thread::move_into_link_name_space(
        // SAFETY: the parent keeps netns open until the child has exec'd.
        unsafe { BorrowedFd::borrow_raw(netns) },
        Some(LinkNameSpaceType::Network),
    )
}

async fn run_in_namespace(
    pid: u32,
    mut command: tokio::process::Command,
) -> Result<bool, anyhow::Error> {
    let namespaces = tokio::task::spawn_blocking(move || {
        let netns = File::open(format!("/proc/{pid}/ns/net"))
            .with_context(|| format!("failed to open network namespace of pid {pid}"))?;
        if identity(&netns)? == identity(File::open("/proc/self/ns/net")?)? {
            return Ok(None);
        }

        let users = user_namespaces(&netns)?;

        Ok::<_, anyhow::Error>(Some((netns, users)))
    })
    .await??;
    let Some((netns, users)) = namespaces else {
        return Ok(false);
    };

    let raw_users: Vec<RawFd> = users.iter().map(AsRawFd::as_raw_fd).collect();
    let raw_netns = netns.as_raw_fd();
    // SAFETY: enter only issues raw setns/capset/prctl syscalls on borrowed fds and does not
    // allocate or take locks, so it is safe to run between fork and exec.
    unsafe {
        command.pre_exec(move || enter(&raw_users, raw_netns).map_err(Into::into));
    }

    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn bandwidth helper")?;
    drop((netns, users));

    let output = tokio::time::timeout(HELPER_TIMEOUT, child.wait_with_output())
        .await
        .context("bandwidth helper timed out")??;

    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    Ok(true)
}

fn apply_here(limits: BandwidthLimits, relay: bool) -> Result<(), anyhow::Error> {
    let mut route = Route::open()?;
    let links = route.links()?;
    let link = container_link(&links)?;

    match shaping(limits.upload, link.mtu)? {
        Some(shaping) => route.shape(link.index, HANDLE, shaping),
        None => route.unshape(link.index, HANDLE),
    }
    .with_context(|| format!("failed to shape upload on {}", link.name))?;

    let download = shaping(limits.download, link.mtu)?;
    let download = match relay {
        true => download.map(relayed),
        false => download,
    };

    match download {
        Some(shaping) => {
            route.add_ifb(IFB)?;
            let ifb = route
                .links()?
                .into_iter()
                .find(|candidate| candidate.name == IFB)
                .context("ifb device disappeared")?;
            route.set_up(ifb.index)?;
            route.shape(ifb.index, HANDLE, shaping)?;
            route.add_ingress(link.index)?;
            route.redirect(link.index, ifb.index)
        }
        None => {
            route.delete_ingress(link.index)?;
            match links.iter().find(|candidate| candidate.name == IFB) {
                Some(ifb) => route.delete_link(ifb.index),
                None => Ok(()),
            }
        }
    }
    .with_context(|| format!("failed to shape download on {}", link.name))
}

// Rootless engines relay download traffic through a userspace stack (pasta/slirp4netns) that
// acknowledges TCP on the remote's behalf, so drops here never slow the real sender down and
// only cost local retransmits. Deep buffers and a lax CoDel target queue the excess instead.
fn relayed(shaping: Shaping) -> Shaping {
    Shaping {
        memory: 32 * 1024 * 1024,
        packets: 10240,
        target: 1_000_000,
        interval: 10_000_000,
        ..shaping
    }
}

fn container_link(links: &[Link]) -> Result<Link, anyhow::Error> {
    let mut candidates = links
        .iter()
        .filter(|link| link.is_up() && !link.is_loopback() && link.name != IFB);

    match (candidates.next(), candidates.next()) {
        (Some(link), None) => Ok(link.clone()),
        (None, _) => bail!("container has no network interface"),
        (Some(_), Some(_)) => {
            bail!("bandwidth limits require exactly one container network interface")
        }
    }
}

fn shaping(bits: u64, mtu: u32) -> Result<Option<Shaping>, anyhow::Error> {
    if bits == 0 {
        return Ok(None);
    }

    let rate = bits / 8;
    let frame = u64::from(mtu) + 14;
    let quantum = if bits < 40_000_000 { 300 } else { frame };
    let burst = (rate / 200)
        .clamp(64 * 1024, 4 * 1024 * 1024)
        .max(2 * frame);
    let memory = (rate / 10).clamp(4 * 1024 * 1024, 32 * 1024 * 1024);
    let packets = (memory / frame).clamp(1024, 10240);
    let frame_time = frame * 8 * 1_000_000 / bits;
    let target = (frame_time * 3 / 2).clamp(50_000, 5_000_000);

    Ok(Some(Shaping {
        rate,
        burst: u32::try_from(burst)?,
        memory: u32::try_from(memory)?,
        packets: u32::try_from(packets)?,
        quantum: u32::try_from(quantum)?,
        flows: 4096,
        target: u32::try_from(target)?,
        interval: u32::try_from(target * 10)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use netlink_packet_route::link::LinkFlags;

    const HELPER_ENV: &str = "WINGS_BANDWIDTH_TEST_HELPER";
    const UP: LinkFlags = LinkFlags::Up;

    fn link(index: u32, name: &str, flags: LinkFlags) -> Link {
        Link {
            index,
            name: name.into(),
            mtu: 1500,
            flags,
        }
    }

    // container_link

    #[test]
    fn picks_single_up_interface() {
        let links = [
            link(1, "lo", UP | LinkFlags::Loopback),
            link(2, "tunl0", LinkFlags::empty()),
            link(3, IFB, UP),
            link(17, "eth0", UP),
        ];

        assert_eq!(container_link(&links).unwrap().name, "eth0");
    }

    #[test]
    fn rejects_multiple_or_missing_interfaces() {
        assert!(container_link(&[link(2, "eth0", UP), link(3, "eth1", UP)]).is_err());
        assert!(container_link(&[link(1, "lo", UP | LinkFlags::Loopback)]).is_err());
    }

    // shaping

    #[test]
    fn shaping_scales_with_rate() {
        assert_eq!(shaping(0, 1500).unwrap(), None);

        let slow = shaping(1_000_000, 1500).unwrap().unwrap();
        assert_eq!(slow.rate, 125_000);
        assert_eq!(slow.burst, 64 * 1024);
        assert_eq!(slow.memory, 4 * 1024 * 1024);
        assert_eq!(slow.quantum, 300);

        let fast = shaping(10_000_000_000, 1500).unwrap().unwrap();
        assert_eq!(fast.rate, 1_250_000_000);
        assert_eq!(fast.burst, 4 * 1024 * 1024);
        assert_eq!(fast.memory, 32 * 1024 * 1024);
        assert_eq!(fast.quantum, 1514);

        for shaping in [slow, fast] {
            assert!((1024..=10240).contains(&shaping.packets));
            assert_eq!(shaping.target, 50_000);
            assert_eq!(shaping.interval, 500_000);
        }

        let jumbo = shaping(5_000_000, 65520).unwrap().unwrap();
        let frame_time = 65534u32 * 8 * 1000 / 5000;
        assert!(jumbo.burst >= 2 * 65534);
        assert!(jumbo.target > frame_time);
        assert_eq!(jumbo.interval, jumbo.target * 10);
    }

    // relayed

    #[test]
    fn relayed_download_queues_instead_of_dropping() {
        let shaping = relayed(shaping(50_000_000, 1500).unwrap().unwrap());

        assert_eq!(shaping.rate, 6_250_000);
        assert_eq!(shaping.memory, 32 * 1024 * 1024);
        assert_eq!(shaping.packets, 10240);
        assert_eq!(shaping.target, 1_000_000);
        assert_eq!(shaping.interval, 10_000_000);
    }

    // validate_rate

    #[test]
    fn validates_rates() {
        assert!(validate_rate(0).is_ok());
        assert!(validate_rate(MINIMUM_RATE).is_ok());
        assert!(validate_rate(MINIMUM_RATE - 1).is_err());
        assert!(validate_rate(MAXIMUM_RATE + 1).is_err());
        assert!(shaping(MINIMUM_RATE, 1500).unwrap().is_some());
    }

    // run_in_namespace

    fn run(args: &[&str]) -> String {
        let output = std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8(output.stdout).unwrap()
    }

    fn in_namespace(pid: u32, args: &[&str]) -> String {
        let target = pid.to_string();
        let mut full = vec!["nsenter", "--target", &target, "--net"];
        if !rustix::process::geteuid().is_root() {
            full.extend(["--user", "--preserve-credentials"]);
        }
        full.push("--");
        full.extend_from_slice(args);

        run(&full)
    }

    fn qdiscs(pid: u32, iface: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(&in_namespace(
            pid,
            &["tc", "-j", "qdisc", "show", "dev", iface],
        ))
        .unwrap()
    }

    fn kinds(qdiscs: &[serde_json::Value]) -> Vec<String> {
        qdiscs
            .iter()
            .map(|qdisc| {
                format!(
                    "{} {}",
                    qdisc["kind"].as_str().unwrap(),
                    qdisc["handle"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn has_link(pid: u32, name: &str) -> bool {
        let links: Vec<serde_json::Value> =
            serde_json::from_str(&in_namespace(pid, &["ip", "-j", "link", "show"])).unwrap();

        links.iter().any(|link| link["ifname"] == name)
    }

    fn apply_through_helper(pid: u32, limits: BandwidthLimits, relay: bool) {
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "server::bandwidth::linux::tests::helper_entry",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(
                HELPER_ENV,
                format!("{} {} {relay}", limits.upload, limits.download),
            );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(runtime.block_on(run_in_namespace(pid, command)).unwrap());
    }

    #[test]
    #[ignore = "entry point for the namespace helper tests"]
    fn helper_entry() {
        let Ok(rates) = std::env::var(HELPER_ENV) else {
            return;
        };
        let args: Vec<OsString> = rates.split(' ').map(OsString::from).collect();

        assert_eq!(helper_main(&args), 0);
    }

    fn check_shaping(unshare: &[&str]) {
        let mut child = std::process::Command::new("unshare")
            .args(unshare)
            .args([
                "sh",
                "-c",
                "ip link add wbc0 type veth peer name wbh0 && ip link set wbc0 up && sleep 60",
            ])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let pid = child.id();
        let relay = unshare.contains(&"--user");

        apply_through_helper(
            pid,
            BandwidthLimits {
                upload: 8_000_000,
                download: 16_000_000,
            },
            relay,
        );
        apply_through_helper(
            pid,
            BandwidthLimits {
                upload: 80_000_000,
                download: 160_000_000,
            },
            relay,
        );

        let upload = qdiscs(pid, "wbc0");
        let download = qdiscs(pid, IFB);
        assert!(kinds(&upload).contains(&"tbf 5742:".to_string()));
        assert!(kinds(&upload).contains(&"fq_codel 5743:".to_string()));
        assert!(kinds(&upload).contains(&"ingress ffff:".to_string()));
        assert_eq!(kinds(&download), ["tbf 5742:", "fq_codel 5743:"]);
        assert_eq!(upload[0]["options"]["rate"], 10_000_000);
        assert_eq!(download[0]["options"]["rate"], 20_000_000);
        assert_eq!(download[1]["options"]["flows"], 4096);
        let relayed_memory = match relay {
            true => 32 * 1024 * 1024,
            false => 4 * 1024 * 1024,
        };
        assert_eq!(download[1]["options"]["memory_limit"], relayed_memory);
        assert_eq!(download[1]["options"]["quantum"], 1514);

        let filters = in_namespace(pid, &["tc", "filter", "show", "dev", "wbc0", "ingress"]);
        assert!(filters.contains("matchall"), "{filters}");
        assert!(
            filters.contains(&format!("Redirect to device {IFB}")),
            "{filters}"
        );

        apply_through_helper(pid, BandwidthLimits::default(), relay);
        apply_through_helper(pid, BandwidthLimits::default(), relay);

        let cleared = kinds(&qdiscs(pid, "wbc0"));
        assert!(
            cleared
                .iter()
                .all(|kind| !kind.starts_with("tbf") && !kind.starts_with("ingress")),
            "{cleared:?}"
        );
        assert!(!has_link(pid, IFB));

        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    #[ignore = "requires root"]
    fn shapes_namespace_owned_by_own_user_namespace() {
        assert!(rustix::process::geteuid().is_root());

        check_shaping(&["--net"]);
    }

    #[test]
    #[ignore = "requires root or unprivileged user namespaces"]
    fn shapes_root_mapped_namespace() {
        check_shaping(&["--user", "--map-root-user", "--net"]);
    }

    #[test]
    #[ignore = "requires root or unprivileged user namespaces"]
    fn shapes_identity_mapped_namespace() {
        let user = format!("--map-user={}", rustix::process::geteuid().as_raw());
        let group = format!("--map-group={}", rustix::process::getegid().as_raw());

        check_shaping(&["--user", &user, &group, "--keep-caps", "--net"]);
    }

    #[test]
    #[ignore = "requires root or unprivileged user namespaces"]
    fn shapes_nested_namespace() {
        check_shaping(&[
            "--user",
            "--map-root-user",
            "unshare",
            "--user",
            "--map-user=1000",
            "--map-group=1000",
            "--keep-caps",
            "--net",
        ]);
    }
}
