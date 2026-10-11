# Proxmox VE LXC runtime

This branch is introducing Proxmox VE 9.2 LXC as an alternate Wings runtime while
keeping Docker as the preferred runtime. The implementation is deliberately placed behind
the existing `ServerExecutor` boundary so the fork can continue to merge upstream
Docker changes with minimal conflict.

Runtime selection now happens behind `ServerExecutor`. New installations start with
`runtime.backend: auto`: Wings selects a reachable Docker daemon when one is
present, otherwise selects a local Proxmox VE LXC runtime. It persists that
selection to `config.yml`, so installing Docker later does not change an already
configured LXC node. `runtime.backend: pve_lxc` remains available to force the
PVE executor without connecting to Docker. PVE boot validates that Wings is running on Linux, requires Proxmox VE 9.2
or newer, discovers the local node, rejects a configured remote cluster node, and
checks `/cluster/nextid` as a read-only capability probe. The local-node requirement
matches the runtime's use of local `pct`/LXC processes, host bind paths, host
firewalling, and cgroup/procfs telemetry.

The typed `pct`, `pvesh`, `pvesm`, and `pveversion` wrapper covers VMID allocation, cluster
LXC inventory, container status, start/shutdown/stop/destroy, and deterministic
LXC creation arguments. It also covers Proxmox's OCI registry pull endpoint,
storage-content discovery, asynchronous UPID polling, and deterministic OCI
template cache names. Inventory uses a stable marker tag plus server UUID to
recover Wings ownership after restart without another mapping database. Server
data is intended to stay on the Wings host and be bind-mounted at
`/home/container`, matching the path expected by existing eggs while allowing an
LXC root filesystem to be replaced during image updates.

Example configuration:

```yaml
runtime:
  backend: pve_lxc
  pve_lxc:
    template_storage: local
    # "auto" chooses the active rootdir-capable storage with the most free
    # space that can fit the requested rootfs. Set a storage name to pin it.
    rootfs_storage: auto
    # VLAN-aware bridge carrying the isolated game-server subnet.
    bridge: vmbr0
    # Applied to every LXC veth. Leave unset only when the bridge itself is
    # dedicated to the game-server network.
    vlan_tag: 30
    # Used for direct private allocations when edge forwarding is disabled.
    network_prefix: 24
    gateway: 10.0.30.1
    # Optional edge publishing. The panel allocation is the VPS public IP.
    # Wings matches it to a WireGuard peer endpoint and derives the control IP
    # from that peer's IPv4 /32 AllowedIPs entry.
    edge_wireguard_interface: wg-calagopus
    edge_ssh_identity_path: /etc/calagopus-wings/edge-forward
    edge_known_hosts_path: /etc/calagopus-wings/edge-known-hosts
    rootfs_size_gib: 8
    console_log_max_bytes: 5242880
    tag_prefix: calagopus
    managed_file_directory: /var/lib/lxc/calagopus-wings-managed
    unprivileged: true
    firewall:
      # Prefer PVE guest rules when the datacenter firewall is enabled, then
      # fall back to host-local nftables or iptables.
      backend: auto
      source_file_max_entries: 10000
      source_file_max_bytes: 1048576
```

With `rootfs_storage: auto`, Wings orders active, enabled Proxmox storages that
support `rootdir` by free capacity. It creates the LXC on the largest pool that
has at least the requested rootfs size available, then falls through to the
next pool if the preferred pool cannot fit it.

Panel setup and node statistics report the filesystem that contains
`system.data_directory`. Persistent game data is bind-mounted from that path, so
rootfs pools do not increase allocatable server storage. Rootfs selection and
panel game-data capacity are intentionally reported separately.

PVE's low-level unprivileged bind-mount setup must be able to traverse every host
directory component used as a raw file source. Wings therefore stages managed
`/etc/machine-id`, `/etc/hosts`, `/etc/passwd`, and `/etc/group` files under the
PVE-specific `managed_file_directory` with execute-only traversal for non-root
users, instead of weakening the existing 0700 `system.vmount_directory`. The
configured staging path must be absolute and its parent components must already
be traversable on the PVE host.

## Compatibility plan

The PVE runtime should preserve the contracts already exposed by `ProcessHandle`
and `ServerExecutor`:

1. Pull the configured OCI image into Proxmox template storage, then create one LXC
   per Calagopus server using a cluster-assigned VMID.
2. Tag each CT with a stable Calagopus marker and server UUID so Wings can recover
   ownership after restart without maintaining a second mapping database.
3. Map memory, swap and CPU limits to native LXC settings and mount the existing
   Wings server data directory at `/home/container`.
4. Preserve the OCI image process semantics and expose them through a Wings-owned
   process session. The server process uses the OCI image entrypoint as the LXC
   init process and Wings attaches to the PVE console for stdin/stdout.
5. Run install and script jobs through the same execution layer, with explicit
   resource/time limits.
6. Resolve PVE networking separately from Docker port publishing. The first target
   is bridged per-container networking; host DNAT can be added as a separate policy
   when allocations need host-port translation.

## Implemented boundary

- Runtime selection is isolated in `server::executor::create_runtime`; existing
  Docker behavior remains the default path.
- PVE boot validates the host/PVE version, resolves the target node, and verifies
  that a cluster VMID can be allocated.
- PVE cluster inventory filters to the selected node and recovers requested server
  UUIDs from Calagopus ownership tags.
- Automatic runtime probing is bounded to three seconds per candidate. Proxmox
  asynchronous tasks have a 15-minute deadline, and locked configuration helpers
  have a 30-second deadline, so a stuck Docker socket, OCI pull, or PVE config
  lock cannot hold Wings startup or an install forever.
- The LXC network is configured entirely in Wings' runtime config. `bridge`
  selects the PVE bridge and `vlan_tag` optionally tags each veth. Without edge
  publishing, `network_prefix` plus `gateway` define the isolated game subnet and
  a primary panel allocation becomes the static `net0` address. With edge
  publishing enabled, panel allocations are public VPS addresses and every main
  or helper CT uses DHCP on the hidden bridge instead.
- Edge publishing needs no per-VPS address in Wings configuration. Wings reads
  `wg show <interface> dump`, matches the panel allocation IP to a peer's current
  public endpoint, and uses that peer's IPv4 `/32` AllowedIPs address for its
  restricted SSH control connection. This continues to work when a hypervisor's
  home WAN address changes and lets the panel allocation alone choose among
  multiple edge VPS peers. Before applying a mapping, Wings clears the server UUID
  from every discovered edge peer so allocation changes cannot leave stale DNAT.
  Once the CT starts, Wings resolves its DHCP IPv4 address through the Proxmox
  interface API and sends that hidden address plus the panel ports to the selected
  edge controller. Cleanup clears the mapping on every edge peer. The SSH
  identity must be a root-owned regular file with mode `0600` or more restrictive.
  Each edge should restrict that key to the forwarding controller with an OpenSSH
  `command="...",restrict` authorized-key entry.
  For a running owned CT, Wings can query the Proxmox LXC interface API, ignore loopback
  and link-local-only addresses, collect all usable IPv4/IPv6 addresses, prefer
  IPv4 when resolving a single tunnel target, and resolve that target directly to
  the CT address and requested game port. The same primary address is exposed as
  the runtime's published address for this initial bridged model.
- Used-port discovery now follows that direct-bridge model. Wings inventories all
  running LXC containers on the selected local node, matches their actual bridged
  addresses against the queried allocation IPs, resolves each CT's init PID, and
  reads the CT network namespace through `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`.
  TCP reports listening sockets; UDP reports bound/connected reservations. Wildcard
  sockets apply to every queried usable address on that CT, IPv4-mapped IPv6
  bindings are normalized, Calagopus-owned server CTs are attributed to their
  server UUID, and other running LXCs are returned as used with no server owner.
  This detects direct-address collisions without adding Docker-style host-port
  publishing or DNAT. A container that disappears or becomes unreadable during
  inventory is logged and skipped instead of aborting allocation discovery for
  every other container.
- Server firewall policy is now wired into the PVE runtime without introducing a
  Docker-style host NAT layer. Wings creates a host-local nftables or iptables
  backend and expands configured allocation ports directly against every usable
  bridged CT address. PVE firewall specs intentionally contain no published host
  bindings, so rules target the CT destination IP/port rather than an emulated
  host port.
- Firewall state participates in the PVE lifecycle: the backend boots with the
  runtime, startup reconciliation rebuilds rules for known servers, setup and
  process attachment synchronize rules, configuration sync refreshes them, and
  server cleanup clears them. A running CT with configured firewall rules fails
  closed if Wings cannot resolve a usable bridged address or cannot use the
  selected host-local firewall backend. Starting such a CT stops it again when
  its rules cannot be applied.
- `runtime.pve_lxc.firewall.backend: auto` now prefers VM-scoped Proxmox
  firewall rules when the datacenter firewall is enabled and otherwise retains
  the host-local fallback. `proxmox` requires the datacenter firewall and fails
  clearly when it is disabled; Wings never changes the cluster-wide setting.
  Managed rules and source-file IP sets are written atomically under Proxmox's
  VM firewall lock, preserve unrelated administrator rules, appear in the PVE
  UI, and carry stable comments so reconciliation removes only Wings-owned
  entries. Managed LXC veths enable PVE firewall processing with `firewall=1`.
  Reconciliation is restricted to tagged containers on this Wings instance's
  configured local PVE node, so another cluster node's Wings instance cannot
  clear its rules. If `auto` falls back from Proxmox to a host-local backend,
  Wings first removes its own stale guest rules while preserving administrator
  rules. Wings owns guest firewall mode for its tagged containers and
  sets the guest input policy to `ACCEPT` because panel firewall policy
  allows unmatched traffic, while Proxmox otherwise defaults unmatched guest
  input to `DROP`. Only the ordered panel rules appear in the guest rule list.
  The panel's terminal unrestricted deny is emitted as a protocol-free,
  port-free PVE `DROP`, so "Deny Everything Else" covers all remaining guest
  input rather than only the server's allocated ports.
  When the configured bridge uses a host-local DHCP/DNS service, the PVE host
  firewall must allow those service ports from the game subnet. A masqueraded
  bridge used with the legacy PVE firewall also needs the standard `fwbr+`
  conntrack-zone rule so reply traffic returns through the same zone.
- OCI image references without a tag are normalized to `:latest`. Tagged
  references are pulled through `/nodes/{node}/storage/{storage}/oci-registry-pull`,
  and Wings waits for the returned Proxmox task to stop with `exitstatus: OK`.
- Live Proxmox VE 9.2.2 validation confirmed that `oci-registry-pull` can emit
  image-copy progress on stdout before the JSON task UPID even when
  `--output-format json` is requested. The CLI parser therefore accepts both a
  clean JSON response and the real PVE progress-plus-UPID response instead of
  assuming stdout contains only JSON.
- OCI templates use a deterministic `calagopus-oci-<sha256>.tar` cache key derived
  from the normalized image reference. The Docker image-fetch cache settings also
  control LXC template freshness. Once stale, a mutable tag is pulled again and
  Wings reads the resolved manifest digest from the OCI archive. Container image
  ownership tags use that content digest, so a changed upstream tag triggers the
  normal staged rootfs replacement flow.
- Digest (`@sha256:...`) references are rejected clearly for now because the PVE
  OCI pull API currently accepts tagged references.
- `pct create` arguments model memory, swap, cores, bridge selection, rootfs
  storage, and ownership tags. Bind mounts are deliberately configured in a
  second step: after the OCI CT rootfs is created, Wings reads PVE's resolved
  `lxc.init.uid`/`lxc.init.gid`, rejects a root/default image user, then configures
  `/home/container` with `pct set --mp0` and PVE 9.2's per-mount `idmap` option.
  That maps the image UID/GID directly to the UID/GID Wings already uses to own
  server files on the host without changing container-wide `lxc.idmap` or host
  `/etc/subuid` and `/etc/subgid` ranges. Because PVE's per-mount idmap only
  applies to unprivileged CTs, this runtime currently rejects
  `pve_lxc.unprivileged: false` at boot.
- Server mounts now use the same allowed-mount validation as the Docker runtime.
  PVE `mpN` entries support the main `/home/container` data mount, optional
  `/dev/hugepages`, configured directory mounts, and read-only mounts. Each source
  is canonicalized and maps the OCI process UID/GID to Wings' configured host
  UID/GID, preserving the host-side identity used by the Docker runtime instead of
  granting the process ownership based on the mounted directory's owner.
  Native `mpN` is directory-oriented, so Wings' generated per-file mounts use
  low-level `lxc.mount.entry` bind mounts with `ro,create=file`. Managed
  `machine-id`, `hosts`, `passwd`, and `group` files are copied from Wings' vmount
  directory into a PVE-specific staging directory with traversable parent paths,
  then mounted read-only into the CT. Changes to those source files are reflected
  when Wings next reconciles the runtime configuration.
  Runtime config reconciliation owns only those four target paths and preserves
  unrelated low-level LXC entries. Disabling one of the corresponding Wings
  features removes a stale managed entry on the next config reconciliation.
- KVM and configured character/block devices can be passed through with PVE 9.2
  `devN`. The host device's numeric UID/GID and mode are preserved on the CT device
  node. Configured devices must use the same source and target path.
  `devN` can express read-only or read/write access here; Docker's independent
  `m` (mknod) permission and write-only access are rejected instead of being
  silently approximated.
- Mount and device configuration is reconciled as one `pct set` operation. Desired
  `mpN`/`devN` entries are replaced in place and stale slots owned by the managed
  CT are deleted, so removing an egg mount/device cannot leave old passthrough
  configuration behind after Wings restarts and reuses the CT.
- The two-stage create helper is transactional for this preparation phase: if OCI
  user inspection or mount/device configuration fails, it destroys the newly
  created CT. A cleanup failure is returned alongside the original preparation
  failure so an orphaned CT cannot be hidden.
- Server configuration can now be translated into that preparation flow: Wings
  resolves the configured OCI image/cache, allocates a VMID, applies the runtime
  storage/bridge/tag settings, uses the existing server data path and host
  UID/GID, then performs the transactional create + mount sequence from
  `setup_server_process` before returning the usable PVE `ProcessHandle`.
- Preparation now reconciles ownership before allocating a VMID. Each new CT gets
  a deterministic OCI-image identity tag derived from the resolved manifest
  digest. A single existing CT with the same server and image tags is reused,
  its mutable resource limits are synchronized, and its OCI user is re-read from
  PVE. Duplicate permanent or staged CT claims fail explicitly.
- A stopped owned CT whose OCI image identity changed is replaced transactionally.
  Wings first resolves the target template and creates/configures a second CT with
  a server-specific staging tag, while the old CT and host-owned server data stay
  intact. Only after OCI-user discovery plus mount/device reconciliation succeeds
  does Wings destroy the old rootfs and promote the staged CT to the normal server
  ownership tag. If removing the old CT fails, the new staging CT is discarded
  when possible. If Wings exits or tag promotion fails after the old CT is gone,
  the staging tag is discoverable and the next setup resumes promotion instead of
  creating an untracked duplicate. Stale staging CTs from abandoned image changes
  are cleaned up only while stopped. A running old or staging CT is never killed
  implicitly by image reconciliation; it must be stopped before replacement.
  `/home/container` remains the same Wings-host directory throughout this flow, so
  replacement affects the OCI rootfs rather than persistent server data.
- PVE resource mapping uses `memory_limit + overhead_memory` directly as the CT RAM
  limit, maps panel swap as PVE's additional swap amount, and maps CPU percent to
  `cpulimit` CPU-time units (`100% = 1`, `250% = 2.5`). Unlimited memory, unlimited
  swap (`-1`), and CPU pinning via `build.threads` currently fail explicitly
  because they do not yet have exact PVE mappings in this runtime.
- The CLI resource update path uses `pct set` for memory, swap, and CPU time. It
  writes `cpulimit=0` when the panel CPU limit is disabled so an old limit cannot
  survive a configuration change. `cores` is updated when an explicit value is
  present.
- The CLI layer can spawn a Wings-owned `lxc-attach` session with piped standard
  I/O, a clean explicitly supplied environment, and an explicit UID/GID,
  including OCI images whose configured process user is root.
- Server setup now creates or reuses the owned CT, applies runtime environment
  variables and `lxc.signal.halt` under PVE's config lock, then exposes it through
  a PVE `ProcessHandle`. Environment keys supplied by Wings replace matching
  existing values while unrelated low-level entries are preserved. PVE serializes
  its high-level `env` property as `lxc.environment.runtime`, which reaches hooks
  but not CT init on the tested LXC 7 host. Wings therefore retains the PVE `env`
  metadata and also writes reconciled `lxc.environment` entries for the init
  process. Both PVE representations are normalized by variable name before the
  panel overlay is applied, making repeated synchronization idempotent.
- New CTs are created with `cmode=console`. The process handle attaches with
  `pct console` through a PTY, creates a session with the PTY slave as the
  controlling terminal, and forwards Wings stdin. The PTY master uses separate
  Tokio file handles for reading and writing so an idle blocking read cannot
  prevent console commands or graceful-stop input. Wings converts producer line
  feeds to terminal carriage returns at this boundary, line-buffers stdout into
  both existing broadcast paths, applies the same console throttling policy used
  by the Docker path, and reconnects the console while the CT remains running.
  `pct console` connection banners are excluded from broadcasts and runtime logs.
- Filtered console lines are retained on the Wings host at
  `<log_directory>/pve-lxc/<server UUID>.log`. Fresh server setup truncates the
  file; process reattachment preserves it. `console_log_max_bytes` bounds each
  file and starts a fresh retained log at the limit. `logs(Some(n))` seeks
  backward to the requested trailing lines without loading the entire file;
  `logs(None)` streams the full retained log.
- Process state is polled from `pct status`. A newly prepared CT suppresses the
  initial stopped state until `pct start` succeeds. A CT that starts and exits
  between status polls still emits stopped and enters normal crash handling. PVE does not expose
  Docker-equivalent process exit-code/OOM metadata through this path, so a stopped
  CT currently reports `exit_code: -1` and `oom_killed: false`.
- Signal-based stops set `lxc.signal.halt` from the configured Wings stop signal
  and request a graceful `lxc-stop --nowait --nokill`. Command-based stops are
  sent over the attached console. Hard kill uses `pct stop`. Immediate restart
  after a graceful stop can hit PVE's transient monitor-socket teardown window;
  `pct start` is retried only for that known failure, after checking whether the
  CT actually started despite the client error.
- `sync_configuration` updates mutable PVE resource limits plus runtime environment
  and halt-signal configuration. Panel entrypoint overrides are rejected for now;
  the OCI image entrypoint is used as the server process.
- Normal server cleanup hard-stops a running CT and destroys the owned container,
  so the next normal setup starts from a fresh OCI root filesystem while keeping
  the host-owned server data directory.
- Installation and ad-hoc script execution now use short-lived helper CTs rather
  than Docker. Helpers have role-specific ownership tags so they cannot be
  mistaken for the main server CT. They reuse the configured OCI image pull/cache
  path, mount the server data at `/mnt/server`, and mount a host staging directory
  at `/mnt/install` or `/mnt/script` with the same host-managed UID/GID mapping used
  by the main data mount.
- Helper CTs execute the requested entrypoint plus staged script through
  `lxc.init.cmd`, making the job itself PID 1. `lxc.console.logfile` writes console
  output to a durable Wings-host file, which lets Wings stream output without a
  long-lived `lxc-attach` child and lets an in-progress installer be reattached
  after a Wings restart. Installer status/progress files remain host-backed and
  use the existing Wings installation result flow. The status file begins with a
  failure marker and is cleared only after a successful installer exit, so a
  killed or OOM-terminated helper cannot be reported as successful completion.
- Both helper and game CTs use a small host-managed init wrapper that waits for
  PVE's host-side DHCP hook to install a default route before invoking the OCI
  entrypoint. The game wrapper then `exec`s the original OCI command. Installer
  wrappers also write a nonzero script exit to the existing installation status
  file so an early helper failure cannot be reported as a successful install.
- Installer helpers persist until normal installation cleanup so their retained
  console/status data remains available for result evaluation. Script helpers are
  automatically destroyed after the CT stops and their final console bytes have
  been drained; their per-run staging directory is removed at the same time.
- Helper process state uses the same PVE status polling limitation as the main
  process (`exit_code: -1`, `oom_killed: false`). A helper that starts and exits
  between polls still emits a running transition before stopped so very short
  installers cannot strand the existing installation state machine waiting for a
  transition it never observed.
- OCI template preparation is serialized across main and helper provisioning so
  concurrent requests cannot corrupt the shared cache. Container creation itself
  remains concurrent. A VMID collision from another cluster client is retried
  with a newly allocated ID up to three times.
- Main-server resource telemetry now uses Proxmox
  `/nodes/{node}/lxc/{vmid}/status/current` to discover the running CT init PID,
  then reuses Wings' existing cgroup-v2 sampler against that process. It publishes
  memory usage/limit, CPU percent, configured CPU limit, per-container network
  byte/packet counters, uptime, disk usage, and current server state through the
  existing resource-usage watch channel. CPU percent is calculated from cgroup
  CPU-time deltas using the same semantics as the Docker path.
- The PVE stats worker re-resolves the runtime PID and cgroup if the CT restarts,
  its cgroup files disappear, or the sampler stops delivering. Offline state
  clears live-container metrics while preserving disk usage. A running CT with no
  usable PID or cgroup-v2 path is retried and reported as unavailable rather than
  falling back to guessed host-wide values.
- Tundra can run as a native child process when Docker is unavailable. Wings
  renders the same control-plane config and Unix socket used by the Docker path,
  installs the configured `tundra-node` binary into its managed data directory,
  tracks the child with its PID file, and reconnects to an existing owned process
  after a Wings restart. PVE inventory publishes each running CT as
  `pid:<init-pid>`; the Tundra node resolves that reference directly through
  procfs, so Docker is not required to discover the CT network namespace, address,
  or managed hosts file. Docker remains the preferred runtime when both backends
  are available. The matching Tundra source change is preserved in
  `patches/tundra-pve-lxc-process-ref.patch` until it can be merged upstream.
  The patched daemon advertises `process_container_refs` in its metrics response;
  Wings refuses to publish LXC references unless that capability is present.
  CI verifies the patch against pinned Tundra commit
  `ccb05e1406232f8c39f05a984133277026cd79d6`.
- Adopting an already-running LXC reconciles Wings-owned runtime files and
  `lxc.mount.entry` records. This creates Tundra's managed hosts file immediately;
  when the feature was enabled after the CT started, the new read-only
  `/etc/hosts` bind mount takes effect on that CT's next restart.

## Initial support contract

- Native Tundra requires a `tundra-node` built with
  `patches/tundra-pve-lxc-process-ref.patch`. Wings does not build or install that
  patched binary; operators must supply the compatible executable configured for
  the node. Capability negotiation fails closed when an unpatched daemon connects.
- Panel entrypoint overrides, CPU pinning, unlimited memory, unlimited swap, and
  digest-form image references are rejected explicitly. PVE OCI pulls currently
  do not receive the Docker private-registry credentials from Wings.
- One primary IPv4 allocation selects the CT address or edge peer. Additional
  allocation ports are supported on that address; multiple allocation IPs are
  not yet mapped to extra LXC interfaces.
- PID limits, block-I/O weight, and a writable-rootfs toggle do not yet have LXC
  mappings. The OCI rootfs remains writable and Wings enforces the implemented
  memory, swap, CPU-time, mount, device, network, and firewall settings.
- Edge publishing is an optional deployment component. It discovers peers from
  the configured WireGuard interface and invokes the restricted edge controller
  over SSH with pinned host keys. Controller commands have bounded SSH process
  execution and failures fail the required network-policy synchronization; Wings
  stops a newly started server when its required edge mapping cannot be applied.
  The forced-command controller receives `clear <server UUID>` with no stdin, or
  `sync <server UUID>` with JSON stdin containing `ip`, `tcp`, and `udp`. WireGuard
  discovery times out after five seconds and each SSH operation after 15 seconds.
  Sites that do not configure the edge identity use direct bridged allocations
  and have no dependency on that controller.

## Disposable PVE smoke test

`scripts/pve-lxc-smoke-test.sh` exercises the host contracts the runtime depends
on without requiring a running Wings instance. Run it as root on a disposable PVE
9.2+ node. By default it uses `local` for OCI templates, `local-lvm` for rootfs,
`vmbr0` for networking, and the non-root
`docker.io/nginxinc/nginx-unprivileged:alpine` image. Those values can be
overridden with `TEMPLATE_STORAGE`, `ROOTFS_STORAGE`, `BRIDGE`, and `IMAGE`.

The smoke test pulls/reuses the OCI template, creates an unprivileged CT with the
same `pct create` shape used by Wings, reads PVE's resolved `lxc.init.uid/gid`,
applies the per-mount idmap for `/home/container`, starts the CT, verifies the
interfaces and `status/current` APIs, checks the init PID's cgroup and network
namespace proc files, writes through the mapped data mount as the OCI user,
checks init command, environment, console logging and a read-only managed file,
then tests graceful stop, immediate restart with the same transient-error retry
policy, hard stop, and rootfs recreation with persistent host-backed data.
The CT and temporary host data are cleaned up automatically unless `KEEP_CT=1` is
set. The OCI template cache is intentionally retained for repeat runs.

The smoke test passed end-to-end on a disposable node running PVE 9.2.2
(`pve-manager/9.2.2`, kernel `7.0.2-6-pve`) on September 28, 2026. The immediate
restart encountered one monitor teardown error and succeeded on retry. The run
also verified OCI template reuse, DHCP/interface discovery, `status/current`
init-PID discovery, the `/home/container` per-mount idmap, host ownership
translation, cgroup-v2 and `/proc/{pid}/net/{tcp,tcp6,udp,udp6}` visibility,
runtime environment reaching init, durable console output, read-only managed
`/etc/hosts`, graceful and hard stops, rootfs recreation, and persistent data.
The tagged CT and its two temporary host directories were removed. PVE's
`pct config` output also contained a NUL byte during this OCI flow; the runtime
and smoke test strip NULs before parsing the otherwise textual configuration.

### Panel-to-edge Minecraft validation

The deployed Wings binary passed an end-to-end panel-created Paper server test on
a disposable PVE node:

- The installer helper acquired `10.70.0.20` from the host-only
  `vmbr-calagopus` DHCP service and downloaded the Paper server jar.
- The game CT ran unprivileged on the same bridge and acquired `10.70.0.21`.
  Its OCI entrypoint waited for DHCP, downloaded the Mojang runtime jar, generated
  a world, and reported `Done (27.464s)` while listening on `0.0.0.0:25565`.
- Wings selected the WireGuard peer whose endpoint matched the panel allocation
  `192.0.2.10`, then installed TCP and UDP DNAT rules on that edge for
  `192.0.2.10:25565 -> 10.70.0.21:25565`.
- A TCP probe from the development host to `192.0.2.10:25565` and a second
  probe on the edge to `10.70.0.21:25565` both succeeded. The panel reported the
  server running with live CPU, memory, disk, uptime, and network telemetry.
- A panel console `list` command reached Paper and returned its online-player
  response. The panel Stop action then sent Paper's configured stop command,
  Paper saved all three dimensions, VMID 100 reached `stopped`, and a subsequent
  panel Start returned the server to `Done (22.133s)`. No `pct console` connection
  banners appeared in the panel or persisted runtime log. A fresh probe to the
  public allocation succeeded after restart.
- PVE can temporarily return JSON `null` from the interfaces endpoint while a CT
  finishes shutting down. Wings treats that response as an empty interface list,
  allowing an immediate panel Restart to clear stale firewall state and continue.
  A live restart after this change returned Paper to `Done (23.479s)`.
- Paper 26.3 with Java 25 exhausted the original 1 GiB test limit during initial
  world creation. PVE's kernel log confirmed a memory-cgroup OOM kill. Raising
  the panel limit to 4 GiB produced a stable server at about 1.4 GiB resident
  memory. This was a workload sizing issue rather than an LXC networking failure.

### Native Tundra validation

During live validation, the PVE node was enrolled in the panel private network at its
Tailscale address on UDP 7100 with Docker absent. Wings launched the native
`tundra-node`, issued and published its node certificate through the existing
control-plane shim, and the panel reported the daemon connected with its snapshot
applied. The running Minecraft LXC joined with hostname `test-mc.tunnel` and
offered TCP 25565. Tundra accepted the Wings `pid:<init-pid>` reference, adopted
the CT without Docker, and applied a snapshot containing the LXC server. Metrics
reported the control link up and the daemon listening on UDP 7100. A second
private-network member is still required to exercise an inter-node QUIC relay and
end-to-end hostname connection.

## Remaining work before production use

- Define a verified PVE-safe equivalent for the optional managed
  `/sys/class/dmi/id/product_uuid` file. The regular generated files use live
  read-only LXC file bind mounts, but sysfs behavior still needs real-PVE
  validation before claiming parity for this path.
- Confirm private-registry authentication behavior for PVE's OCI pull path.
- Continue live PVE 9.2 validation for less common Wings behavior: helper
  reattachment after a daemon restart, one-shot script cleanup, and
  host-local nftables/iptables filtering on bridged CT traffic. Main process
  startup, helper installation, DHCP, telemetry, WireGuard peer selection, edge
  DNAT synchronization, and public connectivity have now been exercised through
  the Rust runtime against the live panel.

A cached Rust 1.97 toolchain is available on the current macOS development host;
formatting passes there. The macOS test build cannot produce a Wings binary because
existing filesystem code uses Linux-only `rustix` APIs and the PVE console-spawn
method is intentionally compiled only on Linux. On September 28, 2026, the branch
was archived into a disposable Rust 1.97.1 LXC on a disposable PVE build container with locked Cargo caches.
`cargo check --tests --offline --target x86_64-unknown-linux-gnu` passed, followed
by `cargo test --offline --target x86_64-unknown-linux-gnu`: 743 passed, 9 ignored,
0 failed. `CARGO_GIT_BRANCH` was supplied because the source archive omitted
`.git`. The tagged build CT, uploaded archives, and temporary Rust OCI template
were removed after the run. This validates Linux compilation and unit tests, but
it does not run a configured Wings daemon or the full PVE executor against a live
panel. The later live validation above fills that gap for the primary install,
start, telemetry, console-command, graceful-stop, and edge-forwarding paths. The
current PVE-specific unit suite also passes all 60 targeted tests on the PVE test
node before the deployed release build.
