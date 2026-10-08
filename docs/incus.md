# Incus 7.0 LTS executor (experimental)

This backend follows [PR #34's LXC runtime approach](https://github.com/calagopus/wings/pull/34), with Incus replacing Proxmox and [Incus NAT proxy devices](https://linuxcontainers.org/incus/docs/main/reference/devices_proxy/) publishing allocations. Select it explicitly with `runtime.backend: incus`; Docker remains the default. Runtime configuration changes require a restart.

## Architecture

| PR #34 model | Incus implementation |
| --- | --- |
| Shared runtime factory | `create_runtime` returns an executor and an optional Docker connection |
| OCI templates in managed storage | Digest-pinned OCI imports through the official Incus client, cached by Incus fingerprint, with image environment defaults preserved |
| Separate runtime and helper LXC containers | Owned `wgs-`, `wgi-`, and `wgx-` Incus instances |
| Existing Wings server directory bound into LXC | Host directory mounted at `/home/container`, or `/mnt/server` for helpers |
| OCI user and host data ownership | Incus resolves the OCI UID/GID; `raw.idmap` maps the non-root Wings data account to that user |
| Host file APIs, quotas, backups, and inotify | Existing Wings filesystem and disk-limiter implementation remains responsible |
| Proxmox bridge/edge forwarding | Incus-managed bridge, private addresses, and TCP/UDP NAT proxy devices |

Images are pulled from the egg/helper registry reference. There is no local Containerfile/Buildah recipe path. The official Incus client handles OCI conversion through `image export` and `image import`, using temporary archives and a private client configuration without modifying operator CLI remotes. This avoids Incus 7.0.1's OCI relay-copy alias bug. Allow temporary disk space for the converted archives beneath the Wings root directory. Incus instance, storage, lifecycle, console, and forwarding operations use the REST API over the local Unix socket.

Root disks are disposable Incus storage volumes. Private launch scripts and process-control files use separate Incus custom volumes mounted at `/opt/wings-control`, outside panel-visible data and the image's `/run` mounts. A simple file entrypoint preserves multiline arguments through LXC's configuration parser. Process files live in the image-user-owned `/opt/wings-control/process` child directory. Instance cleanup preserves the host server directory. Explicit server deletion uses Wings's normal filesystem deletion path.

## Requirements and configuration

### Build on the node

Build from this branch on the node to use its native architecture and system libraries. Install Rust 1.99.0 or newer through rustup, plus a C/C++ toolchain, Clang, CMake, pkg-config, and OpenSSL development headers. The cloud build used CMake 3.30 or newer. On Debian/Ubuntu, the native packages are:

```sh
apt-get update
apt-get install -y build-essential clang cmake pkg-config libssl-dev git curl
```

From the cloned checkout:

```sh
rustup toolchain install 1.99.0 --profile minimal
cargo +1.99.0 build --locked --release -p wings-rs --bin wings-rs
./target/release/wings-rs --help
```

The first release build downloads dependencies and compiles bundled native libraries; allow several minutes and sufficient RAM. Building does not install or restart Wings or Incus. Configure the backend and check server startup before replacing an existing service.

If the build cannot obtain its bundled `fusequota` helper automatically, download the official release and pass its absolute path to the build. Existing compiled dependencies are reused:

```sh
mkdir -p target
curl -fL --retry 3 \
  https://github.com/calagopus/fusequota/releases/download/a39bc56/fusequota-x86_64-linux \
  -o "$PWD/target/fusequota-x86_64-linux"
FUSEQUOTA_BINARY_PATH="$PWD/target/fusequota-x86_64-linux" \
FUSEQUOTA_RELEASE=a39bc56 \
cargo +1.99.0 build --locked --release -p wings-rs --bin wings-rs
```

### Host requirements

- Linux and **Incus 7.0.1 or a later 7.0 LTS maintenance release**. The daemon version and required API extensions are checked; feature releases such as 7.1 are rejected.
- A root Wings service with local Incus socket access, storage-driver prerequisites, the Incus client, `skopeo`, and host `nftables`.
- A non-root Wings data UID/GID, with host directories owned by that account. The instance itself remains unprivileged with isolated ID maps. Helpers run as container root mapped to the Wings data account.
- When `newuidmap`/`newgidmap` are installed, delegate the Wings data IDs to the Incus daemon account (normally root) in `/etc/subuid` and `/etc/subgid`, in addition to its normal subordinate ranges. For UID/GID 1000, the additional entries are `root:1000:1` in each file. Restart Incus after changing its ID-map delegation.
- OCI images containing `/bin/sh`, used by the argv-preserving process supervisor.
- Keep existing Wings filesystem and disk-limiter settings appropriate to the host. The backend does not replace them or require disabling inotify.

Merge into the normal panel-generated configuration and use real pool names/addresses:

```yaml
runtime:
  backend: incus
  incus:
    socket: /var/lib/incus/unix.socket
    project: wings
    storage_pool: wings
    storage_driver: dir
    storage_config: {}
    root_disk_size: 10GiB
    network: wingsbr0
    ipv4_address: 10.76.0.1/16
    listen_addresses: []
    operation_timeout_seconds: 120
    image_import_timeout_seconds: 1800
    max_concurrent_imports: 2
    incus_path: incus
    skopeo_path: skopeo
system:
  machine_id:
    enabled: false
  user:
    uid: 1000
    gid: 1000
tundra:
  enabled: false
docker:
  firewall:
    backend: nftables
```

Wings creates a missing storage pool automatically before importing images. The default `dir` driver uses Incus's normal storage directory, usually `/var/lib/incus/storage-pools/wings`. The default bridge subnet is `10.76.0.1/16`. Existing pools are reused with their actual driver; Wings does not change their configuration or delete them. `storage_driver` and `storage_config` apply only when creating a missing pool.

All container-capable storage drivers provided by the installed Incus daemon can be selected, including `dir`, `btrfs`, `zfs`, `lvm`, and `ceph`. Incus validates the driver, its prerequisites, and its options. `cephfs` and `cephobject` cannot provide container root disks and are rejected. These are Incus storage drivers, rather than Docker image storage drivers.

`storage_config` passes string values directly to Incus's [storage-pool configuration API](https://linuxcontainers.org/incus/docs/main/reference/storage_drivers/). For example, to create a Btrfs loop-backed pool:

```yaml
runtime:
  backend: incus
  incus:
    storage_pool: wings
    storage_driver: btrfs
    storage_config:
      size: "50GiB"
```

For an existing ZFS pool or LVM volume group, set `storage_driver` to `zfs` or `lvm` and `storage_config.source` to its name. Other driver options, including Ceph cluster and pool settings, use the same mapping. Install the selected driver's host tools before starting Wings. Leaving `source` unset with `dir` uses the native Incus storage location; setting it selects another directory.

Incus applies `root_disk_size` and the control-volume quota through the selected driver. With `dir`, these limits are enforced only if the backing filesystem supports and enables project quotas; otherwise Incus skips them. Server files remain in the Wings data directory and use Wings's configured disk limiter, independently of the Incus storage driver.

Existing bridges are not readdressed automatically. Nodes already using `10.76.0.1/24` should retain that explicit `ipv4_address` until a planned subnet migration. A different configured subnet produces an error without changing the bridge or its running containers.

The project owns its images, profiles, and private control volumes. It uses `features.networks=false` to share a Wings-owned managed bridge in Incus's default project. Wings creates that bridge with NAT/DHCP and assigns private instance addresses, with MAC/IP filtering and NIC port isolation.

Disable Wings's machine-ID mounts on physical hosts. The default product-UUID target `/sys/class/dmi/id/product_uuid` includes a sysfs symlink on physical hosts, which LXC refuses as a bind-mount target. Private process files are placed in an image-user-owned child directory inside the control volume: Incus 7.0's file API does not change permissions or ownership when asked to create a directory that already exists, including the volume root.

## Allocation proxy devices

Panel allocation IPv4 addresses are used directly, including `0.0.0.0`. Each instance gets two NAT proxy devices per allocation IP: TCP and UDP, with the allocated port list connected to the same ports on its static private bridge IP. For example, `0.0.0.0:5000` listens on all host IPv4 destinations; `10.0.10.20:5000` listens only on that destination IP. `nat=true` avoids a userspace relay and preserves the client's source address. The host must be the container's gateway, as it is with the Wings-managed bridge.

`listen_addresses` is retained for compatibility with earlier configurations and is not used by the Incus executor. Allocation IPs directly determine proxy bindings; use a concrete allocation IP when a feature needs a reachable advertised address. Wings does not assign external IPs or configure upstream routing; a public address translated by a router still needs that router's port forwarding. Current support is IPv4 on managed bridges.

Wings reserves instance device names beginning with `wings-port-`. It updates only these allocation devices, preserves the other instance settings/devices, sends instance ETags, and waits for asynchronous REST operations. Publication occurs after the guest acquires its private address. Cleanup removes the allocation devices; deleting the instance also deletes its device definitions and active NAT rules. Devices remain attached when a container stops, so their allocations remain reserved for that server.

Before adding devices, Wings rejects wildcard/concrete port overlaps within a server and checks existing host-bound proxies across all Incus projects, including profile devices. Use one Wings process for the node; simultaneous external edits and unrelated host NAT rules are not coordinated by this check.

On startup, Wings migrates its previous network forwards to proxy devices and republishes running instances from their allocation journals. Panel reconciliation then refreshes running instances from current allocations. Migration removes only forwards owned entirely by this node. A forward mixed with unrelated entries causes a clear error without removing those entries. Incus 7.0 rejects a concrete-IP proxy if a network forward already uses that IP, even for different ports, so the old forward object must be removed before the new proxy is installed. Migration briefly interrupts published traffic; game files and container processes are retained.

Inspect the devices with:

```bash
incus config device show wgs-SERVER_UUID --project wings
```

`incus network forward list` no longer shows the allocations after migration.

Incus owns forwarding/NAT. The existing host nftables firewall preserves panel rule order and source-file sets. Incus ACLs have different action ordering, so they do not replace Wings's ordered firewall. The `docker.firewall.backend` setting currently selects this host policy backend; `auto`, `nftables`, and explicit `disabled` are supported.

## Panel Private Network (Tundra)

Set `tundra.enabled: true` to enable the existing panel private-network control plane. With Incus, Wings runs its bundled Tundra node as a supervised host child process. No Docker daemon, daemon image, or separate executable installation is needed. Leave `tundra.binary` empty; `tundra.image` and `tundra.source_image` are used only by the Docker provider.

```yaml
tundra:
  enabled: true
  binary: ""
```

The embedded node comes from the pinned `Luxxy-GF/tundra` fork, with native Incus REST discovery. Snapshots contain stable `wgs-SERVER_UUID` references rather than cached PIDs. Discovery is scoped to the configured Incus project and Wings ownership marker and excludes installers/script helpers. The node inspects each game's private IPv4 and host PID, binds the existing TCP/UDP private frontends in its network namespace, and updates the Wings-owned hosts file for `.tunnel` names. Incus stages that read-only file at `/opt/wings-private-hosts`; a final relative LXC bind mounts it over Incus 7.0's generated `/etc/hosts`. Namespace starts, stops, and PID changes are detected by one-second polling. Frozen containers retain their namespace association.

The panel still controls server membership, advertised private ports, peer certificates, and directional ACLs. The existing QUIC relay, JWT admission checks, revocation, and panel-unreachable behavior stay shared with Docker. Allow the panel-configured node tunnel UDP port through the host/upstream firewall. NIC port isolation stays enabled; private traffic passes through Tundra rather than allowing unrestricted direct bridge traffic. Killing Wings also kills its child; Wings restarts a failed node during reconciliation. Changing node configuration restarts the child and can interrupt active private flows.

Like the upstream Docker implementation, private frontend ports must not collide with wildcard listeners already running in the source container. Give servers distinct service ports when a source's application binds all IPv4 addresses on a destination's private port.

## Extra mounts and game-data quotas

Panel mounts go through the same normalized-path and `allowed_mounts` checks used by Docker. Incus disk devices preserve `read_only`; administrator-provided files/directories must already have permissions suitable for the image user. The image UID/GID is mapped to the Wings host data account for the whole instance. Extra mounts are not automatically owned or charged to the server data quota.

The persistent data directory remains outside the disposable Incus root disk. `runtime.incus.root_disk_size` requests a quota for the image/system disk, subject to the driver capability described above; it does not limit files in `/home/container`. Choose Wings's existing filesystem limiter to enforce the panel's game-data disk limit:

```yaml
system:
  disk_limiter_mode: fuse_quota
```

`fuse_quota` supports an ordinary host data directory and uses the bundled fusequota helper, host FUSE support, and `/dev/fuse`. Incus waits for the quota mount and control socket before binding it into a game, installer, or script helper. Quota attachment/update failures abort creation instead of falling back to an unprotected directory. `btrfs_subvolume` requires the Wings **data directory** to reside on a Btrfs filesystem; using a Btrfs Incus storage pool alone is insufficient. Existing ordinary directories need an explicit filesystem migration before switching to Btrfs subvolumes. XFS and ZFS keep their shared limiter paths but require their filesystem-specific host setup and separate live validation.

`disk_limiter_mode: none` keeps the existing usage checks without a kernel/FUSE write quota. Changing the limiter on an existing running node requires stopping servers and planning the data/mount transition.

## Image progress and installer permissions

Image checks, cache hits, OCI export/conversion, import, and completion are reported to the panel console. Incus CLI carriage-return progress updates become bounded console lines; long silent operations emit a periodic elapsed-time message. The official Incus client handles daemon operation events during import. Registry download/conversion happens in the client, so subscribing only to `/1.0/events` would miss it. Incus 7.0 does not expose Docker-style per-layer registry byte progress through this conversion path; no synthetic percentages are reported.

Before an installer or script helper starts, Wings repairs ownership of its server data using the configured Wings UID/GID. This prevents mapped OCI root from receiving permission errors on a freshly root-owned `/mnt/server`. Administrator extra mounts are not changed. An installer that ignores errors and exits successfully can still report success; its script should fail on failed commands.

## Restart recovery, backups, and transfers

Wings owns game autostart (`boot.autostart=false` in Incus). On a Wings restart it reattaches to an existing running game, checks the data mount's device/inode against the guest mount, reapplies the quota, and reconciles allocations and firewall policy. An unavailable daemon or stale mount produces a recovery error and blocks automatic replacement. After a node reboot, Wings uses the saved server state and the panel's `auto_start_behavior` to start games again. Keep the Wings root/data directories on persistent storage and run Wings after Incus is ready.

Local backups and node transfers contain the persistent game files, not the disposable OCI root disk or supervisor volume. Restored/transferred files use the destination Wings data UID/GID. Incus node transfers enforce the destination game-data limit; an oversized transfer reports failure and may leave partial files for the normal transfer cleanup/retry workflow. Other backends retain their existing transfer behavior. A transfer does not migrate arbitrary administrator extra mounts: configure those paths separately on the destination.

## Registry credentials and image cleanup

Incus uses the existing registry map, with exact registry host/port keys:

```yaml
docker:
  registries:
    registry.example.com:
      username: pull-user
      password: YOUR_REGISTRY_PASSWORD
runtime:
  backend: incus
  incus:
    image_cache_retention_days: 30
```

For Docker Hub, use `docker.io` (the conventional `https://index.docker.io/v1/` key is also accepted). Credentials are stored in a mode-0600 temporary auth file inside a private import directory, supplied to both Skopeo inspection and Incus conversion, and removed when the operation finishes. Passwords are not passed in URLs or command arguments. A private Skopeo wrapper preserves authentication and configured CA trust when Incus 7.0 replaces its subprocess environment for an HTTP proxy. TLS verification stays enabled. Credential prefixes do not match other registry hosts.

Cleanup runs at startup and hourly. The default retention is 30 days since the last cache use; `0` disables it. It removes only cache records and Incus images bearing this node's owner/cache markers. Running and stopped instances protect their base images, administrator aliases protect images, and pulls serialize against cleanup. A failed inventory request stops cleanup. Images imported by earlier releases without ownership markers, and administrator images deduplicated by Incus, are retained. Cleanup never removes game files, storage pools, or instance root disks. Use a single Wings process for a project and coordinate external image/instance edits with cleanup: Incus 7.0 image deletion has no atomic conditional ETag check.

## Current limitations

This is an experimental implementation following the PR's architecture, with incomplete feature parity.

- IPv6, remote Incus, clusters/OVN, forced outgoing-IP SNAT, device passthrough, custom seccomp, OOM-disable, and CPU boosts remain unsupported and are rejected when requested.
- Full game eggs and their installer scripts still require hardware validation.
- Native Incus `raw.idmap` is an instance-wide mapping, unlike Proxmox's per-mount `mpN` ID maps. Extra directories must be accessible to the mapped Wings data UID/GID; the executor does not recursively change administrator-owned mount contents.
- Repository-scoped credential keys, token/helper-based authentication overrides, and private-registry proxy combinations need separate validation; the implemented credential map uses exact registry host/port keys.
- Console replay completeness, XFS/ZFS data quotas, snapshot/remote backup adapters, multiplex transfers, and automated backend migration need separate validation.
- I/O priority supports Docker weights 10 or multiples of 100 through 1000. Other weights are rejected.
- Console input waits five seconds after WebSocket attachment, but Incus does not acknowledge native relay readiness. Early reconnect input can be lost on slow hosts. Early-input reliability remains a limitation requiring hardware checks.
- The supervisor records exit codes. Forced kills can leave an unknown code (`-1`); there is no inferred OOM flag.
- `used_ports` reflects Incus proxies and remaining legacy forwards, but does not completely represent host-service conflicts or unrelated NAT rules.
