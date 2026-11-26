# Incus executor (experimental)

Wings can run servers as Incus application containers instead of Docker containers. Select it with
`runtime.backend: incus`; Docker remains the default. Changing the backend needs a restart, and
servers are not migrated between backends.

The panel needs no changes, and the `docker.*` settings it generates apply to both runtimes.

## Requirements

- Linux 5.6 or newer with cgroup v2, and **Incus 7.0.1 or any newer 7.x release**. The daemon version and the
  API extensions Wings uses are checked at startup.
- Wings running as root on the Incus host, with access to the local Incus socket and to
  `/var/log/incus`.
- The `incus` client, `skopeo` and `nftables`. Incus packages that ship their own `skopeo` under
  `/opt/incus/bin` work without installing another.
- A non-root Wings data user and group (`system.user`).
- Images that contain `/bin/sh`.

Testing so far used Debian 13 on x86_64 with Incus 7.6 and the `dir` and `btrfs` storage drivers.
The 7.0 LTS series, other architectures and other storage drivers have not been tested.

## Configuration

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
    ipv6_address: fd76:c0a1:7761::1/64
    log_directory: /var/log/incus
    operation_timeout_seconds: 120
    image_import_timeout_seconds: 1800
    max_concurrent_imports: 2
    image_cache_retention_days: 30
    incus_path: incus
    skopeo_path: skopeo
```

`backend: incus` is enough for the defaults. Wings creates its project, storage pool and bridge if
they are missing, marks them as its own, and refuses to use ones it does not own. Existing pools
are used with their actual driver and are never deleted.

`storage_driver` and `storage_config` only apply when Wings creates a pool. For example:

```yaml
runtime:
  incus:
    storage_driver: btrfs
    storage_config:
      source: /dev/disk/by-id/your-disk # the disk is formatted by Incus
```

`wings-rs service-install` writes a service unit that depends on Incus instead of Docker when the
configuration selects this runtime. Keep `KillMode=process`, so that restarting Wings does not
kill the disk quota helpers that running servers use.

## How Docker settings apply

| Setting | Incus behaviour |
| --- | --- |
| Memory, overhead multipliers, swap, CPU, pinning, I/O weight, PID limit | Applied as for Docker, and updated live. I/O weight is rounded to Incus's 0 to 10 priority. Incus releases without sized swap limits only turn swap on or off |
| `cpu_period`, `cfs_burst`, `startup_boost`, `runtime_boost`, `numa_memory_binding` | Supported |
| `installer_limits` | Supported for installers and scripts |
| `tmpfs_size`, `shm_size`, `container_ulimits`, `container_sysctls`, `domainname` | Supported |
| `container_pid_limit`, `container_apply_seccomp`, egg seccomp removals, `container_apparmor_profile` | Supported. The Wings seccomp profile is translated to liblxc's format |
| `network.dns`, `dns_options`, `interface` binding rules, `ispn`, `disable_interface_binding` | Supported. `127.0.0.1` allocations listen on the bridge gateway |
| `network.enable_icc`, `network_mtu`, `interfaces.v6.enabled` | Applied to the Incus bridge |
| `network.is_internal` | Turns off NAT on the bridge, which is weaker than a Docker internal network |
| `network.mode` of `host` or `container:*` | Not supported; Wings refuses to start |
| `registries`, `registry_image_fetch_cache` | Supported, including the local copy being used when a registry cannot be reached |
| `bandwidth.backend` | `disabled` turns limits off. Otherwise Incus shapes the network device itself |
| `firewall` | `auto`, `nftables` and `disabled`. Other backends are not supported |
| `delete_container_on_stop`, `log_config` `max-size` | Supported |
| `lxcfs` | Not needed; Incus provides LXCFS itself |
| `mount_options`, `userns_mode`, `server_name_in_container_name`, rootless settings | Not applicable; rootless mode is refused |
| `system.passwd`, `system.machine_id`, panel mounts, devices, KVM and huge pages | Supported. Mount targets under `/sys` are resolved on the host and skipped if it lacks them |

Disabling the OOM killer has no effect, which matches Docker on cgroup v2.

## Instances

Server instances are named `wgs-<uuid>`, installers `wgi-<uuid>` and scripts `wgx-<uuid>-<id>`.
Instances are recreated for every start.

A server runs as the Wings data user with no capabilities, `no_new_privs`, a read-only root
filesystem, a size-limited `/tmp`, and the trash directory hidden. The data directory is mounted at
`/home/container`. Installers run as the container's root user, mapped to the Wings data user on the
host, with the data directory at `/mnt/server`.

Incus does not report an application container's exit code or out-of-memory kills, so a small shell
supervisor runs the game and records both on a private volume at `/opt/wings-control`. Stop signals
are sent to the game process itself. If the image has GNU `env`, the supervisor also forwards a
signal sent to the instance, for example when the host shuts down. Images without it (such as
Alpine) run the game in the foreground, where a host shutdown cannot ask it to stop first.

Environment variables containing line breaks have them replaced by spaces.

## Console and statistics

Output is read from the console log Incus keeps under `log_directory`, so nothing is lost or
repeated when Wings or Incus restarts. Input is written straight to the instance's terminal, as
Docker does it, using the pseudoterminal held by the liblxc monitor process (Linux 5.6 or newer).
The Incus console API is not used, so a console opened with `incus console` is not disturbed.

Resource usage and out-of-memory events come from the instance's cgroup, read the same way as for
Docker containers.

## Images

Wings downloads the image layers itself and reports per-layer progress to the panel. The console
shows overall progress in the style of the `incus` command:

```
Retrieving image: 100% (332.04MB/s)
Unpacking image: 62%
Image imported with fingerprint: a95644307d9d
```

The `incus` client then converts the downloaded layers into an instance image, using `skopeo` to
read them. Layers and images are cached under `incus-images` in the Wings root directory and removed
after `image_cache_retention_days` without use (`0` keeps them). Images in use, or not imported by
this node, are kept. An image reference ending in `~` is never pulled and must already be cached
on the node.

Registry credentials come from `docker.registries`. They are written to a private temporary file
for the conversion, which is removed afterwards or at the next startup.

## Networking

Instances get static private addresses on the bridge. Allocations are published with Incus NAT proxy
devices (`wings-port-*`), which preserve client addresses. Before a server starts, Wings checks that
no running instance or host service already listens on its ports.

Wings adds one nftables table, `inet wings_incus_<bridge>`, so servers can reach each other through
published allocations, and to apply a forced outgoing IPv4 address. Panel firewall rules use the
same `inet wings` table as with Docker. Public addresses are not assigned or routed by Wings.

With IPv6 enabled, Incus turns on IPv6 forwarding on the host. Check that the host keeps its own
IPv6 route if it learns it from router advertisements.

`tundra.enabled` runs the private network node as a supervised host process, with no Docker daemon.
It has not been tested on a live node.

## Disk limits

Server data stays in the Wings data directory and uses the configured `system.disk_limiter_mode`,
as with Docker. `fuse_quota` has been tested; the other limiters share the same code but need their
own filesystem setup.

`root_disk_size` limits the disposable system disk, which only installers and scripts can write to.
The `dir` driver enforces it only if the backing filesystem has project quotas.

## Backups and transfers

Backups and node transfers contain the server data directory. On Incus, incoming transfers are
subject to the destination's disk limit. Extra mounts are not transferred.

## Not yet verified

Live testing has not covered Tundra, private registries, multi-node transfers, backups, the XFS,
ZFS and btrfs subvolume disk limiters, huge pages, NUMA memory binding, AppArmor profiles, internal
networks, measured bandwidth throughput, or upgrading a node that ran an earlier version of this
runtime.
