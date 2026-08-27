![Calagopus Logo](https://calagopus.com/fulllogo.svg)

# Calagopus Wings

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/github/license/calagopus/wings?color=blue)](https://github.com/calagopus/wings/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/calagopus/wings)](https://github.com/calagopus/wings/issues)
[![GitHub stars](https://img.shields.io/github/stars/calagopus/wings)](https://github.com/calagopus/wings/stargazers)
[![Discord](https://img.shields.io/discord/1429911351777824892?label=discord&logo=discord&color=5865F2)](https://discord.gg/uSM8tvTxBV)

A rewrite of [Pterodactyl Wings](https://github.com/pterodactyl/wings) in the Rust programming language. This rewrite aims to be 100% API compatible while implementing new features, better performance and more stability.

[Todo](https://notes.rjns.dev/workspace/cb7ccae8-0508-4f90-9161-d1e69b0ca8f0/uAVAL7iHSQpDk1SiSUPL1)

## Installation

For installation instructions, please refer to the [Docs](https://calagopus.com/docs/wings/installation).

## Added Config Options

[Read full Config Reference](https://calagopus.com/docs/wings/configuration)

```yml
api:
  # custom redirects for the api server, e.g. / -> https://yourpanel.com
  redirects: {}
  # max amount of active file pulls per server
  server_remote_download_limit: 3
  # cidrs to block on the remote download pull endpoint
  remote_download_blocked_cidrs:
  - '0.0.0.0/8'
  - '127.0.0.0/8'
  - '10.0.0.0/8'
  - '100.64.0.0/10'
  - '172.16.0.0/12'
  - '192.168.0.0/16'
  - '169.254.0.0/16'
  - '192.0.0.0/24'
  - '198.18.0.0/15'
  - '224.0.0.0/4'
  - '240.0.0.0/4'
  - ::/128
  - ::1/128
  - fe80::/10
  - fc00::/7
  - 2002::/16
  - ff00::/8
  # whether to disable the /openapi.json endpoint
  disable_openapi_docs: false
  # how many entries can be listed on a single page on the /list-directory API call, 0 means unlimited
  directory_entry_limit: 10000
  # send server logs of an offline server when connecting to ws
  send_offline_server_logs: false
  # how many threads to use when searching files using file search
  file_search_threads: 4
  # how many threads to use when copying directories
  file_copy_threads: 4
  # how many threads to use when decompressing .zip/.7z/.ddup
  file_decompression_threads: 2
  # how many threads to use when compressing .gz/.xz/.7z
  file_compression_threads: 2
  # how often a jwt can be used to download a file/backup until expiry, 0 means unlimited (2 minimum recommended)
  max_jwt_uses: 5

system:
  # path for temporary mountpoints for servers
  vmount_directory: /var/lib/pterodactyl/vmounts

  # how many concurrent disk checks to allow for all servers globally, this applies to all disk checks - so also partial checks.
  # 2 means no more than 2 servers will be checked at any given time
  disk_check_concurrency: 2
  # how often to do a full disk check when inotify is used, this is to prevent gradual desync between the
  # actual disk usage and the inotify events. 6 means that a full disk check will be done every 6 inotify disk checks.
  # so, if disk_check_interval is 150 seconds, then a full disk check will be done every 900 seconds (15 minutes)
  full_disk_check_every: 6
  # apply a real quota limit to each server
  # none, btrfs_subvolume, zfs_dataset, xfs_quota, (experimental) fuse_quota
  disk_limiter_mode: none
  # use inotify to selectively rescan disk usage instead of forcing full rescans
  disk_check_use_inotify: true

  # use multiple threads to run chown on server startup
  check_permissions_on_boot_threads: 4

  sftp:
    # whether to even enable to sftp (ssh) server
    enabled: true
    # the algorithm to use for the ssh host key
    key_algorithm: ssh-ed25519
    # whether to disable password auth for the sftp (ssh) server
    disable_password_auth: false
    # how many entries can be listed on readdir, 0 means unlimited
    directory_entry_limit: 20000
    # how many entries to send on each readdir call (chunk size)
    directory_entry_send_amount: 500

    limits:
      # how many failed password authentication attempts within cooldown
      authentication_password_attempts: 3
      # how many failed public key authentication attempts within cooldown
      authentication_pubkey_attempts: 20
      # how long in seconds to cooldown after reaching max authentication attempts (if 0, no cooldown is applied)
      # the cooldown is a sliding window, so if you make 3 failed attempts in 1 minute, you will have to wait 60 seconds from the last attempt
      authentication_cooldown: 60
      # how many concurrent connections a single user can have
      max_connections_per_user: 10
      # how many concurrent channels a single connection can have
      max_channels_per_connection: 10
      # how many concurrent open handles a single channel can have
      max_handles_per_channel: 32
      # how many concurrent open handles a single server can have
      max_handles_total: 1024

    shell:
      # whether to enable the wings remote shell (allows server management over ssh)
      enabled: true

      cli:
        # what to call the internal cli for managing server actions (e.g. ".wings help")
        name: ".wings"

    activity:
      # whether to log successful sftp logins in server activity
      log_logins: false
      # whether to log file read actions in server activity
      log_file_reads: false

  file_history:
    enabled: true
    zstd_level: 19
    anchor_interval: 4
    keep_chains: 2
    file_size_cap: 1048576
    per_file_disk_budget: 5242880
    per_server_disk_budget: 209715200
    maintenance_interval: 3600

  backups:
    # what compression level to use? best_speed, good_speed, good_compression, best_compression (higher compression = more CPU usage, better compression)
    compression_level: best_speed
    # allow browsing backups via the web file manager
    mounting:
      # whether backup "mounting" is enabled
      enabled: true
      # what the start of the path should be for browsing
      # in this case, ".backups/<backup uuid>"
      path: .backups

    # settings for the wings backup driver
    wings:
      # how many threads to use when creating a .gz/.xz/.7z wings backup
      create_threads: 4
      # how many threads to use when restoring a zip wings backup
      restore_threads: 4
      # what archive format to use for local (wings) backups
      # tar, tar_gz, tar_xz, tar_lzip, tar_bz2, tar_lz4, tar_zstd, zip, seven_zip
      archive_format: tar_gz

    # settings for the s3 backup driver
    s3:
      # how many threads to use when creating a .gz s3 backup
      create_threads: 4
      # how long in seconds to wait until a backup part is uploaded to s3
      part_upload_timeout: 7200
      # how often to attempt retrying each failed backup part
      retry_limit: 10

    # settings for the ddup-bak backup driver
    ddup_bak:
      # how many threads to use when creating a ddup-bak backup
      create_threads: 4
      # the compression format to use for each ddup-bak chunk
      # none, deflate, gzip, brotli
      compression_format: deflate

    # settings for the restic backup driver
    restic:
      # the repository to use for restic backups (must already be initialized, can be overriden by panel)
      repository: /var/lib/pterodactyl/backups/restic
      # the password file to use for authenticating against the repository (can be overriden by panel)
      password-file: /var/lib/pterodactyl/backups/restic_password
      # how long to wait for a repository lock if locked in seconds (can be overriden by panel)
      retry_lock_seconds: 60
      # the restic cli environment for each command (useful for s3 credentials, etc, can be overriden by panel)
      environment: {}

    # settings for the btrfs backup driver
    btrfs:
      # how many threads to use when restoring a btrfs backup (snapshot)
      restore_threads: 4
      # whether to create the snapshots as read-only
      create_read_only: true

    # settings for the zfs backup driver
    zfs:
      # how many threads to use when restoring a zfs backup (snapshot)
      restore_threads: 4

    # settings for the pbs backup driver
    pbs:
      # how many threads to use when creating a pbs backup
      create_threads: 4
      # how many download streams to use when restoring a pbs backup
      download_concurrency: 4

docker:
  # the docker-compatible socket or http address to connect to
  socket: /var/run/docker.sock
  # whether to add (part) of the server name in the container name
  server_name_in_container_name: false
  # delete docker containers when a server is stopped/killed/crashes (a lot better for your cpu)
  delete_container_on_stop: true

  network:
    # whether to disable binding to a specific ip
    disable_interface_binding: false

    interfaces:
      v4:
        # whether to enable ipv4 support for the docker network
        enabled: true
      v6:
        # whether to enable ipv6 support for the docker network
        enabled: true

  registry_image_fetch_cache:
    # whether to enable caching of docker registry image fetches (pulls)
    enabled: true
    # how long in seconds to cache docker registry image fetches (pulls)
    duration: 300

  installer_limits:
    # how long in seconds to wait until an install container is considered failed, 0 means no limit
    timeout: 1800

remote_headers: {}

remote_query:
  # how often to attempt retrying some important api requests (exponential backoff)
  retry_limit: 10

# whether to ignore requests to upgrade wings remotely
ignore_panel_wings_upgrades: false
```

## Added Features

### API

- `GET /openapi.json` endpoint for getting a full OpenAPI documentation of the wings API
- `GET /api/stats` API endpoint for seeing node usage
- `GET /api/system/logs` API endpoint for listing all wings log files
- `GET /api/system/logs/{file}` API endpoint for reading a wings log file
- `POST /api/system/upgrade` API endpoint for remotely upgrading the wings binary
- `POST /api/servers/{server}/script` API endpoint for running custom scripts async on the server
- `POST /api/servers/{server}/ws/permissions` API endpoint for live updating user permissions on a server
- `POST /api/servers/{server}/ws/broadcast` API endpoint for broadcasting a websocket message to multiple users
- `POST /api/servers/{server}/install/abort` API endpoint for aborting a server installation process
- `GET /api/servers/{server}/logs/install` API endpoint for getting server installation logs
- `GET /api/servers/{server}/version` API endpoint for getting a version hash for a server
- `GET /api/servers/{server}/files/fingerprints` API endpoint for getting fingerprints for many files at once
- `GET /api/servers/{server}/files/list` API endpoint for listing files with pagination and file sorting
- `POST /api/servers/{server}/files/search` API endpoint for searching for file names/content
- `GET /api/servers/{server}/download/directory` API endpoint for downloading directories on-the-fly as archives

---

- properly support egg `file_denylist`
- add support for browsing `.zip`, `.7z`, and `.ddup` archives in the file manager
- add support for browsing `/home/container/` mounts as virtual directories in the file manager
- add support for `name` property on `POST /api/servers/{server}/files/copy`
- add support for opening individual compressed file (e.g. `.log.gz`) in `GET /api/servers/{server}/files/contents`
- add (real) folder size support on `GET /api/servers/{server}/files/list-directory`
- add multithreading support to `POST /api/servers/{server}/files/decompress`
- add zip and 7z support to `POST /api/servers/{server}/files/compress`
- add support for `ignored_files` in the file upload jwt
- allow transferring backups in server transfers
- reworked file operations so progress can be tracked via websocket events and in the background

### Shell

- add ability to connect via ssh and access server console
- add `.wings` CLI to do basic server actions like power

### SFTP

- add support for the [check-file](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00#section-3) SFTP extension
- add support for the [copy-file](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00#section-6) SFTP extension
- add support for the [space-available](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00#section-4) SFTP extension
- add support for the [limits@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L524) SFTP extension
- add support for the [statvfs@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L437) SFTP extension
- add support for the [hardlink@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L478) SFTP extension
- add support for the [fsync@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L494) SFTP extension
- add support for the [lsetstat@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L508) SFTP extension
- add support for the [users-groups-by-id@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L643) SFTP extension
- add support for the [posix-rename@openssh.com](https://github.com/openssh/openssh-portable/blob/5f98660c51e673f521e0216c7ed20205c4af10ed/PROTOCOL#L420) SFTP extension
- properly support egg `file_denylist`

### Backups

- add [`ddup-bak`](https://github.com/0x7d8/ddup-bak) backup driver
- add [`btrfs`](https://github.com/kdave/btrfs-progs) backup driver
- add [`zfs`](https://github.com/openzfs/zfs) backup driver
- add [`restic`](https://github.com/restic/restic) backup driver
- add ability to create `zip` and `7z` archives on `wings` backup driver
- add ability to browse backups (for some drivers)

### CLI

- add `service-install` command to automatically setup a service for wings
- add `migrate-disk-limiter` command to migrate to btrfs/zfs disk limiter without needing to do a transfer for each server

## Star History

![Star History Chart](https://api.star-history.com/chart?repos=calagopus/wings&type=date&legend=top-left&sealed_token=B2O-QGHUHAa_2R6TXAtmVmA-ASHkIyhBD3Rm6jlD9mOeO9XJsHW0uBvsZ-5zINucUHJPH5c29w8c7lL_2Kr7tb5770-KK58lG2pGrET0ksegRMrP1IEbft05EdOtyO6RAUCo1FCK5gnNscF6lwXhRp5LLQd08n2sZgUisdnct1irxGRvQmzUx9o-Bk4o)
