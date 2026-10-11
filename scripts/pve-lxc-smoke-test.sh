#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-docker.io/nginxinc/nginx-unprivileged:alpine}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
ROOTFS_STORAGE="${ROOTFS_STORAGE:-local-lvm}"
BRIDGE="${BRIDGE:-vmbr0}"
ROOTFS_SIZE_GIB="${ROOTFS_SIZE_GIB:-2}"
MEMORY_MIB="${MEMORY_MIB:-256}"
SWAP_MIB="${SWAP_MIB:-256}"
HOST_DATA_UID="${HOST_DATA_UID:-1000}"
HOST_DATA_GID="${HOST_DATA_GID:-1000}"
KEEP_CT="${KEEP_CT:-0}"

if [[ ${EUID} -ne 0 ]]; then
  echo "error: run this smoke test as root on the Proxmox node" >&2
  exit 1
fi

for command in pveversion pvesh pct lxc-attach lxc-stop sha256sum perl tr awk stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: required command not found: $command" >&2
    exit 1
  fi
done

node="$(pvesh get /cluster/status --output-format json | perl -MJSON::PP -0777 -e '
  my $rows = decode_json(<STDIN>);
  for my $row (@$rows) {
    next if ($row->{type} // q{}) ne q{node};
    next if !($row->{local} // 0);
    print $row->{name} // q{};
    last;
  }
')"
if [[ -z "$node" ]]; then
  echo "error: Proxmox cluster status did not identify the local node" >&2
  exit 1
fi
version="$(pveversion | sed -n 's#^pve-manager/\([0-9][0-9.]*\)/.*#\1#p')"
if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)(\.|$) ]]; then
  echo "error: Proxmox VE 9.2 or newer is required; found ${version:-unknown}" >&2
  exit 1
fi
major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
if [[ "$major" -lt 9 || ( "$major" -eq 9 && "$minor" -lt 2 ) ]]; then
  echo "error: Proxmox VE 9.2 or newer is required; found ${version:-unknown}" >&2
  exit 1
fi

vmid="$(pvesh get /cluster/nextid)"
if [[ ! "$vmid" =~ ^[0-9]+$ || "$vmid" -le 0 ]]; then
  echo "error: Proxmox returned an invalid next VMID: ${vmid:-empty}" >&2
  exit 1
fi
# Mirror runtime.pve_lxc.min_vmid so the disposable CT does not squat a low
# ID reserved for infrastructure. Override with MIN_VMID=100 to test the floor.
min_vmid="${MIN_VMID:-200}"
if [[ ! "$min_vmid" =~ ^[0-9]+$ || "$min_vmid" -lt 100 ]]; then
  echo "error: MIN_VMID must be a VMID at or above 100, got ${min_vmid:-empty}" >&2
  exit 1
fi
if [[ "$vmid" -lt "$min_vmid" ]]; then
  used_vmids="$(pvesh get /cluster/resources --type vm --output-format json | perl -ne 'while (/\"vmid\"\s*:\s*\"?(\d+)\"?/g) { print "$1\n" }' | sort -n -u)"
  candidate="$min_vmid"
  while printf '%s\n' "$used_vmids" | grep -qx "$candidate"; do
    candidate=$((candidate + 1))
  done
  vmid="$candidate"
fi
server_uuid="$(cat /proc/sys/kernel/random/uuid)"
run_tag="calagopus-smoke"
server_tag="calagopus-server-${server_uuid}"
normalized_image="$IMAGE"
last_component="${normalized_image##*/}"
if [[ "$last_component" != *:* ]]; then
  normalized_image="${normalized_image}:latest"
fi
if [[ "$normalized_image" == *@* ]]; then
  echo "error: digest image references are not supported by the current runtime" >&2
  exit 1
fi

image_digest="$(printf '%s' "$normalized_image" | sha256sum | awk '{print $1}')"
image_tag="calagopus-image-${image_digest:0:32}"
template_name="calagopus-oci-${image_digest}"
template_volid="${TEMPLATE_STORAGE}:vztmpl/${template_name}.tar"
data_dir="/var/lib/calagopus-pve-smoke/${server_uuid}"
managed_dir="/var/lib/calagopus-pve-smoke-managed/${server_uuid}"
managed_parent="${managed_dir%/*}"
managed_parent_created=0
managed_parent_mode=""
created_ct=0
config_file="$(mktemp /tmp/calagopus-smoke-config.XXXXXX)"

cleanup() {
  local status=0
  if [[ "$KEEP_CT" == "1" ]]; then
    echo "KEEP_CT=1: leaving CT $vmid and $data_dir in place"
    return
  fi

  if pct config "$vmid" >"$config_file" 2>/dev/null; then
    if grep -Eq "^tags: .*${run_tag}" "$config_file"; then
      if pct status "$vmid" 2>/dev/null | grep -q running; then
        pct stop "$vmid" >/dev/null 2>&1 || status=1
      fi
      pct destroy "$vmid" --purge 1 >/dev/null 2>&1 || status=1
    else
      echo "warning: refusing to clean CT $vmid because the smoke-test tag is missing" >&2
      status=1
    fi
  fi
  rm -f "$config_file"
  rm -rf "$data_dir"
  rm -rf "$managed_dir"
  if [[ "$managed_parent_created" == "1" ]]; then
    rmdir "$managed_parent" 2>/dev/null || true
  elif [[ -n "$managed_parent_mode" && -d "$managed_parent" ]]; then
    chmod "$managed_parent_mode" "$managed_parent" || status=1
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "warning: smoke-test cleanup was incomplete" >&2
  fi
}
trap cleanup EXIT INT TERM

json_field() {
  local field="$1"
  perl -MJSON::PP -0777 -e '
    my $field = shift @ARGV;
    local $/;
    my $json = decode_json(<STDIN>);
    my $value = $json->{$field};
    print $value if defined $value;
  ' "$field"
}

ensure_template() {
  if pvesh get "/nodes/${node}/storage/${TEMPLATE_STORAGE}/content" --content vztmpl --output-format json \
      | grep -Fq "\"volid\":\"${template_volid}\""; then
    echo "template: reusing $template_volid"
    return
  fi

  echo "template: pulling $normalized_image"
  local output upid task_json task_status exit_status
  output="$(pvesh create "/nodes/${node}/storage/${TEMPLATE_STORAGE}/oci-registry-pull" \
    --reference "$normalized_image" \
    --filename "$template_name" \
    --output-format json)"
  printf '%s\n' "$output"

  upid="$(printf '%s\n' "$output" \
    | sed -n -e 's/^"\(UPID:.*\)"$/\1/p' -e '/^UPID:/p' \
    | tail -n 1)"
  if [[ -z "$upid" ]]; then
    echo "error: OCI pull completed without a parseable UPID" >&2
    exit 1
  fi

  while true; do
    task_json="$(pvesh get "/nodes/${node}/tasks/${upid}/status" --output-format json)"
    task_status="$(printf '%s' "$task_json" | json_field status)"
    if [[ "$task_status" == "stopped" ]]; then
      exit_status="$(printf '%s' "$task_json" | json_field exitstatus)"
      if [[ "$exit_status" != "OK" ]]; then
        echo "error: OCI pull task failed: ${exit_status:-unknown}" >&2
        exit 1
      fi
      break
    fi
    sleep 1
  done

  if ! pvesh get "/nodes/${node}/storage/${TEMPLATE_STORAGE}/content" --content vztmpl --output-format json \
      | grep -Fq "\"volid\":\"${template_volid}\""; then
    echo "error: OCI pull task succeeded but $template_volid is absent" >&2
    exit 1
  fi
}

create_ct() {
  echo "ct: creating VMID $vmid"
  pct create "$vmid" "$template_volid" \
    --hostname "calagopus-smoke-${vmid}" \
    --rootfs "${ROOTFS_STORAGE}:${ROOTFS_SIZE_GIB}" \
    --memory "$MEMORY_MIB" \
    --swap "$SWAP_MIB" \
    --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp,type=veth,host-managed=1" \
    --unprivileged 1 \
    --cmode console \
    --onboot 0 \
    --cores 1 \
    --cpulimit 1 \
    --tags "calagopus;${run_tag};${server_tag};${image_tag}"
  created_ct=1
}

configure_data_mount() {
  local config uid gid
  config="$(pct config "$vmid" | tr -d '\000')"
  uid="$(printf '%s\n' "$config" | awk -F': *' '$1 == "lxc.init.uid" {print $2; exit}')"
  gid="$(printf '%s\n' "$config" | awk -F': *' '$1 == "lxc.init.gid" {print $2; exit}')"
  if [[ ! "$uid" =~ ^[0-9]+$ || ! "$gid" =~ ^[0-9]+$ ]]; then
    echo "error: OCI image did not resolve to numeric lxc.init.uid/gid values" >&2
    printf '%s\n' "$config" >&2
    exit 1
  fi

  echo "oci user: uid=$uid gid=$gid"
  mkdir -p "$data_dir"
  chown "$HOST_DATA_UID:$HOST_DATA_GID" "$data_dir"
  chmod 0750 "$data_dir"

  pct set "$vmid" --mp0 \
    "${data_dir},mp=/home/container,backup=0,idmap=u:${uid}:${HOST_DATA_UID}:1;g:${gid}:${HOST_DATA_GID}:1"

  OCI_UID="$uid"
  OCI_GID="$gid"
}

wait_for_address() {
  local attempt interfaces usable
  for attempt in $(seq 1 30); do
    interfaces="$(pvesh get "/nodes/${node}/lxc/${vmid}/interfaces" --output-format json 2>/dev/null || true)"
    usable="$(printf '%s' "$interfaces" | perl -MJSON::PP -0777 -e '
      my $rows = eval { decode_json(<STDIN>) } // [];
      for my $row (@$rows) {
        next if ($row->{name} // q{}) eq q{lo};
        for my $address (@{$row->{q{ip-addresses}} // []}) {
          my $ip = $address->{q{ip-address}};
          next if !defined($ip);
          next if $ip eq q{0.0.0.0} || $ip eq q{::} || $ip eq q{::1};
          next if $ip =~ /^127\./ || $ip =~ /^169\.254\./ || $ip =~ /^fe[89ab][0-9a-f]:/i;
          print 1;
          exit;
        }
      }
    ')"
    if [[ "$usable" == "1" ]]; then
      printf '%s\n' "$interfaces"
      return
    fi
    sleep 1
  done
  echo "error: container did not report an interface address" >&2
  exit 1
}

verify_running_contracts() {
  local runtime_json pid cgroup_file host_owner
  runtime_json="$(pvesh get "/nodes/${node}/lxc/${vmid}/status/current" --output-format json)"
  pid="$(printf '%s' "$runtime_json" | json_field pid)"
  if [[ -z "$pid" || "$pid" == "0" || ! -d "/proc/$pid" ]]; then
    echo "error: status/current did not expose a usable CT init PID" >&2
    printf '%s\n' "$runtime_json" >&2
    exit 1
  fi
  echo "runtime status: $runtime_json"
  echo "interfaces:"
  wait_for_address

  lxc-attach -n "$vmid" --clear-env -u "$OCI_UID" -g "$OCI_GID" -- \
    /bin/sh -c 'printf "calagopus-pve-smoke\n" > /home/container/smoke-marker && cat /home/container/smoke-marker'

  if [[ "$(cat "$data_dir/smoke-marker")" != "calagopus-pve-smoke" ]]; then
    echo "error: host-backed /home/container marker mismatch" >&2
    exit 1
  fi
  host_owner="$(stat -c '%u:%g' "$data_dir/smoke-marker")"
  if [[ "$host_owner" != "${HOST_DATA_UID}:${HOST_DATA_GID}" ]]; then
    echo "error: mount idmap produced host owner $host_owner, expected ${HOST_DATA_UID}:${HOST_DATA_GID}" >&2
    exit 1
  fi
  echo "mount idmap: container ${OCI_UID}:${OCI_GID} -> host $host_owner"

  cgroup_file="/proc/${pid}/cgroup"
  if [[ ! -r "$cgroup_file" ]]; then
    echo "error: cannot read $cgroup_file" >&2
    exit 1
  fi
  echo "cgroup: $(cat "$cgroup_file")"

  if [[ ! -r "/proc/${pid}/net/tcp" || ! -r "/proc/${pid}/net/tcp6" \
      || ! -r "/proc/${pid}/net/udp" || ! -r "/proc/${pid}/net/udp6" ]]; then
    echo "error: CT network namespace proc files are unavailable through /proc/$pid/net" >&2
    exit 1
  fi
  if ! awk 'NR > 1 && $4 == "0A" { found = 1 } END { exit !found }' \
      "/proc/${pid}/net/tcp" "/proc/${pid}/net/tcp6"; then
    echo "error: no TCP listener was visible through the CT init PID network namespace" >&2
    exit 1
  fi
  echo "proc net: tcp/tcp6/udp/udp6 are readable for init PID $pid"
}

configure_runtime_contracts() {
  local wrapper_path console_log managed_hosts
  wrapper_path="$data_dir/runtime-wrapper.sh"
  console_log="$data_dir/runtime-console.log"
  managed_hosts="$managed_dir/hosts"

  if pct status "$vmid" | grep -q running; then
    pct stop "$vmid"
  fi

  cat >"$wrapper_path" <<'EOF'
#!/bin/sh
printf 'calagopus-init-wrapper %s\n' "${CALAGOPUS_SMOKE:-missing}"
exec nginx -g 'daemon off;'
EOF
  chown "$HOST_DATA_UID:$HOST_DATA_GID" "$wrapper_path"
  chmod 0755 "$wrapper_path"

  if [[ -d "$managed_parent" ]]; then
    managed_parent_mode="$(stat -c '%a' "$managed_parent")"
  else
    mkdir -p "$managed_parent"
    managed_parent_created=1
  fi
  mkdir -p "$managed_dir"
  chmod 0711 "$managed_parent" "$managed_dir"
  cat >"$managed_hosts" <<'EOF'
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
# calagopus-managed-hosts
EOF
  chmod 0644 "$managed_hosts"
  rm -f "$console_log"

  perl -MPVE::LXC::Config - "$vmid" "$console_log" "$managed_hosts" <<'PERL'
use strict;
use warnings;

my ($vmid, $console_log, $managed_hosts) = @ARGV;

sub mount_target {
    my ($entry) = @_;
    return undef if !defined($entry);
    my @fields = grep { length($_) } split(/\s+/, $entry);
    return scalar(@fields) >= 2 ? $fields[1] : undef;
}

PVE::LXC::Config->lock_config($vmid, sub {
    my $conf = PVE::LXC::Config->load_config($vmid);
    my @environment;
    push @environment, split(/\0/, $conf->{env}, -1)
        if defined($conf->{env}) && length($conf->{env});
    for my $entry (@{$conf->{lxc} // []}) {
        next if ref($entry) ne 'ARRAY' || @$entry < 2;
        push @environment, $entry->[1]
            if $entry->[0] eq 'lxc.environment' || $entry->[0] eq 'lxc.environment.runtime';
    }
    my %index;
    for my $i (0 .. $#environment) {
        my ($name) = split(/=/, $environment[$i], 2);
        $index{$name} = $i if defined($name) && length($name);
    }
    my $smoke_environment = 'CALAGOPUS_SMOKE=runtime-config';
    if (exists($index{CALAGOPUS_SMOKE})) {
        $environment[$index{CALAGOPUS_SMOKE}] = $smoke_environment;
    } else {
        push @environment, $smoke_environment;
    }

    my @lxc = grep {
        my $keep = ref($_) ne 'ARRAY'
            || @$_ < 2
            || ($_->[0] ne 'lxc.environment'
                && $_->[0] ne 'lxc.environment.runtime'
                && $_->[0] ne 'lxc.signal.halt'
                && $_->[0] ne 'lxc.init.cmd'
                && $_->[0] ne 'lxc.console.logfile'
                && $_->[0] ne 'lxc.cgroup2.memory.max'
                && $_->[0] ne 'lxc.cgroup2.memory.swap.max');
        if ($keep && ref($_) eq 'ARRAY' && @$_ >= 2 && $_->[0] eq 'lxc.mount.entry') {
            my $target = mount_target($_->[1]);
            $keep = 0 if defined($target) && $target eq 'etc/hosts';
        }
        $keep;
    } @{$conf->{lxc} // []};

    $conf->{env} = join("\0", @environment);
    push @lxc, map { ['lxc.environment', $_] } @environment;
    push @lxc, ['lxc.signal.halt', 'SIGTERM'];
    push @lxc, ['lxc.init.cmd', '/bin/sh /home/container/runtime-wrapper.sh'];
    push @lxc, ['lxc.console.logfile', $console_log];
    push @lxc, ['lxc.cgroup2.memory.max', 'max'];
    push @lxc, ['lxc.cgroup2.memory.swap.max', 'max'];
    push @lxc, [
        'lxc.mount.entry',
        "$managed_hosts etc/hosts none bind,ro,create=file 0 0",
    ];
    $conf->{lxc} = \@lxc;
    PVE::LXC::Config->write_config($vmid, $conf);
});
PERL

  CONSOLE_LOG="$console_log"
}

wait_for_stopped() {
  local attempt
  for attempt in $(seq 1 40); do
    if pct status "$vmid" | grep -q stopped; then
      return
    fi
    sleep 0.25
  done
  echo "error: CT $vmid did not stop after lxc-stop request" >&2
  exit 1
}

wait_for_running_pid() {
  local attempt status_json pid
  for attempt in $(seq 1 40); do
    status_json="$(pvesh get "/nodes/${node}/lxc/${vmid}/status/current" --output-format json 2>/dev/null || true)"
    pid="$(printf '%s' "$status_json" | json_field pid 2>/dev/null || true)"
    if [[ -n "$pid" ]] && pct status "$vmid" 2>/dev/null | grep -q running; then
      return
    fi
    sleep 0.25
  done
  echo "error: CT $vmid did not expose a stable running PID" >&2
  exit 1
}

start_ct() {
  local attempt output
  for attempt in $(seq 1 20); do
    if output="$(pct start "$vmid" 2>&1)"; then
      return
    fi
    if [[ "$output" != *"monitor socket"* && "$output" != *"got timeout"* \
        && "$output" != *"unable to get PID for CT"* ]]; then
      printf '%s\n' "$output" >&2
      return 1
    fi
    if pct status "$vmid" 2>/dev/null | grep -q running; then
      return
    fi
    echo "start: retrying after transient monitor teardown (attempt $attempt)" >&2
    sleep 0.5
  done
  printf '%s\n' "$output" >&2
  return 1
}

verify_runtime_contracts() {
  local attempt runtime_json pid cgroup_path memory_max swap_max
  configure_runtime_contracts
  start_ct

  for attempt in $(seq 1 40); do
    if [[ -f "$CONSOLE_LOG" ]] \
        && grep -Fq 'calagopus-init-wrapper runtime-config' "$CONSOLE_LOG"; then
      break
    fi
    sleep 0.25
  done
  if [[ ! -f "$CONSOLE_LOG" ]] \
      || ! grep -Fq 'calagopus-init-wrapper runtime-config' "$CONSOLE_LOG"; then
    echo "error: lxc.init.cmd/environment output was not captured by lxc.console.logfile" >&2
    exit 1
  fi
  echo "runtime config: init command, environment, and console logfile are active"

  if ! lxc-attach -n "$vmid" --clear-env -u "$OCI_UID" -g "$OCI_GID" -- \
      /bin/sh -c 'grep -Fq "calagopus-managed-hosts" /etc/hosts'; then
    echo "error: managed read-only /etc/hosts bind was not visible in the CT" >&2
    exit 1
  fi
  if lxc-attach -n "$vmid" --clear-env -u "$OCI_UID" -g "$OCI_GID" -- \
      /bin/sh -c 'printf "unexpected-write\n" >> /etc/hosts' >/dev/null 2>&1; then
    echo "error: managed /etc/hosts bind unexpectedly allowed writes" >&2
    exit 1
  fi
  echo "managed file bind: /etc/hosts is visible and read-only"

  runtime_json="$(pvesh get "/nodes/${node}/lxc/${vmid}/status/current" --output-format json)"
  pid="$(printf '%s' "$runtime_json" | json_field pid)"
  cgroup_path="$(awk -F: '$1 == "0" {print $3; exit}' "/proc/${pid}/cgroup")"
  if [[ -z "$cgroup_path" ]]; then
    echo "error: the live PVE smoke test requires a cgroup v2 host" >&2
    exit 1
  fi
  memory_max="$(cat "/sys/fs/cgroup${cgroup_path}/memory.max")"
  swap_max="$(cat "/sys/fs/cgroup${cgroup_path}/memory.swap.max")"
  if [[ "$memory_max" != "max" || "$swap_max" != "max" ]]; then
    echo "error: PVE did not preserve unlimited cgroup2 memory settings on start" >&2
    echo "memory.max=$memory_max memory.swap.max=$swap_max" >&2
    exit 1
  fi
  if ! pct config "$vmid" | grep -Fq 'lxc.cgroup2.memory.max: max' \
      || ! pct config "$vmid" | grep -Fq 'lxc.cgroup2.memory.swap.max: max'; then
    echo "error: PVE dropped unlimited cgroup2 memory settings from CT config" >&2
    exit 1
  fi
  echo "cgroup2: PVE preserved memory.max=max and memory.swap.max=max after start"

  verify_running_contracts

  lxc-stop -n "$vmid" --nowait --nokill
  wait_for_stopped
  echo "shutdown: lxc-stop --nowait --nokill honored lxc.signal.halt"

  start_ct
  wait_for_running_pid
  pct stop "$vmid"
  if ! pct status "$vmid" | grep -q stopped; then
    echo "error: pct stop did not hard-stop CT $vmid" >&2
    exit 1
  fi
  echo "shutdown: pct stop hard-stop path works"
}

stop_and_destroy_ct() {
  if pct status "$vmid" | grep -q running; then
    if ! pct shutdown "$vmid" --timeout 10; then
      pct stop "$vmid"
    fi
  fi
  pct destroy "$vmid" --purge 1
  created_ct=0
}

echo "PVE $version node=$node vmid=$vmid image=$normalized_image"
ensure_template
create_ct
configure_data_mount
start_ct
verify_running_contracts
verify_runtime_contracts

# Recreate the rootfs while keeping the host-backed data path. This exercises the
# persistence assumption used by staged image replacement.
echo "replacement: recreating CT rootfs while preserving $data_dir"
stop_and_destroy_ct
create_ct
configure_data_mount
start_ct
persisted_marker="$(lxc-attach -n "$vmid" --clear-env -u "$OCI_UID" -g "$OCI_GID" -- \
  /bin/sh -c 'cat /home/container/smoke-marker')"
if [[ "$persisted_marker" != "calagopus-pve-smoke" ]]; then
  echo "error: persistent server data did not survive CT rootfs replacement" >&2
  exit 1
fi
echo "replacement: persistent marker survived rootfs recreation"
verify_running_contracts

echo "PASS: PVE LXC OCI lifecycle/runtime-config/idmap/procfs/replacement contracts"
