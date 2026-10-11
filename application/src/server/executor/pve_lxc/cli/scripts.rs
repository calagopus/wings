pub(super) const APPLY_RUNTIME_CONFIG_PERL: &str = r#"
use strict;
use warnings;
use JSON::PP qw(decode_json);
use PVE::LXC::Config;

my $input;
{
    local $/;
    $input = <STDIN>;
}
my $payload = decode_json($input // '{}');
my $vmid = int($payload->{vmid} // 0);
die "invalid VMID\n" if $vmid <= 0;

my $overlay = $payload->{environment} // [];
die "environment must be an array\n" if ref($overlay) ne 'ARRAY';

my $managed_mounts = $payload->{managed_file_mounts};
my $managed_targets = $payload->{managed_file_targets};
my %managed_target;
if (defined($managed_mounts)) {
    die "managed_file_mounts must be an array\n" if ref($managed_mounts) ne 'ARRAY';
    die "managed_file_targets must be an array\n" if ref($managed_targets) ne 'ARRAY';
    for my $target (@$managed_targets) {
        die "invalid managed file target\n" if ref($target) || !defined($target) || !length($target);
        $managed_target{$target} = 1;
    }
    for my $mount (@$managed_mounts) {
        die "invalid managed file mount\n" if ref($mount) ne 'HASH';
        my $target = $mount->{target};
        my $entry = $mount->{entry};
        die "invalid managed file mount target\n"
            if ref($target) || !defined($target) || !exists($managed_target{$target});
        die "invalid managed file mount entry\n"
            if ref($entry) || !defined($entry) || !length($entry);
    }
}

sub mount_target {
    my ($entry) = @_;
    return undef if !defined($entry);
    my @fields = grep { length($_) } split(/\s+/, $entry);
    return scalar(@fields) >= 2 ? $fields[1] : undef;
}

PVE::LXC::Config->lock_config($vmid, sub {
    my $conf = PVE::LXC::Config->load_config($vmid);
    my @lxc = @{$conf->{lxc} // []};
    my @environment;

    if (defined($conf->{env}) && length($conf->{env})) {
        push @environment, split(/\0/, $conf->{env}, -1);
    }
    for my $entry (@lxc) {
        next if ref($entry) ne 'ARRAY' || @$entry < 2;
        push @environment, $entry->[1]
            if $entry->[0] eq 'lxc.environment' || $entry->[0] eq 'lxc.environment.runtime';
    }

    # PVE exposes the same values through both `env` and low-level
    # lxc.environment records. Collapse those views before applying the panel
    # overlay so each synchronization is idempotent.
    my @normalized;
    my %index;
    for my $variable (@environment) {
        my ($name) = split(/=/, $variable, 2);
        next if !defined($name) || !length($name);
        if (exists($index{$name})) {
            $normalized[$index{$name}] = $variable;
        } else {
            $index{$name} = scalar(@normalized);
            push @normalized, $variable;
        }
    }
    @environment = @normalized;
    for my $variable (@$overlay) {
        my ($name) = split(/=/, $variable, 2);
        die "invalid environment entry\n" if !defined($name) || !length($name);
        if (exists($index{$name})) {
            $environment[$index{$name}] = $variable;
        } else {
            $index{$name} = scalar(@environment);
            push @environment, $variable;
        }
    }

    @lxc = grep {
        my $keep = ref($_) ne 'ARRAY'
            || @$_ < 2
            || ($_->[0] ne 'lxc.environment'
                && $_->[0] ne 'lxc.environment.runtime'
                && $_->[0] ne 'lxc.signal.halt'
                && $_->[0] ne 'lxc.init.cmd'
                && $_->[0] ne 'lxc.console.logfile'
                && $_->[0] ne 'lxc.cgroup.cpuset.cpus'
                && $_->[0] ne 'lxc.cgroup2.cpuset.cpus'
                && $_->[0] ne 'lxc.cgroup.pids.max'
                && $_->[0] ne 'lxc.cgroup2.pids.max'
                && $_->[0] ne 'lxc.cgroup.blkio.weight'
                && $_->[0] ne 'lxc.cgroup2.io.weight'
                && $_->[0] ne 'lxc.cgroup.memory.limit_in_bytes'
                && $_->[0] ne 'lxc.cgroup2.memory.max'
                && $_->[0] ne 'lxc.cgroup.memory.memsw.limit_in_bytes'
                && $_->[0] ne 'lxc.cgroup2.memory.swap.max');
        if ($keep && defined($managed_mounts) && ref($_) eq 'ARRAY' && @$_ >= 2
                && $_->[0] eq 'lxc.mount.entry') {
            my $target = mount_target($_->[1]);
            $keep = 0 if defined($target) && exists($managed_target{$target});
        }
        $keep;
    } @lxc;
    # PVE 9.2 serializes its `env` property as lxc.environment.runtime, but
    # LXC 7 applies that subkey only to hooks. Mirror the merged environment
    # through lxc.environment so PID 1 receives both OCI and panel variables.
    $conf->{env} = join("\0", @environment);
    push @lxc, map { ['lxc.environment', $_] } @environment;
    if (defined($payload->{halt_signal}) && length($payload->{halt_signal})) {
        push @lxc, ['lxc.signal.halt', $payload->{halt_signal}];
    }
    if (defined($payload->{init_command}) && length($payload->{init_command})) {
        push @lxc, ['lxc.init.cmd', $payload->{init_command}];
    }
    if (defined($payload->{console_logfile}) && length($payload->{console_logfile})) {
        push @lxc, ['lxc.console.logfile', $payload->{console_logfile}];
    }
    if (defined($payload->{cpuset_cpus}) && length($payload->{cpuset_cpus})) {
        push @lxc, ['lxc.cgroup2.cpuset.cpus', $payload->{cpuset_cpus}];
    }
    if (defined($payload->{pids_limit}) && $payload->{pids_limit} > 0) {
        push @lxc, ['lxc.cgroup2.pids.max', $payload->{pids_limit}];
    }
    if (defined($payload->{io_weight}) && $payload->{io_weight} > 0) {
        push @lxc, ['lxc.cgroup2.io.weight', $payload->{io_weight}];
    }
    if ($payload->{memory_unlimited}) {
        push @lxc, ['lxc.cgroup2.memory.max', 'max'];
    }
    if ($payload->{swap_unlimited}) {
        push @lxc, ['lxc.cgroup2.memory.swap.max', 'max'];
    }
    if (defined($managed_mounts)) {
        push @lxc, map { ['lxc.mount.entry', $_->{entry}] } @$managed_mounts;
    }

    $conf->{lxc} = \@lxc;
    PVE::LXC::Config->write_config($vmid, $conf);
});
"#;

pub(super) const APPLY_FIREWALL_CONFIG_PERL: &str = r#"
use strict;
use warnings;
use JSON::PP qw(decode_json);
use PVE::Firewall;

my $input;
{
    local $/;
    $input = <STDIN>;
}
my $payload = decode_json($input // '{}');
my $vmid = int($payload->{vmid} // 0);
die "invalid VMID\n" if $vmid <= 0;
my $prefix = $payload->{managed_prefix} // '';
die "invalid managed prefix\n" if ref($prefix) || !length($prefix);
my $rules = $payload->{rules} // [];
my $ipsets = $payload->{ipsets} // {};
die "rules must be an array\n" if ref($rules) ne 'ARRAY';
die "ipsets must be an object\n" if ref($ipsets) ne 'HASH';

for my $rule (@$rules) {
    die "invalid firewall rule\n" if ref($rule) ne 'HASH';
    die "invalid firewall rule type\n"
        if ref($rule->{type}) || ($rule->{type} // '') ne 'in';
    die "invalid firewall rule action\n"
        if ref($rule->{action}) || ($rule->{action} // '') !~ /\A(?:ACCEPT|DROP)\z/;
    die "invalid firewall rule interface\n"
        if ref($rule->{iface}) || ($rule->{iface} // '') !~ /\A[A-Za-z0-9_.-]+\z/;
    if (defined($rule->{proto})) {
        die "invalid firewall rule protocol\n"
            if ref($rule->{proto}) || $rule->{proto} !~ /\A(?:tcp|udp)\z/;
    }
    if (defined($rule->{dport})) {
        die "invalid firewall rule destination port\n"
            if ref($rule->{dport}) || $rule->{dport} !~ /\A[0-9]+(?:,[0-9]+)*\z/;
        for my $port (split(/,/, $rule->{dport})) {
            die "invalid firewall rule destination port\n" if $port < 1 || $port > 65535;
        }
    }
    if (defined($rule->{source})) {
        die "invalid firewall rule source\n"
            if ref($rule->{source}) || $rule->{source} =~ /[\x00\r\n]/;
    }
}

# Match the pve-firewall daemon's initialization before loading and rewriting
# existing cluster or guest rules.
PVE::Firewall::init();

PVE::Firewall::lock_vmfw_conf($vmid, 10, sub {
    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $conf = PVE::Firewall::load_vmfw_conf($cluster_conf, 'ct', $vmid);

    $conf->{rules} = [grep {
        my $comment = $_->{comment} // '';
        index($comment, $prefix) != 0;
    } @{$conf->{rules} // []}];

    for my $name (keys %{$conf->{ipset} // {}}) {
        my $comment = $conf->{ipset_comments}->{$name} // '';
        next if index($comment, $prefix) != 0;
        delete $conf->{ipset}->{$name};
        delete $conf->{ipset_comments}->{$name};
    }

    for my $name (keys %$ipsets) {
        die "invalid ipset name\n" if $name !~ /^[A-Za-z][A-Za-z0-9_-]{0,30}$/;
        my $set = $ipsets->{$name};
        die "ipset entries must be an array\n" if ref($set) ne 'ARRAY';
        $conf->{ipset}->{$name} = [map { { cidr => $_ } } @$set];
        $conf->{ipset_comments}->{$name} = "$prefix source file";
    }

    unshift @{$conf->{rules}}, @$rules;
    if (@$rules) {
        # Wings owns firewall mode for its tagged containers so the guest
        # behavior matches the panel's default-allow rule model.
        $conf->{options}->{enable} = 1;
        $conf->{options}->{policy_in} = 'ACCEPT';
    } elsif (!@{$conf->{rules}}) {
        $conf->{options}->{enable} = 0;
    }

    PVE::Firewall::save_vmfw_conf($vmid, $conf);
});
"#;
