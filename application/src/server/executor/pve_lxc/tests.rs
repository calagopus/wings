use super::*;

#[test]
fn successful_start_followed_by_first_stopped_probe_emits_stopped() {
    let mut seen_running = false;
    let status = PveProcessHandle::observed_status(
        cli::ContainerStatus::Stopped,
        true,
        &mut seen_running,
        Some((42, true)),
    );
    assert!(matches!(
        status,
        Some(crate::server::executor::ProcessStatus::Stopped {
            exit_code: 42,
            oom_killed: true,
        })
    ));
}

#[test]
fn parses_managed_exit_status_strictly() {
    assert_eq!(
        PveProcessHandle::parse_exit_status("exit_code=137\noom_killed=1\n"),
        Some((137, true))
    );
    assert_eq!(
        PveProcessHandle::parse_exit_status("oom_killed=0\nexit_code=0\n"),
        Some((0, false))
    );
    assert_eq!(PveProcessHandle::parse_exit_status("exit_code=0\n"), None);
    assert_eq!(
        PveProcessHandle::parse_exit_status("exit_code=nope\noom_killed=0\n"),
        None
    );
}

#[tokio::test]
async fn runtime_log_never_exceeds_its_retention_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("console.log");
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .unwrap();
    let mut size = 0;

    PveProcessHandle::write_bounded_log(&mut file, &mut size, 8, b"first", true)
        .await
        .unwrap();
    PveProcessHandle::write_bounded_log(&mut file, &mut size, 8, b"second", true)
        .await
        .unwrap();
    PveProcessHandle::write_bounded_log(&mut file, &mut size, 8, b"oversized-line", true)
        .await
        .unwrap();
    file.flush().await.unwrap();

    let data = tokio::fs::read(&path).await.unwrap();
    assert_eq!(data, b"ed-line\n");
    assert_eq!(data.len(), 8);
    assert_eq!(size, 8);
}

#[test]
fn static_allocation_uses_explicit_isolated_vlan_network() {
    assert_eq!(
        PveLxcExecutor::network_for_allocation(
            "vmbr0",
            Some(30),
            Some(24),
            Some("10.0.30.1"),
            Some("10.0.30.42"),
        )
        .unwrap(),
        "name=eth0,bridge=vmbr0,firewall=1,tag=30,ip=10.0.30.42/24,gw=10.0.30.1,type=veth"
    );
}

#[test]
fn static_allocation_never_derives_the_management_network() {
    let error =
        PveLxcExecutor::network_for_allocation("vmbr0", Some(30), None, None, Some("10.0.30.42"))
            .unwrap_err();
    assert!(error.to_string().contains("network_prefix"));

    assert_eq!(
        PveLxcExecutor::dhcp_network("vmbr0", Some(30)).unwrap(),
        "name=eth0,bridge=vmbr0,firewall=1,tag=30,ip=dhcp,type=veth,host-managed=1"
    );
}

#[test]
fn network_bridge_rejects_option_injection() {
    assert!(PveLxcExecutor::dhcp_network("vmbr0 firewall=0", None).is_err());
    assert!(PveLxcExecutor::dhcp_network("vmbr0,firewall=0", None).is_err());
}

#[test]
fn accepts_pve_9_2_and_newer() {
    assert_eq!(
        PveVersion::parse("pve-manager/9.2.1/abcdef")
            .ok()
            .map(PveVersion::is_supported),
        Some(true)
    );
    assert_eq!(
        PveVersion::parse("pve-manager/10.0.0/abcdef")
            .ok()
            .map(PveVersion::is_supported),
        Some(true)
    );
}

#[test]
fn rejects_pve_older_than_9_2() {
    assert_eq!(
        PveVersion::parse("pve-manager/9.1.7/abcdef")
            .ok()
            .map(PveVersion::is_supported),
        Some(false)
    );
}

#[test]
fn pve_runtime_only_targets_the_local_node() {
    assert_eq!(
        PveLxcExecutor::runtime_node("", "pve-a").ok().as_deref(),
        Some("pve-a")
    );
    assert_eq!(
        PveLxcExecutor::runtime_node("pve-a", "pve-a")
            .ok()
            .as_deref(),
        Some("pve-a")
    );
    assert!(PveLxcExecutor::runtime_node("pve-b", "pve-a").is_err());
}

#[test]
fn proc_net_parser_reports_listeners_and_udp_reservations() {
    fn proc_ipv4(address: std::net::Ipv4Addr) -> String {
        format!("{:08X}", u32::from_le_bytes(address.octets()))
    }

    let any = proc_ipv4(std::net::Ipv4Addr::UNSPECIFIED);
    let loopback = proc_ipv4(std::net::Ipv4Addr::LOCALHOST);
    let tcp = format!(
        "  sl  local_address rem_address   st\n   0: {any}:63DD 00000000:0000 0A\n   1: {loopback}:C350 0100007F:9C40 01\n"
    );
    let udp = format!(
        "  sl  local_address rem_address   st\n   0: {any}:4ABC 00000000:0000 07\n   1: {loopback}:D431 0100007F:0035 01\n   2: {any}:0000 00000000:0000 07\n"
    );

    assert_eq!(
        PveLxcExecutor::parse_proc_net_ports(&tcp, ProcNetFamily::Ipv4, true).unwrap(),
        vec![BoundPort {
            family: ProcNetFamily::Ipv4,
            address: None,
            port: 25565,
        }]
    );
    assert_eq!(
        PveLxcExecutor::parse_proc_net_ports(&udp, ProcNetFamily::Ipv4, false).unwrap(),
        vec![
            BoundPort {
                family: ProcNetFamily::Ipv4,
                address: None,
                port: 19132,
            },
            BoundPort {
                family: ProcNetFamily::Ipv4,
                address: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                port: 54321,
            },
        ]
    );
}

#[test]
fn proc_net_parser_decodes_ipv6_and_matches_ipv4_mapped_bindings() {
    fn proc_ipv6(address: std::net::Ipv6Addr) -> String {
        address
            .octets()
            .chunks_exact(4)
            .map(|chunk| {
                format!(
                    "{:08X}",
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                )
            })
            .collect::<String>()
    }

    let address: std::net::Ipv6Addr = "fd12:3456::20".parse().unwrap();
    let raw = proc_ipv6(address);
    let table = format!(
        "  sl  local_address rem_address   st\n   0: {raw}:63DD 00000000000000000000000000000000:0000 0A\n"
    );
    assert_eq!(
        PveLxcExecutor::parse_proc_net_ports(&table, ProcNetFamily::Ipv6, true).unwrap(),
        vec![BoundPort {
            family: ProcNetFamily::Ipv6,
            address: Some(IpAddr::V6(address)),
            port: 25565,
        }]
    );

    let mapped = BoundPort {
        family: ProcNetFamily::Ipv6,
        address: Some(IpAddr::V6("::ffff:10.42.0.20".parse().unwrap())),
        port: 25565,
    };
    assert!(PveLxcExecutor::bound_port_matches_address(
        mapped,
        "10.42.0.20".parse().unwrap()
    ));
    assert!(!PveLxcExecutor::bound_port_matches_address(
        mapped,
        "10.42.0.21".parse().unwrap()
    ));
    assert!(PveLxcExecutor::bound_port_matches_address(
        BoundPort {
            family: ProcNetFamily::Ipv6,
            address: None,
            port: 19132,
        },
        "fd12:3456::20".parse().unwrap()
    ));
    assert!(!PveLxcExecutor::bound_port_matches_address(
        BoundPort {
            family: ProcNetFamily::Ipv4,
            address: None,
            port: 19132,
        },
        "fd12:3456::20".parse().unwrap()
    ));
}

#[test]
fn ownership_tags_require_marker_and_server_uuid() {
    let server_uuid = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let server_tag = PveLxcExecutor::server_tag("calagopus", server_uuid);
    let tags = vec!["calagopus".to_string(), server_tag];

    assert_eq!(
        PveLxcExecutor::server_from_tags("calagopus", &tags),
        Some(server_uuid)
    );
    assert_eq!(PveLxcExecutor::server_from_tags("other", &tags), None);
}

#[test]
fn helper_tags_are_distinct_from_servers_and_roles() {
    let server_uuid = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let installer_tag = PveLxcExecutor::helper_tag(
        "calagopus",
        PveLxcExecutor::INSTALLER_HELPER_ROLE,
        server_uuid,
    );
    let tags = vec!["calagopus".to_string(), installer_tag];

    assert_eq!(PveLxcExecutor::server_from_tags("calagopus", &tags), None);
    assert_eq!(
        PveLxcExecutor::helper_from_tags("calagopus", PveLxcExecutor::INSTALLER_HELPER_ROLE, &tags,),
        Some(server_uuid)
    );
    assert_eq!(
        PveLxcExecutor::helper_from_tags("calagopus", PveLxcExecutor::SCRIPT_HELPER_ROLE, &tags,),
        None
    );
    assert_eq!(
        PveLxcExecutor::helper_from_tags("other", PveLxcExecutor::INSTALLER_HELPER_ROLE, &tags,),
        None
    );
}

#[test]
fn replacement_tags_are_distinct_and_recoverable() {
    let server_uuid = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let replacement_tag = PveLxcExecutor::replacement_tag("calagopus", server_uuid);
    let tags = vec!["calagopus".to_string(), replacement_tag];

    assert_eq!(PveLxcExecutor::server_from_tags("calagopus", &tags), None);
    assert_eq!(
        PveLxcExecutor::replacement_from_tags("calagopus", &tags),
        Some(server_uuid)
    );
}

#[test]
fn image_drift_plan_recovers_staged_replacements() {
    let desired = "calagopus-image-new";
    let existing = cli::ClusterContainer {
        vmid: 101,
        node: "pve-a".to_string(),
        status: Some(cli::ContainerStatus::Stopped),
        tags: vec!["calagopus-image-old".to_string()],
    };
    let staged = cli::ClusterContainer {
        vmid: 102,
        node: "pve-a".to_string(),
        status: Some(cli::ContainerStatus::Stopped),
        tags: vec![desired.to_string()],
    };

    assert_eq!(
        PveLxcExecutor::plan_server_container(Some(&existing), Some(&staged), desired),
        ServerContainerPlan::ReplaceWithStaged {
            old_vmid: 101,
            staged_vmid: 102,
        }
    );
    assert_eq!(
        PveLxcExecutor::plan_server_container(None, Some(&staged), desired),
        ServerContainerPlan::RecoverStaged { staged_vmid: 102 }
    );
}

#[test]
fn image_drift_plan_discards_stale_staging_without_replacing_good_container() {
    let desired = "calagopus-image-current";
    let existing = cli::ClusterContainer {
        vmid: 101,
        node: "pve-a".to_string(),
        status: Some(cli::ContainerStatus::Stopped),
        tags: vec![desired.to_string()],
    };
    let stale = cli::ClusterContainer {
        vmid: 102,
        node: "pve-a".to_string(),
        status: Some(cli::ContainerStatus::Stopped),
        tags: vec!["calagopus-image-old-attempt".to_string()],
    };

    assert_eq!(
        PveLxcExecutor::plan_server_container(Some(&existing), Some(&stale), desired),
        ServerContainerPlan::Reuse {
            vmid: 101,
            stale_replacement: Some(102),
        }
    );
    assert_eq!(
        PveLxcExecutor::plan_server_container(None, Some(&stale), desired),
        ServerContainerPlan::CreateFresh {
            stale_replacement: Some(102),
        }
    );
}

#[test]
fn owned_container_lookup_rejects_duplicate_claims() {
    let server_uuid = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let tags = vec![
        "calagopus".to_string(),
        PveLxcExecutor::server_tag("calagopus", server_uuid),
    ];
    let containers = vec![
        cli::ClusterContainer {
            vmid: 101,
            node: "pve-a".to_string(),
            status: Some(cli::ContainerStatus::Stopped),
            tags: tags.clone(),
        },
        cli::ClusterContainer {
            vmid: 102,
            node: "pve-a".to_string(),
            status: Some(cli::ContainerStatus::Stopped),
            tags,
        },
    ];

    assert!(
        PveLxcExecutor::owned_server_container(&containers, "pve-a", "calagopus", server_uuid,)
            .is_err()
    );
    assert_eq!(
        PveLxcExecutor::owned_server_container(&containers, "pve-b", "calagopus", server_uuid,)
            .ok()
            .flatten(),
        None
    );
}

#[test]
fn owned_helper_lookup_rejects_duplicate_claims() {
    let server_uuid = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let tags = vec![
        "calagopus".to_string(),
        PveLxcExecutor::helper_tag(
            "calagopus",
            PveLxcExecutor::INSTALLER_HELPER_ROLE,
            server_uuid,
        ),
    ];
    let containers = vec![
        cli::ClusterContainer {
            vmid: 201,
            node: "pve-a".to_string(),
            status: Some(cli::ContainerStatus::Running),
            tags: tags.clone(),
        },
        cli::ClusterContainer {
            vmid: 202,
            node: "pve-a".to_string(),
            status: Some(cli::ContainerStatus::Stopped),
            tags,
        },
    ];

    assert!(
        PveLxcExecutor::owned_helper_container(
            &containers,
            "pve-a",
            "calagopus",
            PveLxcExecutor::INSTALLER_HELPER_ROLE,
            server_uuid,
        )
        .is_err()
    );
    assert_eq!(
        PveLxcExecutor::owned_helper_container(
            &containers,
            "pve-a",
            "calagopus",
            PveLxcExecutor::SCRIPT_HELPER_ROLE,
            server_uuid,
        )
        .ok()
        .flatten(),
        None
    );
}

#[test]
fn direct_bridge_firewall_spec_targets_container_addresses_without_published_bindings() {
    let server_uuid = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let mappings = HashMap::from([
        (
            compact_str::CompactString::from("10.42.0.20"),
            vec![25566, 25565, 25565],
        ),
        (compact_str::CompactString::from("10.42.0.21"), vec![19132]),
    ]);
    let rules = vec![crate::server::firewall::FirewallRule {
        action: crate::server::firewall::FirewallRuleAction::Deny,
        protocols: HashSet::from([crate::server::firewall::FirewallRuleProtocol::Tcp]),
        sources: Vec::new(),
        ports: None,
        source_file: None,
    }];
    let spec = PveLxcExecutor::direct_bridge_firewall_spec(
        server_uuid,
        &mappings,
        &rules,
        vec![
            "fd12:3456::20".parse().unwrap(),
            "10.42.0.20".parse().unwrap(),
            "10.42.0.20".parse().unwrap(),
        ],
        None,
    );

    assert!(spec.bindings.is_empty());
    assert_eq!(spec.container_ports, vec![19132, 25565, 25566]);
    assert_eq!(
        spec.container_ips,
        vec![
            "10.42.0.20".parse::<IpAddr>().unwrap(),
            "fd12:3456::20".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(spec.rules, rules);

    let concrete = crate::server::firewall::expand_rules(&spec);
    assert_eq!(concrete.len(), 6);
    assert!(
        concrete
            .iter()
            .all(|rule| matches!(rule.dst, crate::server::firewall::RuleDst::Container { .. }))
    );
}

#[test]
fn console_input_uses_terminal_enter_without_doubling_crlf() {
    assert_eq!(
        PveProcessHandle::normalize_console_input(b"list\n".to_vec()),
        b"list\r"
    );
    assert_eq!(
        PveProcessHandle::normalize_console_input(b"first\r\nsecond\n".to_vec()),
        b"first\rsecond\r"
    );
    assert_eq!(
        PveProcessHandle::normalize_console_input(vec![0x03]),
        vec![0x03]
    );
    assert!(PveProcessHandle::is_pct_console_banner(
        b"Connected to tty 0\r"
    ));
    assert!(PveProcessHandle::is_pct_console_banner(
        b"Type <Ctrl+z q> to exit the console, <Ctrl+z Ctrl+z> to enter Ctrl+z itself\r"
    ));
    assert!(!PveProcessHandle::is_pct_console_banner(
        b"[Server thread/INFO]: Connected to tty 0"
    ));
}

#[test]
fn halt_signal_matches_wings_stop_semantics() {
    assert_eq!(
        PveProcessHandle::halt_signal("signal", Some("SIGABRT")),
        Some("SIGABRT".to_string())
    );
    assert_eq!(
        PveProcessHandle::halt_signal("signal", Some("c")),
        Some("SIGINT".to_string())
    );
    assert_eq!(
        PveProcessHandle::halt_signal("signal", Some("SIGTERM")),
        Some("SIGTERM".to_string())
    );
    assert_eq!(
        PveProcessHandle::halt_signal("signal", Some("SIGQUIT")),
        Some("SIGQUIT".to_string())
    );
    assert_eq!(
        PveProcessHandle::halt_signal("signal", Some("unexpected")),
        Some("SIGKILL".to_string())
    );
    assert_eq!(PveProcessHandle::halt_signal("command", Some("stop")), None);
}

#[test]
fn device_permissions_require_exact_pve_devn_semantics() {
    let path = std::path::Path::new("/dev/kvm");

    assert_eq!(
        PveLxcExecutor::device_deny_write("r", path).ok(),
        Some(true)
    );
    assert_eq!(
        PveLxcExecutor::device_deny_write("rw", path).ok(),
        Some(false)
    );
    assert_eq!(
        PveLxcExecutor::device_deny_write("wr", path).ok(),
        Some(false)
    );
    assert!(PveLxcExecutor::device_deny_write("w", path).is_err());
    assert!(PveLxcExecutor::device_deny_write("m", path).is_err());
    assert_eq!(
        PveLxcExecutor::device_deny_write("rwm", path).ok(),
        Some(false)
    );
    assert!(PveLxcExecutor::device_deny_write("rwx", path).is_err());
}

#[tokio::test]
async fn lxc_pid_limit_overrides_the_legacy_docker_setting() {
    let config = crate::config::Config::mock();
    config
        .mutate_in_place_for_testing()
        .docker
        .container_pid_limit = 256;
    assert_eq!(PveLxcExecutor::pids_limit(&config), Some(256));

    config
        .mutate_in_place_for_testing()
        .runtime
        .pve_lxc
        .pids_limit = Some(1024);
    assert_eq!(PveLxcExecutor::pids_limit(&config), Some(1024));

    config
        .mutate_in_place_for_testing()
        .runtime
        .pve_lxc
        .pids_limit = Some(0);
    assert_eq!(PveLxcExecutor::pids_limit(&config), None);
}

#[tokio::test]
async fn edge_ssh_user_is_configurable_and_validated() {
    let config = crate::config::Config::mock();
    {
        let inner = config.mutate_in_place_for_testing();
        inner.runtime.pve_lxc.edge_ssh_identity_path = "/root/edge-key".to_string();
        inner.runtime.pve_lxc.edge_known_hosts_path = "/root/known-hosts".to_string();
        inner.runtime.pve_lxc.edge_ssh_user = "edge-forward".to_string();
    }

    let resolved = PveLxcExecutor::edge_forwarding_config(&config)
        .expect("valid edge configuration")
        .expect("configured edge forwarding");
    assert_eq!(resolved.1, "edge-forward");

    config
        .mutate_in_place_for_testing()
        .runtime
        .pve_lxc
        .edge_ssh_user = "root@host".to_string();
    assert!(PveLxcExecutor::edge_forwarding_config(&config).is_err());
}
