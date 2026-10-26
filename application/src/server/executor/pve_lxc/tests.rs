use super::*;

#[test]
fn auto_rootfs_selection_uses_largest_sufficient_storage_deterministically() {
    let storages = vec![
        cli::LxcStorage {
            name: "pool-b".to_string(),
            total_bytes: 900,
            available_bytes: 400,
        },
        cli::LxcStorage {
            name: "pool-a".to_string(),
            total_bytes: 800,
            available_bytes: 400,
        },
        cli::LxcStorage {
            name: "pool-c".to_string(),
            total_bytes: 700,
            available_bytes: 399,
        },
    ];

    assert_eq!(
        PveLxcExecutor::select_rootfs_storage("auto", 400, &storages).unwrap(),
        "pool-a"
    );
}

#[test]
fn runtime_entrypoint_has_a_short_generic_network_gate() {
    let script = PveProcessHandle::runtime_entrypoint_script("/mnt/server/.wings-exit-status");

    assert!(script.contains("while [ \"$attempt\" -lt 120 ]"));
    assert!(script.contains("/proc/net/route"));
    assert!(script.contains("/proc/net/fib_trie"));
    assert!(script.contains("169") && script.contains("254"));
    assert!(script.contains("timed out waiting for usable network"));
    assert!(!script.contains("DHCP"));
    assert!(script.contains("/mnt/server/.wings-exit-status"));
}

#[test]
fn pending_start_does_not_publish_transient_running_state() {
    let mut seen_running = false;
    assert!(
        PveProcessHandle::observed_status(
            cli::ContainerStatus::Running,
            false,
            &mut seen_running,
            None,
        )
        .is_none()
    );
    assert!(!seen_running);
}

#[test]
fn installer_entrypoint_has_a_short_generic_network_gate() {
    let script = PveLxcExecutor::helper_entrypoint_script();

    assert!(script.contains("while [ \"$attempt\" -lt 120 ]"));
    assert!(script.contains("/proc/net/route"));
    assert!(script.contains("/proc/net/fib_trie"));
    assert!(script.contains("169") && script.contains("254"));
    assert!(script.contains("timed out waiting for usable network"));
    assert!(!script.contains("DHCP"));
}

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
fn stopped_forwarding_clear_retries_until_success() {
    let installed = AtomicBool::new(false);
    assert!(!PveProcessHandle::should_clear_forwarding(
        cli::ContainerStatus::Stopped,
        &installed,
    ));

    PveProcessHandle::record_forwarding_sync(&installed, true, false);
    assert!(!installed.load(Ordering::Acquire));
    PveProcessHandle::record_forwarding_sync(&installed, true, true);
    assert!(PveProcessHandle::should_clear_forwarding(
        cli::ContainerStatus::Stopped,
        &installed,
    ));
    assert!(installed.load(Ordering::Acquire));

    PveProcessHandle::record_forwarding_sync(&installed, false, false);
    assert!(PveProcessHandle::should_clear_forwarding(
        cli::ContainerStatus::Stopped,
        &installed,
    ));
    PveProcessHandle::record_forwarding_sync(&installed, false, true);
    assert!(!PveProcessHandle::should_clear_forwarding(
        cli::ContainerStatus::Stopped,
        &installed,
    ));
    assert!(!PveProcessHandle::should_clear_forwarding(
        cli::ContainerStatus::Running,
        &installed,
    ));

    let source = include_str!("server_process.rs");
    let monitor = source
        .split("let status_task = tokio::spawn")
        .nth(1)
        .unwrap()
        .split("let stats_cli")
        .next()
        .unwrap();
    assert!(source.contains("Arc::clone(&forwarding_installed)"));
    assert!(monitor.contains("sync_allocation_forwarding"));
    assert!(!monitor.contains(".stop("));
    assert!(!monitor.contains(".start("));
}

#[test]
fn adopted_sync_failure_path_cannot_stop_the_guest() {
    let source = include_str!("mod.rs");
    let attach = source
        .split("async fn attach_server_process")
        .nth(1)
        .unwrap()
        .split("async fn cleanup_server_process")
        .next()
        .unwrap();

    assert!(!attach.contains("stop_after_firewall_failure"));
    assert!(!attach.contains(".stop("));
}

#[test]
fn configuration_sync_policy_failure_cannot_stop_the_guest() {
    let source = include_str!("server_process.rs");
    let sync = source
        .split("async fn sync_configuration")
        .nth(1)
        .unwrap()
        .split("async fn start")
        .next()
        .unwrap();
    assert!(!sync.contains("stop_after_firewall_failure"));
    assert!(!sync.contains(".stop("));
}

#[test]
fn firewall_failure_cannot_skip_allocation_forwarding_sync() {
    let source = include_str!("server_process.rs");
    let sync = source
        .split("pub(super) async fn sync_firewall")
        .nth(1)
        .unwrap()
        .split("pub(super) async fn stop_after_firewall_failure")
        .next()
        .unwrap();
    assert!(sync.contains("if let Err(error) = self.firewall.sync(&spec).await"));
    assert!(sync.contains("PveLxcExecutor::sync_allocation_forwarding("));
    assert!(sync.contains("aggregate_reconciliation_errors"));
}

#[test]
fn missing_guest_address_is_aggregated_without_short_circuiting_reconciliation() {
    let (addresses, error) = PveProcessHandle::finish_address_resolution(
        Vec::new(),
        Some(anyhow::anyhow!("interface query failed")),
        1234,
    );
    assert!(addresses.is_empty());
    assert!(format!("{:#}", error.unwrap()).contains("interface query failed"));

    let source = include_str!("server_process.rs");
    let sync = source
        .split("pub(super) async fn sync_firewall")
        .nth(1)
        .unwrap()
        .split("pub(super) async fn stop_after_firewall_failure")
        .next()
        .unwrap();
    assert!(sync.contains("finish_address_resolution"));
    assert!(sync.contains("self.firewall.sync(&spec).await"));
    assert!(sync.contains("sync_allocation_forwarding"));
}

#[test]
fn startup_reconcile_updates_forwarding_for_all_known_servers() {
    let source = include_str!("mod.rs");
    let reconcile = source
        .split("async fn reconcile_firewall")
        .nth(1)
        .unwrap()
        .split("async fn setup_server_process")
        .next()
        .unwrap();

    assert!(reconcile.contains("Self::prepare_network_specs("));
    let address_failure = reconcile
        .split("failed to resolve Proxmox LXC addresses while reconciling server")
        .nth(1)
        .unwrap()
        .split("} else {")
        .next()
        .unwrap();
    assert!(!address_failure.contains("continue"));
    assert!(address_failure.contains("Vec::new()"));
    assert!(reconcile.contains("forwarding_specs.insert(server_uuid, spec)"));
    assert!(reconcile.contains("forwarding::without_binding_conflicts"));
    assert!(reconcile.contains("forwarding::sync_all(&forwarding_network, &forwarding_specs)"));
    assert!(reconcile.contains("aggregate_reconciliation_errors"));
}

#[test]
fn nonempty_allocation_mappings_require_network_policy_without_default() {
    let mut configuration = crate::server::configuration::ServerConfiguration::mock(
        uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31),
    );
    configuration.allocations.default = None;
    configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080]);

    assert!(PveLxcExecutor::network_policy_required(&configuration));
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
fn pve_lxc_always_uses_dhcp_on_the_configured_isolated_network() {
    assert_eq!(
        PveLxcExecutor::dhcp_network("vmbr0", Some(30)).unwrap(),
        "name=eth0,bridge=vmbr0,firewall=1,tag=30,ip=dhcp,type=veth"
    );
}

#[test]
fn dhcp_network_has_no_nonstandard_host_metadata() {
    assert_eq!(
        PveLxcExecutor::dhcp_network("vmbr0", Some(30)).unwrap(),
        "name=eth0,bridge=vmbr0,firewall=1,tag=30,ip=dhcp,type=veth"
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

#[test]
fn native_forwarding_maps_every_ipv4_allocation_for_tcp_and_udp() {
    let mut configuration = crate::server::configuration::ServerConfiguration::mock(
        uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31),
    );
    configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080, 10823]);
    configuration
        .allocations
        .mappings
        .insert("198.51.100.10".into(), vec![8080]);

    let spec = forwarding::ForwardingSpec::from_configuration(
        &configuration,
        "10.203.41.28".parse().unwrap(),
    )
    .unwrap()
    .unwrap();
    let script = forwarding::reconcile_script(configuration.uuid, &[], Some(&spec));

    for (ip, port) in [
        ("192.0.2.60", 8080),
        ("192.0.2.60", 10823),
        ("198.51.100.10", 8080),
    ] {
        for protocol in ["tcp", "udp"] {
            assert!(script.contains(&format!(
                "ip daddr {ip} {protocol} dport {port} dnat to 10.203.41.28:{port}"
            )));
            assert!(script.contains(&format!(
                "ip daddr 10.203.41.28 {protocol} dport {port} ct status dnat accept"
            )));
            assert!(script.contains(&format!(
                "ip daddr 10.203.41.28 {protocol} dport {port} ct status dnat masquerade"
            )));
        }
    }
}

#[test]
fn native_forwarding_discovers_only_its_servers_persisted_rules() {
    let server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let other = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let listing = format!(
        r#"table ip wings_pve_forward {{
	chain prerouting {{
		ip daddr 192.0.2.60 tcp dport 8080 comment "wings-pve:{server}" # handle 7
		ip daddr 198.51.100.10 tcp dport 8080 comment "wings-pve:{other}" # handle 8
	}}
	chain forward {{
		ip daddr 10.203.41.28 tcp dport 8080 accept comment "wings-pve:{server}" # handle 11
	}}
}}
"#
    );

    assert_eq!(
        forwarding::managed_rules(&listing)
            .unwrap()
            .into_iter()
            .filter(|rule| rule.server == server)
            .collect::<Vec<_>>(),
        vec![
            forwarding::ManagedRule::new_binding(
                server,
                "prerouting",
                7,
                "192.0.2.60".parse().unwrap(),
                8080,
            ),
            forwarding::ManagedRule::new(server, "forward", 11),
        ]
    );
}

#[test]
fn native_forwarding_reconcile_removes_only_the_servers_existing_rules() {
    let server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let rules = vec![
        forwarding::ManagedRule::new(server, "prerouting", 7),
        forwarding::ManagedRule::new(server, "forward", 11),
    ];

    let script = forwarding::reconcile_script(server, &rules, None);
    assert!(script.contains("delete rule ip wings_pve_forward prerouting handle 7"));
    assert!(script.contains("delete rule ip wings_pve_forward forward handle 11"));
    assert!(!script.contains("flush table"));
    assert!(!script.contains("delete table"));
}

#[test]
fn empty_allocation_mappings_clear_without_a_guest_address() {
    let configuration = crate::server::configuration::ServerConfiguration::mock(
        uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31),
    );

    assert_eq!(
        forwarding::ForwardingSpec::from_configuration(
            &configuration,
            "10.203.41.28".parse().unwrap()
        )
        .unwrap(),
        None
    );
}

#[test]
fn forwarding_network_context_validates_and_derives_guest_cidr() {
    let context = forwarding::NetworkContext::new("vmbr42", Some(24), Some("10.203.41.1"))
        .expect("valid forwarding network context");
    assert_eq!(context.bridge(), "vmbr42");
    assert_eq!(context.guest_cidr(), "10.203.41.0/24");

    for (bridge, prefix, gateway) in [
        ("", Some(24), Some("10.203.41.1")),
        ("vmbr0;flush", Some(24), Some("10.203.41.1")),
        ("vmbr0", Some(0), Some("10.203.41.1")),
        ("vmbr0", Some(33), Some("10.203.41.1")),
        ("vmbr0", Some(24), Some("not-an-ip")),
        ("vmbr0", Some(24), None),
    ] {
        assert!(forwarding::NetworkContext::new(bridge, prefix, gateway).is_err());
    }
}

#[test]
fn allocation_forwarding_selects_ipv4_from_the_configured_guest_subnet() {
    let addresses = vec![
        "172.16.0.20".parse::<IpAddr>().unwrap(),
        "10.203.41.28".parse::<IpAddr>().unwrap(),
        "192.168.50.8".parse::<IpAddr>().unwrap(),
    ];
    let context = forwarding::NetworkContext::new("vmbr42", Some(24), Some("10.203.41.1")).unwrap();

    assert_eq!(
        context.guest_destination(&addresses).unwrap(),
        "10.203.41.28".parse::<Ipv4Addr>().unwrap()
    );
}

#[test]
fn forwarding_network_rejects_loopback_and_link_local_destinations() {
    let loopback = forwarding::NetworkContext::new("vmbr42", Some(8), Some("127.0.0.1")).unwrap();
    assert!(
        loopback
            .guest_destination(&["127.0.0.2".parse().unwrap()])
            .is_err()
    );

    let link_local =
        forwarding::NetworkContext::new("vmbr42", Some(16), Some("169.254.1.1")).unwrap();
    assert!(
        link_local
            .guest_destination(&["169.254.1.2".parse().unwrap()])
            .is_err()
    );
}

#[test]
fn native_forwarding_reconcile_all_removes_orphans_and_installs_complete_desired_set() {
    let desired_server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let orphan = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let mut configuration = crate::server::configuration::ServerConfiguration::mock(desired_server);
    configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080]);
    let spec = forwarding::ForwardingSpec::from_configuration(
        &configuration,
        "10.203.41.28".parse().unwrap(),
    )
    .unwrap()
    .unwrap();
    let desired = std::collections::BTreeMap::from([(desired_server, spec)]);
    let network = forwarding::NetworkContext::new("vmbr42", Some(24), Some("10.203.41.1")).unwrap();

    let script = forwarding::replace_table_script(&network, &desired, true);

    assert!(
        script.starts_with("delete table ip wings_pve_forward\nadd table ip wings_pve_forward\n")
    );
    for chain in [
        "pve_conntrack_zone",
        "prerouting",
        "output",
        "forward",
        "postrouting",
    ] {
        assert!(script.contains(&format!("add chain ip wings_pve_forward {chain}")));
        assert!(!script.contains(&format!("flush chain ip wings_pve_forward {chain}")));
    }
    assert!(script.contains("iifname \"fwbr*\" ct zone set 1"));
    assert!(!script.contains("iifname \"fwbr*\" ip saddr"));
    assert!(
        script.contains(
            "ip saddr 10.203.41.0/24 oifname != \"vmbr42\" oifname != \"fwbr*\" masquerade"
        )
    );
    assert!(script.contains(&format!("comment \"wings-pve:{desired_server}\"")));
    assert!(!script.contains(&orphan.to_string()));

    let absent_script = forwarding::replace_table_script(&network, &desired, false);
    assert!(absent_script.starts_with("add table ip wings_pve_forward\n"));
    assert!(!absent_script.contains("delete table"));
}

#[test]
fn native_forwarding_rejects_duplicate_desired_binding_owners() {
    let first = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let second = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let mut first_configuration = crate::server::configuration::ServerConfiguration::mock(first);
    first_configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080]);
    let mut second_configuration = crate::server::configuration::ServerConfiguration::mock(second);
    second_configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080]);
    let desired = std::collections::BTreeMap::from([
        (
            first,
            forwarding::ForwardingSpec::from_configuration(
                &first_configuration,
                "10.203.41.28".parse().unwrap(),
            )
            .unwrap()
            .unwrap(),
        ),
        (
            second,
            forwarding::ForwardingSpec::from_configuration(
                &second_configuration,
                "10.203.41.29".parse().unwrap(),
            )
            .unwrap()
            .unwrap(),
        ),
    ]);

    let error = forwarding::validate_binding_owners(&desired).unwrap_err();

    let message = format!("{error:#}");
    assert!(message.contains("192.0.2.60:8080"));
    assert!(message.contains(&first.to_string()));
    assert!(message.contains(&second.to_string()));
}

#[test]
fn native_forwarding_runtime_update_rejects_binding_owned_by_another_uuid() {
    let server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let other = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let mut configuration = crate::server::configuration::ServerConfiguration::mock(server);
    configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080]);
    let spec = forwarding::ForwardingSpec::from_configuration(
        &configuration,
        "10.203.41.28".parse().unwrap(),
    )
    .unwrap()
    .unwrap();
    let listing = format!(
        r#"table ip wings_pve_forward {{
    chain prerouting {{
        ip daddr 192.0.2.60 tcp dport 8080 dnat to 10.203.41.29:8080 comment "wings-pve:{other}" # handle 7
    }}
}}
"#
    );
    let existing = forwarding::managed_rules(&listing).unwrap();

    let error = forwarding::validate_runtime_binding_owners(server, &spec, &existing).unwrap_err();

    assert!(format!("{error:#}").contains(&other.to_string()));
}

#[test]
fn native_forwarding_runtime_conflict_atomically_clears_the_updating_server() {
    let server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let other = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let mut configuration = crate::server::configuration::ServerConfiguration::mock(server);
    configuration
        .allocations
        .mappings
        .insert("192.0.2.60".into(), vec![8080]);
    let spec = forwarding::ForwardingSpec::from_configuration(
        &configuration,
        "10.203.41.28".parse().unwrap(),
    )
    .unwrap()
    .unwrap();
    let existing = vec![
        forwarding::ManagedRule::new(server, "output", 4),
        forwarding::ManagedRule::new_binding(
            other,
            "prerouting",
            7,
            "192.0.2.60".parse().unwrap(),
            8080,
        ),
    ];

    let (script, conflict) = forwarding::runtime_reconcile_plan(server, Some(&spec), &existing);

    assert!(conflict.is_some());
    assert!(script.contains("delete rule ip wings_pve_forward output handle 4"));
    assert!(!script.contains("add rule"));
    assert!(!script.contains("handle 7"));
}

#[test]
fn malformed_forwarding_does_not_discard_the_firewall_spec() {
    let server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let mut configuration = crate::server::configuration::ServerConfiguration::mock(server);
    configuration
        .allocations
        .mappings
        .insert("not-an-ip".into(), vec![8080]);
    let network = forwarding::NetworkContext::new("vmbr42", Some(24), Some("10.203.41.1")).unwrap();

    let (firewall, forwarding) = PveLxcExecutor::prepare_network_specs(
        &configuration,
        vec!["10.203.41.28".parse().unwrap()],
        Some(1234),
        true,
        &network,
    );

    assert_eq!(firewall.server, server);
    assert_eq!(
        firewall.target,
        Some(crate::server::firewall::FirewallTarget::ProxmoxLxc {
            vmid: 1234,
            interface: "net0".to_string(),
        })
    );
    assert!(forwarding.unwrap_err().to_string().contains("not-an-ip"));
}

#[test]
fn native_forwarding_rejects_unknown_managed_chain_names() {
    let server = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let listing = format!(
        r#"table ip wings_pve_forward {{
    chain prerouting; delete table inet filter {{
        comment "wings-pve:{server}" # handle 7
    }}
}}
"#
    );

    let error = forwarding::managed_rules(&listing).unwrap_err();

    assert!(format!("{error:#}").contains("unexpected managed nftables chain"));
}

#[test]
fn ipv4_forwarding_parser_requires_enabled_kernel_setting() {
    assert!(forwarding::parse_ipv4_forwarding("1\n").is_ok());

    for value in ["0\n", "2\n", "enabled\n", ""] {
        let error = forwarding::parse_ipv4_forwarding(value).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("net.ipv4.ip_forward=1"));
        assert!(message.contains("/proc/sys/net/ipv4/ip_forward"));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn nft_script_timeout_bounds_stdin_write_close_and_wait() {
    let oversized = vec![b'x'; 1024 * 1024];
    let started = std::time::Instant::now();

    let error = forwarding::run_script_with(
        std::path::Path::new("/bin/sh"),
        &["-c", "sleep 30"],
        &oversized,
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("timed out applying"));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn startup_forwarding_quarantines_every_owner_of_a_duplicate_binding() {
    let first = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let second = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let healthy = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b33);
    fn spec(server: uuid::Uuid, allocation: &str, destination: &str) -> forwarding::ForwardingSpec {
        let mut configuration = crate::server::configuration::ServerConfiguration::mock(server);
        configuration
            .allocations
            .mappings
            .insert(allocation.into(), vec![8080]);
        forwarding::ForwardingSpec::from_configuration(&configuration, destination.parse().unwrap())
            .unwrap()
            .unwrap()
    }
    let desired = std::collections::BTreeMap::from([
        (first, spec(first, "192.0.2.60", "10.203.41.28")),
        (second, spec(second, "192.0.2.60", "10.203.41.29")),
        (healthy, spec(healthy, "198.51.100.10", "10.203.41.30")),
    ]);

    let (desired, errors) = forwarding::without_binding_conflicts(desired);

    assert_eq!(desired.keys().copied().collect::<Vec<_>>(), vec![healthy]);
    assert_eq!(errors.len(), 1);
    let message = format!("{:#}", errors[0]);
    assert!(message.contains(&first.to_string()));
    assert!(message.contains(&second.to_string()));
}

#[test]
fn startup_reconciliation_error_reports_every_malformed_server() {
    let first = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b31);
    let second = uuid::Uuid::from_u128(0x8f9ae020_60b9_4c5f_8ce2_8f0dfb8d7b32);
    let error = PveLxcExecutor::aggregate_reconciliation_errors(vec![
        anyhow::anyhow!("server {first}: invalid allocation address"),
        anyhow::anyhow!("server {second}: missing guest address"),
    ])
    .unwrap_err();

    let message = format!("{error:#}");
    assert!(message.contains(&first.to_string()));
    assert!(message.contains("invalid allocation address"));
    assert!(message.contains(&second.to_string()));
    assert!(message.contains("missing guest address"));
}

#[test]
fn startup_reconcile_applies_forwarding_once_after_preparing_all_servers() {
    let source = include_str!("mod.rs");
    let reconcile = source
        .split("async fn reconcile_firewall")
        .nth(1)
        .unwrap()
        .split("async fn setup_server_process")
        .next()
        .unwrap();
    let loop_end = reconcile.find("forwarding::sync_all").unwrap();

    assert_eq!(reconcile.matches("forwarding::sync_all").count(), 1);
    assert!(!reconcile[..loop_end].contains("sync_allocation_forwarding"));
    assert!(reconcile.contains("forwarding_specs.remove(&server_uuid)"));
    assert!(reconcile.contains("aggregate_reconciliation_errors"));
}
