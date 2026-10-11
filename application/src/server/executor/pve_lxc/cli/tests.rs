use super::*;

#[test]
fn create_arguments_leave_data_mount_for_post_create_configuration() {
    let args = PveCli::create_args(&CreateContainerSpec {
        vmid: 1234,
        template: "local:vztmpl/oci-minecraft.tar".to_string(),
        hostname: "server-1234".to_string(),
        rootfs_storage: "local-lvm".to_string(),
        rootfs_size_gib: 8,
        memory_mib: 4096,
        swap_mib: 1024,
        cpu_limit_percent: Some(250),
        cores: Some(2),
        network: "name=eth0,bridge=vmbr0,ip=dhcp,type=veth,host-managed=1".to_string(),
        tags: vec!["calagopus".to_string(), "calagopus-server".to_string()],
        unprivileged: true,
    });

    assert_eq!(args.first().map(String::as_str), Some("create"));
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--rootfs", "local-lvm:8"])
    );
    assert!(args.windows(2).any(|pair| {
        pair == [
            "--net0",
            "name=eth0,bridge=vmbr0,ip=dhcp,type=veth,host-managed=1",
        ]
    }));
    assert!(!args.iter().any(|arg| arg == "--mp0"));
    assert!(args.windows(2).any(|pair| pair == ["--cores", "2"]));
    assert!(args.windows(2).any(|pair| pair == ["--cpulimit", "2.5"]));
    assert!(args.windows(2).any(|pair| pair == ["--cmode", "console"]));
    assert!(
        args.windows(2)
            .any(|pair| { pair == ["--tags", "calagopus;calagopus-server"] })
    );
}

#[test]
fn formats_panel_cpu_percent_for_proxmox_cpu_time() {
    assert_eq!(PveCli::format_cpu_limit_percent(1), "0.01");
    assert_eq!(PveCli::format_cpu_limit_percent(50), "0.5");
    assert_eq!(PveCli::format_cpu_limit_percent(100), "1");
    assert_eq!(PveCli::format_cpu_limit_percent(250), "2.5");
    assert_eq!(PveCli::format_cpu_limit_percent(225), "2.25");
}

#[test]
fn enables_firewall_on_existing_network_configuration() {
    let config = "arch: amd64\nnet0: name=eth0,bridge=vmbr0,ip=dhcp,type=veth\n";
    assert_eq!(
        PveCli::network_with_firewall(config).unwrap().as_deref(),
        Some("name=eth0,bridge=vmbr0,ip=dhcp,type=veth,firewall=1")
    );

    let disabled = "net0: name=eth0,bridge=vmbr0,firewall=0,ip=dhcp,type=veth\n";
    assert_eq!(
        PveCli::network_with_firewall(disabled).unwrap().as_deref(),
        Some("name=eth0,bridge=vmbr0,ip=dhcp,type=veth,firewall=1")
    );

    let enabled = "net0: name=eth0,bridge=vmbr0,ip=dhcp,type=veth,firewall=1\n";
    assert_eq!(PveCli::network_with_firewall(enabled).unwrap(), None);
    assert!(PveCli::network_with_firewall("arch: amd64\n").is_err());
}

#[test]
fn set_tags_replaces_container_tags_atomically() {
    assert_eq!(
        PveCli::set_tags_args(
            1234,
            &[
                "calagopus".to_string(),
                "calagopus-server-1234".to_string(),
                "calagopus-image-deadbeef".to_string(),
            ],
        ),
        vec![
            "set",
            "1234",
            "--tags",
            "calagopus;calagopus-server-1234;calagopus-image-deadbeef",
        ]
    );
}

#[test]
fn maps_panel_resources_to_native_pve_limits() {
    assert_eq!(
        PveCli::panel_resources(2048, 256, 1024, 250, None).ok(),
        Some(ContainerResources {
            memory_mib: 2304,
            swap_mib: 1024,
            memory_unlimited: false,
            swap_unlimited: false,
            cpu_limit_percent: Some(250),
            cores: None,
        })
    );
    assert_eq!(
        PveCli::panel_resources(2048, 0, 0, 0, None).ok(),
        Some(ContainerResources {
            memory_mib: 2048,
            swap_mib: 0,
            memory_unlimited: false,
            swap_unlimited: false,
            cpu_limit_percent: None,
            cores: None,
        })
    );
}

#[test]
fn rejects_invalid_resource_limits() {
    assert!(PveCli::panel_resources(-1, 0, 0, 0, None).is_err());
    assert!(PveCli::panel_resources(2048, 0, -2, 0, None).is_err());
    assert!(PveCli::panel_resources(2048, 0, 0, 0, Some("3-1")).is_err());
}

#[test]
fn maps_unlimited_memory_and_swap_to_lxc_overrides() {
    assert_eq!(
        PveCli::panel_resources(0, 0, 0, 0, None).ok(),
        Some(ContainerResources {
            memory_mib: 16,
            swap_mib: 0,
            memory_unlimited: true,
            swap_unlimited: true,
            cpu_limit_percent: None,
            cores: None,
        })
    );
    assert_eq!(
        PveCli::panel_resources(2048, 0, -1, 0, None).ok(),
        Some(ContainerResources {
            memory_mib: 2048,
            swap_mib: 0,
            memory_unlimited: false,
            swap_unlimited: true,
            cpu_limit_percent: None,
            cores: None,
        })
    );
}

#[test]
fn accepts_panel_cpu_pinning_syntax() {
    assert!(PveCli::panel_resources(2048, 0, 0, 0, Some("0-3,8")).is_ok());
    assert!(PveCli::panel_resources(2048, 0, 0, 0, Some("0,,2")).is_err());
}

#[test]
fn converts_docker_block_io_weight_to_cgroup_v2() {
    assert_eq!(PveCli::cgroup2_io_weight(None).ok(), Some(None));
    assert_eq!(PveCli::cgroup2_io_weight(Some(10)).ok(), Some(Some(1)));
    assert_eq!(PveCli::cgroup2_io_weight(Some(500)).ok(), Some(Some(4950)));
    assert_eq!(
        PveCli::cgroup2_io_weight(Some(1000)).ok(),
        Some(Some(10_000))
    );
    assert!(PveCli::cgroup2_io_weight(Some(9)).is_err());
}

#[test]
fn resource_update_arguments_set_all_mutable_limits_and_clear_cpu_limit() {
    assert_eq!(
        PveCli::set_resources_args(
            1234,
            &ContainerResources {
                memory_mib: 4096,
                swap_mib: 512,
                memory_unlimited: false,
                swap_unlimited: false,
                cpu_limit_percent: Some(250),
                cores: Some(4),
            },
        ),
        vec![
            "set",
            "1234",
            "--memory",
            "4096",
            "--swap",
            "512",
            "--cpulimit",
            "2.5",
            "--cores",
            "4",
        ]
    );

    assert_eq!(
        PveCli::set_resources_args(
            1234,
            &ContainerResources {
                memory_mib: 2048,
                swap_mib: 0,
                memory_unlimited: false,
                swap_unlimited: false,
                cpu_limit_percent: None,
                cores: None,
            },
        ),
        vec![
            "set",
            "1234",
            "--memory",
            "2048",
            "--swap",
            "0",
            "--cpulimit",
            "0",
        ]
    );
}

#[test]
fn parses_non_root_oci_user_from_pct_config() {
    assert_eq!(
        PveCli::parse_oci_user(
            "arch: amd64\nlxc.init.uid: 1000\nlxc.init.gid: 1001\nostype: unmanaged\n"
        )
        .ok(),
        Some(ContainerOciUser {
            uid: 1000,
            gid: 1001,
        })
    );
    assert_eq!(
        PveCli::parse_oci_user("lxc.init.uid: 0\nlxc.init.gid: 1000\n").ok(),
        Some(ContainerOciUser { uid: 0, gid: 1000 })
    );
    assert_eq!(
        PveCli::parse_oci_user("arch: amd64\n").ok(),
        Some(ContainerOciUser { uid: 0, gid: 0 })
    );
}

#[test]
fn pct_config_text_tolerates_nul_bytes() {
    let config = PveCli::decode_config_output(
        b"arch: amd64\0\nlxc.init.uid: 1000\nlxc.init.gid: 1001\0\n".to_vec(),
    )
    .unwrap_or_default();

    assert_eq!(
        PveCli::parse_oci_user(&config).ok(),
        Some(ContainerOciUser {
            uid: 1000,
            gid: 1001,
        })
    );
}

#[test]
fn data_mount_arguments_map_resolved_image_user_to_host_owner() {
    let args = PveCli::set_data_mount_args(&DataMountSpec {
        vmid: 1234,
        data_path: "/var/lib/calagopus-wings/volumes/example".to_string(),
        container_uid: 1000,
        container_gid: 1001,
        host_data_uid: 988,
        host_data_gid: 989,
    })
    .unwrap_or_default();

    assert_eq!(
        args,
        vec![
            "set",
            "1234",
            "--mp0",
            "/var/lib/calagopus-wings/volumes/example,mp=/home/container,backup=0,idmap=u:1000:988:1;g:1001:989:1",
        ]
    );
}

#[test]
fn data_mount_arguments_support_root_in_an_unprivileged_container() {
    let spec = DataMountSpec {
        vmid: 1234,
        data_path: "/var/lib/calagopus-wings/volumes/example".to_string(),
        container_uid: 0,
        container_gid: 1000,
        host_data_uid: 988,
        host_data_gid: 988,
    };

    assert_eq!(
            PveCli::set_data_mount_args(&spec).ok(),
            Some(vec![
                "set".to_string(),
                "1234".to_string(),
                "--mp0".to_string(),
                "/var/lib/calagopus-wings/volumes/example,mp=/home/container,backup=0,idmap=u:0:988:1;g:1000:988:1".to_string(),
            ])
        );
}

#[test]
fn bind_mount_arguments_support_multiple_targets_and_reject_duplicates() {
    let mounts = vec![
        BindMountSpec {
            slot: 0,
            source_path: "/srv/server".to_string(),
            target_path: "/mnt/server".to_string(),
            read_only: false,
            container_uid: 1000,
            container_gid: 1001,
            host_uid: 988,
            host_gid: 989,
        },
        BindMountSpec {
            slot: 1,
            source_path: "/srv/install".to_string(),
            target_path: "/mnt/install".to_string(),
            read_only: true,
            container_uid: 1000,
            container_gid: 1001,
            host_uid: 988,
            host_gid: 989,
        },
    ];

    assert_eq!(
        PveCli::set_bind_mount_args(1234, &mounts).unwrap_or_default(),
        vec![
            "set",
            "1234",
            "--mp0",
            "/srv/server,mp=/mnt/server,backup=0,idmap=u:1000:988:1;g:1001:989:1",
            "--mp1",
            "/srv/install,mp=/mnt/install,backup=0,idmap=u:1000:988:1;g:1001:989:1,ro=1",
        ]
    );

    let mut duplicate = mounts.clone();
    duplicate[1].slot = 0;
    assert!(PveCli::set_bind_mount_args(1234, &duplicate).is_err());

    let mut unsafe_path = mounts;
    unsafe_path[1].target_path = "/mnt/install,bad".to_string();
    assert!(PveCli::set_bind_mount_args(1234, &unsafe_path).is_err());
    unsafe_path[1].target_path = "/mnt/../etc".to_string();
    assert!(PveCli::set_bind_mount_args(1234, &unsafe_path).is_err());
}

#[test]
fn device_arguments_set_ownership_mode_and_write_policy() {
    let devices = vec![
        DevicePassthroughSpec {
            slot: 0,
            path: "/dev/kvm".to_string(),
            uid: 1000,
            gid: 1001,
            mode: 0o660,
            deny_write: false,
        },
        DevicePassthroughSpec {
            slot: 1,
            path: "/dev/dri/renderD128".to_string(),
            uid: 1000,
            gid: 1001,
            mode: 0o640,
            deny_write: true,
        },
    ];

    assert_eq!(
        PveCli::set_devices_args(1234, &devices).unwrap_or_default(),
        vec![
            "set",
            "1234",
            "--dev0",
            "path=/dev/kvm,uid=1000,gid=1001,mode=0660",
            "--dev1",
            "path=/dev/dri/renderD128,uid=1000,gid=1001,mode=0640,deny-write=1",
        ]
    );

    let mut duplicate = devices.clone();
    duplicate[1].slot = 0;
    assert!(PveCli::set_devices_args(1234, &duplicate).is_err());

    let mut unsafe_path = devices.clone();
    unsafe_path[1].path = "/dev/dri/renderD128,bad".to_string();
    assert!(PveCli::set_devices_args(1234, &unsafe_path).is_err());
    unsafe_path[1].path = "/dev/../etc/shadow".to_string();
    assert!(PveCli::set_devices_args(1234, &unsafe_path).is_err());

    let mut root_owned = devices;
    root_owned[0].uid = 0;
    root_owned[0].gid = 0;
    assert!(PveCli::set_devices_args(1234, &root_owned).is_ok());
}

#[test]
fn mount_and_device_reconciliation_removes_stale_slots() {
    let mounts = vec![BindMountSpec {
        slot: 0,
        source_path: "/srv/server".to_string(),
        target_path: "/home/container".to_string(),
        read_only: false,
        container_uid: 1000,
        container_gid: 1001,
        host_uid: 988,
        host_gid: 989,
    }];
    let devices = vec![DevicePassthroughSpec {
        slot: 0,
        path: "/dev/kvm".to_string(),
        uid: 1000,
        gid: 1001,
        mode: 0o660,
        deny_write: false,
    }];
    let current_config = r#"
rootfs: local-lvm:vm-1234-disk-0,size=8G
mp0: /srv/old-server,mp=/home/container
mp2: /srv/removed,mp=/mnt/removed
dev0: path=/dev/kvm
dev3: path=/dev/dri/renderD128
lxc.init.uid: 1000
"#;

    assert_eq!(
        PveCli::reconcile_mounts_and_devices_args(1234, current_config, &mounts, &devices,)
            .unwrap_or_default(),
        vec![
            "set",
            "1234",
            "--mp0",
            "/srv/server,mp=/home/container,backup=0,idmap=u:1000:988:1;g:1001:989:1",
            "--dev0",
            "path=/dev/kvm,uid=1000,gid=1001,mode=0660",
            "--delete",
            "mp2,dev3",
        ]
    );
}

#[test]
fn parses_pct_status() {
    assert_eq!(
        ContainerStatus::parse("status: running\n").ok(),
        Some(ContainerStatus::Running)
    );
    assert_eq!(
        ContainerStatus::parse("status: stopped\n").ok(),
        Some(ContainerStatus::Stopped)
    );
    assert!(ContainerStatus::parse("status: mounted").is_err());
}

#[test]
fn parses_local_cluster_node() {
    let output = br#"[
            {"type":"cluster","name":"og-cluster"},
            {"type":"node","name":"pve-a","local":0},
            {"type":"node","name":"pve-b","local":1}
        ]"#;

    assert_eq!(
        PveCli::parse_local_node(output).ok().as_deref(),
        Some("pve-b")
    );
}

#[test]
fn orders_available_active_lxc_storages() {
    let output = br#"[
            {"storage":"local-lvm","active":1,"enabled":1,"content":"images,rootdir","avail":100},
            {"storage":"zfs","active":1,"enabled":1,"content":"rootdir,images","avail":200},
            {"storage":"local","active":1,"enabled":1,"content":"iso,vztmpl","avail":300},
            {"storage":"disabled","active":1,"enabled":0,"content":"rootdir","avail":400},
            {"storage":"offline","active":0,"enabled":1,"content":"rootdir","avail":500}
        ]"#;

    assert_eq!(
        PveCli::parse_available_lxc_storages(output).ok(),
        Some(vec![
            LxcStorage {
                name: "zfs".to_string(),
                available_bytes: 200,
            },
            LxcStorage {
                name: "local-lvm".to_string(),
                available_bytes: 100,
            },
        ])
    );
}

#[test]
fn parses_lxc_resources_and_ignores_vms() {
    let output = br#"[
            {"type":"qemu","vmid":101,"node":"pve-a","status":"running"},
            {"type":"lxc","vmid":102,"node":"pve-b","status":"running","tags":"calagopus;calagopus-server-abc"},
            {"type":"lxc","vmid":"103","node":"pve-b","status":"stopped"}
        ]"#;

    let containers = PveCli::parse_containers(output).unwrap_or_default();
    assert_eq!(containers.len(), 2);
    assert_eq!(
        containers.first().map(|container| container.vmid),
        Some(102)
    );
    assert_eq!(
        containers
            .first()
            .and_then(|container| container.tags.first())
            .map(String::as_str),
        Some("calagopus")
    );
    assert_eq!(
        containers
            .first()
            .and_then(|container| container.tags.get(1))
            .map(String::as_str),
        Some("calagopus-server-abc")
    );
    assert_eq!(containers.get(1).map(|container| container.vmid), Some(103));
}

#[test]
fn parses_container_interfaces_and_prefers_usable_ipv4() {
    let interfaces = PveCli::parse_interfaces(
        br#"[
                {"name":"lo","ip-addresses":[
                    {"ip-address":"127.0.0.1","ip-address-type":"inet","prefix":8},
                    {"ip-address":"::1","ip-address-type":"inet6","prefix":128}
                ]},
                {"name":"eth0","ip-addresses":[
                    {"ip-address":"fe80::1234","ip-address-type":"inet6","prefix":64},
                    {"ip-address":"fd12:3456::20","ip-address-type":"inet6","prefix":64},
                    {"ip-address":"10.42.0.20","ip-address-type":"inet","prefix":24}
                ]}
            ]"#,
    )
    .unwrap_or_default();

    assert_eq!(interfaces.len(), 2);
    assert_eq!(
        PveCli::primary_container_address(&interfaces),
        "10.42.0.20".parse().ok()
    );
    assert_eq!(
        PveCli::interfaces_args("pve-a", 1234),
        vec![
            "get",
            "/nodes/pve-a/lxc/1234/interfaces",
            "--output-format",
            "json",
        ]
    );
}

#[test]
fn stopped_container_null_interface_response_is_empty() {
    assert_eq!(PveCli::parse_interfaces(b"null").unwrap(), Vec::new());
}

#[test]
fn container_addresses_returns_all_usable_addresses_sorted_and_deduplicated() {
    let interfaces = vec![
        ContainerInterface {
            name: "lo".to_string(),
            addresses: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        },
        ContainerInterface {
            name: "eth0".to_string(),
            addresses: vec![
                "fd12:3456::20".parse().unwrap(),
                "10.42.0.20".parse().unwrap(),
                "fe80::1234".parse().unwrap(),
                "10.42.0.20".parse().unwrap(),
                "0.0.0.0".parse().unwrap(),
                "ff02::1".parse().unwrap(),
            ],
        },
    ];

    assert_eq!(
        PveCli::container_addresses(&interfaces),
        vec![
            "10.42.0.20".parse::<IpAddr>().unwrap(),
            "fd12:3456::20".parse::<IpAddr>().unwrap(),
        ]
    );
}

#[test]
fn parses_runtime_status_for_cgroup_discovery() {
    assert_eq!(
        PveCli::parse_runtime_status(br#"{"status":"running","pid":"4321","uptime":87}"#,).ok(),
        Some(ContainerRuntimeStatus {
            status: ContainerStatus::Running,
            pid: Some(4321),
            uptime_seconds: 87,
        })
    );
    assert_eq!(
        PveCli::parse_runtime_status(br#"{"status":"stopped","uptime":"0"}"#).ok(),
        Some(ContainerRuntimeStatus {
            status: ContainerStatus::Stopped,
            pid: None,
            uptime_seconds: 0,
        })
    );
    assert!(PveCli::parse_runtime_status(br#"{"status":"mounted"}"#).is_err());
    assert_eq!(
        PveCli::runtime_status_args("pve-a", 1234),
        vec![
            "get",
            "/nodes/pve-a/lxc/1234/status/current",
            "--output-format",
            "json",
        ]
    );
}

#[test]
fn container_address_falls_back_to_non_link_local_ipv6() {
    let interfaces = vec![ContainerInterface {
        name: "eth0".to_string(),
        addresses: vec![
            "fe80::1234"
                .parse()
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            "fd12:3456::20"
                .parse()
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        ],
    }];

    assert_eq!(
        PveCli::primary_container_address(&interfaces),
        "fd12:3456::20".parse().ok()
    );
}

#[test]
fn normalizes_oci_references_for_proxmox() {
    assert_eq!(
        PveCli::normalize_oci_reference("ghcr.io/example/game").ok(),
        Some("ghcr.io/example/game:latest".to_string())
    );
    assert_eq!(
        PveCli::normalize_oci_reference("registry.example:5000/example/game:v2").ok(),
        Some("registry.example:5000/example/game:v2".to_string())
    );
    assert!(PveCli::normalize_oci_reference("game@sha256:abc").is_err());
}

#[test]
fn oci_cache_name_is_stable_and_reference_specific() {
    let first = PveCli::oci_cache_filename("ghcr.io/example/game:latest");
    let again = PveCli::oci_cache_filename("ghcr.io/example/game:latest");
    let other = PveCli::oci_cache_filename("ghcr.io/example/game:v2");

    assert_eq!(first, again);
    assert_ne!(first, other);
    assert!(first.starts_with("calagopus-oci-"));
    assert_eq!(first.len(), "calagopus-oci-".len() + 64);
}

#[test]
fn oci_image_tag_uses_resolved_revision_digest() {
    let first = PveCli::oci_revision_tag(
        "sha256:052a0ffb2620d9d59dfd81caa280af01ca8e6fe744649b11da481c00a8562d40",
    )
    .unwrap_or_default();
    let other = PveCli::oci_revision_tag(
        "5c093e071615ce61063007dfb363fd5bb878d4673954445e2a4ee5e7de3fae3b",
    )
    .unwrap_or_default();

    assert_ne!(first, other);
    assert_eq!(first, "calagopus-image-052a0ffb2620d9d59dfd81caa280af01");
    assert!(PveCli::oci_revision_tag("sha256:not-a-digest").is_err());
}

#[test]
fn oci_pull_arguments_use_proxmox_storage_endpoint() {
    let args = PveCli::pull_oci_args(&OciTemplatePullSpec {
        node: "pve-a".to_string(),
        storage: "local".to_string(),
        reference: "ghcr.io/example/game:latest".to_string(),
        filename: "calagopus-oci-abc".to_string(),
    });

    assert_eq!(
        args,
        vec![
            "create",
            "/nodes/pve-a/storage/local/oci-registry-pull",
            "--reference",
            "ghcr.io/example/game:latest",
            "--filename",
            "calagopus-oci-abc",
            "--output-format",
            "json",
        ]
    );
}

#[test]
fn parses_oci_pull_task_after_proxmox_progress_output() {
    let upid = "UPID:pve4:000348B0:005B00EB:6ABACCF1:ociregistrypull:template.tar:root@pam:";
    let noisy = format!(
        "Getting image source signatures\nCopying blob sha256:abc\nWriting manifest to image destination\n\"{upid}\"\n"
    );

    assert_eq!(
        PveCli::parse_oci_pull_task(noisy.as_bytes())
            .ok()
            .as_deref(),
        Some(upid)
    );
    assert_eq!(
        PveCli::parse_oci_pull_task(format!("\"{upid}\"").as_bytes())
            .ok()
            .as_deref(),
        Some(upid)
    );
    assert!(PveCli::parse_oci_pull_task(b"copy completed without task id\n").is_err());
}

#[test]
fn parses_storage_content_and_task_status() {
    let content = PveCli::parse_storage_content(
        br#"[{"volid":"local:vztmpl/calagopus-oci-abc.tar","content":"vztmpl"}]"#,
    )
    .unwrap_or_default();
    assert_eq!(
        content.first(),
        Some(&StorageContent {
            volid: "local:vztmpl/calagopus-oci-abc.tar".to_string(),
            content: Some("vztmpl".to_string()),
        })
    );

    assert_eq!(
        PveCli::parse_task_status(br#"{"status":"running"}"#).ok(),
        Some(TaskStatus {
            state: TaskState::Running,
            exit_status: None,
        })
    );
    assert_eq!(
        PveCli::parse_task_status(br#"{"status":"stopped","exitstatus":"OK"}"#).ok(),
        Some(TaskStatus {
            state: TaskState::Stopped,
            exit_status: Some("OK".to_string()),
        })
    );
}

#[test]
fn attached_process_runs_as_explicit_non_root_user_with_clean_environment() {
    let args = PveCli::attach_args(&AttachProcessSpec {
        vmid: 1234,
        uid: 1000,
        gid: 1000,
        environment: vec![
            "STARTUP=java -jar server.jar".to_string(),
            "SERVER_MEMORY=4096".to_string(),
        ],
        command: vec!["/bin/bash".to_string(), "/entrypoint.sh".to_string()],
    })
    .unwrap_or_default();

    assert_eq!(
        args,
        vec![
            "-n",
            "1234",
            "--clear-env",
            "-u",
            "1000",
            "-g",
            "1000",
            "-v",
            "STARTUP=java -jar server.jar",
            "-v",
            "SERVER_MEMORY=4096",
            "--",
            "/bin/bash",
            "/entrypoint.sh",
        ]
    );
}

#[test]
fn attached_process_supports_root_and_rejects_invalid_input() {
    let spec = AttachProcessSpec {
        vmid: 1234,
        uid: 0,
        gid: 1000,
        environment: Vec::new(),
        command: vec!["/bin/true".to_string()],
    };
    assert!(PveCli::attach_args(&spec).is_ok());

    let mut spec = spec;
    spec.command.clear();
    assert!(PveCli::attach_args(&spec).is_err());

    spec.command.push("/bin/true".to_string());
    spec.environment.push("BROKEN".to_string());
    assert!(PveCli::attach_args(&spec).is_err());
}

#[test]
fn runtime_configuration_uses_stdin_payload_and_validates_line_safety() {
    let payload = PveCli::runtime_config_payload(&RuntimeConfigSpec {
        vmid: 1234,
        environment: vec![
            "STARTUP=java -jar server.jar".to_string(),
            "SERVER_MEMORY=4096".to_string(),
        ],
        halt_signal: Some("SIGINT".to_string()),
        init_command: Some("/bin/bash /mnt/install/install.sh".to_string()),
        console_logfile: Some("/var/log/calagopus/install.log".to_string()),
        cpuset_cpus: Some("0-3,8".to_string()),
        pids_limit: Some(5120),
        io_weight: Some(4950),
        memory_unlimited: true,
        swap_unlimited: true,
        managed_file_mounts: Some(vec![ManagedFileMountSpec {
            source_path: "/var/lib/calagopus wings/vmount/example/hosts".to_string(),
            target_path: "/etc/hosts".to_string(),
        }]),
    })
    .unwrap_or_default();
    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap_or_default();

    assert_eq!(
        value.get("vmid").and_then(serde_json::Value::as_u64),
        Some(1234)
    );
    assert_eq!(
        value
            .get("environment")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        value.get("halt_signal").and_then(serde_json::Value::as_str),
        Some("SIGINT")
    );
    assert_eq!(
        value
            .get("init_command")
            .and_then(serde_json::Value::as_str),
        Some("/bin/bash /mnt/install/install.sh")
    );
    assert_eq!(
        value
            .get("console_logfile")
            .and_then(serde_json::Value::as_str),
        Some("/var/log/calagopus/install.log")
    );
    assert_eq!(
        value.get("cpuset_cpus").and_then(serde_json::Value::as_str),
        Some("0-3,8")
    );
    assert_eq!(
        value.get("pids_limit").and_then(serde_json::Value::as_u64),
        Some(5120)
    );
    assert_eq!(
        value.get("io_weight").and_then(serde_json::Value::as_u64),
        Some(4950)
    );
    assert_eq!(
        value
            .get("memory_unlimited")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .get("swap_unlimited")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .get("managed_file_mounts")
            .and_then(serde_json::Value::as_array)
            .and_then(|mounts| mounts.first())
            .and_then(|mount| mount.get("entry"))
            .and_then(serde_json::Value::as_str),
        Some(
            "/var/lib/calagopus\\040wings/vmount/example/hosts etc/hosts none bind,ro,create=file 0 0"
        )
    );
    assert_eq!(
        value
            .get("managed_file_targets")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(5)
    );

    let mut invalid = RuntimeConfigSpec {
        vmid: 1234,
        environment: vec!["BROKEN".to_string()],
        halt_signal: None,
        init_command: None,
        console_logfile: None,
        cpuset_cpus: None,
        pids_limit: None,
        io_weight: None,
        memory_unlimited: false,
        swap_unlimited: false,
        managed_file_mounts: None,
    };
    assert!(PveCli::runtime_config_payload(&invalid).is_err());
    invalid.environment = vec!["GOOD=bad\nvalue".to_string()];
    assert!(PveCli::runtime_config_payload(&invalid).is_err());
    invalid.environment.clear();
    invalid.console_logfile = Some("relative.log".to_string());
    assert!(PveCli::runtime_config_payload(&invalid).is_err());
    invalid.console_logfile = None;
    invalid.managed_file_mounts = Some(vec![ManagedFileMountSpec {
        source_path: "/var/lib/calagopus/hosts".to_string(),
        target_path: "/etc/shadow".to_string(),
    }]);
    assert!(PveCli::runtime_config_payload(&invalid).is_err());

    invalid.managed_file_mounts = Some(vec![ManagedFileMountSpec {
        source_path: "relative/hosts".to_string(),
        target_path: "/etc/hosts".to_string(),
    }]);
    assert!(PveCli::runtime_config_payload(&invalid).is_err());

    invalid.managed_file_mounts = Some(vec![
        ManagedFileMountSpec {
            source_path: "/var/lib/calagopus/hosts-a".to_string(),
            target_path: "/etc/hosts".to_string(),
        },
        ManagedFileMountSpec {
            source_path: "/var/lib/calagopus/hosts-b".to_string(),
            target_path: "/etc/hosts".to_string(),
        },
    ]);
    assert!(PveCli::runtime_config_payload(&invalid).is_err());
}

#[test]
fn init_command_encoding_matches_lxc_whole_word_quoting() {
    assert_eq!(
        PveCli::encode_init_command(&[
            "/bin/bash".to_string(),
            "/mnt/install/install.sh".to_string(),
        ])
        .ok()
        .as_deref(),
        Some("/bin/bash /mnt/install/install.sh")
    );
    assert_eq!(
        PveCli::encode_init_command(&[
            "/opt/my shell/bash".to_string(),
            "/mnt/install/install.sh".to_string(),
        ])
        .ok()
        .as_deref(),
        Some("\"/opt/my shell/bash\" /mnt/install/install.sh")
    );
    assert!(PveCli::encode_init_command(&["both'\"quotes here".to_string()]).is_err());
}

#[test]
fn lifecycle_arguments_request_nonblocking_graceful_shutdown_and_console() {
    assert_eq!(
        PveCli::request_shutdown_args(1234),
        vec!["-n", "1234", "--nowait", "--nokill"]
    );
    assert_eq!(
        PveCli::console_args(1234),
        vec!["console", "1234", "--escape", "^z"]
    );
}
