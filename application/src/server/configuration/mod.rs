use anyhow::Context;
use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use serde_default::DefaultFromSerde;
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use utoipa::ToSchema;

pub mod process;
pub mod seccomp;

fn is_plain_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn parse_cpu_list(list: &str) -> Option<Vec<u64>> {
    let mut cpus = Vec::new();

    for part in list.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        match part.split_once('-') {
            Some((start, end)) => {
                let start: u64 = start.trim().parse().ok()?;
                let end: u64 = end.trim().parse().ok()?;
                if start > end {
                    return None;
                }

                cpus.extend(start..=end);
            }
            None => cpus.push(part.parse().ok()?),
        }
    }

    Some(cpus)
}

fn numa_memory_nodes(threads: &str) -> Option<String> {
    static NUMA_NODE_CPUS: OnceLock<Vec<(u64, Vec<u64>)>> = OnceLock::new();

    let nodes = NUMA_NODE_CPUS.get_or_init(|| {
        let mut nodes = Vec::new();

        let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") else {
            return nodes;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name
                .to_string_lossy()
                .strip_prefix("node")
                .and_then(|id| id.parse().ok())
            else {
                continue;
            };

            let Ok(cpulist) = std::fs::read_to_string(entry.path().join("cpulist")) else {
                continue;
            };

            if let Some(cpus) = parse_cpu_list(&cpulist) {
                nodes.push((id, cpus));
            }
        }

        nodes
    });

    if nodes.len() < 2 {
        return None;
    }

    let cpus = parse_cpu_list(threads)?;
    let mut node_ids = BTreeSet::new();
    for cpu in cpus {
        node_ids.insert(nodes.iter().find(|(_, cpus)| cpus.contains(&cpu))?.0);
    }

    if node_ids.is_empty() {
        return None;
    }

    Some(
        node_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(","),
    )
}

#[derive(ToSchema, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Mount {
    #[serde(skip_deserializing, default)]
    pub default: bool,

    pub target: compact_str::CompactString,
    pub source: compact_str::CompactString,
    pub read_only: bool,
}

#[derive(Default)]
pub struct AllowedMounts(Vec<PathBuf>);

impl AllowedMounts {
    pub async fn load(config: &crate::config::Config) -> Self {
        let configured = config.load().allowed_mounts.clone();

        Self::from_entries(configured).await
    }

    pub async fn from_entries<E: AsRef<Path>>(entries: impl IntoIterator<Item = E>) -> Self {
        let entries = entries.into_iter();

        let mut allowed = Vec::with_capacity(entries.size_hint().0);
        for entry in entries {
            let entry = entry.as_ref();

            match tokio::fs::canonicalize(entry).await {
                Ok(path) => allowed.push(path),
                Err(err) => {
                    tracing::warn!(
                        "ignoring allowed_mounts entry {}, it could not be resolved: {:#?}",
                        entry.display(),
                        err
                    );
                }
            }
        }

        Self(allowed)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Mount {
    pub async fn resolve_allowed_source(
        &self,
        allowed: &AllowedMounts,
    ) -> Result<PathBuf, anyhow::Error> {
        if allowed.is_empty() {
            return Err(anyhow::anyhow!("allowed_mounts is empty"));
        }

        if !is_plain_absolute_path(Path::new(self.target.as_str())) {
            return Err(anyhow::anyhow!(
                "target {} is not an absolute, normalized path",
                self.target
            ));
        }

        let source = Path::new(self.source.as_str());
        if !is_plain_absolute_path(source) {
            return Err(anyhow::anyhow!(
                "source {} is not an absolute, normalized path",
                self.source
            ));
        }

        let source = tokio::fs::canonicalize(source)
            .await
            .with_context(|| format!("source {} could not be resolved", self.source))?;

        if !allowed.0.iter().any(|allowed| source.starts_with(allowed)) {
            return Err(anyhow::anyhow!(
                "source {} resolves to {}, which is outside allowed_mounts",
                self.source,
                source.display()
            ));
        }

        Ok(source)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ScheduleAction {
    pub uuid: uuid::Uuid,

    #[serde(flatten)]
    pub action: super::schedule::actions::ScheduleAction,
}

#[derive(ToSchema, Clone, Deserialize, Serialize)]
pub struct Schedule {
    pub uuid: uuid::Uuid,
    #[schema(value_type = serde_json::Value)]
    pub triggers: Vec<super::schedule::ScheduleTrigger>,
    #[schema(value_type = serde_json::Value)]
    pub condition: super::schedule::conditions::ScheduleCondition,
    #[schema(value_type = Vec<serde_json::Value>)]
    pub actions: Vec<ScheduleAction>,
}

nestify::nest! {
    #[derive(ToSchema, Deserialize, Serialize)]
    pub struct ServerConfiguration {
        pub uuid: uuid::Uuid,
        pub start_on_completion: Option<bool>,

        #[schema(inline)]
        pub meta: #[derive(ToSchema, Deserialize, Serialize)] pub struct ServerConfigurationMeta {
            pub name: compact_str::CompactString,
            pub description: compact_str::CompactString,
        },

        pub suspended: bool,
        pub invocation: compact_str::CompactString,
        pub skip_egg_scripts: bool,

        pub entrypoint: Option<Vec<String>>,
        pub environment: HashMap<compact_str::CompactString, serde_json::Value>,
        #[serde(default)]
        pub labels: HashMap<String, String>,
        #[serde(default)]
        pub backups: Vec<uuid::Uuid>,
        #[serde(default)]
        pub schedules: Vec<Schedule>,

        #[schema(inline)]
        pub allocations: #[derive(ToSchema, Deserialize, Serialize, PartialEq, Eq)] pub struct ServerConfigurationAllocations {
            pub force_outgoing_ip: bool,

            #[schema(inline)]
            pub default: Option<#[derive(ToSchema, Deserialize, Serialize, PartialEq, Eq)] pub struct ServerConfigurationAllocationsDefault {
                pub ip: compact_str::CompactString,
                pub port: u16,
            }>,

            #[serde(default, deserialize_with = "crate::deserialize::deserialize_defaultable")]
            pub mappings: HashMap<compact_str::CompactString, Vec<u16>>,
        },
        #[schema(inline)]
        pub build: #[derive(ToSchema, Deserialize, Serialize)] pub struct ServerConfigurationBuild {
            pub memory_limit: i64,
            #[serde(default, deserialize_with = "crate::deserialize::deserialize_defaultable")]
            pub overhead_memory: i64,
            pub swap: i64,
            pub io_weight: Option<u16>,
            pub cpu_limit: i64,
            pub disk_space: u64,
            pub threads: Option<compact_str::CompactString>,
            pub oom_disabled: bool,
        },
        pub mounts: Vec<Mount>,
        #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
        pub firewall: Vec<super::firewall::FirewallRule>,
        #[schema(inline)]
        pub egg: #[derive(ToSchema, Deserialize, Serialize)] pub struct ServerConfigurationEgg {
            pub id: uuid::Uuid,
            #[serde(default, deserialize_with = "crate::deserialize::deserialize_defaultable")]
            pub file_denylist: Vec<compact_str::CompactString>,
        },

        #[schema(inline)]
        pub container: #[derive(ToSchema, Deserialize, Serialize, PartialEq, Eq)] pub struct ServerConfigurationContainer {
            pub image: compact_str::CompactString,
            pub timezone: Option<compact_str::CompactString>,

            #[serde(default)]
            pub hugepages_passthrough_enabled: bool,
            #[serde(default)]
            pub kvm_passthrough_enabled: bool,

            #[serde(default)]
            #[schema(inline)]
            pub seccomp: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde, PartialEq, Eq)] pub struct ServerConfigurationContainerSeccomp {
                #[serde(default)]
                pub remove_allowed: Vec<compact_str::CompactString>,
            },
        },

        #[serde(default)]
        #[schema(inline)]
        pub auto_kill: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde, Clone, Copy)] pub struct ServerConfigurationAutoKill {
            #[serde(default)]
            pub enabled: bool,
            #[serde(default)]
            pub seconds: u64,
        },

        #[serde(default)]
        pub auto_start_behavior: crate::models::ServerAutoStartBehavior,

        #[serde(default)]
        #[schema(inline)]
        pub features: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde, Clone, Copy)] pub struct ServerConfigurationFeatures {
            #[serde(default)]
            #[schema(inline)]
            pub startup_cpu_boost: Option<#[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde, Clone, Copy)] #[serde(default)] pub struct ServerConfigurationFeaturesStartupCpuBoost {
                #[serde(default)]
                pub enabled: bool,
                #[serde(default = "crate::config::docker_startup_boost_timeout")]
                pub timeout: u64,
            }>,

            #[serde(default)]
            #[schema(inline)]
            pub runtime_cpu_boost: Option<#[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde, Clone, Copy)] #[serde(default)] pub struct ServerConfigurationFeaturesRuntimeCpuBoost {
                #[serde(default)]
                pub enabled: bool,
                #[serde(default = "crate::config::docker_runtime_boost_threshold")]
                pub threshold: u64,
                #[serde(default = "crate::config::docker_runtime_boost_sustained")]
                pub sustained: u64,
                #[serde(default = "crate::config::docker_runtime_boost_multiple")]
                pub multiple: f64,
                #[serde(default = "crate::config::docker_runtime_boost_duration")]
                pub duration: u64,
                #[serde(default = "crate::config::docker_runtime_boost_cooldown")]
                pub cooldown: u64,
            }>,
        },
    }
}

impl ServerConfigurationFeatures {
    pub fn startup_cpu_boost(
        &self,
        config: &crate::config::Config,
    ) -> crate::config::DockerStartupBoost {
        let node = config.load().docker.startup_boost;

        match self.startup_cpu_boost {
            Some(boost) => crate::config::DockerStartupBoost {
                enabled: boost.enabled,
                timeout: boost.timeout,
                max_concurrent: node.max_concurrent,
            },
            None => node,
        }
    }

    pub fn runtime_cpu_boost(
        &self,
        config: &crate::config::Config,
    ) -> crate::config::DockerRuntimeBoost {
        let node = config.load().docker.runtime_boost;

        match self.runtime_cpu_boost {
            Some(boost) => crate::config::DockerRuntimeBoost {
                enabled: boost.enabled,
                threshold: boost.threshold,
                sustained: boost.sustained,
                multiple: boost.multiple,
                duration: boost.duration,
                cooldown: boost.cooldown,
                max_concurrent: node.max_concurrent,
            },
            None => node,
        }
    }
}

impl ServerConfigurationBuild {
    pub fn has_pending_restart(&self, other: &Self) -> bool {
        self.memory_limit != other.memory_limit
            || self.overhead_memory != other.overhead_memory
            || self.swap != other.swap
            || self.io_weight != other.io_weight
            || self.threads != other.threads
            || self.oom_disabled != other.oom_disabled
    }
}

impl ServerConfiguration {
    #[cfg(test)]
    pub fn mock(uuid: uuid::Uuid) -> Self {
        Self {
            uuid,
            start_on_completion: None,
            meta: ServerConfigurationMeta {
                name: "Example Server".into(),
                description: "This is an example server configuration.".into(),
            },
            suspended: false,
            invocation: "java -Xmx{{SERVER_MEMORY}}M -jar server.jar".into(),
            skip_egg_scripts: false,
            entrypoint: None,
            environment: HashMap::new(),
            labels: HashMap::new(),
            backups: Vec::new(),
            schedules: Vec::new(),
            allocations: ServerConfigurationAllocations {
                force_outgoing_ip: false,
                default: None,
                mappings: HashMap::new(),
            },
            build: ServerConfigurationBuild {
                memory_limit: 2048,
                overhead_memory: 256,
                swap: 1024,
                io_weight: Some(500),
                cpu_limit: 2,
                disk_space: 10240,
                threads: None,
                oom_disabled: false,
            },
            mounts: Vec::new(),
            firewall: Vec::new(),
            egg: ServerConfigurationEgg {
                id: uuid::Uuid::new_v4(),
                file_denylist: Vec::new(),
            },
            container: ServerConfigurationContainer {
                image: "example/image:latest".into(),
                timezone: None,
                hugepages_passthrough_enabled: false,
                kvm_passthrough_enabled: false,
                seccomp: ServerConfigurationContainerSeccomp {
                    remove_allowed: Vec::new(),
                },
            },
            auto_kill: ServerConfigurationAutoKill {
                enabled: false,
                seconds: 0,
            },
            auto_start_behavior: crate::models::ServerAutoStartBehavior::default(),
            features: ServerConfigurationFeatures::default(),
        }
    }

    fn machine_id_path(&self, config: &crate::config::Config) -> PathBuf {
        config.vmount_path(self.uuid).join("machine-id")
    }

    fn machine_uuid_path(&self, config: &crate::config::Config) -> PathBuf {
        config.vmount_path(self.uuid).join("machine-uuid")
    }

    async fn vmounts(&self, config: &crate::config::Config) -> Vec<Mount> {
        let mut mounts = Vec::new();

        #[cfg(unix)]
        if config.load().system.machine_id.enabled {
            mounts.push(Mount {
                default: false,
                target: "/etc/machine-id".into(),
                source: self
                    .machine_id_path(config)
                    .to_string_lossy()
                    .to_compact_string(),
                read_only: true,
            });
            if !config.load().system.user.rootless.enabled
                && tokio::fs::metadata("/sys/class/dmi/id/product_uuid")
                    .await
                    .is_ok()
            {
                mounts.push(Mount {
                    default: false,
                    target: "/sys/class/dmi/id/product_uuid".into(),
                    source: self
                        .machine_uuid_path(config)
                        .to_string_lossy()
                        .to_compact_string(),
                    read_only: true,
                });
            }
        }

        mounts
    }

    pub async fn mounts(
        &self,
        config: &crate::config::Config,
        filesystem: &super::filesystem::Filesystem,
    ) -> Vec<Mount> {
        let mut mounts = self.vmounts(config).await;

        mounts.push(Mount {
            default: true,
            target: "/home/container".into(),
            source: filesystem
                .get_base_fs_mount_path()
                .await
                .to_string_lossy()
                .into(),
            read_only: false,
        });

        #[cfg(unix)]
        if self.container.hugepages_passthrough_enabled {
            mounts.push(Mount {
                default: false,
                target: "/dev/hugepages".into(),
                source: "/dev/hugepages".into(),
                read_only: false,
            });
        }

        #[cfg(unix)]
        if config.load().system.passwd.enabled {
            let cfg = config.load();

            mounts.push(Mount {
                default: false,
                target: "/etc/group".into(),
                source: cfg
                    .system
                    .passwd
                    .directory
                    .as_path(&cfg)
                    .join("group")
                    .to_string_lossy()
                    .to_compact_string(),
                read_only: true,
            });
            mounts.push(Mount {
                default: false,
                target: "/etc/passwd".into(),
                source: cfg
                    .system
                    .passwd
                    .directory
                    .as_path(&cfg)
                    .join("passwd")
                    .to_string_lossy()
                    .to_compact_string(),
                read_only: true,
            });
        }

        if !self.mounts.is_empty() {
            let allowed = AllowedMounts::load(config).await;

            for mount in &self.mounts {
                let source = match mount.resolve_allowed_source(&allowed).await {
                    Ok(source) => source,
                    Err(err) => {
                        tracing::warn!(
                            server = %self.uuid,
                            "not mounting {} -> {}: {:#}",
                            mount.source,
                            mount.target,
                            err
                        );

                        continue;
                    }
                };

                mounts.push(Mount {
                    source: source.to_string_lossy().to_compact_string(),
                    ..mount.clone()
                });
            }
        }

        mounts
    }

    pub async fn ensure_vmounts(
        &self,
        config: &crate::config::Config,
    ) -> Result<(), std::io::Error> {
        let machine_id_path = self.machine_id_path(config);
        if let Some(parent) = machine_id_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&machine_id_path, self.uuid.simple().to_string()).await?;

        let machine_uuid_path = self.machine_uuid_path(config);
        if let Some(parent) = machine_uuid_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&machine_uuid_path, self.uuid.to_string()).await?;

        Ok(())
    }

    pub async fn remove_vmounts(&self, config: &crate::config::Config) {
        let vmount_path = config.vmount_path(self.uuid);
        if let Err(err) = tokio::fs::remove_dir_all(&vmount_path).await {
            tracing::error!(
                server = %self.uuid,
                "failed to remove vmounts at {}: {:?}",
                vmount_path.to_string_lossy(),
                err
            );
        }
    }

    pub fn convert_container_resources(
        &self,
        config: &crate::config::Config,
    ) -> bollard::models::Resources {
        let real_memory = if self.build.memory_limit > 0 {
            self.build.memory_limit + self.build.overhead_memory
        } else {
            0
        };

        let memory = match real_memory {
            0 => None,
            limit => Some(
                config
                    .load()
                    .docker
                    .overhead
                    .get_memory(limit.into())
                    .as_bytes() as i64,
            ),
        };

        if self.build.oom_disabled && crate::server::executor::docker::cgroup::is_unified() {
            tracing::warn!(
                server = %self.uuid,
                "oom_disabled is set, but the container engine discards it on cgroup v2 hosts"
            );
        }

        let mut resources = bollard::models::Resources {
            memory,
            memory_reservation: match real_memory {
                0 => None,
                limit => Some(limit * 1024 * 1024),
            },
            memory_swap: match memory {
                None => {
                    if self.build.swap != 0 {
                        tracing::warn!(
                            server = %self.uuid,
                            swap = self.build.swap,
                            "ignoring the swap limit, it cannot be set without a memory limit"
                        );
                    }

                    None
                }
                Some(memory) => match self.build.swap {
                    0 => Some(memory),
                    -1 => Some(-1),
                    limit => Some(memory + limit * 1024 * 1024),
                },
            },
            blkio_weight: self.build.io_weight,
            oom_kill_disable: Some(self.build.oom_disabled),
            pids_limit: match config.load().docker.container_pid_limit {
                0 => None,
                limit => Some(limit as i64),
            },
            cpuset_cpus: self.build.threads.clone().map(|t| t.into()),
            cpuset_mems: if config.load().docker.numa_memory_binding {
                self.build.threads.as_deref().and_then(numa_memory_nodes)
            } else {
                None
            },
            ..Default::default()
        };

        if self.build.cpu_limit > 0 {
            let period = config.load().docker.cpu_period_us();

            resources.cpu_quota = Some(self.build.cpu_limit * period / 100);
            resources.cpu_period = Some(period);
        } else {
            resources.cpu_quota = Some(-1);
        }

        resources
    }

    pub fn environment(&self, config: &crate::config::Config) -> Vec<String> {
        let mut environment = self.environment.clone();
        environment.reserve(5);

        environment.insert(
            "TZ".into(),
            serde_json::Value::String(self.container.timezone.as_ref().map_or_else(
                || config.load().system.timezone.to_string(),
                |tz| tz.to_string(),
            )),
        );
        environment.insert(
            "STARTUP".into(),
            serde_json::Value::String(self.invocation.to_string()),
        );
        environment.insert(
            "SERVER_MEMORY".into(),
            serde_json::Value::from(self.build.memory_limit),
        );
        if let Some(default) = &self.allocations.default {
            environment.insert(
                "SERVER_IP".into(),
                serde_json::Value::String(default.ip.to_string()),
            );
            environment.insert("SERVER_PORT".into(), serde_json::Value::from(default.port));
        }

        environment
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    match v {
                        serde_json::Value::String(s) => s,
                        _ => v.to_string(),
                    }
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(source: impl AsRef<Path>) -> Mount {
        Mount {
            default: false,
            target: "/home/container/mounted".into(),
            source: source.as_ref().to_string_lossy().to_compact_string(),
            read_only: false,
        }
    }

    fn resources(memory_limit: i64, swap: i64) -> bollard::models::Resources {
        let config = tokio_test::block_on(async { crate::config::Config::mock() });

        let mut configuration = ServerConfiguration::mock(uuid::Uuid::new_v4());
        configuration.build.memory_limit = memory_limit;
        configuration.build.overhead_memory = 0;
        configuration.build.swap = swap;

        configuration.convert_container_resources(&config)
    }

    // ServerConfiguration::convert_container_resources

    #[test]
    fn convert_container_resources_disables_swap_by_matching_the_memory_limit() {
        let resources = resources(2048, 0);

        assert!(resources.memory.is_some());
        assert_eq!(resources.memory_swap, resources.memory);
    }

    #[test]
    fn convert_container_resources_passes_unlimited_swap_through() {
        assert_eq!(resources(2048, -1).memory_swap, Some(-1));
    }

    #[test]
    fn convert_container_resources_adds_a_positive_swap_limit_to_the_memory_limit() {
        let resources = resources(2048, 512);

        assert_eq!(
            resources.memory_swap,
            Some(resources.memory.unwrap() + 512 * 1024 * 1024)
        );
    }

    #[test]
    fn convert_container_resources_never_sets_swap_without_a_memory_limit() {
        for swap in [0, -1, 512] {
            let resources = resources(0, swap);

            assert_eq!(resources.memory, None);
            assert_eq!(resources.memory_swap, None);
        }
    }

    #[test]
    fn convert_container_resources_leaves_cpu_shares_at_the_host_default() {
        assert_eq!(resources(2048, 0).cpu_shares, None);
    }

    // Mount::resolve_allowed_source

    #[test]
    fn resolve_allowed_source_accepts_a_subdirectory_of_an_allowed_path() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            let source = allowed_root.join("server-storage");
            std::fs::create_dir_all(&source).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert_eq!(
                mount(&source)
                    .resolve_allowed_source(&allowed)
                    .await
                    .unwrap(),
                source.canonicalize().unwrap()
            );
        });
    }

    #[test]
    fn resolve_allowed_source_accepts_an_allowed_path_itself() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            std::fs::create_dir_all(&allowed_root).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert_eq!(
                mount(&allowed_root)
                    .resolve_allowed_source(&allowed)
                    .await
                    .unwrap(),
                allowed_root.canonicalize().unwrap()
            );
        });
    }

    #[test]
    fn resolve_allowed_source_rejects_parent_dir_traversal() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            std::fs::create_dir_all(&allowed_root).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert!(
                mount(allowed_root.join("../..").as_path())
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
            assert!(
                mount(allowed_root.join("../../../etc").as_path())
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn resolve_allowed_source_rejects_a_sibling_sharing_a_string_prefix() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("data");
            let sibling = root.path().join("database");
            std::fs::create_dir_all(&allowed_root).unwrap();
            std::fs::create_dir_all(&sibling).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert!(
                mount(&sibling)
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn resolve_allowed_source_rejects_a_symlink_out_of_an_allowed_path() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            let outside = root.path().join("outside");
            std::fs::create_dir_all(&allowed_root).unwrap();
            std::fs::create_dir_all(&outside).unwrap();

            let escape = allowed_root.join("escape");
            std::os::unix::fs::symlink(&outside, &escape).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert!(
                mount(&escape)
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn resolve_allowed_source_rejects_a_relative_source() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            std::fs::create_dir_all(&allowed_root).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert!(
                mount(Path::new("allowed"))
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn resolve_allowed_source_rejects_a_source_that_does_not_exist() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            std::fs::create_dir_all(&allowed_root).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            assert!(
                mount(allowed_root.join("missing").as_path())
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn resolve_allowed_source_rejects_a_non_normalized_target() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            std::fs::create_dir_all(&allowed_root).unwrap();

            let allowed = AllowedMounts::from_entries([&allowed_root]).await;

            let mut mount = mount(&allowed_root);
            mount.target = "/home/container/../../etc".into();

            assert!(mount.resolve_allowed_source(&allowed).await.is_err());
        });
    }

    #[test]
    fn resolve_allowed_source_rejects_everything_when_the_allowlist_is_empty() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("anything");
            std::fs::create_dir_all(&source).unwrap();

            let allowed = AllowedMounts::from_entries(Vec::<PathBuf>::new()).await;

            assert!(allowed.is_empty());
            assert!(
                mount(&source)
                    .resolve_allowed_source(&allowed)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn allowed_mounts_drops_entries_that_do_not_resolve() {
        tokio_test::block_on(async {
            let root = tempfile::tempdir().unwrap();
            let allowed_root = root.path().join("allowed");
            std::fs::create_dir_all(&allowed_root).unwrap();

            let allowed =
                AllowedMounts::from_entries([&allowed_root, &root.path().join("missing")]).await;

            assert_eq!(allowed.0, vec![allowed_root.canonicalize().unwrap()]);
        });
    }
}
