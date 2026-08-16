use super::DockerCompatJsonExt;
use anyhow::Context;
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub struct HostMountTable {
    container_id: String,
    /// (destination inside the wings container, source on the engine host)
    mounts: Vec<(PathBuf, PathBuf)>,
}

impl HostMountTable {
    pub async fn discover(docker: &bollard::Docker) -> Result<Self, anyhow::Error> {
        let mountinfo = tokio::fs::read_to_string("/proc/self/mountinfo")
            .await
            .context("failed to read /proc/self/mountinfo")?;
        let container_id = container_id_from_mountinfo(&mountinfo)?;

        let inspect = docker
            .inspect_container_settled(&container_id, None)
            .await
            .with_context(|| format!("failed to inspect own container {container_id}"))?;
        if inspect.id.as_deref() != Some(container_id.as_str()) {
            return Err(anyhow::anyhow!(
                "container engine returned id {:?} when inspecting own container {}",
                inspect.id,
                container_id
            ));
        }

        let mut mounts = Vec::new();
        for mount in inspect.mounts.unwrap_or_default() {
            let (Some(source), Some(destination)) = (mount.source, mount.destination) else {
                continue;
            };
            if !matches!(mount.typ.as_deref(), Some("bind" | "volume")) || !source.starts_with('/')
            {
                continue;
            }

            mounts.push((PathBuf::from(destination), PathBuf::from(source)));
        }

        Ok(Self {
            container_id,
            mounts,
        })
    }

    #[inline]
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    #[inline]
    pub fn mounts(&self) -> impl Iterator<Item = (&Path, &Path)> {
        self.mounts
            .iter()
            .map(|(destination, source)| (destination.as_path(), source.as_path()))
    }

    pub fn translate(&self, path: &Path) -> Option<PathBuf> {
        self.mounts
            .iter()
            .filter(|(destination, _)| path.starts_with(destination))
            .max_by_key(|(destination, _)| destination.components().count())
            .map(
                |(destination, source)| match path.strip_prefix(destination) {
                    Ok(remainder) if !remainder.as_os_str().is_empty() => source.join(remainder),
                    _ => source.clone(),
                },
            )
    }

    pub fn validate_directories(
        &self,
        cfg: &crate::config::InnerConfig,
    ) -> Result<(), anyhow::Error> {
        let mut directories = vec![
            (&cfg.system.data_directory, "system.data_directory"),
            (&cfg.system.tmp_directory, "system.tmp_directory"),
            (&cfg.system.vmount_directory, "system.vmount_directory"),
        ];
        #[cfg(unix)]
        if cfg.system.passwd.enabled {
            directories.push((&cfg.system.passwd.directory, "system.passwd.directory"));
        }

        for (directory, name) in directories {
            let directory = directory.as_path(cfg);
            if self.translate(&directory).is_none() {
                return Err(anyhow::anyhow!(
                    "{name} '{directory}' is not covered by any mount of the wings container, so the container engine on the host cannot see it. add a volume for it (e.g. '/path/on/host:{directory}')",
                    directory = directory.display(),
                ));
            }
        }

        Ok(())
    }
}

pub fn translate_source(table: Option<&HostMountTable>, source: &str) -> String {
    table
        .and_then(|table| table.translate(Path::new(source)))
        .map_or_else(
            || source.to_string(),
            |path| path.to_string_lossy().into_owned(),
        )
}

fn container_id_from_mountinfo(mountinfo: &str) -> Result<String, anyhow::Error> {
    static ID_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?:^|/)(?:overlay-)?containers/([0-9a-f]{64})/")
            .expect("Failed to compile regex")
    });

    let mut container_id: Option<&str> = None;
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        let (Some(root), Some(mount_point)) = (fields.nth(3), fields.next()) else {
            continue;
        };

        if !matches!(
            mount_point,
            "/etc/resolv.conf" | "/etc/hostname" | "/etc/hosts" | "/run/.containerenv"
        ) {
            continue;
        }

        let Some(id) = ID_REGEX
            .captures(root)
            .and_then(|captures| captures.get(1))
            .map(|id| id.as_str())
        else {
            continue;
        };

        if container_id.is_some_and(|existing| existing != id) {
            return Err(anyhow::anyhow!(
                "conflicting container ids in /proc/self/mountinfo"
            ));
        }
        container_id = Some(id);
    }

    container_id.map(str::to_string).ok_or_else(|| {
        anyhow::anyhow!(
            "no container id found in /proc/self/mountinfo, unsupported container engine"
        )
    })
}
