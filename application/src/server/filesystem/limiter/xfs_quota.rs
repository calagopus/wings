use crate::server::{filesystem::limiter::DiskLimiterExt, resources::ResourceUsageWatchExt};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    process::Command,
    sync::{Mutex, RwLock},
};

type DiskUsageMap = HashMap<
    uuid::Uuid,
    (
        PathBuf,
        PathBuf,
        u32,
        i64,
        tokio::sync::watch::Sender<crate::server::resources::ResourceUsage>,
    ),
>;

static DISK_USAGE: LazyLock<Arc<RwLock<DiskUsageMap>>> = LazyLock::new(|| {
    let disk_usage: Arc<RwLock<DiskUsageMap>> = Arc::new(RwLock::new(HashMap::new()));
    let disk_usage_clone = Arc::clone(&disk_usage);

    tokio::spawn(async move {
        loop {
            let mut mount_groups: HashMap<PathBuf, Vec<u32>> = HashMap::new();

            {
                let usage_map = disk_usage_clone.read().await;
                if !usage_map.is_empty() {
                    for (_, mount, pid, _, _) in usage_map.values() {
                        mount_groups.entry(mount.clone()).or_default().push(*pid);
                    }
                }
            }

            if mount_groups.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            let mut results: HashMap<u32, i64> = HashMap::new();

            for (mount_point, pids) in mount_groups {
                match fetch_xfs_quota(&mount_point).await {
                    Ok(quota_map) => {
                        for pid in pids {
                            if let Some(usage) = quota_map.get(&pid) {
                                results.insert(pid, *usage);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "failed to get XFS quota report for {}: {}",
                            mount_point.display(),
                            e
                        );
                    }
                }
            }

            {
                let mut usage_map = disk_usage_clone.write().await;
                for (_, _, pid, usage_ref, resource_usage) in usage_map.values_mut() {
                    if let Some(new_usage) = results.get(pid) {
                        *usage_ref = *new_usage;
                        resource_usage.publish_disk_usage((*new_usage).max(0) as u64);
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    disk_usage
});

async fn fetch_xfs_quota(mount_point: &Path) -> Result<HashMap<u32, i64>, String> {
    let output = Command::new("xfs_quota")
        .arg("-x")
        .arg("-c")
        .arg("report -p -b -N")
        .arg(mount_point)
        .output()
        .await
        .map_err(|e| format!("execution error: {:?}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut usage_map = HashMap::new();

    for line in output_str.lines() {
        let mut line_split = line.split_whitespace();
        if let (Some(id_str), Some(usage_str)) = (line_split.next(), line_split.next()) {
            let id_str = id_str.trim_start_matches('#');

            if let (Ok(pid), Ok(used)) = (id_str.parse::<u32>(), usage_str.parse::<i64>()) {
                usage_map.insert(pid, used * 1024);
            }
        }
    }
    Ok(usage_map)
}

static ETC_PROJECTS_LOCK: Mutex<()> = Mutex::const_new(());

fn uuid_to_project_id(uuid: &uuid::Uuid) -> u32 {
    let uuid_bytes = uuid.as_bytes();
    u32::from_be_bytes([uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3]])
}

async fn atomic_write_etc_projects(
    project_id: u32,
    path: &Path,
    remove: bool,
) -> Result<(), std::io::Error> {
    let _lock = ETC_PROJECTS_LOCK.lock().await;
    let file_path = Path::new("/etc/projects");
    let tmp_path = Path::new("/etc/projects.tmp");

    let contents = tokio::fs::read_to_string(file_path)
        .await
        .unwrap_or_default();

    let id_prefix = format!("{}:", project_id);
    let mut new_contents = String::with_capacity(contents.len());
    let mut found = false;

    for line in contents.lines() {
        if line.starts_with(&id_prefix) {
            if remove {
                continue;
            }
            found = true;
        }
        new_contents.push_str(line);
        new_contents.push('\n');
    }

    if !remove && found {
        return Ok(());
    }
    if !remove && !found {
        new_contents.push_str(&format!("{}:{}\n", project_id, path.display()));
    }

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp_path)
        .await?;

    tmp_file.write_all(new_contents.as_bytes()).await?;
    tmp_file.sync_all().await?;
    drop(tmp_file);

    tokio::fs::rename(tmp_path, file_path).await?;
    Ok(())
}

async fn get_mount_point(path: &Path) -> Result<PathBuf, std::io::Error> {
    let output = Command::new("df")
        .arg("--output=target")
        .arg(path)
        .output()
        .await?;

    if !output.status.success() {
        return Err(std::io::Error::other(String::from_utf8_lossy(
            &output.stderr,
        )));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let line = output_str
        .lines()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("Unexpected output format from df command"))?;

    Ok(PathBuf::from(line.trim()))
}

pub struct XfsQuotaLimiter<'a> {
    pub filesystem: &'a crate::server::filesystem::Filesystem,
}

#[async_trait::async_trait]
impl<'a> DiskLimiterExt for XfsQuotaLimiter<'a> {
    async fn setup(&self) -> Result<(), std::io::Error> {
        tracing::debug!(
            path = %self.filesystem.base_path.display(),
            "setting up xfs disk limiter for volume"
        );

        if tokio::fs::metadata(&self.filesystem.base_path)
            .await
            .is_err()
        {
            tokio::fs::create_dir_all(&self.filesystem.base_path).await?;
        }

        let project_id = uuid_to_project_id(&self.filesystem.uuid);

        atomic_write_etc_projects(project_id, &self.filesystem.base_path, false).await?;

        let mount_point = match get_mount_point(&self.filesystem.base_path).await {
            Ok(mp) => mp,
            Err(e) => {
                tracing::warn!("failed to get mount point (using path as fallback): {}", e);
                self.filesystem.base_path.clone()
            }
        };

        let output = Command::new("xfs_quota")
            .arg("-x")
            .arg("-c")
            .arg(format!("project -s {project_id}"))
            .arg(&mount_point)
            .output()
            .await?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "Failed to set up XFS project quota: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        DISK_USAGE
            .write()
            .await
            .entry(self.filesystem.uuid)
            .or_insert((
                self.filesystem.base_path.clone(),
                mount_point,
                project_id,
                -1,
                self.filesystem.resource_usage.clone(),
            ));

        Ok(())
    }

    async fn attach(&self) -> Result<(), std::io::Error> {
        tracing::debug!(
            path = %self.filesystem.base_path.display(),
            "attaching xfs disk limiter for volume"
        );

        let project_id = uuid_to_project_id(&self.filesystem.uuid);

        let mount_point = match get_mount_point(&self.filesystem.base_path).await {
            Ok(mp) => mp,
            Err(_) => self.filesystem.base_path.clone(),
        };

        DISK_USAGE.write().await.insert(
            self.filesystem.uuid,
            (
                self.filesystem.base_path.clone(),
                mount_point,
                project_id,
                -1,
                self.filesystem.resource_usage.clone(),
            ),
        );
        Ok(())
    }

    async fn disk_usage(&self) -> Result<u64, std::io::Error> {
        let map = DISK_USAGE.read().await;
        if let Some(usage) = map.get(&self.filesystem.uuid)
            && usage.3 >= 0
        {
            return Ok(usage.3 as u64);
        }

        Err(std::io::Error::other(format!(
            "Failed to load XFS disk usage for {}",
            self.filesystem.base_path.display()
        )))
    }

    async fn update_disk_limit(&self, limit: u64) -> Result<(), std::io::Error> {
        tracing::debug!(
            path = %self.filesystem.base_path.display(),
            limit = limit,
            "setting xfs disk limit"
        );

        let project_id = uuid_to_project_id(&self.filesystem.uuid);

        let mount_point = {
            let map = DISK_USAGE.read().await;
            match map.get(&self.filesystem.uuid) {
                Some(u) => u.1.clone(),
                None => self.filesystem.base_path.clone(),
            }
        };

        let limit_mb = if limit == 0 {
            "0".to_string()
        } else {
            format!("{}m", limit / 1024 / 1024)
        };

        let output = Command::new("xfs_quota")
            .arg("-x")
            .arg("-c")
            .arg(format!(
                "limit -p bsoft={limit_mb} bhard={limit_mb} {project_id}"
            ))
            .arg(&mount_point)
            .output()
            .await?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "Failed to set XFS disk limit for {}: {}",
                self.filesystem.base_path.display(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    async fn destroy(&self) -> Result<(), std::io::Error> {
        tracing::debug!(
            path = %self.filesystem.base_path.display(),
            "destroying xfs project quota for server"
        );

        self.update_disk_limit(0).await?;

        let project_id = uuid_to_project_id(&self.filesystem.uuid);

        atomic_write_etc_projects(project_id, &self.filesystem.base_path, true).await?;

        super::remove_volume(self.filesystem).await?;
        DISK_USAGE.write().await.remove(&self.filesystem.uuid);

        Ok(())
    }
}
