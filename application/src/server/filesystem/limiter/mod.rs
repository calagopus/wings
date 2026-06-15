use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[cfg(unix)]
pub(crate) mod btrfs_subvolume;
#[cfg(unix)]
pub(crate) mod fuse_quota;
pub(crate) mod none;
#[cfg(unix)]
pub(crate) mod xfs_quota;
#[cfg(unix)]
pub(crate) mod zfs_dataset;

#[async_trait::async_trait]
pub trait DiskLimiterExt: Send + Sync {
    async fn setup(&self) -> Result<(), std::io::Error>;
    async fn attach(&self) -> Result<(), std::io::Error>;
    async fn destroy(&self) -> Result<(), std::io::Error>;

    async fn startup(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), std::io::Error> {
        Ok(())
    }

    async fn disk_usage(&self) -> Result<u64, std::io::Error>;
    async fn update_disk_limit(&self, limit: u64) -> Result<(), std::io::Error>;
}

#[derive(ToSchema, Deserialize, Serialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DiskLimiterMode {
    #[default]
    None,
    #[cfg(unix)]
    BtrfsSubvolume,
    #[cfg(unix)]
    ZfsDataset,
    #[cfg(unix)]
    XfsQuota,
    #[cfg(unix)]
    FuseQuota,
}

impl DiskLimiterMode {
    pub fn get_limiter<'a>(
        self,
        filesystem: &'a crate::server::filesystem::Filesystem,
    ) -> Box<dyn DiskLimiterExt + 'a> {
        match self {
            DiskLimiterMode::None => Box::new(none::NoneLimiter { filesystem }),
            #[cfg(unix)]
            DiskLimiterMode::BtrfsSubvolume => {
                Box::new(btrfs_subvolume::BtrfsSubvolumeLimiter { filesystem })
            }
            #[cfg(unix)]
            DiskLimiterMode::ZfsDataset => Box::new(zfs_dataset::ZfsDatasetLimiter { filesystem }),
            #[cfg(unix)]
            DiskLimiterMode::XfsQuota => Box::new(xfs_quota::XfsQuotaLimiter { filesystem }),
            #[cfg(unix)]
            DiskLimiterMode::FuseQuota => Box::new(fuse_quota::FuseQuotaLimiter { filesystem }),
        }
    }
}
