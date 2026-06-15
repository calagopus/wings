use crate::{
    remote::backups::RawServerBackup,
    server::backup::{Backup, BackupCleanExt, BackupCreateExt, BackupFindExt},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::AtomicU64};
use utoipa::ToSchema;

pub mod btrfs;
pub mod ddup_bak;
pub mod pbs;
pub mod restic;
pub mod s3;
pub mod wings;
pub mod zfs;

#[derive(ToSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[schema(rename_all = "kebab-case")]
pub enum BackupAdapter {
    Wings,
    S3,
    DdupBak,
    Btrfs,
    Zfs,
    Restic,
    ProxmoxBackupServer,
}

impl BackupAdapter {
    #[inline]
    pub fn variants() -> &'static [Self] {
        &[
            Self::Wings,
            Self::S3,
            Self::DdupBak,
            Self::Btrfs,
            Self::Zfs,
            Self::Restic,
            Self::ProxmoxBackupServer,
        ]
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Wings => "wings",
            Self::S3 => "s3",
            Self::DdupBak => "ddup-bak",
            Self::Btrfs => "btrfs",
            Self::Zfs => "zfs",
            Self::Restic => "restic",
            Self::ProxmoxBackupServer => "proxmox-backup-server",
        }
    }
}

impl BackupAdapter {
    pub async fn find_all(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<(Self, Backup)>, anyhow::Error> {
        for adapter in Self::variants() {
            if let Some(backup) = match adapter {
                BackupAdapter::Wings => {
                    <wings::WingsBackup as BackupFindExt>::find(state, uuid).await
                }
                BackupAdapter::S3 => Ok(None),
                BackupAdapter::DdupBak => {
                    <ddup_bak::DdupBakBackup as BackupFindExt>::find(state, uuid).await
                }
                BackupAdapter::Btrfs => {
                    <btrfs::BtrfsBackup as BackupFindExt>::find(state, uuid).await
                }
                BackupAdapter::Zfs => <zfs::ZfsBackup as BackupFindExt>::find(state, uuid).await,
                BackupAdapter::Restic => {
                    <restic::ResticBackup as BackupFindExt>::find(state, uuid).await
                }
                BackupAdapter::ProxmoxBackupServer => {
                    <pbs::PbsBackup as BackupFindExt>::find(state, uuid).await
                }
            }? {
                return Ok(Some((*adapter, backup)));
            }
        }

        Ok(None)
    }

    pub async fn find(
        self,
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error> {
        match self {
            BackupAdapter::Wings => wings::WingsBackup::find(state, uuid).await,
            BackupAdapter::S3 => s3::S3Backup::find(state, uuid).await,
            BackupAdapter::DdupBak => ddup_bak::DdupBakBackup::find(state, uuid).await,
            BackupAdapter::Btrfs => btrfs::BtrfsBackup::find(state, uuid).await,
            BackupAdapter::Zfs => zfs::ZfsBackup::find(state, uuid).await,
            BackupAdapter::Restic => restic::ResticBackup::find(state, uuid).await,
            BackupAdapter::ProxmoxBackupServer => pbs::PbsBackup::find(state, uuid).await,
        }
    }

    pub async fn create(
        self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error> {
        match self {
            BackupAdapter::Wings => {
                wings::WingsBackup::create(server, uuid, progress, total, ignore, ignore_raw).await
            }
            BackupAdapter::S3 => {
                s3::S3Backup::create(server, uuid, progress, total, ignore, ignore_raw).await
            }
            BackupAdapter::DdupBak => {
                ddup_bak::DdupBakBackup::create(server, uuid, progress, total, ignore, ignore_raw)
                    .await
            }
            BackupAdapter::Btrfs => {
                btrfs::BtrfsBackup::create(server, uuid, progress, total, ignore, ignore_raw).await
            }
            BackupAdapter::Zfs => {
                zfs::ZfsBackup::create(server, uuid, progress, total, ignore, ignore_raw).await
            }
            BackupAdapter::Restic => {
                restic::ResticBackup::create(server, uuid, progress, total, ignore, ignore_raw)
                    .await
            }
            BackupAdapter::ProxmoxBackupServer => {
                pbs::PbsBackup::create(server, uuid, progress, total, ignore, ignore_raw).await
            }
        }
    }

    pub async fn clean(
        self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        match self {
            BackupAdapter::Wings => wings::WingsBackup::clean(server, uuid).await,
            BackupAdapter::S3 => s3::S3Backup::clean(server, uuid).await,
            BackupAdapter::DdupBak => ddup_bak::DdupBakBackup::clean(server, uuid).await,
            BackupAdapter::Btrfs => btrfs::BtrfsBackup::clean(server, uuid).await,
            BackupAdapter::Zfs => zfs::ZfsBackup::clean(server, uuid).await,
            BackupAdapter::Restic => restic::ResticBackup::clean(server, uuid).await,
            BackupAdapter::ProxmoxBackupServer => pbs::PbsBackup::clean(server, uuid).await,
        }
    }
}
