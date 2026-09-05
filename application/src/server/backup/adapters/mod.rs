use crate::{
    remote::backups::RawServerBackup,
    server::backup::{
        Backup, BackupCleanExt, BackupCreateExt, BackupFindExt, BackupStreamCreateExt, DumpReader,
    },
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::AtomicU64};
use tokio::io::AsyncReadExt;
use utoipa::ToSchema;

pub mod btrfs;
pub mod ddup_bak;
pub mod kopia;
pub mod pbs;
pub mod restic;
pub mod s3;
pub mod wings;
pub mod zfs;

async fn prepare_dump_reader(mut reader: DumpReader) -> Result<DumpReader, anyhow::Error> {
    let mut first_byte = [0; 1];
    if reader.read(&mut first_byte).await? == 0 {
        return Err(anyhow::anyhow!("database dump is 0 bytes"));
    }

    Ok(Box::new(std::io::Cursor::new(first_byte).chain(reader)))
}

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
    Kopia,
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
            Self::Kopia,
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
            Self::Kopia => "kopia",
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
                BackupAdapter::Kopia => {
                    <kopia::KopiaBackup as BackupFindExt>::find(state, uuid).await
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
            BackupAdapter::Kopia => kopia::KopiaBackup::find(state, uuid).await,
        }
    }

    pub async fn create(
        self,
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
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
            BackupAdapter::Kopia => {
                kopia::KopiaBackup::create(server, uuid, progress, total, ignore, ignore_raw).await
            }
        }
    }

    pub async fn create_from_stream(
        self,
        state: &crate::routes::State,
        uuid: uuid::Uuid,
        extension: &str,
        reader: DumpReader,
    ) -> Result<RawServerBackup, anyhow::Error> {
        super::validate_dump_extension(extension)?;
        let reader = prepare_dump_reader(reader).await?;

        match self {
            BackupAdapter::Wings => {
                wings::WingsBackup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::S3 => {
                s3::S3Backup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::DdupBak => {
                ddup_bak::DdupBakBackup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::Btrfs => {
                btrfs::BtrfsBackup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::Zfs => {
                zfs::ZfsBackup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::Restic => {
                restic::ResticBackup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::ProxmoxBackupServer => {
                pbs::PbsBackup::create_from_stream(state, uuid, extension, reader).await
            }
            BackupAdapter::Kopia => {
                kopia::KopiaBackup::create_from_stream(state, uuid, extension, reader).await
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
            BackupAdapter::Kopia => kopia::KopiaBackup::clean(server, uuid).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dump_is_rejected_before_adapter_creation() {
        tokio_test::block_on(async {
            let result = prepare_dump_reader(Box::new(tokio::io::empty())).await;
            assert!(result.is_err_and(|err| err.to_string().contains("0 bytes")));
        });
    }

    #[test]
    fn dump_preflight_preserves_every_byte() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            for input in [b"a".as_slice(), b"database dump"] {
                let mut reader = prepare_dump_reader(Box::new(std::io::Cursor::new(input))).await?;
                let mut output = Vec::new();
                reader.read_to_end(&mut output).await?;
                assert_eq!(output, input);
            }

            Ok(())
        })
    }

    #[test]
    fn dump_preflight_propagates_source_errors() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let source =
                tokio_util::io::StreamReader::new(futures::stream::iter([Err::<bytes::Bytes, _>(
                    std::io::Error::other("source failed"),
                )]));
            assert!(
                prepare_dump_reader(Box::new(source))
                    .await
                    .is_err_and(|err| err.to_string().contains("source failed"))
            );

            let source = tokio_util::io::StreamReader::new(futures::stream::iter([
                Ok(bytes::Bytes::from_static(b"a")),
                Err(std::io::Error::other("source failed")),
            ]));
            let mut reader = prepare_dump_reader(Box::new(source)).await?;
            let mut output = Vec::new();
            let result = reader.read_to_end(&mut output).await;
            assert_eq!(output, b"a");
            assert!(result.is_err_and(|err| err.to_string().contains("source failed")));

            Ok(())
        })
    }
}
