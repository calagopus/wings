use crate::{
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::filesystem::{
        archive::{ArchiveFormat, StreamableArchiveFormat},
        virtualfs::{ByteRange, VirtualReadableFilesystem},
    },
    utils::TokioStdoutTakeExt,
};
use axum::http::{HeaderMap, HeaderValue};
use serde::Serialize;
use std::sync::{Arc, atomic::AtomicU64};
use utoipa::ToSchema;

pub mod adapters;
pub mod manager;
pub mod transfer;

#[derive(Clone, ToSchema, Serialize)]
pub struct BackupDownloadInfo {
    pub archive_format: Option<ArchiveFormat>,
    pub size: Option<u64>,
}

pub struct BackupStream {
    pub reader: DumpReader,
    pub size: Option<u64>,
    pub file_name: compact_str::CompactString,
}

impl BackupStream {
    fn from_process(
        mut child: tokio::process::Child,
        size: Option<u64>,
        file_name: compact_str::CompactString,
    ) -> Result<Self, anyhow::Error> {
        let stdout = child.take_stdout()?;
        let (reader, signal) = crate::io::fallible_reader::FallibleReader::new_with_eof(stdout);

        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) if status.success() => signal.succeed(),
                Ok(status) => signal.fail(format!("database dump process exited with {status}")),
                Err(err) => signal.fail(err),
            }
        });

        Ok(Self {
            reader: Box::new(reader),
            size,
            file_name,
        })
    }
}

pub type DumpReader = Box<dyn tokio::io::AsyncRead + Send + Unpin>;

const DATABASE_DUMP_EXTENSIONS: &[&str] = &["sql", "archive", "rdb", "dump"];

pub fn validate_dump_extension(extension: &str) -> Result<(), anyhow::Error> {
    if DATABASE_DUMP_EXTENSIONS.contains(&extension) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("unsupported database dump extension"))
    }
}

pub enum Backup {
    Wings(adapters::wings::WingsBackup),
    S3(adapters::s3::S3Backup),
    DdupBak(adapters::ddup_bak::DdupBakBackup),
    Btrfs(adapters::btrfs::BtrfsBackup),
    Zfs(adapters::zfs::ZfsBackup),
    Restic(adapters::restic::ResticBackup),
    ProxmoxBackupServer(adapters::pbs::PbsBackup),
    Kopia(adapters::kopia::KopiaBackup),
}

impl Backup {
    pub fn uuid(&self) -> uuid::Uuid {
        match self {
            Backup::Wings(backup) => backup.uuid(),
            Backup::S3(backup) => backup.uuid(),
            Backup::DdupBak(backup) => backup.uuid(),
            Backup::Btrfs(backup) => backup.uuid(),
            Backup::Zfs(backup) => backup.uuid(),
            Backup::Restic(backup) => backup.uuid(),
            Backup::ProxmoxBackupServer(backup) => backup.uuid(),
            Backup::Kopia(backup) => backup.uuid(),
        }
    }

    #[inline]
    pub fn adapter(&self) -> adapters::BackupAdapter {
        match self {
            Backup::Wings(_) => adapters::BackupAdapter::Wings,
            Backup::S3(_) => adapters::BackupAdapter::S3,
            Backup::DdupBak(_) => adapters::BackupAdapter::DdupBak,
            Backup::Btrfs(_) => adapters::BackupAdapter::Btrfs,
            Backup::Zfs(_) => adapters::BackupAdapter::Zfs,
            Backup::Restic(_) => adapters::BackupAdapter::Restic,
            Backup::ProxmoxBackupServer(_) => adapters::BackupAdapter::ProxmoxBackupServer,
            Backup::Kopia(_) => adapters::BackupAdapter::Kopia,
        }
    }

    pub async fn download_info(&self) -> Result<BackupDownloadInfo, anyhow::Error> {
        match self {
            Backup::Wings(backup) => backup.download_info().await,
            Backup::S3(backup) => backup.download_info().await,
            Backup::DdupBak(backup) => backup.download_info().await,
            Backup::Btrfs(backup) => backup.download_info().await,
            Backup::Zfs(backup) => backup.download_info().await,
            Backup::Restic(backup) => backup.download_info().await,
            Backup::ProxmoxBackupServer(backup) => backup.download_info().await,
            Backup::Kopia(backup) => backup.download_info().await,
        }
    }

    pub async fn download(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        range: Option<ByteRange>,
    ) -> Result<ApiResponse, anyhow::Error> {
        match self {
            Backup::Wings(backup) => backup.download(state, archive_format, range).await,
            Backup::S3(backup) => backup.download(state, archive_format, range).await,
            Backup::DdupBak(backup) => backup.download(state, archive_format, range).await,
            Backup::Btrfs(backup) => backup.download(state, archive_format, range).await,
            Backup::Zfs(backup) => backup.download(state, archive_format, range).await,
            Backup::Restic(backup) => backup.download(state, archive_format, range).await,
            Backup::ProxmoxBackupServer(backup) => {
                backup.download(state, archive_format, range).await
            }
            Backup::Kopia(backup) => backup.download(state, archive_format, range).await,
        }
    }

    pub async fn restore(
        &self,
        server: &crate::server::Server,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        match self {
            Backup::Wings(backup) => backup.restore(server, progress, total, download_url).await,
            Backup::S3(backup) => backup.restore(server, progress, total, download_url).await,
            Backup::DdupBak(backup) => backup.restore(server, progress, total, download_url).await,
            Backup::Btrfs(backup) => backup.restore(server, progress, total, download_url).await,
            Backup::Zfs(backup) => backup.restore(server, progress, total, download_url).await,
            Backup::Restic(backup) => backup.restore(server, progress, total, download_url).await,
            Backup::ProxmoxBackupServer(backup) => {
                backup.restore(server, progress, total, download_url).await
            }
            Backup::Kopia(backup) => backup.restore(server, progress, total, download_url).await,
        }
    }

    pub async fn read_stream(
        &self,
        state: &crate::routes::State,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<BackupStream, anyhow::Error> {
        match self {
            Backup::Wings(backup) => backup.read_stream(state, download_url).await,
            Backup::S3(backup) => backup.read_stream(state, download_url).await,
            Backup::DdupBak(backup) => backup.read_stream(state, download_url).await,
            Backup::Btrfs(backup) => backup.read_stream(state, download_url).await,
            Backup::Zfs(backup) => backup.read_stream(state, download_url).await,
            Backup::Restic(backup) => backup.read_stream(state, download_url).await,
            Backup::ProxmoxBackupServer(backup) => backup.read_stream(state, download_url).await,
            Backup::Kopia(backup) => backup.read_stream(state, download_url).await,
        }
    }

    pub async fn download_database(
        &self,
        state: &crate::routes::State,
    ) -> Result<ApiResponse, anyhow::Error> {
        if let Backup::Wings(backup) = self {
            return backup
                .download(state, StreamableArchiveFormat::default(), None)
                .await;
        }

        let stream = self.read_stream(state, None).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_DISPOSITION,
            HeaderValue::try_from(format!("attachment; filename={}", stream.file_name))?,
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(size) = stream.size {
            headers.insert(axum::http::header::CONTENT_LENGTH, size.into());
        }

        Ok(ApiResponse::new_stream(stream.reader).with_headers(headers))
    }

    pub async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error> {
        match self {
            Backup::Wings(backup) => backup.delete(state).await,
            Backup::S3(backup) => backup.delete(state).await,
            Backup::DdupBak(backup) => backup.delete(state).await,
            Backup::Btrfs(backup) => backup.delete(state).await,
            Backup::Zfs(backup) => backup.delete(state).await,
            Backup::Restic(backup) => backup.delete(state).await,
            Backup::ProxmoxBackupServer(backup) => backup.delete(state).await,
            Backup::Kopia(backup) => backup.delete(state).await,
        }
    }

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        match self {
            Backup::Wings(backup) => backup.browse(server).await,
            Backup::S3(backup) => backup.browse(server).await,
            Backup::DdupBak(backup) => backup.browse(server).await,
            Backup::Btrfs(backup) => backup.browse(server).await,
            Backup::Zfs(backup) => backup.browse(server).await,
            Backup::Restic(backup) => backup.browse(server).await,
            Backup::ProxmoxBackupServer(backup) => backup.browse(server).await,
            Backup::Kopia(backup) => backup.browse(server).await,
        }
    }
}

#[async_trait::async_trait]
pub trait BackupFindExt {
    async fn exists(state: &crate::routes::State, uuid: uuid::Uuid) -> Result<bool, anyhow::Error>;
    async fn find(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<Backup>, anyhow::Error>;
}

#[async_trait::async_trait]
pub trait BackupCreateExt {
    async fn create(
        server: &crate::server::Server,
        uuid: uuid::Uuid,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        ignore: ignore::gitignore::Gitignore,
        ignore_raw: compact_str::CompactString,
    ) -> Result<RawServerBackup, anyhow::Error>;
}

#[async_trait::async_trait]
pub trait BackupStreamCreateExt {
    async fn create_from_stream(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
        extension: &str,
        reader: DumpReader,
    ) -> Result<RawServerBackup, anyhow::Error>;
}

#[async_trait::async_trait]
pub trait BackupStreamExt {
    async fn read_stream(
        &self,
        state: &crate::routes::State,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<BackupStream, anyhow::Error>;
}

#[async_trait::async_trait]
pub trait BackupExt {
    fn uuid(&self) -> uuid::Uuid;

    async fn download_info(&self) -> Result<BackupDownloadInfo, anyhow::Error> {
        Ok(BackupDownloadInfo {
            archive_format: None,
            size: None,
        })
    }

    async fn download(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        range: Option<ByteRange>,
    ) -> Result<ApiResponse, anyhow::Error>;

    async fn restore(
        &self,
        server: &crate::server::Server,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error>;
    async fn delete(&self, state: &crate::routes::State) -> Result<(), anyhow::Error>;

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error>;
}

#[async_trait::async_trait]
pub trait BackupCleanExt {
    async fn clean(server: &crate::server::Server, uuid: uuid::Uuid) -> Result<(), anyhow::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn dump_extensions_round_trip_with_every_compression() -> Result<(), anyhow::Error> {
        use crate::io::compression::CompressionType;
        use adapters::wings::WingsBackupFile;

        for extension in DATABASE_DUMP_EXTENSIONS {
            validate_dump_extension(extension)?;

            for compression in CompressionType::variants() {
                let name = WingsBackupFile::Dump {
                    extension: (*extension).into(),
                    compression: *compression,
                }
                .extension();
                let parsed = WingsBackupFile::parse_dump(&name)
                    .ok_or_else(|| anyhow::anyhow!("dump was not discoverable: {name}"))?;

                assert_eq!(parsed.extension(), name);
                assert!(
                    format!("{}.{name}", uuid::Uuid::nil())
                        .parse::<ArchiveFormat>()
                        .is_err()
                );
            }
        }

        Ok(())
    }

    #[test]
    fn rejects_ambiguous_and_unsafe_dump_extensions() {
        for extension in [
            "",
            "sql.gz",
            "tar",
            "zip",
            "7z",
            "gz",
            "part",
            "../sql",
            "sql/path",
            "sql\\path",
        ] {
            assert!(validate_dump_extension(extension).is_err(), "{extension}");
        }

        for file_name in ["unknown", "tar", "zip", "sql.part", "sql.s3.gz"] {
            assert!(
                adapters::wings::WingsBackupFile::parse_dump(file_name).is_none(),
                "{file_name}"
            );
        }
    }

    fn stream(script: &str) -> Result<BackupStream, anyhow::Error> {
        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        BackupStream::from_process(child, None, "dump.sql".into())
    }

    #[test]
    fn successful_process_reads_to_eof() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let mut stream = stream("printf dump")?;
            let mut out = Vec::new();
            stream.reader.read_to_end(&mut out).await?;
            assert_eq!(out, b"dump");

            Ok(())
        })
    }

    #[test]
    fn failed_process_reports_partial_dump() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let mut stream = stream("printf partial; exit 7")?;
            let mut out = Vec::new();
            let result = stream.reader.read_to_end(&mut out).await;
            assert_eq!(out, b"partial");
            assert!(result.is_err_and(|err| err.to_string().contains("exit status: 7")));

            Ok(())
        })
    }

    #[test]
    fn closed_stdout_waits_for_process_failure() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let mut stream = stream("exec 1>&-; sleep 0.05; exit 9")?;
            let mut out = Vec::new();
            let result = stream.reader.read_to_end(&mut out).await;
            assert!(out.is_empty());
            assert!(result.is_err_and(|err| err.to_string().contains("exit status: 9")));

            Ok(())
        })
    }
}
