use crate::{
    remote::backups::RawServerBackup,
    response::ApiResponse,
    server::filesystem::{
        archive::{ArchiveFormat, StreamableArchiveFormat},
        ignore_list::IgnoreList,
        virtualfs::{ByteRange, VirtualReadableFilesystem},
    },
    utils::TokioStdoutTakeExt,
};
use axum::http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
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

/// Dispatch surface of a backup instance; lets [`Backup`] forward to whichever adapter it holds.
trait BackupDyn: BackupExt + BackupStreamExt {}

impl<T: BackupExt + BackupStreamExt> BackupDyn for T {}

macro_rules! backup_adapters {
    ($($variant:ident($backup:ty) => $name:literal),* $(,)?) => {
        pub enum Backup {
            $($variant($backup),)*
        }

        impl Backup {
            #[inline]
            pub fn adapter(&self) -> adapters::BackupAdapter {
                match self {
                    $(Self::$variant(_) => adapters::BackupAdapter::$variant,)*
                }
            }

            #[inline]
            fn inner(&self) -> &(dyn BackupDyn + Send + Sync) {
                match self {
                    $(Self::$variant(backup) => backup,)*
                }
            }
        }

        #[derive(ToSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
        pub enum BackupAdapter {
            $(#[serde(rename = $name)] #[schema(rename = $name)] $variant,)*
        }

        impl BackupAdapter {
            #[inline]
            pub fn variants() -> &'static [Self] {
                &[$(Self::$variant,)*]
            }

            #[inline]
            pub fn to_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }

            pub async fn find(
                self,
                state: &crate::routes::State,
                uuid: uuid::Uuid,
            ) -> Result<Option<Backup>, anyhow::Error> {
                match self {
                    $(Self::$variant => <$backup as BackupFindExt>::find(state, uuid).await,)*
                }
            }

            pub async fn create(
                self,
                server: &crate::server::Server,
                uuid: uuid::Uuid,
                progress: crate::server::filesystem::archive::create::ArchiveProgress,
                total: Arc<AtomicU64>,
                ignore: IgnoreList,
                ignore_raw: compact_str::CompactString,
            ) -> Result<RawServerBackup, anyhow::Error> {
                match self {
                    $(Self::$variant => {
                        <$backup as BackupCreateExt>::create(
                            server, uuid, progress, total, ignore, ignore_raw,
                        )
                        .await
                    })*
                }
            }

            async fn create_from_prepared_stream(
                self,
                state: &crate::routes::State,
                uuid: uuid::Uuid,
                extension: &str,
                reader: DumpReader,
            ) -> Result<RawServerBackup, anyhow::Error> {
                match self {
                    $(Self::$variant => {
                        <$backup as BackupStreamCreateExt>::create_from_stream(
                            state, uuid, extension, reader,
                        )
                        .await
                    })*
                }
            }

            pub async fn clean(
                self,
                server: &crate::server::Server,
                uuid: uuid::Uuid,
            ) -> Result<(), anyhow::Error> {
                match self {
                    $(Self::$variant => <$backup as BackupCleanExt>::clean(server, uuid).await,)*
                }
            }
        }
    };
}

backup_adapters! {
    Wings(adapters::wings::WingsBackup) => "wings",
    S3(adapters::s3::S3Backup) => "s3",
    DdupBak(adapters::ddup_bak::DdupBakBackup) => "ddup-bak",
    Btrfs(adapters::btrfs::BtrfsBackup) => "btrfs",
    Zfs(adapters::zfs::ZfsBackup) => "zfs",
    Restic(adapters::restic::ResticBackup) => "restic",
    ProxmoxBackupServer(adapters::pbs::PbsBackup) => "proxmox-backup-server",
    Kopia(adapters::kopia::KopiaBackup) => "kopia",
}

impl Backup {
    #[inline]
    pub fn uuid(&self) -> uuid::Uuid {
        self.inner().uuid()
    }

    pub async fn download_info(&self) -> Result<BackupDownloadInfo, anyhow::Error> {
        self.inner().download_info().await
    }

    pub async fn download(
        &self,
        state: &crate::routes::State,
        archive_format: StreamableArchiveFormat,
        range: Option<ByteRange>,
    ) -> Result<ApiResponse, anyhow::Error> {
        self.inner().download(state, archive_format, range).await
    }

    pub async fn restore(
        &self,
        server: &crate::server::Server,
        progress: crate::server::filesystem::archive::create::ArchiveProgress,
        total: Arc<AtomicU64>,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<(), anyhow::Error> {
        self.inner()
            .restore(server, progress, total, download_url)
            .await
    }

    pub async fn read_stream(
        &self,
        state: &crate::routes::State,
        download_url: Option<compact_str::CompactString>,
    ) -> Result<BackupStream, anyhow::Error> {
        self.inner().read_stream(state, download_url).await
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
        self.inner().delete(state).await
    }

    async fn browse(
        &self,
        server: &crate::server::Server,
    ) -> Result<Arc<dyn VirtualReadableFilesystem>, anyhow::Error> {
        self.inner().browse(server).await
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
        ignore: IgnoreList,
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

    // BackupAdapter
    #[test]
    fn backup_adapter_wire_names_are_stable() -> Result<(), anyhow::Error> {
        let expected = [
            "wings",
            "s3",
            "ddup-bak",
            "btrfs",
            "zfs",
            "restic",
            "proxmox-backup-server",
            "kopia",
        ];

        let names: Vec<&str> = BackupAdapter::variants()
            .iter()
            .map(|adapter| adapter.to_str())
            .collect();
        assert_eq!(names, expected);

        for adapter in BackupAdapter::variants() {
            let json = serde_json::to_string(adapter)?;
            assert_eq!(json, format!("\"{}\"", adapter.to_str()));
            assert_eq!(serde_json::from_str::<BackupAdapter>(&json)?, *adapter);
        }

        let schema = serde_json::to_value(<BackupAdapter as utoipa::PartialSchema>::schema())?;
        let schema_names: Vec<&str> = schema
            .get("enum")
            .and_then(|values| values.as_array())
            .ok_or_else(|| anyhow::anyhow!("schema has no enum values: {schema}"))?
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        assert_eq!(schema_names, expected);

        Ok(())
    }
}
