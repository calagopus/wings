use crate::io::compression::CompressionType;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use utoipa::ToSchema;

pub mod create;
mod extract;
pub mod multi_reader;

/// Largest zip symlink entry read as a link target; bigger ones are not symlinks
/// any real archiver writes, so they are skipped instead of buffered.
pub const ZIP_SYMLINK_MAX_BYTES: u64 = 2048;

pub fn generated_archive_name(extension: &str) -> compact_str::CompactString {
    compact_str::format_compact!(
        "archive-{}.{}",
        chrono::Local::now().format("%Y-%m-%dT%H%M%S%z"),
        extension
    )
}

#[derive(Debug, Clone, Copy)]
pub enum ArchiveType {
    None,
    Tar,
    Zip,
    Rar,
    SevenZip,
    Ddup,
    Pxar,
    Itaf,
}

#[derive(Debug, ToSchema, Deserialize, Serialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Tar,
    #[default]
    TarGz,
    TarXz,
    TarLzip,
    TarBz2,
    TarLz4,
    TarZstd,
    Zip,
    SevenZip,
}

impl ArchiveFormat {
    #[inline]
    pub fn variants() -> &'static [ArchiveFormat] {
        &[
            ArchiveFormat::Tar,
            ArchiveFormat::TarGz,
            ArchiveFormat::TarXz,
            ArchiveFormat::TarLzip,
            ArchiveFormat::TarBz2,
            ArchiveFormat::TarLz4,
            ArchiveFormat::TarZstd,
            ArchiveFormat::Zip,
            ArchiveFormat::SevenZip,
        ]
    }

    #[inline]
    pub fn archive_type(self) -> ArchiveType {
        match self {
            ArchiveFormat::Zip => ArchiveType::Zip,
            ArchiveFormat::SevenZip => ArchiveType::SevenZip,
            _ => ArchiveType::Tar,
        }
    }

    #[inline]
    pub fn compression_format(self) -> CompressionType {
        match self {
            ArchiveFormat::Tar => CompressionType::None,
            ArchiveFormat::TarGz => CompressionType::Gz,
            ArchiveFormat::TarXz => CompressionType::Xz,
            ArchiveFormat::TarLzip => CompressionType::Lzip,
            ArchiveFormat::TarBz2 => CompressionType::Bz2,
            ArchiveFormat::TarLz4 => CompressionType::Lz4,
            ArchiveFormat::TarZstd => CompressionType::Zstd,
            _ => CompressionType::None,
        }
    }

    #[inline]
    pub fn extension(self) -> &'static str {
        match self {
            ArchiveFormat::Tar => "tar",
            ArchiveFormat::TarGz => "tar.gz",
            ArchiveFormat::TarXz => "tar.xz",
            ArchiveFormat::TarLzip => "tar.lz",
            ArchiveFormat::TarBz2 => "tar.bz2",
            ArchiveFormat::TarLz4 => "tar.lz4",
            ArchiveFormat::TarZstd => "tar.zst",
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::SevenZip => "7z",
        }
    }

    #[inline]
    pub fn mime_type(self) -> &'static str {
        match self {
            ArchiveFormat::Tar => "application/x-tar",
            ArchiveFormat::TarGz => "application/gzip",
            ArchiveFormat::TarXz => "application/x-xz",
            ArchiveFormat::TarLzip => "application/x-lzip",
            ArchiveFormat::TarBz2 => "application/x-bzip2",
            ArchiveFormat::TarLz4 => "application/x-lz4",
            ArchiveFormat::TarZstd => "application/zstd",
            ArchiveFormat::Zip => "application/zip",
            ArchiveFormat::SevenZip => "application/x-7z-compressed",
        }
    }
}

impl std::str::FromStr for ArchiveFormat {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with(".tar") {
            Ok(ArchiveFormat::Tar)
        } else if s.ends_with(".tar.gz") {
            Ok(ArchiveFormat::TarGz)
        } else if s.ends_with(".tar.xz") {
            Ok(ArchiveFormat::TarXz)
        } else if s.ends_with(".tar.lz") {
            Ok(ArchiveFormat::TarLzip)
        } else if s.ends_with(".tar.bz2") {
            Ok(ArchiveFormat::TarBz2)
        } else if s.ends_with(".tar.lz4") {
            Ok(ArchiveFormat::TarLz4)
        } else if s.ends_with(".tar.zst") {
            Ok(ArchiveFormat::TarZstd)
        } else if s.ends_with(".zip") {
            Ok(ArchiveFormat::Zip)
        } else if s.ends_with(".7z") {
            Ok(ArchiveFormat::SevenZip)
        } else {
            Err("Invalid archive format")
        }
    }
}

#[derive(ToSchema, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum StreamableArchiveFormat {
    Tar,
    #[default]
    TarGz,
    TarXz,
    TarLzip,
    TarBz2,
    TarLz4,
    TarZstd,

    Itaf,
    ItafGz,
    ItafXz,
    ItafLzip,
    ItafBz2,
    ItafLz4,
    ItafZstd,

    Zip,
}

impl StreamableArchiveFormat {
    #[inline]
    pub fn compression_format(self) -> CompressionType {
        match self {
            StreamableArchiveFormat::Tar | StreamableArchiveFormat::Itaf => CompressionType::None,
            StreamableArchiveFormat::TarGz | StreamableArchiveFormat::ItafGz => CompressionType::Gz,
            StreamableArchiveFormat::TarXz | StreamableArchiveFormat::ItafXz => CompressionType::Xz,
            StreamableArchiveFormat::TarLzip | StreamableArchiveFormat::ItafLzip => {
                CompressionType::Lzip
            }
            StreamableArchiveFormat::TarBz2 | StreamableArchiveFormat::ItafBz2 => {
                CompressionType::Bz2
            }
            StreamableArchiveFormat::TarLz4 | StreamableArchiveFormat::ItafLz4 => {
                CompressionType::Lz4
            }
            StreamableArchiveFormat::TarZstd | StreamableArchiveFormat::ItafZstd => {
                CompressionType::Zstd
            }
            StreamableArchiveFormat::Zip => CompressionType::None,
        }
    }

    #[inline]
    pub fn extension(self) -> &'static str {
        match self {
            StreamableArchiveFormat::Tar => "tar",
            StreamableArchiveFormat::TarGz => "tar.gz",
            StreamableArchiveFormat::TarXz => "tar.xz",
            StreamableArchiveFormat::TarLzip => "tar.lz",
            StreamableArchiveFormat::TarBz2 => "tar.bz2",
            StreamableArchiveFormat::TarLz4 => "tar.lz4",
            StreamableArchiveFormat::TarZstd => "tar.zst",
            StreamableArchiveFormat::Itaf => "itaf",
            StreamableArchiveFormat::ItafGz => "itaf.gz",
            StreamableArchiveFormat::ItafXz => "itaf.xz",
            StreamableArchiveFormat::ItafLzip => "itaf.lz",
            StreamableArchiveFormat::ItafBz2 => "itaf.bz2",
            StreamableArchiveFormat::ItafLz4 => "itaf.lz4",
            StreamableArchiveFormat::ItafZstd => "itaf.zst",
            StreamableArchiveFormat::Zip => "zip",
        }
    }

    #[inline]
    pub fn mime_type(self) -> &'static str {
        match self {
            StreamableArchiveFormat::Tar => "application/x-tar",
            StreamableArchiveFormat::TarGz | StreamableArchiveFormat::ItafGz => "application/gzip",
            StreamableArchiveFormat::TarXz | StreamableArchiveFormat::ItafXz => "application/x-xz",
            StreamableArchiveFormat::TarLzip | StreamableArchiveFormat::ItafLzip => {
                "application/x-lzip"
            }
            StreamableArchiveFormat::TarBz2 | StreamableArchiveFormat::ItafBz2 => {
                "application/x-bzip2"
            }
            StreamableArchiveFormat::TarLz4 | StreamableArchiveFormat::ItafLz4 => {
                "application/x-lz4"
            }
            StreamableArchiveFormat::TarZstd | StreamableArchiveFormat::ItafZstd => {
                "application/zstd"
            }
            StreamableArchiveFormat::Itaf => "application/octet-stream",
            StreamableArchiveFormat::Zip => "application/zip",
        }
    }

    #[inline]
    pub const fn is_tar(self) -> bool {
        matches!(
            self,
            StreamableArchiveFormat::Tar
                | StreamableArchiveFormat::TarGz
                | StreamableArchiveFormat::TarXz
                | StreamableArchiveFormat::TarLzip
                | StreamableArchiveFormat::TarBz2
                | StreamableArchiveFormat::TarLz4
                | StreamableArchiveFormat::TarZstd
        )
    }

    #[inline]
    pub const fn is_itaf(self) -> bool {
        matches!(
            self,
            StreamableArchiveFormat::Itaf
                | StreamableArchiveFormat::ItafGz
                | StreamableArchiveFormat::ItafXz
                | StreamableArchiveFormat::ItafLzip
                | StreamableArchiveFormat::ItafBz2
                | StreamableArchiveFormat::ItafLz4
                | StreamableArchiveFormat::ItafZstd
        )
    }
}

pub fn zip_entry_get_modified_time(
    entry: &zip::read::ZipFile<impl std::io::Read>,
) -> Option<std::time::SystemTime> {
    for field in entry.extra_data_fields() {
        if let zip::extra_fields::ExtraField::ExtendedTimestamp(ext) = field
            && let Some(mod_time) = ext.mod_time()
        {
            return Some(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mod_time as u64),
            );
        }

        if let zip::extra_fields::ExtraField::Ntfs(ntfs) = field {
            let mtime = sevenz_rust2::NtTime::new(ntfs.mtime());

            return Some(std::time::SystemTime::from(mtime));
        }
    }

    if let Some(time) = entry.last_modified()
        && time.is_valid()
    {
        let chrono_date = chrono::NaiveDate::from_ymd_opt(
            time.year() as i32,
            time.month() as u32,
            time.day() as u32,
        )?;
        let chrono_time = chrono::NaiveTime::from_hms_opt(
            time.hour() as u32,
            time.minute() as u32,
            time.second() as u32,
        )?;

        return Some(
            std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(
                    chrono_date.and_time(chrono_time).and_utc().timestamp() as u64,
                ),
        );
    }

    None
}

pub fn zip_entry_get_created_time(
    entry: &zip::read::ZipFile<impl std::io::Read>,
) -> Option<std::time::SystemTime> {
    for field in entry.extra_data_fields() {
        if let zip::extra_fields::ExtraField::ExtendedTimestamp(ext) = field
            && let Some(cr_time) = ext.cr_time()
        {
            return Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(cr_time as u64));
        }

        if let zip::extra_fields::ExtraField::Ntfs(ntfs) = field {
            let ctime = sevenz_rust2::NtTime::new(ntfs.ctime());

            return Some(std::time::SystemTime::from(ctime));
        }
    }

    None
}

pub fn zip_entry_read_symlink_target(entry: impl Read) -> Result<String, std::io::Error> {
    let mut target = String::new();
    entry
        .take(ZIP_SYMLINK_MAX_BYTES + 1)
        .read_to_string(&mut target)?;

    if target.len() as u64 > ZIP_SYMLINK_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "symlink target size exceeds maximum allowed size",
        ));
    }

    Ok(target)
}

pub fn open_zip<R: Read + Seek + Clone>(reader: R) -> zip::result::ZipResult<zip::ZipArchive<R>> {
    let config = zip::read::Config {
        archive_offset: zip::read::ArchiveOffset::Known(0),
    };

    zip::ZipArchive::with_config(config, reader.clone()).or_else(|_| zip::ZipArchive::new(reader))
}

pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

pub enum SeekableSource {
    File(std::fs::File),
    Reader(Box<dyn ReadSeek>),
}

impl Read for SeekableSource {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SeekableSource::File(file) => file.read(buf),
            SeekableSource::Reader(reader) => reader.read(buf),
        }
    }
}

impl Seek for SeekableSource {
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            SeekableSource::File(file) => file.seek(pos),
            SeekableSource::Reader(reader) => reader.seek(pos),
        }
    }
}

pub enum ArchiveSource {
    File { file: std::fs::File, path: PathBuf },
    Seekable(Box<dyn ReadSeek>),
    Stream(Box<dyn Read + Send>),
}

impl ArchiveSource {
    fn name(&self) -> &'static str {
        match self {
            ArchiveSource::File { .. } => "file",
            ArchiveSource::Seekable(_) => "seekable stream",
            ArchiveSource::Stream(_) => "stream",
        }
    }

    #[inline]
    pub fn is_seekable(&self) -> bool {
        !matches!(self, ArchiveSource::Stream(_))
    }

    pub fn file(self) -> Result<(std::fs::File, PathBuf), anyhow::Error> {
        match self {
            ArchiveSource::File { file, path } => Ok((file, path)),
            source => Err(anyhow::anyhow!(
                "archive source is a {}, not a file",
                source.name()
            )),
        }
    }

    pub fn seekable(self) -> Result<SeekableSource, anyhow::Error> {
        match self {
            ArchiveSource::File { file, .. } => Ok(SeekableSource::File(file)),
            ArchiveSource::Seekable(reader) => Ok(SeekableSource::Reader(reader)),
            source => Err(anyhow::anyhow!(
                "archive source is a {}, not seekable",
                source.name()
            )),
        }
    }

    pub fn stream(self) -> Box<dyn Read + Send> {
        match self {
            ArchiveSource::File { file, .. } => Box::new(file),
            ArchiveSource::Seekable(reader) => Box::new(reader),
            ArchiveSource::Stream(reader) => reader,
        }
    }
}

pub type ExtractFileFn = Arc<dyn Fn(&Path) + Send + Sync>;
pub type ExtractPathFn = Arc<dyn Fn(&Path) -> PathBuf + Send + Sync>;

#[derive(Clone, Default)]
pub struct ExtractOptions {
    pub threads: Option<usize>,
    pub on_file: Option<ExtractFileFn>,
    /// Rewrites entry paths before they are resolved under the destination.
    pub map_path: Option<ExtractPathFn>,
    /// Counts written file bytes instead of archive bytes read.
    pub count_written: bool,
}

impl ExtractOptions {
    #[inline]
    fn threads(&self, server: &crate::server::Server) -> usize {
        self.threads.unwrap_or_else(|| {
            server
                .app_state
                .config
                .load()
                .api
                .file_decompression_threads
        })
    }

    fn resolve(&self, destination: &Path, path: &Path) -> Option<PathBuf> {
        match &self.map_path {
            Some(map_path) => extract::resolve_entry_path(destination, &map_path(path)),
            None => extract::resolve_entry_path(destination, path),
        }
    }

    /// Splits `progress` into the progress counted while reading and while writing.
    fn progress(
        &self,
        progress: &create::ArchiveProgress,
    ) -> (create::ArchiveProgress, create::ArchiveProgress) {
        if self.count_written {
            (progress.without_bytes(), progress.clone())
        } else {
            (progress.clone(), progress.without_bytes())
        }
    }

    #[inline]
    fn on_file(&self, path: &Path) {
        if let Some(on_file) = &self.on_file {
            on_file(path);
        }
    }
}

pub struct Archive {
    pub compression: CompressionType,
    pub archive: ArchiveType,

    pub server: crate::server::Server,

    pub size: Option<u64>,
    pub source: ArchiveSource,
}

impl Archive {
    pub const MAX_DIRECTORY_MTIME_ENTRIES: usize = 10_000_000;

    pub async fn open(server: crate::server::Server, path: PathBuf) -> Result<Self, anyhow::Error> {
        let mut file = server.filesystem.async_open(&path).await?;

        let mut header = [0; 64];
        #[allow(clippy::unused_io_amount)]
        file.read(&mut header).await?;
        file.seek(SeekFrom::Start(0)).await?;

        let (compression_format, archive_format) = Self::detect(&path, &header);

        tracing::debug!(
            path = %path.display(),
            "inferred archive format: {:?}, compression format: {:?}",
            archive_format,
            compression_format
        );

        let size = file.metadata().await.ok().map(|metadata| metadata.len());

        Ok(Self {
            compression: compression_format,
            archive: archive_format,
            server,
            size,
            source: ArchiveSource::File {
                file: file.into_std().await,
                path,
            },
        })
    }

    pub fn from_file(
        server: crate::server::Server,
        compression: CompressionType,
        archive: ArchiveType,
        file: std::fs::File,
        path: PathBuf,
        size: Option<u64>,
    ) -> Self {
        Self {
            compression,
            archive,
            server,
            size,
            source: ArchiveSource::File { file, path },
        }
    }

    pub fn from_seekable(
        server: crate::server::Server,
        compression: CompressionType,
        archive: ArchiveType,
        reader: impl Read + Seek + Send + 'static,
        size: Option<u64>,
    ) -> Self {
        Self {
            compression,
            archive,
            server,
            size,
            source: ArchiveSource::Seekable(Box::new(reader)),
        }
    }

    pub fn from_stream(
        server: crate::server::Server,
        compression: CompressionType,
        archive: ArchiveType,
        reader: impl Read + Send + 'static,
        size: Option<u64>,
    ) -> Self {
        Self {
            compression,
            archive,
            server,
            size,
            source: ArchiveSource::Stream(Box::new(reader)),
        }
    }

    pub fn detect(path: impl AsRef<Path>, header: &[u8]) -> (CompressionType, ArchiveType) {
        let path = path.as_ref();
        let inferred = infer::get(header);

        let get_archive_format = || -> ArchiveType {
            match path.extension() {
                Some(ext)
                    if [
                        "tar", "tgz", "tbz", "tbz2", "txz", "tlz", "tlz", "tlzf", "tlz4", "tzst",
                    ]
                    .contains(&ext.to_str().unwrap_or_default()) =>
                {
                    ArchiveType::Tar
                }
                Some(ext) if ext == "ddup" => ArchiveType::Ddup,
                Some(ext) if ext == "pxar" => ArchiveType::Pxar,
                Some(ext) if ext == "itaf" => ArchiveType::Itaf,
                _ => path
                    .file_stem()
                    .map_or(ArchiveType::None, |stem| match stem.to_str() {
                        Some(s) if s.ends_with(".tar") => ArchiveType::Tar,
                        Some(s) if s.ends_with(".pxar") => ArchiveType::Pxar,
                        Some(s) if s.ends_with(".itaf") => ArchiveType::Itaf,
                        _ => ArchiveType::None,
                    }),
            }
        };

        if pbs_client::pxar::is_pxar_header(header) {
            return (CompressionType::None, ArchiveType::Pxar);
        }

        if header.starts_with(b"ITAF") {
            return (CompressionType::None, ArchiveType::Itaf);
        }

        match inferred.map(|f| f.mime_type()) {
            Some("application/zip") => (CompressionType::None, ArchiveType::Zip),
            Some("application/x-tar") => (CompressionType::None, ArchiveType::Tar),
            Some("application/vnd.rar") => (CompressionType::None, ArchiveType::Rar),
            Some("application/x-7z-compressed") => (CompressionType::None, ArchiveType::SevenZip),
            mime => (
                mime.map_or(CompressionType::None, |mime| {
                    CompressionType::from_mime(mime)
                }),
                get_archive_format(),
            ),
        }
    }

    pub async fn extract(
        self,
        destination: PathBuf,
        destination_filesystem: Arc<dyn super::virtualfs::VirtualWritableFilesystem>,
        progress: create::ArchiveProgress,
        total: Option<Arc<AtomicU64>>,
        options: ExtractOptions,
    ) -> Result<(), anyhow::Error> {
        match self.archive {
            ArchiveType::None => {
                extract::extract_none(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::Tar => {
                extract::extract_tar(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::Zip => {
                extract::extract_zip(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::Rar => {
                extract::extract_rar(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::SevenZip => {
                extract::extract_seven_zip(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::Ddup => {
                extract::extract_ddup(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::Pxar => {
                extract::extract_pxar(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
            ArchiveType::Itaf => {
                extract::extract_itaf(
                    self,
                    destination,
                    destination_filesystem,
                    progress,
                    total,
                    options,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // zip_entry_read_symlink_target

    #[test]
    fn zip_entry_read_symlink_target_returns_targets_up_to_the_limit() {
        assert_eq!(
            zip_entry_read_symlink_target("../world/région.dat".as_bytes())
                .map_err(|err| err.kind()),
            Ok("../world/région.dat".to_string())
        );

        let exact = "a".repeat(ZIP_SYMLINK_MAX_BYTES as usize);

        assert_eq!(
            zip_entry_read_symlink_target(exact.as_bytes()).map_err(|err| err.kind()),
            Ok(exact)
        );
    }

    #[test]
    fn zip_entry_read_symlink_target_rejects_targets_over_the_limit() {
        let long = "a".repeat(ZIP_SYMLINK_MAX_BYTES as usize + 1);

        assert_eq!(
            zip_entry_read_symlink_target(long.as_bytes()).map_err(|err| err.kind()),
            Err(std::io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn zip_entry_read_symlink_target_stops_reading_an_oversized_stream() {
        let total = 1024 * 1024;
        let mut source = std::io::repeat(b'a').take(total);

        assert_eq!(
            zip_entry_read_symlink_target(&mut source).map_err(|err| err.kind()),
            Err(std::io::ErrorKind::InvalidData)
        );

        let consumed = total - source.limit();
        assert!(
            consumed <= 64 * 1024,
            "read {consumed} bytes of a {total} byte stream"
        );
    }
}
