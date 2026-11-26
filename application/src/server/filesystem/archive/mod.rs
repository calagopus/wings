use crate::{io::compression::CompressionType, server::filesystem::cap::FileType};
use chrono::{Datelike, Timelike};
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

/// The zip (DOS) timestamp for `time`, or `None` when it falls outside 1980..=2107.
pub fn zip_datetime(time: impl Into<chrono::DateTime<chrono::Utc>>) -> Option<zip::DateTime> {
    let time = time.into();

    zip::DateTime::from_date_and_time(
        u16::try_from(time.year()).ok()?,
        time.month() as u8,
        time.day() as u8,
        time.hour() as u8,
        time.minute() as u8,
        time.second() as u8,
    )
    .ok()
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

/// p7zip convention: the high 16 bits of a 7z entry's windows attributes hold
/// the unix `st_mode` when this bit is set.
pub const SEVEN_ZIP_UNIX_EXTENSION: u32 = 0x8000;
const SEVEN_ZIP_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const SEVEN_ZIP_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Windows attributes for an entry of `file_type` with permission bits `mode`.
/// Symlinks are stored as entries whose content is the link target.
pub fn seven_zip_attributes(file_type: FileType, mode: u16) -> u32 {
    let (unix_type, windows) = match file_type {
        FileType::Dir => (S_IFDIR, SEVEN_ZIP_ATTRIBUTE_DIRECTORY),
        FileType::Symlink => (S_IFLNK, SEVEN_ZIP_ATTRIBUTE_ARCHIVE),
        FileType::File | FileType::Unknown => (S_IFREG, SEVEN_ZIP_ATTRIBUTE_ARCHIVE),
    };

    ((unix_type | u32::from(mode & 0o7777)) << 16) | SEVEN_ZIP_UNIX_EXTENSION | windows
}

/// The unix file type and permission bits of a 7z entry, if it carries any.
pub fn seven_zip_unix_mode(entry: &sevenz_rust2::ArchiveEntry) -> Option<(FileType, u32)> {
    if !entry.has_windows_attributes || entry.windows_attributes & SEVEN_ZIP_UNIX_EXTENSION == 0 {
        return None;
    }

    let mode = entry.windows_attributes >> 16;
    let file_type = match mode & S_IFMT {
        S_IFDIR => FileType::Dir,
        S_IFREG => FileType::File,
        S_IFLNK => FileType::Symlink,
        _ => FileType::Unknown,
    };

    Some((file_type, mode & 0o7777))
}

pub fn seven_zip_entry_is_symlink(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    !entry.is_directory()
        && seven_zip_unix_mode(entry)
            .is_some_and(|(file_type, _)| matches!(file_type, FileType::Symlink))
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

        let mut header = Vec::with_capacity(512);
        (&mut file).take(512).read_to_end(&mut header).await?;
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

    // zip_datetime

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, s)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn zip_datetime_accepts_the_dos_range_bounds() {
        let first = zip_datetime(utc(1980, 1, 1, 0, 0, 0)).unwrap();
        assert_eq!(
            (
                first.year(),
                first.month(),
                first.day(),
                first.hour(),
                first.minute(),
                first.second()
            ),
            (1980, 1, 1, 0, 0, 0)
        );

        let last = zip_datetime(utc(2107, 12, 31, 23, 59, 58)).unwrap();
        assert_eq!(
            (
                last.year(),
                last.month(),
                last.day(),
                last.hour(),
                last.minute(),
                last.second()
            ),
            (2107, 12, 31, 23, 59, 58)
        );
    }

    #[test]
    fn zip_datetime_rejects_times_outside_the_dos_range() {
        assert!(zip_datetime(utc(1979, 12, 31, 23, 59, 59)).is_none());
        assert!(zip_datetime(utc(2108, 1, 1, 0, 0, 0)).is_none());
        assert!(zip_datetime(std::time::SystemTime::UNIX_EPOCH).is_none());
        // 67536 as u16 == 2000
        assert!(zip_datetime(utc(67536, 1, 1, 0, 0, 0)).is_none());
        assert!(zip_datetime(utc(-1, 1, 1, 0, 0, 0)).is_none());
    }

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
