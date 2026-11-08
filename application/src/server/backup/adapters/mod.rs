use crate::{
    io::compression::{CompressionType, reader::AsyncCompressionReader},
    remote::backups::RawServerBackup,
    server::backup::{Backup, DumpReader, DumpSource},
};
use tokio::io::AsyncReadExt;

pub mod btrfs;
pub mod ddup_bak;
pub mod kopia;
pub mod pbs;
pub mod restic;
pub mod s3;
pub mod wings;
pub mod zfs;

pub use super::BackupAdapter;

/// Above this many exclusion frontier entries an external engine, which matches
/// every path against every pattern, gets noticeably slow.
const EXCLUSION_FRONTIER_WARN: usize = 20_000;

fn log_configuration_error(adapter: &str, uuid: uuid::Uuid, err: &anyhow::Error) {
    if err
        .downcast_ref::<crate::remote::ApiError>()
        .is_some_and(|err| err.status == reqwest::StatusCode::EXPECTATION_FAILED)
    {
        return;
    }

    tracing::warn!(backup = %uuid, "failed to get {} backup configuration: {:#}", adapter, err);
}

/// A path spelled as a literal pattern for an external engine's glob syntax.
fn glob_literal(path: &std::path::Path) -> String {
    let path = path.to_string_lossy();
    let mut literal = String::with_capacity(path.len());

    for character in path.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            literal.push('\\');
        }
        literal.push(character);
    }

    literal
}

fn log_restoring(server: &crate::server::Server, path: &std::path::Path) {
    server.log_daemon(compact_str::format_compact!(
        "(restoring): {}",
        path.display()
    ));
}

/// Runs `create` for an entry restored by a walk with inline directories, where
/// the parent normally exists already. Only when `create` fails with `NotFound`
/// is the parent created, after which `create` runs once more.
async fn create_with_parent<T, Fut: Future<Output = Result<T, std::io::Error>>>(
    server: &crate::server::Server,
    path: &std::path::Path,
    mut create: impl FnMut() -> Fut,
) -> Result<T, std::io::Error> {
    match create().await {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let Some(parent) = path.parent() else {
                return Err(err);
            };

            server
                .filesystem
                .async_create_chowned_dir_all(parent, None)
                .await?;
            create().await
        }
        result => result,
    }
}

async fn prepare_dump_reader(mut reader: DumpReader) -> Result<DumpReader, anyhow::Error> {
    let mut first_byte = [0; 1];
    if reader.read(&mut first_byte).await? == 0 {
        return Err(anyhow::anyhow!("database dump is 0 bytes"));
    }

    Ok(Box::new(std::io::Cursor::new(first_byte).chain(reader)))
}

fn decompress_dump(reader: DumpReader, compression: CompressionType) -> DumpReader {
    match compression {
        CompressionType::None => reader,
        compression => Box::new(AsyncCompressionReader::new_with_async_reader(
            reader,
            compression,
        )),
    }
}

async fn probe_backup_directory(config: &crate::config::Config) -> Result<(), anyhow::Error> {
    let path = config.resolve_as_path(|cfg| &cfg.system.backup_directory);

    let metadata = tokio::fs::metadata(&path).await.map_err(|err| {
        anyhow::anyhow!(
            "backup directory {} is not accessible: {err}",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(anyhow::anyhow!(
            "backup directory {} is not a directory",
            path.display()
        ));
    }

    let probe = path.join(format!(".calagopus-test-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&probe, b"calagopus")
        .await
        .map_err(|err| {
            anyhow::anyhow!("backup directory {} is not writable: {err}", path.display())
        })?;
    tokio::fs::remove_file(&probe).await?;

    Ok(())
}

async fn probe_command(mut command: tokio::process::Command) -> Result<(), anyhow::Error> {
    let program = command
        .as_std()
        .get_program()
        .to_string_lossy()
        .into_owned();
    let output = command
        .env("LC_ALL", "C")
        .output()
        .await
        .map_err(|err| anyhow::anyhow!("failed to run {program}: {err}"))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

impl BackupAdapter {
    pub async fn find_all(
        state: &crate::routes::State,
        uuid: uuid::Uuid,
    ) -> Result<Option<(Self, Backup)>, anyhow::Error> {
        for adapter in Self::variants() {
            if *adapter == Self::S3 {
                continue;
            }

            if let Some(backup) = adapter.find(state, uuid).await? {
                return Ok(Some((*adapter, backup)));
            }
        }

        Ok(None)
    }

    pub async fn create_from_stream(
        self,
        state: &crate::routes::State,
        uuid: uuid::Uuid,
        extension: &str,
        source: DumpSource,
    ) -> Result<RawServerBackup, anyhow::Error> {
        let (extension, compression) = super::parse_dump_extension(extension)?;

        // Deduplicating adapters compress chunks themselves, and a compressed
        // stream defeats their content-defined chunking.
        let decompress = !matches!(self, Self::Wings | Self::S3);
        let source: DumpSource = Box::pin(async move {
            let reader = prepare_dump_reader(source.await?).await?;

            Ok(if decompress {
                decompress_dump(reader, compression)
            } else {
                reader
            })
        });
        let compression = if decompress {
            CompressionType::None
        } else {
            compression
        };

        self.create_from_prepared_stream(state, uuid, extension, compression, source)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dump_is_rejected() {
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

    // decompress_dump
    #[test]
    fn decompress_dump_passes_uncompressed_through() -> Result<(), anyhow::Error> {
        tokio_test::block_on(async {
            let input = b"database dump".as_slice();
            let mut reader =
                decompress_dump(Box::new(std::io::Cursor::new(input)), CompressionType::None);
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await?;
            assert_eq!(output, input);

            Ok(())
        })
    }

    #[test]
    fn decompress_dump_decodes_gzip() -> Result<(), anyhow::Error> {
        use std::io::Write;

        tokio_test::block_on(async {
            let input = b"database dump".repeat(64);
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&input)?;
            let compressed = encoder.finish()?;

            let mut reader = decompress_dump(
                Box::new(std::io::Cursor::new(compressed)),
                CompressionType::Gz,
            );
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await?;
            assert_eq!(output, input);

            Ok(())
        })
    }

    // glob_literal
    #[test]
    fn glob_literal_escapes_every_metacharacter() {
        assert_eq!(
            glob_literal(std::path::Path::new("game/we*ird?/[x]\\y")),
            "game/we\\*ird\\?/\\[x\\]\\\\y"
        );
        assert_eq!(
            glob_literal(std::path::Path::new("plain/path.txt")),
            "plain/path.txt"
        );
    }

    // create_with_parent
    #[test]
    #[ignore = "requires filesystem syscalls the ci containers deny (eperm)"]
    fn create_with_parent_retries_once_after_creating_parents() {
        tokio_test::block_on(async {
            let (_temp, server) = crate::server::Server::mock_in_tempdir().await;
            let root = server.filesystem.base_path.clone();
            let path = std::path::Path::new("a/b/file.txt");

            let mut attempts = 0;
            create_with_parent(&server, path, || {
                attempts += 1;
                let target = root.join(path);
                async move { std::fs::write(target, b"x") }
            })
            .await
            .unwrap();
            assert_eq!(attempts, 2);
            assert_eq!(std::fs::read(root.join(path)).unwrap(), b"x");

            let mut attempts = 0;
            let result = create_with_parent(&server, std::path::Path::new("c/d/file"), || {
                attempts += 1;
                async { Err::<(), _>(std::io::Error::from(std::io::ErrorKind::NotFound)) }
            })
            .await;
            assert_eq!(attempts, 2);
            assert!(result.is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound));
            assert!(root.join("c/d").is_dir());
        });
    }

    #[test]
    fn create_with_parent_returns_other_errors_untouched() {
        tokio_test::block_on(async {
            let (_temp, server) = crate::server::Server::mock_in_tempdir().await;

            let mut attempts = 0;
            let result = create_with_parent(&server, std::path::Path::new("a/b/file"), || {
                attempts += 1;
                async { Err::<(), _>(std::io::Error::other("create failed")) }
            })
            .await;
            assert_eq!(attempts, 1);
            assert!(result.is_err_and(|err| err.to_string() == "create failed"));
            assert!(!server.filesystem.base_path.join("a").exists());
        });
    }
}
