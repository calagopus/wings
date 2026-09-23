use crate::{
    remote::backups::RawServerBackup,
    server::backup::{Backup, DumpReader},
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

async fn prepare_dump_reader(mut reader: DumpReader) -> Result<DumpReader, anyhow::Error> {
    let mut first_byte = [0; 1];
    if reader.read(&mut first_byte).await? == 0 {
        return Err(anyhow::anyhow!("database dump is 0 bytes"));
    }

    Ok(Box::new(std::io::Cursor::new(first_byte).chain(reader)))
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
        reader: DumpReader,
    ) -> Result<RawServerBackup, anyhow::Error> {
        super::validate_dump_extension(extension)?;
        let reader = prepare_dump_reader(reader).await?;

        self.create_from_prepared_stream(state, uuid, extension, reader)
            .await
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
}
