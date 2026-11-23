use super::{RenameParents, RequestIgnored, VIRTUAL_PATH_MESSAGE, cap::FileType};
use crate::{server::Server, utils::PortablePermissions};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, path::Path};
use tokio::io::AsyncWriteExt;
use utoipa::ToSchema;

mod format;

use format::{FilePatch, GitOperation};

#[derive(ToSchema, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum PatchFormat {
    Git,
    Bsdiff,
}

pub enum PatchError {
    NotFound(&'static str),
    Failed(Cow<'static, str>),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for PatchError {
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(message) => f.write_str(message),
            Self::Failed(message) => f.write_str(message),
            Self::Internal(err) => write!(f, "{err}"),
        }
    }
}

pub struct Patch<'a> {
    files: Vec<FilePatch<'a>>,
}

impl<'a> Patch<'a> {
    /// Parses `contents` as a patch; bsdiff patches apply to `file`, git patches
    /// carry their own paths with `strip` leading components removed.
    pub fn parse(
        format: PatchFormat,
        contents: &'a [u8],
        file: Option<&str>,
        strip: usize,
    ) -> Result<Self, PatchError> {
        let files = match format {
            PatchFormat::Git => FilePatch::parse_git(contents, strip),
            PatchFormat::Bsdiff => {
                FilePatch::parse_bsdiff(contents, file.unwrap_or_default()).map(|patch| vec![patch])
            }
        };

        match files {
            Ok(files) => Ok(Self { files }),
            Err(err) => Err(PatchError::Failed(format!("invalid patch: {err}").into())),
        }
    }

    pub async fn read_file(
        server: &Server,
        root: &Path,
        path: &Path,
        ignored: &RequestIgnored,
    ) -> Result<Vec<u8>, PatchError> {
        let full_path = root.join(path);
        if server.filesystem.async_is_protected_path(&full_path).await {
            return Err(PatchError::Failed(VIRTUAL_PATH_MESSAGE.into()));
        }

        let (root, filesystem) = server
            .filesystem
            .resolve_readable_fs_ignoring(server, root, ignored)
            .await;
        let path = root.join(path);

        if !filesystem
            .async_metadata(&path)
            .await
            .is_ok_and(|m| m.file_type.is_file())
            || (filesystem.is_primary_server_fs()
                && ignored
                    .is_ignored_resolved(server, &path, FileType::File)
                    .await)
        {
            return Err(PatchError::NotFound("patch file not found"));
        }

        let size_limit = server
            .app_state
            .config
            .load()
            .limits
            .file_patch_size
            .as_bytes();
        let mut file = filesystem.async_read_file(&path, None).await?;
        file.read_to_end_capped(size_limit)
            .await?
            .ok_or(PatchError::Failed("patch file is too large".into()))
    }

    pub async fn apply(
        &self,
        server: &Server,
        root: &Path,
        ignored: &RequestIgnored,
        user: Option<uuid::Uuid>,
    ) -> Result<usize, PatchError> {
        for patch in &self.files {
            for path in patch.source.iter().chain(&patch.target) {
                if server
                    .filesystem
                    .async_is_protected_path(&root.join(path))
                    .await
                {
                    return Err(PatchError::Failed(VIRTUAL_PATH_MESSAGE.into()));
                }
            }
        }

        let (root, filesystem) = server
            .filesystem
            .resolve_writable_fs_ignoring(server, root, ignored)
            .await;
        let size_limit = server
            .app_state
            .config
            .load()
            .limits
            .file_patch_size
            .as_bytes();

        let mut changes = Vec::with_capacity(self.files.len());
        for patch in &self.files {
            let source = patch.source.as_ref().map(|path| root.join(path));
            let target = patch.target.as_ref().map(|path| root.join(path));

            for path in source.iter().chain(&target) {
                if filesystem.is_primary_server_fs()
                    && ignored
                        .is_ignored_resolved(server, path, FileType::File)
                        .await
                {
                    return Err(PatchError::NotFound("file not found"));
                }
            }

            if let Some(target) = &target
                && source.as_ref() != Some(target)
                && filesystem.async_symlink_metadata(target).await.is_ok()
            {
                return Err(PatchError::Failed(
                    format!("{} already exists", target.display()).into(),
                ));
            }

            let before = match &source {
                Some(source) => {
                    if !filesystem
                        .async_symlink_metadata(source)
                        .await
                        .is_ok_and(|m| m.file_type.is_file())
                    {
                        return Err(PatchError::NotFound("file not found"));
                    }

                    let mut file = filesystem.async_read_file(source, None).await?;
                    file.read_to_end_capped(size_limit).await?.ok_or_else(|| {
                        PatchError::Failed(
                            format!("{} is too large to patch", source.display()).into(),
                        )
                    })?
                }
                None => Vec::new(),
            };

            let after = tokio::task::block_in_place(|| patch.apply(&before, size_limit)).map_err(
                |err| PatchError::Failed(format!("failed to apply patch: {err}").into()),
            )?;

            changes.push((patch, source, target, before, after));
        }

        let growth: i64 = changes
            .iter()
            .map(|(patch, _, _, before, after)| match patch.operation {
                GitOperation::Copy => after.len() as i64,
                _ => after.len() as i64 - before.len() as i64,
            })
            .sum();
        if filesystem.is_primary_server_fs()
            && !server
                .filesystem
                .trash
                .ensure_headroom(server, growth)
                .await
        {
            return Err(PatchError::Failed("failed to allocate space".into()));
        }

        for (patch, source, target, before, after) in &changes {
            if let Some(source) = source
                && matches!(patch.operation, GitOperation::Delete | GitOperation::Rename)
            {
                let diff_key = server.filesystem.diff_key(source).await;

                if !filesystem.is_primary_server_fs() {
                    filesystem.async_remove_file(source).await?;
                } else if let Some(target) = target {
                    server
                        .filesystem
                        .rename_path(source, target, RenameParents::Create)
                        .await?;

                    let target = server.filesystem.relative_path(target);
                    if let Err(err) = server
                        .diff
                        .rename_file(&diff_key.to_string_lossy(), &target.to_string_lossy())
                        .await
                    {
                        tracing::error!("failed to rename file in diff storage: {:?}", err);
                    }
                } else {
                    if let Err(err) = server
                        .diff
                        .forget_file(&diff_key.to_string_lossy(), None)
                        .await
                    {
                        tracing::error!("failed to forget file from diff storage: {:?}", err);
                    }

                    server.filesystem.truncate_path(source).await?;
                }
            }

            let Some(target) = target else {
                continue;
            };

            if before != after
                || source.as_ref() != Some(target) && !filesystem.is_primary_server_fs()
                || matches!(patch.operation, GitOperation::Create | GitOperation::Copy)
            {
                if let Some(parent) = target.parent() {
                    filesystem.async_create_dir_all(&parent, None).await?;
                }

                let mut file = filesystem.async_create_file(target).await?;
                file.write_all(after).await?;
                file.shutdown().await?;
            }

            if let Some(executable) = patch.executable {
                filesystem
                    .async_set_permissions(
                        target,
                        FileType::File,
                        PortablePermissions::from_mode_file(if executable { 0o755 } else { 0o644 }),
                    )
                    .await?;
            }

            let track = {
                let history = &server.app_state.config.load().system.file_history;

                history.enabled
                    && before.len() as u64 <= history.file_size_cap
                    && after.len() as u64 <= history.file_size_cap
            };
            if track && filesystem.is_primary_server_fs() && before != after && !before.is_empty() {
                let diff_key = server.filesystem.diff_key(target).await;
                if let Err(err) = server
                    .diff
                    .record_edit(
                        &diff_key.to_string_lossy(),
                        Some(before.clone()),
                        after.clone(),
                        user,
                    )
                    .await
                {
                    tracing::warn!(
                        server = %server.uuid,
                        path = %diff_key.display(),
                        "diff: record_edit failed: {err:#}"
                    );
                }
            }
        }

        Ok(changes.len())
    }
}
