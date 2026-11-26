use anyhow::{Context, bail, ensure};
use base64::Engine;
use serde_json::json;
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

pub(super) struct PullEnvironment {
    _directory: tempfile::TempDir,
    /// The Incus client to run.
    pub incus: String,
    pub environment: BTreeMap<String, String>,
}

/// The packaged client binary, whose wrapper script would put its own skopeo ahead of ours.
const PACKAGED_CLIENT: &str = "/opt/incus/bin/incus";

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Finds the configured skopeo, falling back to the copy shipped with Incus packages.
pub(super) fn executable(path: &str) -> anyhow::Result<PathBuf> {
    let name = path;
    let path = Path::new(path);
    if path.components().count() > 1 || path.is_absolute() {
        return std::fs::canonicalize(path).context("resolving configured Skopeo executable");
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(path);
        if candidate
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            return Ok(std::fs::canonicalize(candidate)?);
        }
    }
    if name == "skopeo" {
        let packaged = Path::new("/opt/incus/bin/skopeo");
        if packaged.is_file() {
            return Ok(packaged.into());
        }
    }
    bail!("configured Skopeo executable was not found in PATH")
}

impl PullEnvironment {
    pub async fn new(
        root: &Path,
        cfg: &crate::config::IncusRuntime,
        credentials: Option<(String, String)>,
        registry: &str,
        layout: &Path,
    ) -> anyhow::Result<Self> {
        let directory = tempfile::tempdir_in(root)?;
        let mut environment = BTreeMap::from([
            ("INCUS_CONF".into(), directory.path().display().to_string()),
            ("INCUS_SOCKET".into(), cfg.socket.clone()),
        ]);
        let client_config = json!({"default-remote": "local", "remotes": {
            "local": {"addr": "unix://", "protocol": "incus", "project": cfg.project},
            "oci": {"addr": format!("https://{registry}"), "protocol": "oci", "public": true}
        }});
        tokio::fs::write(
            directory.path().join("config.yml"),
            serde_saphyr::to_string(&client_config)?,
        )
        .await?;
        if let Some((username, password)) = credentials {
            ensure!(
                !username.contains(':'),
                "registry username must not contain a colon"
            );
            let auth =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            let auth_file = directory.path().join("auth.json");
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&auth_file)
                .await?;
            file.write_all(&serde_json::to_vec(
                &json!({"auths": {registry: {"auth": auth}}}),
            )?)
            .await?;
            file.flush().await?;
            environment.insert("REGISTRY_AUTH_FILE".into(), auth_file.display().to_string());
        }
        let binary = executable(&cfg.skopeo_path)?;
        let wrapper = directory.path().join("skopeo");
        let mut script = String::from("#!/bin/sh\n");
        for key in [
            "REGISTRY_AUTH_FILE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NO_PROXY",
            "no_proxy",
        ] {
            if let Some(value) = environment
                .get(key)
                .cloned()
                .or_else(|| std::env::var(key).ok())
            {
                script.push_str(&format!("export {key}={}\n", quote(&value)));
            }
        }
        // Copy the layers Wings has already downloaded instead of fetching them again.
        script.push_str(&format!(
            "layout={}\ncopying=\nfor argument in \"$@\"; do\n  shift\n  case \"$argument\" in\n    copy) copying=1 ;;\n    docker://*) [ -n \"$copying\" ] && argument=\"dir:$layout\" ;;\n  esac\n  set -- \"$@\" \"$argument\"\ndone\n",
            quote(&layout.display().to_string())
        ));
        script.push_str(&format!(
            "exec {} \"$@\"\n",
            quote(&binary.display().to_string())
        ));
        tokio::fs::write(&wrapper, script).await?;
        tokio::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).await?;
        let mut path = directory.path().display().to_string();
        let mut incus = cfg.incus_path.clone();
        if incus == "incus" && Path::new(PACKAGED_CLIENT).exists() {
            incus = PACKAGED_CLIENT.into();
            path.push_str(":/opt/incus/bin");
            environment.insert("LD_LIBRARY_PATH".into(), "/opt/incus/lib/".into());
        }
        environment.insert(
            "PATH".into(),
            format!("{path}:{}", std::env::var("PATH").unwrap_or_default()),
        );
        Ok(Self {
            _directory: directory,
            incus,
            environment,
        })
    }
}
