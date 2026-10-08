use anyhow::{Context, ensure};
use base64::Engine;
use serde_json::json;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path};

pub(super) struct PullEnvironment {
    _directory: tempfile::TempDir,
    pub environment: BTreeMap<String, String>,
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn executable(path: &str) -> anyhow::Result<std::path::PathBuf> {
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
    anyhow::bail!("configured Skopeo executable was not found in PATH")
}

impl PullEnvironment {
    pub async fn new(
        root: &Path,
        cfg: &crate::config::IncusRuntime,
        registries: &std::collections::HashMap<String, crate::config::DockerRegistryConfiguration>,
        registry: &str,
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
            serde_norway::to_string(&client_config)?,
        )
        .await?;
        let credentials = registries.get(registry).or_else(|| {
            (registry == "docker.io")
                .then(|| registries.get("https://index.docker.io/v1/"))
                .flatten()
        });
        if let Some(credentials) = credentials {
            ensure!(
                !credentials.username.contains(':'),
                "registry username must not contain a colon"
            );
            let auth = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", credentials.username, credentials.password));
            let auth_file = directory.path().join("auth.json");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&auth_file)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            tokio::fs::write(
                &auth_file,
                serde_json::to_vec(&json!({"auths": {registry: {"auth": auth}}}))?,
            )
            .await?;
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
        script.push_str(&format!(
            "exec {} \"$@\"\n",
            quote(&binary.display().to_string())
        ));
        tokio::fs::write(&wrapper, script).await?;
        tokio::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).await?;
        environment.insert(
            "PATH".into(),
            format!(
                "{}:{}",
                directory.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        Ok(Self {
            _directory: directory,
            environment,
        })
    }
}
