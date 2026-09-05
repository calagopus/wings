use super::TundraManager;
use crate::{io::hash_reader::HashReader, routes::State};
use futures::StreamExt;
use sha2::Digest;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

pub const CONTAINER_NAME: &str = "calagopus-wings-tundra";
const CONTAINER_TYPE: &str = "tundra_daemon";
const BINARY_NAME: &str = "tundra-node";
const SERVER_PLACEHOLDER: &str = "{server}";
const EXTRACT_CONTAINER_NAME: &str = "calagopus-wings-tundra-extract";
const SOURCE_ENTRYPOINT: &str = "/usr/bin/calagopus-tundra";

const CREATE_ATTEMPTS: u32 = 5;
const CREATE_BACKOFF: Duration = Duration::from_millis(200);
const RESTART_EXEC_POLLS: u32 = 20;
const RESTART_EXEC_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn binary_path(manager: &TundraManager) -> PathBuf {
    manager.data_dir.join("bin").join(BINARY_NAME)
}

fn config_path(manager: &TundraManager) -> PathBuf {
    manager.data_dir.join("config.yml")
}

fn image_digest_path(manager: &TundraManager) -> PathBuf {
    manager
        .data_dir
        .join("bin")
        .join(format!("{BINARY_NAME}.image"))
}

fn sync_binary(source: &Path, dest: &Path) -> Result<bool, anyhow::Error> {
    use std::os::unix::fs::PermissionsExt;

    if std::fs::metadata(dest).is_ok() && file_hash(source)? == file_hash(dest)? {
        return Ok(false);
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let staged = dest.with_extension("incoming");
    std::fs::copy(source, &staged)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&staged, dest)?;

    tracing::info!(binary = %dest.display(), "updated the tundra daemon binary");

    Ok(true)
}

async fn download_binary(
    docker: &bollard::Docker,
    path: &str,
) -> Result<Vec<u8>, bollard::errors::Error> {
    let mut stream = docker.download_from_container(
        EXTRACT_CONTAINER_NAME,
        Some(bollard::query_parameters::DownloadFromContainerOptions {
            path: path.to_string(),
        }),
    );

    let mut archive = Vec::new();
    while let Some(chunk) = stream.next().await {
        archive.extend_from_slice(&chunk?);
    }

    Ok(archive)
}

async fn extract_binary(
    docker: &bollard::Docker,
    manager: &TundraManager,
    image: &str,
) -> Result<bool, anyhow::Error> {
    use std::os::unix::fs::PermissionsExt;

    if !image_exists(docker, image).await {
        tracing::info!(image = %image, "pulling the tundra source image");
        pull_image(docker, image).await?;
    }

    let inspect = docker.inspect_image(image).await?;
    let digest = inspect
        .id
        .ok_or_else(|| anyhow::anyhow!("the tundra source image {image} reports no id"))?;

    let dest = binary_path(manager);
    let digest_path = image_digest_path(manager);
    let guard = std::sync::Arc::clone(&manager.filesystem)
        .lock_owned()
        .await;
    let unchanged = tokio::task::spawn_blocking({
        let dest = dest.clone();
        let digest_path = digest_path.clone();
        let digest = digest.clone();
        move || {
            let _guard = guard;
            std::fs::metadata(dest).is_ok()
                && std::fs::read_to_string(digest_path)
                    .is_ok_and(|current| current.trim() == digest)
        }
    })
    .await?;
    if unchanged {
        return Ok(false);
    }

    let entrypoint = inspect
        .config
        .and_then(|config| config.entrypoint)
        .and_then(|entrypoint| entrypoint.into_iter().next())
        .unwrap_or_else(|| SOURCE_ENTRYPOINT.to_string());

    remove_container(docker, EXTRACT_CONTAINER_NAME).await?;
    docker
        .create_container(
            Some(bollard::query_parameters::CreateContainerOptions {
                name: Some(EXTRACT_CONTAINER_NAME.to_string()),
                ..Default::default()
            }),
            bollard::plugin::ContainerCreateBody {
                image: Some(image.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let archive = download_binary(docker, &entrypoint).await;
    remove_container(docker, EXTRACT_CONTAINER_NAME).await?;

    let archive = archive?;
    let image = image.to_string();
    let guard = std::sync::Arc::clone(&manager.filesystem)
        .lock_owned()
        .await;
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let staged = dest.with_extension("incoming");
        let mut extracted = false;
        for entry in tar::Archive::new(std::io::Cursor::new(archive)).entries()? {
            let mut entry = entry?;
            if entry.header().entry_type().is_file() {
                let mut file = std::fs::File::create(&staged)?;
                std::io::copy(&mut entry, &mut file)?;
                extracted = true;

                break;
            }
        }

        if !extracted {
            return Err(anyhow::anyhow!(
                "{entrypoint} is not a regular file in {image}"
            ));
        }

        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staged, &dest)?;
        std::fs::write(&digest_path, &digest)?;

        tracing::info!(
            binary = %dest.display(),
            image = %image,
            "extracted the tundra daemon binary"
        );

        Ok::<_, anyhow::Error>(true)
    })
    .await?
}

fn render_config(
    manager: &TundraManager,
    tunnel_port: u16,
    metrics_port: u16,
    hosts_path: &Path,
) -> Result<String, anyhow::Error> {
    serde_norway::to_string(&serde_json::json!({
        "remote": {
            "url": format!("unix://{}", manager.socket_path().display()),
            "token": manager.daemon_token(),
        },
        "tunnel_bind": format!("0.0.0.0:{tunnel_port}"),
        "metrics_bind": format!("127.0.0.1:{metrics_port}"),
        "data_dir": manager.data_dir.join("node"),
        "hosts_path": hosts_path,
        "restart": {
            "binary_path": binary_path(manager),
        },
    }))
    .map_err(Into::into)
}

fn sync_config(path: &Path, rendered: &str) -> Result<bool, anyhow::Error> {
    if std::fs::read_to_string(path).is_ok_and(|current| current == rendered) {
        return Ok(false);
    }

    super::write_private(path, rendered.as_bytes())?;
    tracing::info!(config = %path.display(), "wrote the tundra daemon config");

    Ok(true)
}

async fn image_exists(docker: &bollard::Docker, image: &str) -> bool {
    docker
        .list_images(Some(bollard::query_parameters::ListImagesOptions {
            all: true,
            filters: Some(HashMap::from([(
                "reference".to_string(),
                vec![image.to_string()],
            )])),
            ..Default::default()
        }))
        .await
        .is_ok_and(|images| !images.is_empty())
}

async fn pull_image(docker: &bollard::Docker, image: &str) -> Result<(), anyhow::Error> {
    let (name, tag) = image.rsplit_once(':').unwrap_or((image, "latest"));

    let mut stream = docker.create_image(
        Some(bollard::query_parameters::CreateImageOptions {
            from_image: Some(name.to_string()),
            tag: Some(tag.to_string()),
            ..Default::default()
        }),
        None,
        None,
    );

    while let Some(chunk) = stream.next().await {
        chunk?;
    }

    Ok(())
}

fn create_body(
    state: &State,
    manager: &TundraManager,
    image: &str,
) -> bollard::plugin::ContainerCreateBody {
    let config = state.config.load();
    let data_dir = manager.data_dir.display().to_string();
    let vmount_dir = config.system.vmount_directory.as_path(&config);

    let mut binds = vec![
        format!("{data_dir}:{data_dir}"),
        format!("{0}:{0}", vmount_dir.display()),
    ];

    let mut env = Vec::new();
    if config.docker.socket.starts_with('/') {
        binds.push(format!("{0}:{0}", config.docker.socket));
        env.push(format!("DOCKER_HOST=unix://{}", config.docker.socket));
    }

    bollard::plugin::ContainerCreateBody {
        image: Some(image.to_string()),
        entrypoint: Some(vec![
            binary_path(manager).display().to_string(),
            "--config".to_string(),
            config_path(manager).display().to_string(),
        ]),
        cmd: Some(Vec::new()),
        env: Some(env),
        labels: Some(HashMap::from([
            ("Service".to_string(), config.app_name.clone()),
            ("ContainerType".to_string(), CONTAINER_TYPE.to_string()),
        ])),
        host_config: Some(bollard::plugin::HostConfig {
            privileged: Some(true),
            network_mode: Some("host".to_string()),
            pid_mode: Some("host".to_string()),
            binds: Some(binds),
            restart_policy: Some(bollard::models::RestartPolicy {
                name: Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn restart_in_place(
    docker: &bollard::Docker,
    manager: &TundraManager,
) -> Result<(), anyhow::Error> {
    let exec = docker
        .create_exec(
            CONTAINER_NAME,
            bollard::exec::CreateExecOptions::<String> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec![
                    binary_path(manager).display().to_string(),
                    "restart".to_string(),
                    "--config".to_string(),
                    config_path(manager).display().to_string(),
                ]),
                ..Default::default()
            },
        )
        .await?;

    let bollard::exec::StartExecResults::Attached { mut output, .. } =
        docker.start_exec(&exec.id, None).await?
    else {
        return Err(anyhow::anyhow!("the tundra restart exec started detached"));
    };

    let mut stderr = Vec::new();
    while let Some(frame) = output.next().await {
        if let bollard::container::LogOutput::StdErr { message } = frame? {
            stderr.extend_from_slice(&message);
        }
    }

    let settled = 'settle: {
        for _ in 0..RESTART_EXEC_POLLS {
            let inspect = docker.inspect_exec(&exec.id).await?;
            if inspect.running != Some(true) {
                break 'settle Some(inspect.exit_code);
            }

            tokio::time::sleep(RESTART_EXEC_POLL_INTERVAL).await;
        }

        None
    };

    let Some(exit_code) = settled else {
        return Err(anyhow::anyhow!(
            "the tundra restart exec was still running after {:?}",
            RESTART_EXEC_POLL_INTERVAL * RESTART_EXEC_POLLS
        ));
    };

    match exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(anyhow::anyhow!(
            "the tundra restart exec exited with {code}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )),
        None => Err(anyhow::anyhow!(
            "the tundra restart exec reported no exit status: {}",
            String::from_utf8_lossy(&stderr).trim()
        )),
    }
}

async fn remove_container(docker: &bollard::Docker, id: &str) -> Result<(), anyhow::Error> {
    match docker
        .remove_container(
            id,
            Some(bollard::query_parameters::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
    {
        Ok(()) => Ok(()),
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404 | 409,
            ..
        }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn file_hash(path: &Path) -> Result<tundra_common::hash::Hash32, anyhow::Error> {
    let mut reader = HashReader::new_with_hasher(std::fs::File::open(path)?, sha2::Sha256::new());
    std::io::copy(&mut reader, &mut std::io::sink())?;
    Ok(tundra_common::hash::Hash32(reader.finish().into()))
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
struct Applied {
    binary_sha256: tundra_common::hash::Hash32,
    config_sha256: tundra_common::hash::Hash32,
}

impl Applied {
    fn matches(&self, metrics: &serde_json::Value) -> bool {
        metrics
            .get("applied")
            .and_then(|applied| serde_json::from_value::<Self>(applied.clone()).ok())
            .is_some_and(|applied| applied == *self)
    }
}

pub async fn stop(manager: &TundraManager) -> Result<(), anyhow::Error> {
    let docker = manager.docker();
    let inspect = match docker.inspect_container(CONTAINER_NAME, None).await {
        Ok(inspect) => inspect,
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    if !inspect
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .and_then(|labels| labels.get("ContainerType"))
        .is_some_and(|value| value == CONTAINER_TYPE)
    {
        return Err(anyhow::anyhow!(
            "refusing to stop an unowned tundra container"
        ));
    }
    if !manager.disabled() {
        return Ok(());
    }
    remove_container(
        &docker,
        &inspect.id.unwrap_or_else(|| CONTAINER_NAME.to_string()),
    )
    .await?;
    manager.hub.disconnect();
    Ok(())
}

pub async fn ensure(state: &State, manager: &TundraManager) -> Result<(), anyhow::Error> {
    if !manager.serving() {
        return Ok(());
    }

    let config = state.config.load();
    let Some(own) = manager.cached().and_then(|snapshot| {
        snapshot
            .nodes
            .iter()
            .find(|node| node.uuid == config.uuid)
            .cloned()
    }) else {
        tracing::debug!("the panel publishes no tundra entry for this node, not starting one");

        return Ok(());
    };

    let source = config.tundra.binary.as_path(&config);
    let source_image = config.tundra.source_image.clone();
    let metrics_port = config.tundra.metrics_port;
    let hosts_path = config
        .system
        .vmount_directory
        .as_path(&config)
        .join(SERVER_PLACEHOLDER)
        .join("hosts");

    let image = config.tundra.image.clone();
    let docker = manager.docker();
    let desired = create_body(state, manager, &image);
    drop(config);

    if source.as_os_str().is_empty() {
        extract_binary(&docker, manager, &source_image).await?;
    } else {
        let dest = binary_path(manager);
        let digest_path = image_digest_path(manager);
        let guard = std::sync::Arc::clone(&manager.filesystem)
            .lock_owned()
            .await;
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            sync_binary(&source, &dest)?;
            std::fs::remove_file(digest_path).ok();
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }

    let rendered = render_config(manager, own.tunnel_port, metrics_port, &hosts_path)?;
    let path = config_path(manager);
    let binary = binary_path(manager);
    let guard = std::sync::Arc::clone(&manager.filesystem)
        .lock_owned()
        .await;
    let wanted = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        sync_config(&path, &rendered)?;
        Ok::<_, anyhow::Error>(Applied {
            binary_sha256: file_hash(&binary)?,
            config_sha256: tundra_common::hash::sha256(rendered.as_bytes()),
        })
    })
    .await??;

    if !manager.serving() {
        return Ok(());
    }

    let image_id = match docker.inspect_image(&image).await {
        Ok(inspect) => inspect.id,
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => None,
        Err(err) => return Err(err.into()),
    };

    let running = match docker.inspect_container(CONTAINER_NAME, None).await {
        Ok(inspect) => {
            let owned = inspect
                .config
                .as_ref()
                .and_then(|config| config.labels.as_ref())
                .and_then(|labels| labels.get("ContainerType"))
                .is_some_and(|value| value == CONTAINER_TYPE);
            if !owned {
                return Err(anyhow::anyhow!(
                    "container name {CONTAINER_NAME} is taken by a container that was not created by wings, refusing to replace it"
                ));
            }

            let usable = inspect
                .state
                .as_ref()
                .and_then(|state| state.running)
                .unwrap_or(false)
                && inspect
                    .host_config
                    .as_ref()
                    .and_then(|host_config| host_config.network_mode.as_deref())
                    == Some("host")
                && image_id.is_some()
                && inspect.image.as_deref() == image_id.as_deref()
                && inspect
                    .config
                    .as_ref()
                    .and_then(|config| config.env.as_ref())
                    .is_some_and(|env| {
                        desired
                            .env
                            .as_ref()
                            .is_none_or(|wanted| wanted.iter().all(|entry| env.contains(entry)))
                    })
                && inspect
                    .host_config
                    .as_ref()
                    .and_then(|host_config| host_config.binds.as_ref())
                    .is_some_and(|binds| {
                        desired
                            .host_config
                            .as_ref()
                            .and_then(|host_config| host_config.binds.as_ref())
                            .is_none_or(|wanted| {
                                wanted.iter().all(|bind| {
                                    binds.iter().any(|existing| existing.starts_with(bind))
                                })
                            })
                    });
            if !usable {
                remove_container(
                    &docker,
                    &inspect.id.unwrap_or_else(|| CONTAINER_NAME.to_string()),
                )
                .await?;
            }

            usable
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => false,
        Err(err) => return Err(err.into()),
    };

    if running {
        let applied = manager.hub.request_metrics().await;
        if applied
            .as_ref()
            .is_ok_and(|metrics| wanted.matches(metrics))
        {
            return Ok(());
        }

        if manager.serving() && manager.restart_due() {
            tracing::info!("requesting the tundra daemon to apply its current binary and config");
            tokio::time::timeout(Duration::from_secs(30), restart_in_place(&docker, manager))
                .await??;
        }
        return Ok(());
    }

    if !image_exists(&docker, &image).await {
        tracing::info!(image = %image, "pulling the tundra daemon image");
        pull_image(&docker, &image).await?;
    }

    for attempt in 1..=CREATE_ATTEMPTS {
        if !manager.serving() {
            return Ok(());
        }

        match docker
            .create_container(
                Some(bollard::query_parameters::CreateContainerOptions {
                    name: Some(CONTAINER_NAME.to_string()),
                    ..Default::default()
                }),
                desired.clone(),
            )
            .await
        {
            Ok(_) => break,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 409, ..
            }) if attempt < CREATE_ATTEMPTS => {
                tokio::time::sleep(CREATE_BACKOFF * attempt).await;
            }
            Err(err) => return Err(err.into()),
        }
    }

    if !manager.serving() {
        return Ok(());
    }

    match docker.start_container(CONTAINER_NAME, None).await {
        Ok(())
        | Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 304, ..
        }) => {}
        Err(err) => return Err(err.into()),
    }

    if manager.disabled() {
        return stop(manager).await;
    }

    tracing::info!(
        tunnel_port = own.tunnel_port,
        "started the tundra daemon container"
    );

    Ok(())
}
