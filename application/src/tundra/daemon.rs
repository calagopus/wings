use super::TundraManager;
use crate::routes::State;
use anyhow::Context;
use futures::StreamExt;
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

    let source_meta =
        std::fs::metadata(source).context(format!("failed to stat {}", source.display()))?;
    let unchanged = std::fs::metadata(dest).is_ok_and(|dest_meta| {
        dest_meta.len() == source_meta.len()
            && match (dest_meta.modified(), source_meta.modified()) {
                (Ok(dest), Ok(source)) => dest >= source,
                _ => false,
            }
    });
    if unchanged {
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
    if std::fs::metadata(&dest).is_ok()
        && std::fs::read_to_string(&digest_path).is_ok_and(|current| current.trim() == digest)
    {
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

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let staged = dest.with_extension("incoming");
    let mut extracted = false;
    for entry in tar::Archive::new(std::io::Cursor::new(archive?)).entries()? {
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

    Ok(true)
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

fn sync_config(manager: &TundraManager, rendered: &str) -> Result<bool, anyhow::Error> {
    let path = config_path(manager);
    if std::fs::read_to_string(&path).is_ok_and(|current| current == rendered) {
        return Ok(false);
    }

    super::write_private(&path, rendered.as_bytes())?;
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

pub async fn ensure(state: &State, manager: &TundraManager) -> Result<(), anyhow::Error> {
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

    let binary_changed = if source.as_os_str().is_empty() {
        extract_binary(&docker, manager, &source_image).await?
    } else {
        let changed = sync_binary(&source, &binary_path(manager))?;
        std::fs::remove_file(image_digest_path(manager)).ok();

        changed
    };
    let config_changed = sync_config(
        manager,
        &render_config(manager, own.tunnel_port, metrics_port, &hosts_path)?,
    )?;
    if binary_changed || config_changed {
        manager.set_restart_pending(true);
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
        if manager.restart_pending() {
            tracing::info!("restarting the tundra daemon in place");
            restart_in_place(&docker, manager).await?;
            manager.set_restart_pending(false);
        }

        return Ok(());
    }

    if !image_exists(&docker, &image).await {
        tracing::info!(image = %image, "pulling the tundra daemon image");
        pull_image(&docker, &image).await?;
    }

    for attempt in 1..=CREATE_ATTEMPTS {
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

    match docker.start_container(CONTAINER_NAME, None).await {
        Ok(())
        | Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 304, ..
        }) => {}
        Err(err) => return Err(err.into()),
    }

    manager.set_restart_pending(false);

    tracing::info!(
        tunnel_port = own.tunnel_port,
        "started the tundra daemon container"
    );

    Ok(())
}
