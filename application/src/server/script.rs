use super::configuration::string_to_option;
use crate::server::installation::InstallationScript;
use anyhow::Context;
use futures_util::StreamExt;
use rand::distr::SampleString;
use std::{
    collections::HashMap, fs::Permissions, os::unix::fs::PermissionsExt, path::Path, sync::Arc,
};

async fn container_config(
    server: &super::Server,
    container_script: &InstallationScript,
) -> tokio::io::Result<bollard::container::Config<String>> {
    let mut env = server
        .configuration
        .read()
        .await
        .environment(&server.app_state.config);
    env.reserve_exact(container_script.environment.len());

    for (k, v) in &container_script.environment {
        env.push(format!(
            "{k}={}",
            match v {
                serde_json::Value::String(s) => s.clone(),
                _ => v.to_string(),
            }
        ));
    }

    let labels = HashMap::from([
        (
            "Service".to_string(),
            server.app_state.config.app_name.clone(),
        ),
        ("ContainerType".to_string(), "script_runner".to_string()),
    ]);

    let mut resources = server
        .configuration
        .read()
        .await
        .convert_container_resources(&server.app_state.config);

    if resources.memory_reservation.is_some_and(|m| {
        m > 0 && m < server.app_state.config.docker.installer_limits.memory as i64 * 1024 * 1024
    }) {
        resources.memory = None;
        resources.memory_reservation =
            Some(server.app_state.config.docker.installer_limits.memory as i64 * 1024 * 1024);
        resources.memory_swap = None;
    }

    if resources.cpu_quota.is_some_and(|c| {
        c > 0 && c < server.app_state.config.docker.installer_limits.cpu as i64 * 1000
    }) {
        resources.cpu_quota =
            Some(server.app_state.config.docker.installer_limits.cpu as i64 * 1000);
    }

    let tmp_dir =
        Path::new(&server.app_state.config.system.tmp_directory).join(server.uuid.to_string());
    tokio::fs::create_dir_all(&tmp_dir).await?;
    tokio::fs::write(
        tmp_dir.join("script.sh"),
        container_script.script.replace("\r\n", "\n"),
    )
    .await?;
    tokio::fs::set_permissions(&tmp_dir, Permissions::from_mode(0o755)).await?;

    Ok(bollard::container::Config {
        host_config: Some(bollard::secret::HostConfig {
            memory: resources.memory,
            memory_reservation: resources.memory_reservation,
            memory_swap: resources.memory_swap,
            cpu_quota: resources.cpu_quota,
            cpu_period: resources.cpu_period,
            cpu_shares: resources.cpu_shares,
            cpuset_cpus: resources.cpuset_cpus,
            pids_limit: resources.pids_limit,
            blkio_weight: resources.blkio_weight,
            oom_kill_disable: resources.oom_kill_disable,

            mounts: Some(vec![
                bollard::models::Mount {
                    typ: Some(bollard::secret::MountTypeEnum::BIND),
                    source: Some(server.filesystem.base().into()),
                    target: Some("/mnt/server".to_string()),
                    ..Default::default()
                },
                bollard::models::Mount {
                    typ: Some(bollard::secret::MountTypeEnum::BIND),
                    source: Some(tmp_dir.to_string_lossy().to_string()),
                    target: Some("/mnt/script".to_string()),
                    ..Default::default()
                },
            ]),
            network_mode: Some(server.app_state.config.docker.network.mode.clone()),
            dns: Some(server.app_state.config.docker.network.dns.clone()),
            tmpfs: Some(HashMap::from([(
                "/tmp".to_string(),
                format!(
                    "rw,exec,nosuid,size={}M",
                    server.app_state.config.docker.tmpfs_size
                ),
            )])),
            log_config: Some(bollard::secret::HostConfigLogConfig {
                typ: Some(server.app_state.config.docker.log_config.r#type.clone()),
                config: Some(
                    server
                        .app_state
                        .config
                        .docker
                        .log_config
                        .config
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
            }),
            userns_mode: string_to_option(&server.app_state.config.docker.userns_mode),
            auto_remove: Some(true),
            ..Default::default()
        }),
        cmd: Some(vec![
            container_script.entrypoint.to_string(),
            "/mnt/script/script.sh".to_string(),
        ]),
        hostname: Some("script".to_string()),
        image: Some(
            container_script
                .container_image
                .trim_end_matches('~')
                .to_string(),
        ),
        env: Some(env),
        labels: Some(labels),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        ..Default::default()
    })
}

pub async fn script_server(
    server: &super::Server,
    client: &Arc<bollard::Docker>,
    container_script: InstallationScript,
) -> Result<(String, String), anyhow::Error> {
    server
        .pull_image(&container_script.container_image, true)
        .await
        .context("Failed to pull installation container image")?;

    let container = client
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: format!(
                    "{}_script_runner_{}",
                    server.uuid,
                    rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 8)
                ),
                ..Default::default()
            }),
            container_config(server, &container_script).await?,
        )
        .await
        .context("Failed to create installation container")?;

    let start_thread = async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        if let Err(err) = client.start_container::<String>(&container.id, None).await {
            tracing::error!(
                server = %server.uuid,
                "failed to start script runner container: {:#?}",
                err
            );

            return Err(err);
        }

        Ok(())
    };

    let mut output_thread = Box::pin(async {
        let mut stream = client
            .attach_container::<String>(
                &container.id,
                Some(bollard::container::AttachContainerOptions {
                    stream: Some(true),
                    stdout: Some(true),
                    stderr: Some(true),
                    ..Default::default()
                }),
            )
            .await?;

        let mut stdout = String::new();
        let mut stderr = String::new();

        while let Some(Ok(output)) = stream.output.next().await {
            match output {
                bollard::container::LogOutput::StdOut { message } => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                bollard::container::LogOutput::StdErr { message } => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                _ => {}
            }
        }

        Ok((stdout, stderr))
    });

    tokio::select! {
        result = start_thread => {
            if let Err(err) = result {
                Err(err.into())
            } else {
                output_thread.await
            }
        },
        output = &mut output_thread => {
            tracing::debug!(
                server = %server.uuid,
                "script runner container has exited"
            );

            output
        }
    }
}
