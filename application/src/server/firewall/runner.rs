use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::io::AsyncWriteExt;

pub const HELPER_CONTAINER_NAME: &str = "calagopus-wings-firewall";
const HELPER_CONTAINER_TYPE: &str = "firewall_helper";

pub enum CommandRunner {
    Local,
    Docker(DockerHelper),
}

impl CommandRunner {
    pub async fn run(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        match self {
            Self::Local => run_local(program, args, input).await,
            Self::Docker(helper) => helper.run(program, args, input).await,
        }
    }
}

pub struct DockerHelper {
    docker: Arc<bollard::Docker>,
    image: String,
    service_label: String,
    ensure_lock: tokio::sync::Mutex<()>,
}

impl DockerHelper {
    pub fn new(docker: Arc<bollard::Docker>, image: String, service_label: String) -> Self {
        Self {
            docker,
            image,
            service_label,
            ensure_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn ensure(&self) -> Result<(), anyhow::Error> {
        let _guard = self.ensure_lock.lock().await;

        match self
            .docker
            .inspect_container(HELPER_CONTAINER_NAME, None)
            .await
        {
            Ok(inspect) => {
                let owned = inspect
                    .config
                    .as_ref()
                    .and_then(|config| config.labels.as_ref())
                    .and_then(|labels| labels.get("ContainerType"))
                    .is_some_and(|value| value == HELPER_CONTAINER_TYPE);
                if !owned {
                    return Err(anyhow::anyhow!(
                        "container name {HELPER_CONTAINER_NAME} is taken by a container that was not created by wings, refusing to replace it"
                    ));
                }

                let adoptable = inspect
                    .state
                    .as_ref()
                    .and_then(|state| state.running)
                    .unwrap_or(false)
                    && inspect.image.as_deref() == Some(self.image.as_str())
                    && inspect
                        .host_config
                        .as_ref()
                        .and_then(|host_config| host_config.network_mode.as_deref())
                        == Some("host");
                if adoptable {
                    return Ok(());
                }

                self.remove_helper(
                    &inspect
                        .id
                        .unwrap_or_else(|| HELPER_CONTAINER_NAME.to_string()),
                )
                .await?;
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(err) => return Err(err.into()),
        }

        self.create_helper().await
    }

    async fn remove_helper(&self, id: &str) -> Result<(), anyhow::Error> {
        match self
            .docker
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

    async fn create_helper(&self) -> Result<(), anyhow::Error> {
        let body = bollard::plugin::ContainerCreateBody {
            image: Some(self.image.clone()),
            entrypoint: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            cmd: Some(Vec::new()),
            stop_signal: Some("SIGKILL".to_string()),
            labels: Some(HashMap::from([
                ("Service".to_string(), self.service_label.clone()),
                (
                    "ContainerType".to_string(),
                    HELPER_CONTAINER_TYPE.to_string(),
                ),
            ])),
            host_config: Some(bollard::plugin::HostConfig {
                network_mode: Some("host".to_string()),
                cap_add: Some(vec!["NET_ADMIN".to_string()]),
                auto_remove: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        for attempt in 1..=5u32 {
            match self
                .docker
                .create_container(
                    Some(bollard::query_parameters::CreateContainerOptions {
                        name: Some(HELPER_CONTAINER_NAME.to_string()),
                        ..Default::default()
                    }),
                    body.clone(),
                )
                .await
            {
                Ok(_) => break,
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 409, ..
                }) if attempt < 5 => {
                    tokio::time::sleep(std::time::Duration::from_millis(200 * u64::from(attempt)))
                        .await;
                }
                Err(err) => return Err(err.into()),
            }
        }

        match self
            .docker
            .start_container(HELPER_CONTAINER_NAME, None)
            .await
        {
            Ok(())
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, ..
            }) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn run(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        match self.exec(program, args, input).await {
            Ok(output) => Ok(output),
            Err(err)
                if err
                    .chain()
                    .any(|cause| cause.is::<bollard::errors::Error>()) =>
            {
                self.ensure().await?;
                self.exec(program, args, input).await
            }
            Err(err) => Err(err),
        }
    }

    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        let mut cmd = Vec::with_capacity(args.len() + 1);
        cmd.push(program.to_string());
        cmd.extend(args.iter().map(ToString::to_string));

        let exec = self
            .docker
            .create_exec(
                HELPER_CONTAINER_NAME,
                bollard::exec::CreateExecOptions::<String> {
                    attach_stdin: Some(input.is_some()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(cmd),
                    ..Default::default()
                },
            )
            .await?;

        let bollard::exec::StartExecResults::Attached {
            mut output,
            input: mut stdin,
        } = self.docker.start_exec(&exec.id, None).await?
        else {
            return Err(anyhow::anyhow!("exec of {program} started detached"));
        };

        let write = async {
            if let Some(input) = input {
                stdin.write_all(input).await?;
            }
            stdin.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };
        let read = async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            while let Some(frame) = output.next().await {
                match frame? {
                    bollard::container::LogOutput::StdOut { message } => {
                        stdout.extend_from_slice(&message)
                    }
                    bollard::container::LogOutput::StdErr { message } => {
                        stderr.extend_from_slice(&message)
                    }
                    _ => {}
                }
            }

            Ok::<_, anyhow::Error>((stdout, stderr))
        };

        let (write_result, read_result) = tokio::join!(write, read);
        let (stdout, stderr) = read_result?;
        if let Err(err) = write_result {
            tracing::debug!("firewall helper exec stdin write: {err}");
        }

        let mut exit_code = None;
        for _ in 0..20 {
            let inspect = self.docker.inspect_exec(&exec.id).await?;
            if inspect.running != Some(true) {
                exit_code = inspect.exit_code;
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        match exit_code {
            Some(0) => Ok(String::from_utf8_lossy(&stdout).into_owned()),
            code => Err(anyhow::anyhow!(
                "{program} exited with {}: {}",
                code.map_or_else(|| "unknown status".to_string(), |code| code.to_string()),
                String::from_utf8_lossy(&stderr).trim()
            )),
        }
    }
}

async fn run_local(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
) -> Result<String, anyhow::Error> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(if input.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command.spawn()?;

    if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stdin of {program}"))?;
        stdin.write_all(input).await?;
        drop(stdin);
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
