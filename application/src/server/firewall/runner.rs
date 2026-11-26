use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::io::AsyncWriteExt;

pub struct HelperContainer {
    pub name: &'static str,
    pub container_type: &'static str,
    pub network_mode: &'static str,
    pub pid_mode: Option<&'static str>,
    pub cap_add: &'static [&'static str],
}

const OWNER_LABEL: &str = "WingsContainer";

impl HelperContainer {
    fn owned_by(&self, inspect: &bollard::models::ContainerInspectResponse, owner: &str) -> bool {
        let labels = inspect
            .config
            .as_ref()
            .and_then(|config| config.labels.as_ref());

        labels
            .and_then(|labels| labels.get("ContainerType"))
            .is_some_and(|value| value == self.container_type)
            && labels
                .and_then(|labels| labels.get(OWNER_LABEL))
                .is_some_and(|value| value == owner)
    }
}

pub const FIREWALL_HELPER: HelperContainer = HelperContainer {
    name: "calagopus-wings-firewall",
    container_type: "firewall_helper",
    network_mode: "host",
    pid_mode: None,
    cap_add: &["NET_ADMIN"],
};

type ExecOutput = std::pin::Pin<
    Box<
        dyn futures::Stream<Item = Result<bollard::container::LogOutput, bollard::errors::Error>>
            + Send,
    >,
>;

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

    pub async fn spawn(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<StreamingCommand, anyhow::Error> {
        match self {
            Self::Local => spawn_local(program, args).await,
            Self::Docker(helper) => match helper.spawn(program, args).await {
                Ok(command) => Ok(command),
                Err(err)
                    if err
                        .chain()
                        .any(|cause| cause.is::<bollard::errors::Error>()) =>
                {
                    helper.ensure().await?;
                    helper.spawn(program, args).await
                }
                Err(err) => Err(err),
            },
        }
    }
}

enum StreamingProcess {
    Local {
        child: tokio::process::Child,
        stdin: Option<tokio::process::ChildStdin>,
    },
    Docker {
        docker: Arc<bollard::Docker>,
        exec_id: String,
        stdin: Option<std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>>,
        output: ExecOutput,
    },
}

pub struct StreamingCommand {
    program: String,
    process: StreamingProcess,
}

impl StreamingCommand {
    pub async fn write(&mut self, input: &[u8]) -> Result<(), anyhow::Error> {
        let result = match &mut self.process {
            StreamingProcess::Local { stdin, .. } => match stdin.as_mut() {
                Some(stdin) => stdin.write_all(input).await,
                None => Err(std::io::Error::other("stdin is closed")),
            },
            StreamingProcess::Docker { stdin, .. } => match stdin.as_mut() {
                Some(stdin) => stdin.write_all(input).await,
                None => Err(std::io::Error::other("stdin is closed")),
            },
        };

        result.map_err(|err| anyhow::anyhow!("failed to write to {}: {err}", self.program))
    }

    pub async fn finish(self) -> Result<String, anyhow::Error> {
        let program = self.program;

        match self.process {
            StreamingProcess::Local { child, stdin } => {
                if let Some(mut stdin) = stdin {
                    stdin.shutdown().await.ok();
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
            StreamingProcess::Docker {
                docker,
                exec_id,
                stdin,
                output,
            } => {
                if let Some(mut stdin) = stdin {
                    stdin.shutdown().await.ok();
                }

                let (stdout, stderr) = collect_exec_output(output).await?;
                let exit_code = wait_exec(&docker, &exec_id).await?;

                exec_result(&program, exit_code, stdout, stderr)
            }
        }
    }

    pub async fn abort(self) {
        match self.process {
            StreamingProcess::Local { mut child, stdin } => {
                drop(stdin);
                child.kill().await.ok();
            }
            StreamingProcess::Docker {
                docker,
                exec_id,
                stdin,
                output,
            } => {
                drop(stdin);
                collect_exec_output(output).await.ok();
                wait_exec(&docker, &exec_id).await.ok();
            }
        }
    }
}

struct Tether {
    container_id: String,
    task: tokio::task::JoinHandle<()>,
}

impl Tether {
    fn holds(&self, container_id: Option<&str>) -> bool {
        !self.task.is_finished() && container_id == Some(self.container_id.as_str())
    }
}

impl Drop for Tether {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct DockerHelper {
    docker: Arc<bollard::Docker>,
    spec: &'static HelperContainer,
    name: String,
    owner: String,
    image: String,
    service_label: String,
    tether: tokio::sync::Mutex<Option<Tether>>,
}

impl DockerHelper {
    pub fn new(
        docker: Arc<bollard::Docker>,
        spec: &'static HelperContainer,
        owner: &str,
        image: String,
        service_label: String,
    ) -> Self {
        Self {
            docker,
            spec,
            name: format!(
                "{}-{}",
                spec.name,
                owner.chars().take(12).collect::<String>()
            ),
            owner: owner.to_string(),
            image,
            service_label,
            tether: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn ensure(&self) -> Result<(), anyhow::Error> {
        let mut tether = self.tether.lock().await;

        match self.docker.inspect_container(&self.name, None).await {
            Ok(inspect) => {
                if !self.spec.owned_by(&inspect, &self.owner) {
                    return Err(anyhow::anyhow!(
                        "container name {} is taken by a container that was not created by this wings, refusing to replace it",
                        self.name
                    ));
                }

                let running = inspect
                    .state
                    .as_ref()
                    .and_then(|state| state.running)
                    .unwrap_or(false);
                if running
                    && tether
                        .as_ref()
                        .is_some_and(|tether| tether.holds(inspect.id.as_deref()))
                {
                    return Ok(());
                }

                *tether = None;
                force_remove(
                    &self.docker,
                    &inspect.id.unwrap_or_else(|| self.name.clone()),
                )
                .await?;
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(err) => return Err(err.into()),
        }

        *tether = Some(self.create_helper().await?);

        Ok(())
    }

    pub async fn remove(&self) -> Result<(), anyhow::Error> {
        let mut tether = self.tether.lock().await;
        *tether = None;

        force_remove(&self.docker, &self.name).await
    }

    pub async fn remove_stale(
        docker: &bollard::Docker,
        spec: &HelperContainer,
        owner: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let containers = docker
            .list_containers(Some(bollard::query_parameters::ListContainersOptions {
                all: true,
                filters: Some(HashMap::from([(
                    "label".to_string(),
                    vec![format!("ContainerType={}", spec.container_type)],
                )])),
                ..Default::default()
            }))
            .await?;

        for container in containers {
            let Some(id) = container.id else {
                continue;
            };

            let stale = match container
                .labels
                .as_ref()
                .and_then(|labels| labels.get(OWNER_LABEL))
            {
                None => true,
                Some(container_owner) if Some(container_owner.as_str()) == owner => true,
                Some(container_owner) => {
                    match docker.inspect_container(container_owner, None).await {
                        Ok(inspect) => !inspect
                            .state
                            .as_ref()
                            .and_then(|state| state.running)
                            .unwrap_or(false),
                        Err(bollard::errors::Error::DockerResponseServerError {
                            status_code: 404,
                            ..
                        }) => true,
                        Err(err) => return Err(err.into()),
                    }
                }
            };

            if stale {
                force_remove(docker, &id).await?;
            }
        }

        Ok(())
    }

    async fn create_helper(&self) -> Result<Tether, anyhow::Error> {
        let body = bollard::plugin::ContainerCreateBody {
            image: Some(self.image.clone()),
            entrypoint: Some(vec!["cat".to_string()]),
            cmd: Some(Vec::new()),
            attach_stdin: Some(true),
            open_stdin: Some(true),
            stdin_once: Some(true),
            stop_signal: Some("SIGKILL".to_string()),
            labels: Some(HashMap::from([
                ("Service".to_string(), self.service_label.clone()),
                (
                    "ContainerType".to_string(),
                    self.spec.container_type.to_string(),
                ),
                (OWNER_LABEL.to_string(), self.owner.clone()),
            ])),
            host_config: Some(bollard::plugin::HostConfig {
                network_mode: Some(self.spec.network_mode.to_string()),
                pid_mode: self.spec.pid_mode.map(str::to_string),
                cap_add: Some(self.spec.cap_add.iter().map(ToString::to_string).collect()),
                auto_remove: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut container_id = None;
        for attempt in 1..=5u32 {
            match self
                .docker
                .create_container(
                    Some(bollard::query_parameters::CreateContainerOptions {
                        name: Some(self.name.clone()),
                        ..Default::default()
                    }),
                    body.clone(),
                )
                .await
            {
                Ok(response) => {
                    container_id = Some(response.id);
                    break;
                }
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 409, ..
                }) if attempt < 5 => {
                    tokio::time::sleep(std::time::Duration::from_millis(200 * u64::from(attempt)))
                        .await;
                }
                Err(err) => return Err(err.into()),
            }
        }
        let container_id =
            container_id.ok_or_else(|| anyhow::anyhow!("failed to create {}", self.name))?;

        match self.attach_and_start(&container_id).await {
            Ok(task) => Ok(Tether { container_id, task }),
            Err(err) => {
                force_remove(&self.docker, &container_id).await.ok();

                Err(err)
            }
        }
    }

    async fn attach_and_start(
        &self,
        container_id: &str,
    ) -> Result<tokio::task::JoinHandle<()>, anyhow::Error> {
        let bollard::container::AttachContainerResults { mut output, input } = self
            .docker
            .attach_container(
                container_id,
                Some(bollard::query_parameters::AttachContainerOptions {
                    stdin: true,
                    stream: true,
                    ..Default::default()
                }),
            )
            .await?;

        let task = tokio::spawn(async move {
            let _input = input;
            while let Some(Ok(_)) = output.next().await {}
        });

        match self.docker.start_container(container_id, None).await {
            Ok(())
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, ..
            }) => Ok(task),
            Err(err) => {
                task.abort();

                Err(err.into())
            }
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

    async fn start_exec(
        &self,
        program: &str,
        args: &[&str],
        attach_stdin: bool,
    ) -> Result<
        (
            String,
            ExecOutput,
            std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
        ),
        anyhow::Error,
    > {
        let mut cmd = Vec::with_capacity(args.len() + 1);
        cmd.push(program.to_string());
        cmd.extend(args.iter().map(ToString::to_string));

        let exec = self
            .docker
            .create_exec(
                &self.name,
                bollard::exec::CreateExecOptions::<String> {
                    attach_stdin: Some(attach_stdin),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(cmd),
                    ..Default::default()
                },
            )
            .await?;

        let bollard::exec::StartExecResults::Attached { output, input } =
            self.docker.start_exec(&exec.id, None).await?
        else {
            return Err(anyhow::anyhow!("exec of {program} started detached"));
        };

        Ok((exec.id, output, input))
    }

    async fn spawn(&self, program: &str, args: &[&str]) -> Result<StreamingCommand, anyhow::Error> {
        let (exec_id, output, stdin) = self.start_exec(program, args, true).await?;

        Ok(StreamingCommand {
            program: program.to_string(),
            process: StreamingProcess::Docker {
                docker: Arc::clone(&self.docker),
                exec_id,
                stdin: Some(stdin),
                output,
            },
        })
    }

    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        let (exec_id, output, mut stdin) = self.start_exec(program, args, input.is_some()).await?;

        let write = async {
            if let Some(input) = input {
                stdin.write_all(input).await?;
            }
            stdin.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };

        let (write_result, read_result) = tokio::join!(write, collect_exec_output(output));
        let (stdout, stderr) = read_result?;
        if let Err(err) = write_result {
            tracing::debug!("{} exec stdin write: {err}", self.name);
        }

        let exit_code = wait_exec(&self.docker, &exec_id).await?;

        exec_result(program, exit_code, stdout, stderr)
    }
}

async fn force_remove(docker: &bollard::Docker, id: &str) -> Result<(), anyhow::Error> {
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
        Ok(())
        | Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404 | 409,
            ..
        }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn collect_exec_output(mut output: ExecOutput) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    while let Some(frame) = output.next().await {
        match frame? {
            bollard::container::LogOutput::StdOut { message } => stdout.extend_from_slice(&message),
            bollard::container::LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
            _ => {}
        }
    }

    Ok((stdout, stderr))
}

async fn wait_exec(docker: &bollard::Docker, exec_id: &str) -> Result<Option<i64>, anyhow::Error> {
    for _ in 0..20 {
        let inspect = docker.inspect_exec(exec_id).await?;
        if inspect.running != Some(true) {
            return Ok(inspect.exit_code);
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    Ok(None)
}

fn exec_result(
    program: &str,
    exit_code: Option<i64>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<String, anyhow::Error> {
    match exit_code {
        Some(0) => Ok(String::from_utf8_lossy(&stdout).into_owned()),
        code => Err(anyhow::anyhow!(
            "{program} exited with {}: {}",
            code.map_or_else(|| "unknown status".to_string(), |code| code.to_string()),
            String::from_utf8_lossy(&stderr).trim()
        )),
    }
}

async fn spawn_local(program: &str, args: &[&str]) -> Result<StreamingCommand, anyhow::Error> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to open stdin of {program}"))?;

    Ok(StreamingCommand {
        program: program.to_string(),
        process: StreamingProcess::Local {
            child,
            stdin: Some(stdin),
        },
    })
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
