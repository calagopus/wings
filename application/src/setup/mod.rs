use crate::{
    config::InnerConfig,
    response::{ApiErrorExt, ApiResponse, ApiResponseResult},
};
use anyhow::Context;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::IntoResponse,
    routing::{get, post},
};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

mod enroll;
mod pairing;

pub use enroll::redeem;

const ENROLL_PANEL_URL_ENV: &str = "WINGS_ENROLL_PANEL_URL";
const ENROLL_CODE_ENV: &str = "WINGS_ENROLL_CODE";

struct SetupState {
    config_path: String,
    config: InnerConfig,
    allow_insecure: bool,
    pairing: parking_lot::Mutex<pairing::Pairing>,
    claimed: AtomicBool,
    shutdown: tokio::sync::Notify,
}

pub fn config_missing(path: &str) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound
    )
}

fn write_config(
    path: &str,
    config: &InnerConfig,
    enrollment: enroll::Enrollment,
) -> Result<(), anyhow::Error> {
    let mut config = serde_json::from_value::<InnerConfig>(serde_json::to_value(config)?)?;
    enrollment.apply_identity(&mut config);

    crate::config::Config::save_new(path, config)
}

fn verify(
    state: &SetupState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> bool {
    let signature = headers
        .get(pairing::SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok());

    state
        .pairing
        .lock()
        .verify(method.as_str(), uri.path(), signature, body)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!(
            "calagopus wings {} is waiting to be paired.\nadd this node in your panel and enter the pairing code printed in the wings logs.\n",
            crate::VERSION
        ),
    )
}

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    configured: bool,
}

async fn status() -> ApiResponseResult {
    ApiResponse::new_serialized(StatusResponse {
        version: crate::full_version(),
        configured: false,
    })
    .ok()
}

#[derive(Serialize)]
struct ProbeDocker {
    available: bool,
    version: Option<String>,
}

#[derive(Serialize)]
struct ProbeResponse {
    version: String,
    container: bool,
    architecture: &'static str,
    cpu_count: usize,
    memory_bytes: u64,
    disk_bytes: u64,
    ips: BTreeSet<IpAddr>,
    api_port: u16,
    sftp_port: u16,
    docker: ProbeDocker,
}

async fn probe_docker(socket: &str) -> ProbeDocker {
    let docker = if socket.starts_with("http://") || socket.starts_with("tcp://") {
        bollard::Docker::connect_with_http(socket, 5, bollard::API_DEFAULT_VERSION)
    } else {
        bollard::Docker::connect_with_local(socket, 5, bollard::API_DEFAULT_VERSION)
    };

    let version = match docker {
        Ok(docker) => docker
            .version()
            .await
            .ok()
            .and_then(|version| version.version),
        Err(_) => None,
    };

    ProbeDocker {
        available: version.is_some(),
        version,
    }
}

fn disk_bytes_for(path: &Path) -> u64 {
    let path = path
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .unwrap_or(Path::new("/"));
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    sysinfo::Disks::new_with_refreshed_list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map_or(0, |disk| disk.total_space())
}

async fn probe(
    State(state): State<Arc<SetupState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResponseResult {
    if !verify(&state, &method, &uri, &headers, &body) {
        return ApiResponse::error("invalid pairing code")
            .with_status(StatusCode::UNAUTHORIZED)
            .ok();
    }

    let container = std::env::var("OCI_CONTAINER").is_ok();
    let data_directory = state.config.system.data_directory.as_path(&state.config);

    let (cpu_count, memory_bytes, disk_bytes) = tokio::task::spawn_blocking(move || {
        let mut system = sysinfo::System::new();
        system.refresh_memory();
        system.refresh_cpu_list(sysinfo::CpuRefreshKind::nothing());

        (
            system.cpus().len(),
            system.total_memory(),
            disk_bytes_for(&data_directory),
        )
    })
    .await
    .or_api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to read system information",
    )?;

    let ips = if container {
        BTreeSet::new()
    } else {
        crate::utils::assignable_host_ips(state.config.docker.network.name.clone())
            .await
            .unwrap_or_default()
    };

    ApiResponse::new_serialized(ProbeResponse {
        version: crate::full_version(),
        container,
        architecture: std::env::consts::ARCH,
        cpu_count,
        memory_bytes,
        disk_bytes,
        ips,
        api_port: state.config.api.port,
        sftp_port: state.config.system.sftp.bind_port,
        docker: probe_docker(&state.config.docker.socket).await,
    })
    .ok()
}

#[derive(Deserialize)]
struct EnrollPayload {
    panel_url: String,
    code: String,
}

async fn enroll(
    State(state): State<Arc<SetupState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResponseResult {
    if !verify(&state, &method, &uri, &headers, &body) {
        return ApiResponse::error("invalid pairing code")
            .with_status(StatusCode::UNAUTHORIZED)
            .ok();
    }

    let payload = serde_json::from_slice::<EnrollPayload>(&body)
        .or_api_error(StatusCode::BAD_REQUEST, "invalid enrollment payload")?;

    if state
        .claimed
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return ApiResponse::error("wings is already being paired")
            .with_status(StatusCode::CONFLICT)
            .ok();
    }

    let enrollment =
        match enroll::redeem(&payload.panel_url, &payload.code, state.allow_insecure).await {
            Ok(enrollment) => enrollment,
            Err(err) => {
                eprintln!("{} {err:#}", "failed to enroll with the panel:".red());
                state.claimed.store(false, Ordering::SeqCst);

                return ApiResponse::error(&crate::remote::ApiError::message_or(
                    &err,
                    "wings could not reach the panel",
                ))
                .with_status(StatusCode::BAD_GATEWAY)
                .ok();
            }
        };

    if let Err(err) = write_config(&state.config_path, &state.config, enrollment) {
        eprintln!("{} {err:#}", "failed to write configuration:".red());
        state.claimed.store(false, Ordering::SeqCst);

        return ApiResponse::error("wings failed to write its configuration file")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)
            .ok();
    }

    println!("{}", "paired with the panel, starting wings".green());
    state.shutdown.notify_one();

    ApiResponse::new(Body::empty())
        .with_status(StatusCode::NO_CONTENT)
        .ok()
}

pub async fn run(config_path: &str, allow_insecure: bool) -> Result<(), anyhow::Error> {
    let (config, overrides) = crate::env_overrides::apply_to_config(InnerConfig::default())?;
    for applied in &overrides.applied {
        println!("applied environment override {applied}");
    }
    for unknown in &overrides.unknown {
        eprintln!("ignoring environment override {unknown}, no matching config option");
    }

    let data_directory = config.system.data_directory.as_path(&config);
    if std::fs::read_dir(&data_directory).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(anyhow::anyhow!(
            "no config file at {config_path}, but {} already contains server data. restore the config file or run `calagopus-wings configure`",
            data_directory.display()
        ));
    }

    if let (Ok(panel_url), Ok(code)) = (
        std::env::var(ENROLL_PANEL_URL_ENV),
        std::env::var(ENROLL_CODE_ENV),
    ) {
        match enroll::redeem(&panel_url, &code, allow_insecure).await {
            Ok(enrollment) => {
                write_config(config_path, &config, enrollment)?;
                println!("{}", "enrolled with the panel, starting wings".green());

                return Ok(());
            }
            Err(err) => eprintln!(
                "{} {err:#}",
                format!("failed to enroll using {ENROLL_CODE_ENV}, waiting for pairing instead:")
                    .red()
            ),
        }
    }

    let Ok(host) = config.api.host.parse::<IpAddr>() else {
        return Err(anyhow::anyhow!(
            "no config file at {config_path} and api.host is not an ip address, run `calagopus-wings configure --panel-url <url> --enroll <code>` instead"
        ));
    };
    let address = SocketAddr::from((host, config.api.port));

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to start setup server on {address}"))?;

    println!(
        "{}",
        format!("no config file found at {config_path}, wings is waiting to be paired").yellow()
    );
    println!("add this node in your panel using its address and the pairing code below,");
    println!("or run `calagopus-wings configure --panel-url <url> --enroll <code>`");
    println!("setup server listening on http://{address}");

    let state = Arc::new(SetupState {
        config_path: config_path.to_string(),
        config,
        allow_insecure,
        pairing: parking_lot::Mutex::new(pairing::Pairing::new()),
        claimed: AtomicBool::new(false),
        shutdown: tokio::sync::Notify::new(),
    });

    let router = Router::new()
        .route("/", get(index))
        .route("/setup", get(status))
        .route("/setup/probe", post(probe))
        .route("/setup/enroll", post(enroll))
        .with_state(state.clone());

    axum::serve(listener, router)
        .with_graceful_shutdown({
            let state = state.clone();
            async move { state.shutdown.notified().await }
        })
        .await
        .context("setup server failed")?;

    if !state.claimed.load(Ordering::SeqCst) {
        return Err(anyhow::anyhow!(
            "setup server stopped before wings was paired"
        ));
    }

    Ok(())
}
