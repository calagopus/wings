use crate::{response::ApiResponse, routes::GetState, server::executor::ServerExecutor};
use anyhow::Context;
use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::{HeaderMap, HeaderValue, Method, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use colored::Colorize;
use russh::server::Server;
use std::{fmt::Debug, net::SocketAddr, path::Path, sync::Arc, time::Instant};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa_axum::router::OpenApiRouter;

mod bins;
mod commands;
mod config;
mod deserialize;
mod io;
mod models;
mod payload;
mod remote;
mod response;
mod routes;
mod server;
mod ssh;
mod stats;
mod utils;

use payload::Payload;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_COMMIT: &str = env!("CARGO_GIT_COMMIT");
const GIT_BRANCH: &str = env!("CARGO_GIT_BRANCH");
const TARGET: &str = env!("CARGO_TARGET");

#[cfg(unix)]
const DEFAULT_CONFIG_PATH: &str = "/etc/pterodactyl/config.yml";
#[cfg(windows)]
const DEFAULT_CONFIG_PATH: &str = "C:\\ProgramData\\Calagopus-Wings\\config.yml";

/// 32 KiB - used for general IO
const BUFFER_SIZE: usize = 32 * 1024;
/// 4 MiB - used for transfers
const TRANSFER_BUFFER_SIZE: usize = 4 * 1024 * 1024;

fn full_version() -> String {
    if GIT_BRANCH == "unknown" {
        VERSION.to_string()
    } else {
        format!("{VERSION}:{GIT_COMMIT}@{GIT_BRANCH}")
    }
}

fn spawn_blocking_handled<
    F: FnOnce() -> Result<(), E> + Send + 'static,
    E: Debug + Send + 'static,
>(
    f: F,
) {
    tokio::spawn(async move {
        match tokio::task::spawn_blocking(f).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                tracing::error!("spawned blocking task failed: {:?}", err);
            }
            Err(err) => {
                tracing::error!("spawned blocking task panicked: {:?}", err);
            }
        }
    });
}

fn spawn_handled<
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: Debug + Send + 'static,
>(
    f: F,
) {
    tokio::spawn(async move {
        match f.await {
            Ok(_) => {}
            Err(err) => {
                tracing::error!("spawned async task failed: {:?}", err);
            }
        }
    });
}

#[inline(always)]
#[cold]
fn cold_path() {}

#[inline(always)]
fn likely(b: bool) -> bool {
    if b {
        true
    } else {
        cold_path();
        false
    }
}

#[inline(always)]
fn unlikely(b: bool) -> bool {
    if b {
        cold_path();
        true
    } else {
        false
    }
}

macro_rules! exit_error {
    ($msg:expr) => {
        {
            use ::colored::Colorize;
            eprintln!("{}", $msg.red());
            std::process::exit(1);
        }
    };
    ($fmt:expr, $($arg:tt)*) => {
        {
            use ::colored::Colorize;
            eprintln!("{}", format!($fmt, $($arg)*).red());
            std::process::exit(1);
        }
    };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response<Body> {
    let details = if let Some(s) = err.downcast_ref::<String>() {
        s.as_str()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s
    } else {
        "unknown panic"
    };

    tracing::error!("a panic occurred while handling a request: {}", details);

    ApiResponse::error("internal server error")
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
        .into_response()
}

async fn handle_request(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
    tracing::info!(
        path = req.uri().path(),
        query = req.uri().query().unwrap_or_default(),
        "http {}",
        req.method().to_string().to_lowercase(),
    );

    Ok(crate::response::ACCEPT_HEADER
        .scope(crate::response::accept_from_headers(req.headers()), async {
            next.run(req).await
        })
        .await)
}

async fn handle_cors(
    state: crate::routes::GetState,
    req: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let method = req.method().clone();
    let mut headers = HeaderMap::new();

    headers.insert(
        "Access-Control-Allow-Credentials",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, POST, PATCH, PUT, DELETE, OPTIONS"),
    );
    headers.insert("Access-Control-Allow-Headers", HeaderValue::from_static("Accept, Accept-Encoding, Authorization, Cache-Control, Content-Type, Content-Length, Origin, X-Real-IP, X-CSRF-Token"));

    if state.config.load().allow_cors_private_network {
        headers.insert(
            "Access-Control-Request-Private-Network",
            HeaderValue::from_static("true"),
        );
    }

    headers.insert("Access-Control-Max-Age", HeaderValue::from_static("7200"));

    if let Some(origin) = req.headers().get("Origin")
        && origin.to_str().ok() != Some(state.config.load().remote.as_str())
    {
        for o in state.config.load().allowed_origins.iter() {
            if o == "*" || origin.to_str().ok() == Some(o.as_str()) {
                if let Ok(o) = o.parse() {
                    headers.insert("Access-Control-Allow-Origin", o);
                }

                break;
            }
        }
    }

    if !headers.contains_key("Access-Control-Allow-Origin") {
        if let Ok(origin) = state.config.load().remote.parse() {
            headers.insert("Access-Control-Allow-Origin", origin);
        } else {
            return Ok(ApiResponse::error("invalid remote URL configured")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .into_response());
        }
    }

    if method == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        response.headers_mut().extend(headers);
        *response.status_mut() = StatusCode::NO_CONTENT;

        return Ok(response);
    }

    let mut response = next.run(req).await;
    response.headers_mut().extend(headers);

    Ok(response)
}

async fn main_rt() {
    let cli = crate::commands::CliCommandGroupBuilder::new(
        "wings-rs",
        "The wings server implementing server management for the panel.",
    );

    let mut cli = crate::commands::commands(cli);
    let mut matches = cli.get_matches();

    let config_path = matches
        .get_one::<String>("config")
        .expect("config path is required")
        .clone();
    let debug = *matches
        .get_one::<bool>("debug")
        .expect("debug flag is required");
    let ignore_certificate_errors = matches
        .get_one::<bool>("ignore_certificate_errors")
        .copied()
        .unwrap_or(false);
    let config = crate::config::Config::open(
        &config_path,
        debug,
        matches.subcommand().is_some(),
        ignore_certificate_errors,
    );

    match matches.remove_subcommand() {
        Some((command, arg_matches)) => {
            if let Some((func, arg_matches)) = cli.match_command(command, arg_matches) {
                match func(config.as_ref().ok().map(|e| e.0.clone()), arg_matches).await {
                    Ok(exit_code) => {
                        drop(config);
                        std::process::exit(exit_code);
                    }
                    Err(err) => {
                        drop(config);
                        eprintln!(
                            "{}: {:#?}",
                            "an error occurred while running cli command".red(),
                            err
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                cli.print_help();
                std::process::exit(0);
            }
        }
        None => {
            tracing::info!(" __      ___ _ __   __ _ ___        ");
            tracing::info!(" \\ \\ /\\ / / | '_ \\ / _` / __|       ");
            tracing::info!("  \\ V  V /| | | | | (_| \\__ \\       ");
            tracing::info!("   \\_/\\_/ |_|_| |_|\\__, |___/__ ___ ");
            tracing::info!("                    __/ | | '__/ __|");
            tracing::info!("                   |___/  | |  \\__ \\");
            tracing::info!("{: >25} |_|  |___/", crate::VERSION);
            tracing::info!("github.com/calagopus/wings#{}\n", crate::GIT_COMMIT);
        }
    }

    let (config, _guard) = match config {
        Ok(config) => config,
        Err(err) => exit_error!("failed to load config from {}: {:?}", config_path, err),
    };
    tracing::info!("config loaded from {}", config_path);

    crate::spawn_handled(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let socket = sntpc_net_tokio::UdpSocketWrapper::from(socket);
        let context = sntpc::NtpContext::new(sntpc::StdTimestampGen::default());

        let pool_ntp_addrs = tokio::net::lookup_host(("pool.ntp.org", 123))
            .await
            .context("failed to resolve pool.ntp.org")?;

        let get_pool_time = async |addr: std::net::SocketAddr| {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                sntpc::get_time(addr, &socket, context),
            )
            .await?
            .map_err(|err| std::io::Error::other(format!("{:?}", err)))
            .context("failed to get time from pool.ntp.org")
        };

        for pool_ntp_addr in pool_ntp_addrs {
            let pool_time = match get_pool_time(pool_ntp_addr).await {
                Ok(time) => time,
                Err(err) => {
                    tracing::warn!("failed to get time from {:?}: {:?}", pool_ntp_addr, err);
                    continue;
                }
            };

            let duration = std::time::Duration::from_micros(pool_time.offset().unsigned_abs());

            if duration > std::time::Duration::from_secs(5) {
                if pool_time.offset().is_negative() {
                    tracing::warn!(
                        "system clock is behind by {:.2}s according to {:?}",
                        duration.as_secs_f64(),
                        pool_ntp_addr
                    );
                } else {
                    tracing::warn!(
                        "system clock is ahead by {:.2}s according to {:?}",
                        duration.as_secs_f64(),
                        pool_ntp_addr
                    );
                }
            } else if pool_time.offset().is_negative() {
                tracing::info!(
                    "system clock is behind by {}ms according to {:?}",
                    duration.as_millis(),
                    pool_ntp_addr
                );
            } else {
                tracing::info!(
                    "system clock is ahead by {}ms according to {:?}",
                    duration.as_millis(),
                    pool_ntp_addr
                );
            }
        }

        Ok::<_, anyhow::Error>(())
    });

    tracing::info!("connecting to docker");
    let executor = {
        let config_ref = config.load();
        let docker = Arc::new(
            match if config_ref.docker.socket.starts_with("http://")
                || config_ref.docker.socket.starts_with("tcp://")
            {
                bollard::Docker::connect_with_http(
                    &config_ref.docker.socket,
                    120,
                    bollard::API_DEFAULT_VERSION,
                )
            } else {
                bollard::Docker::connect_with_local(
                    &config_ref.docker.socket,
                    120,
                    bollard::API_DEFAULT_VERSION,
                )
            } {
                Ok(docker) => docker,
                Err(err) => exit_error!("failed to connect to docker: {:?}", err),
            },
        );

        Arc::new(crate::server::executor::docker::DockerExecutor::new(
            docker,
            config.clone(),
        ))
    };

    tracing::info!("running server executor boot tasks");
    if let Err(err) = executor.boot().await {
        exit_error!("failed to boot server executor: {:?}", err);
    }

    match config.client.reset_state().await {
        Ok(_) => tracing::info!("remote state reset successfully"),
        Err(err) => exit_error!("failed to reset remote state: {:?}", err),
    }

    if config.load().system.disk_limiter_mode
        == crate::server::filesystem::limiter::DiskLimiterMode::BtrfsSubvolume
    {
        tracing::info!("cleaning up stale btrfs send snapshots from previous runs");
        crate::server::backup::adapters::btrfs::BtrfsBackup::cleanup_stale_btrfs_send_snapshots(
            &config,
        )
        .await;
    }

    tracing::info!("creating server manager");
    let servers = match config.client.servers().await {
        Ok(servers) => servers,
        Err(err) => exit_error!("failed to fetch servers from remote: {:?}", err),
    };

    let state = Arc::new(crate::routes::AppState {
        start_time: Instant::now(),
        container_type: match std::env::var("OCI_CONTAINER").as_deref() {
            Ok("official") => crate::routes::AppContainerType::Official,
            Ok(_) => crate::routes::AppContainerType::Unknown,
            Err(_) => crate::routes::AppContainerType::None,
        },
        version: crate::full_version(),

        config: Arc::clone(&config),
        executor,
        stats_manager: Arc::new(crate::stats::StatsManager::default()),
        server_manager: Arc::new(crate::server::manager::ServerManager::new(&servers)),
        backup_manager: Arc::new(crate::server::backup::manager::BackupManager::default()),
        inotify_manager: Arc::new(
            crate::server::filesystem::inotify::InotifyManager::new()
                .expect("failed to initialize inotify manager"),
        ),
        mime_cache: moka::future::Cache::new(20480),
    });

    tokio::spawn({
        let state = Arc::clone(&state);

        async move {
            state.server_manager.boot(&state, servers).await;
        }
    });

    let app = OpenApiRouter::new()
        .merge(crate::routes::router(&state))
        .fallback(|state: GetState, req: Request| async move {
            let config = state.config.load();
            if let Some(redirect) = config.api.redirects.get(req.uri().path()) {
                return ApiResponse::new(Body::empty())
                    .with_status(StatusCode::FOUND)
                    .with_header("Location", redirect)
                    .ok();
            }

            ApiResponse::error("route not found")
                .with_status(StatusCode::NOT_FOUND)
                .ok()
        })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handle_cors,
        ))
        .layer(axum::middleware::from_fn(handle_request))
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            handle_panic,
        ))
        .with_state(state.clone());

    let (mut router, mut openapi) = app.split_for_parts();
    openapi.info.version = "1.0.0".into();
    openapi.info.description = None;
    openapi.info.title = format!("{} Wings API", config.load().app_name);
    openapi.info.contact = None;
    openapi.info.license = None;
    if let Some(components) = openapi.components.as_mut() {
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
        );
    }

    for (path, item) in openapi.paths.paths.iter_mut() {
        let operations = [
            ("get", &mut item.get),
            ("post", &mut item.post),
            ("put", &mut item.put),
            ("patch", &mut item.patch),
            ("delete", &mut item.delete),
        ];

        let path = path
            .replace('/', "_")
            .replace(|c| ['{', '}'].contains(&c), "");

        for (method, operation) in operations {
            if let Some(operation) = operation {
                operation.operation_id = Some(format!("{method}{path}"))
            }
        }
    }

    if !config.load().api.disable_openapi_docs {
        router = router.route(
            "/openapi.json",
            axum::routing::get(|| async move { axum::Json(openapi) }),
        );
    }

    if let Err(err) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        exit_error!("Failed to install rustls crypto provider: {:?}", err);
    }

    if config.load().system.sftp.enabled {
        tracing::info!("starting ssh server");

        tokio::spawn({
            let state = Arc::clone(&state);

            async move {
                let mut server = crate::ssh::Server::new(Arc::clone(&state));

                let key_file = Path::new(&state.config.load().system.data_directory)
                    .join(".sftp")
                    .join(format!(
                        "id_{}",
                        state
                            .config
                            .load()
                            .system
                            .sftp
                            .key_algorithm
                            .replace("-", "_")
                    ));
                let key = match tokio::fs::read(&key_file)
                    .await
                    .map(russh::keys::PrivateKey::from_openssh)
                {
                    Ok(Ok(key)) => {
                        tracing::info!(
                            algorithm = %key.algorithm().to_string(),
                            fingerprint = %key.fingerprint(Default::default()),
                            "loaded existing sftp host key"
                        );

                        key
                    }
                    _ => {
                        tracing::info!(
                            algorithm = %state.config.load().system.sftp.key_algorithm,
                            "generating new sftp host key"
                        );

                        let key = match russh::keys::PrivateKey::random(
                            &mut rand::rngs::ThreadRng::default(),
                            match state.config.load().system.sftp.key_algorithm.parse() {
                                Ok(alg) => alg,
                                Err(_) => exit_error!("invalid sftp host key algorithm configured"),
                            },
                        ) {
                            Ok(key) => key,
                            Err(err) => exit_error!("failed to generate sftp host key: {:?}", err),
                        };

                        if let Some(parent) = key_file.parent()
                            && let Err(err) = tokio::fs::create_dir_all(parent).await
                        {
                            exit_error!("failed to create sftp host key directory: {:?}", err);
                        }
                        if let Err(err) = tokio::fs::write(
                            key_file,
                            key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
                                .expect("failed to convert sftp host key to OpenSSH format"),
                        )
                        .await
                        {
                            exit_error!("failed to write sftp host key: {:?}", err);
                        }

                        tracing::info!(
                            algorithm = %key.algorithm().to_string(),
                            fingerprint = %key.fingerprint(Default::default()),
                            "new sftp host key generated"
                        );

                        key
                    }
                };

                let config = russh::server::Config {
                    server_id: russh::SshId::Standard("SSH-2.0-Calagopus-Wings".into()),
                    auth_rejection_time: std::time::Duration::from_secs(0),
                    auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                    maximum_packet_size: 32 * 1024,
                    keepalive_interval: Some(std::time::Duration::from_secs(60)),
                    max_auth_attempts: 6,
                    channel_buffer_size: 1024,
                    event_buffer_size: 1024,
                    keys: vec![key],
                    ..Default::default()
                };

                let address = SocketAddr::from((
                    state.config.load().system.sftp.bind_address,
                    state.config.load().system.sftp.bind_port,
                ));

                tracing::info!(
                    "ssh server listening on {} (app@{}, {}ms)",
                    address.to_string(),
                    crate::VERSION,
                    state.start_time.elapsed().as_millis()
                );

                match server.run_on_address(Arc::new(config), address).await {
                    Ok(_) => {}
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::AddrInUse {
                            exit_error!("failed to start ssh server (address already in use)");
                        } else {
                            exit_error!("failed to start ssh server: {:?}", err);
                        }
                    }
                }
            }
        });
    }

    #[cfg(unix)]
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };

        loop {
            signal.recv().await;
            tracing::info!("received SIGHUP, ignoring");
        }
    });

    if let Ok(host) = state.config.load().api.host.parse::<std::net::IpAddr>() {
        let address = SocketAddr::from((host, state.config.load().api.port));

        if config.load().api.ssl.enabled {
            tracing::info!("loading ssl certs");

            let rustls_config = match axum_server::tls_rustls::RustlsConfig::from_pem_file(
                config.load().api.ssl.cert.as_str(),
                config.load().api.ssl.key.as_str(),
            )
            .await
            {
                Ok(config) => config,
                Err(err) => exit_error!("failed to load SSL certificate and key: {:?}", err),
            };

            tokio::spawn({
                let rustls_config = rustls_config.clone();
                let config = config.clone();

                async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_hours(24)).await;
                        tracing::info!("reloading ssl certs");

                        if let Err(err) = rustls_config
                            .reload_from_pem_file(
                                config.load().api.ssl.cert.as_str(),
                                config.load().api.ssl.key.as_str(),
                            )
                            .await
                        {
                            tracing::error!("failed to reload SSL certificate and key: {:?}", err);
                        } else {
                            tracing::info!("ssl certs reloaded successfully");
                        }
                    }
                }
            });

            tracing::info!("https listening on {}", address.to_string());

            match axum_server::bind_rustls(address, rustls_config)
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                Ok(_) => {}
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::AddrInUse {
                        exit_error!("failed to start https server (address already in use)");
                    } else {
                        exit_error!("failed to start https server: {:?}", err);
                    }
                }
            }
        } else {
            tracing::info!("http listening on {}", address.to_string());

            match axum::serve(
                match tokio::net::TcpListener::bind(address).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::AddrInUse {
                            exit_error!("failed to start http server (address already in use)");
                        } else {
                            exit_error!("failed to start http server: {:?}", err);
                        }
                    }
                },
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                Ok(_) => {}
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::AddrInUse {
                        exit_error!("failed to start http server (address already in use)");
                    } else {
                        exit_error!("failed to start http server: {:?}", err);
                    }
                }
            }
        }
    } else {
        #[cfg(unix)]
        {
            let socket_path = state.config.load().api.host.clone();

            tracing::info!("http server listening on {}", socket_path);

            let router = router.layer(axum::middleware::from_fn(
                |mut req: Request, next: Next| async move {
                    req.extensions_mut().insert(ConnectInfo(SocketAddr::from((
                        std::net::IpAddr::from([127, 0, 0, 1]),
                        0,
                    ))));
                    next.run(req).await
                },
            ));

            let _ = tokio::fs::remove_file(&socket_path).await;
            let listener = match tokio::net::UnixListener::bind(socket_path) {
                Ok(listener) => listener,
                Err(err) => exit_error!("failed to bind to unix socket: {:?}", err),
            };

            if let Err(err) = axum::serve(listener, router.into_make_service()).await {
                exit_error!("failed to start http server: {:?}", err);
            }
        }
        #[cfg(not(unix))]
        {
            exit_error!("unix socket support is only available on unix systems");
        }
    }
}

fn main() {
    let thread_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(1024)
        .thread_name_fn({
            let thread_count = thread_count.clone();
            move || {
                let count = thread_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                format!("calagopus-wings-rt-{count}")
            }
        })
        .name("calagopus-wings-rt")
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(main_rt());
}
