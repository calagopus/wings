use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::Serialize;
    use sysinfo::System;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct ResponseCpu<'a> {
        name: &'a str,
        brand: &'a str,
        vendor_id: &'a str,
        frequency_mhz: u64,
        cpu_count: usize,
    }

    #[derive(ToSchema, Serialize)]
    struct ResponseMemory {
        total_bytes: u64,
        free_bytes: u64,
        used_bytes: u64,
        used_bytes_process: u64,
    }

    #[derive(ToSchema, Serialize)]
    struct ResponseServers {
        total: usize,
        online: usize,
        offline: usize,
    }

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        version: &'a str,
        local_time: chrono::DateTime<chrono::Local>,
        container_type: crate::routes::AppContainerType,

        #[schema(inline)]
        cpu: ResponseCpu<'a>,
        #[schema(inline)]
        memory: ResponseMemory,
        #[schema(inline)]
        servers: ResponseServers,

        architecture: &'static str,
        kernel_version: String,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        let mut sys = System::new_all();
        sys.refresh_cpu_all();

        let used_bytes_process = match crate::utils::process_memory_usage() {
            Some(used_bytes_process) => used_bytes_process,
            None => {
                let mut used_bytes_process = 0;
                if let Ok(current_pid) = sysinfo::get_current_pid() {
                    sys.refresh_processes_specifics(
                        sysinfo::ProcessesToUpdate::Some(&[current_pid]),
                        false,
                        sysinfo::ProcessRefreshKind::nothing().with_memory(),
                    );

                    if let Some(process) = sys.process(current_pid) {
                        used_bytes_process = process.memory();
                    }
                }

                used_bytes_process
            }
        };

        let Some(cpu) = sys.cpus().first() else {
            return ApiResponse::error("failed to retrieve cpu information").ok();
        };

        let mut servers = ResponseServers {
            total: 0,
            online: 0,
            offline: 0,
        };

        for server in state.server_manager.get_servers().await.iter() {
            servers.total += 1;
            if server.state.get_state() == crate::server::state::ServerState::Offline {
                servers.offline += 1;
            } else {
                servers.online += 1;
            }
        }

        ApiResponse::new_serialized(Response {
            version: &state.version,
            local_time: chrono::Local::now(),
            container_type: state.container_type,
            cpu: ResponseCpu {
                name: cpu.name(),
                brand: cpu.brand(),
                vendor_id: cpu.vendor_id(),
                frequency_mhz: cpu.frequency(),
                cpu_count: sys.cpus().len(),
            },
            memory: ResponseMemory {
                total_bytes: sys.total_memory(),
                free_bytes: sys.free_memory(),
                used_bytes: sys.used_memory(),
                used_bytes_process,
            },
            servers,
            architecture: std::env::consts::ARCH,
            kernel_version: System::kernel_long_version(),
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .with_state(state.clone())
}
