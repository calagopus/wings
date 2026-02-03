use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    nestify::nest! {
        #[derive(ToSchema, Deserialize)]
        pub struct Payload {
            debug: Option<bool>,
            app_name: Option<String>,

            #[schema(inline)]
            api: Option<#[derive(ToSchema, Deserialize)] pub struct ApiPayload {
                host: Option<String>,
                port: Option<u16>,

                #[schema(inline)]
                ssl: Option<#[derive(ToSchema, Deserialize)] pub struct ApiSslPayload {
                    enabled: Option<bool>,
                    cert: Option<String>,
                    key: Option<String>,
                }>,

                upload_limit: Option<crate::config::MiB>,
            }>,

            #[schema(inline)]
            system: Option<#[derive(ToSchema, Deserialize)] pub struct SystemPayload {
                #[schema(inline)]
                sftp: Option<#[derive(ToSchema, Deserialize)] pub struct SystemSftpPayload {
                    #[schema(value_type = Option<String>)]
                    bind_address: Option<std::net::IpAddr>,
                    bind_port: Option<u16>,
                }>,
            }>,

            allowed_origins: Option<Vec<String>>,

            allow_cors_private_network: Option<bool>,
            ignore_panel_config_updates: Option<bool>,
        }
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        applied: bool,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<Payload>,
    ) -> ApiResponseResult {
        if state.config.ignore_panel_config_updates {
            return ApiResponse::new_serialized(Response { applied: false }).ok();
        }

        let config = state.config.unsafe_mut();
        if let Some(debug) = data.debug {
            config.debug = debug;
        }
        if let Some(app_name) = data.app_name {
            config.app_name = app_name;
        }
        if let Some(api) = data.api {
            if let Some(host) = api.host {
                config.api.host = host;
            }
            if let Some(port) = api.port {
                config.api.port = port;
            }
            if let Some(ssl) = api.ssl {
                if let Some(enabled) = ssl.enabled {
                    config.api.ssl.enabled = enabled;
                }
                if let Some(cert) = ssl.cert {
                    config.api.ssl.cert = cert;
                }
                if let Some(key) = ssl.key {
                    config.api.ssl.key = key;
                }
            }
            if let Some(upload_limit) = api.upload_limit {
                config.api.upload_limit = upload_limit;
            }
        }
        if let Some(system) = data.system
            && let Some(sftp) = system.sftp
        {
            if let Some(bind_address) = sftp.bind_address {
                config.system.sftp.bind_address = bind_address;
            }
            if let Some(bind_port) = sftp.bind_port {
                config.system.sftp.bind_port = bind_port;
            }
        }
        if let Some(allowed_origins) = data.allowed_origins {
            config.allowed_origins = allowed_origins;
        }
        if let Some(allow_cors_private_network) = data.allow_cors_private_network {
            config.allow_cors_private_network = allow_cors_private_network;
        }
        if let Some(ignore_panel_config_updates) = data.ignore_panel_config_updates {
            config.ignore_panel_config_updates = ignore_panel_config_updates;
        }

        tokio::task::spawn_blocking(move || state.config.save()).await??;

        ApiResponse::new_serialized(Response { applied: true }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
