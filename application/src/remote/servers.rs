use serde::Deserialize;
use utoipa::ToSchema;

#[derive(ToSchema, Deserialize)]
pub struct RawServer {
    pub settings: crate::server::configuration::ServerConfiguration,
    pub process_configuration: crate::server::configuration::process::ProcessConfiguration,
}
