use super::error::PbsError;
use compact_str::ToCompactString;
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::OnceLock,
};

static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

fn resolver() -> Result<&'static TokioResolver, PbsError> {
    if let Some(resolver) = RESOLVER.get() {
        return Ok(resolver);
    }

    let mut builder = TokioResolver::builder_tokio()
        .map_err(|err| PbsError::Transport(err.to_compact_string()))?;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

    let resolver = builder
        .build()
        .map_err(|err| PbsError::Transport(err.to_compact_string()))?;

    Ok(RESOLVER.get_or_init(|| resolver))
}

pub async fn lookup_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, PbsError> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(ip) = IpAddr::from_str(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let lookup = resolver()?
        .lookup_ip(host)
        .await
        .map_err(|err| PbsError::Transport(err.to_compact_string()))?;

    Ok(lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect())
}
