use anyhow::Context;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, OnceLock},
    time::Instant,
};

use crate::net::{host_to_ip, is_blocked_ip};

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
];

static HTTP_CLIENT: OnceLock<Arc<reqwest::Client>> = OnceLock::new();
static RATE_LIMITS: LazyLock<parking_lot::Mutex<HashMap<uuid::Uuid, RateLimitWindow>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

struct RateLimitWindow {
    started: Instant,
    requests: u32,
}

fn blocked_cidrs(config: &crate::config::InnerConfig) -> &Vec<cidr::IpCidr> {
    &config.api.schedule.steps.http_request.blocked_cidrs
}

fn get_client(config: &Arc<crate::config::Config>) -> Result<Arc<reqwest::Client>, anyhow::Error> {
    if let Some(client) = HTTP_CLIENT.get() {
        return Ok(Arc::clone(client));
    }

    let client = Arc::new(
        reqwest::Client::builder()
            .user_agent("Calagopus Wings (https://github.com/calagopus/wings)")
            .connect_timeout(std::time::Duration::from_secs(10))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(crate::net::BlockedIpResolver::new(
                config,
                blocked_cidrs,
                "schedule http request",
            )))
            .build()
            .context("failed to build schedule http request client")?,
    );

    Ok(Arc::clone(HTTP_CLIENT.get_or_init(|| client)))
}

fn check_rate_limit(server: uuid::Uuid, requests: u32, window_seconds: u64) -> bool {
    let window = std::time::Duration::from_secs(window_seconds);
    let mut limits = RATE_LIMITS.lock();

    limits.retain(|uuid, limit| *uuid == server || limit.started.elapsed() < window);

    let entry = limits.entry(server).or_insert_with(|| RateLimitWindow {
        started: Instant::now(),
        requests: 0,
    });

    if entry.started.elapsed() >= window {
        entry.started = Instant::now();
        entry.requests = 0;
    }

    if entry.requests >= requests {
        return false;
    }

    entry.requests += 1;

    true
}

pub struct HttpRequestOptions<'a> {
    pub method: reqwest::Method,
    pub url: &'a reqwest::Url,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: Option<&'a str>,
    pub timeout: std::time::Duration,
    pub capture_body: bool,
}

pub struct HttpRequestOutcome {
    pub status: u16,
    pub body: Option<compact_str::CompactString>,
    pub host: compact_str::CompactString,
}

pub async fn execute(
    config: &Arc<crate::config::Config>,
    server: uuid::Uuid,
    options: HttpRequestOptions<'_>,
) -> Result<HttpRequestOutcome, std::borrow::Cow<'static, str>> {
    let (requests, window_seconds, max_response_size) = {
        let config = config.load();
        let settings = &config.api.schedule.steps.http_request;

        if !settings.enabled {
            return Err("http requests are disabled on this node.".into());
        }

        (
            settings.requests,
            settings.window_seconds,
            settings.max_response_size,
        )
    };

    if !matches!(options.url.scheme(), "http" | "https") {
        return Err("only http and https urls are supported.".into());
    }

    let Some(host) = options.url.host_str() else {
        return Err("url does not contain a host.".into());
    };

    if let Some(ip) = host_to_ip(host)
        && is_blocked_ip(blocked_cidrs(&config.load()), &ip)
    {
        tracing::warn!(
            server = %server,
            "blocking internal IP address in schedule http request: {}",
            ip
        );

        return Err("the requested address is blocked.".into());
    }

    let host = compact_str::CompactString::from(host);

    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in options.headers {
        if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(format!("header `{name}` may not be set.").into());
        }

        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| std::borrow::Cow::from(format!("header name `{name}` is not valid.")))?;
        let value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
            std::borrow::Cow::from(format!("value for header `{name}` is not valid."))
        })?;

        headers.insert(name, value);
    }

    let client =
        get_client(config).map_err(|_| std::borrow::Cow::from("failed to create http client"))?;

    let mut request = client
        .request(options.method, options.url.clone())
        .headers(headers)
        .timeout(options.timeout);
    if let Some(body) = options.body {
        request = request.body(body.to_string());
    }

    if !check_rate_limit(server, requests, window_seconds) {
        return Err("http request rate limit exceeded for this server.".into());
    }

    let mut response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(
                server = %server,
                "failed to send schedule http request: {:?}",
                err.without_url()
            );

            return Err("failed to send the http request".into());
        }
    };

    let status = response.status().as_u16();
    let body = if options.capture_body {
        let mut raw = Vec::new();

        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => return Err("failed to read the http response".into()),
            };

            let remaining = max_response_size.saturating_sub(raw.len());
            if remaining == 0 {
                break;
            }

            raw.extend_from_slice(chunk.get(..chunk.len().min(remaining)).unwrap_or(&chunk));
        }

        let mut body = String::from_utf8_lossy(&raw).into_owned();
        while body.len() > max_response_size {
            body.pop();
        }

        Some(compact_str::CompactString::from(body))
    } else {
        None
    };

    Ok(HttpRequestOutcome { status, body, host })
}
