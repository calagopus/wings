use crate::io::SafeSliceExt;
use hickory_resolver::{
    TokioResolver,
    config::LookupIpStrategy,
    lookup_ip::{LookupIp, LookupIpIter},
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{net::SocketAddr, str::FromStr, sync::Arc};

pub fn host_to_ip(host: &str) -> Option<std::net::IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    std::net::IpAddr::from_str(host).ok()
}

pub fn is_blocked_ip(cidrs: &[cidr::IpCidr], ip: &std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();

    cidrs.iter().any(|cidr| cidr.contains(&ip))
}

#[derive(Clone)]
pub struct BlockedIpResolver {
    config: Arc<crate::config::Config>,
    selector: fn(&crate::config::InnerConfig) -> &Vec<cidr::IpCidr>,
    context: &'static str,
    state: Arc<TokioResolver>,
}

impl BlockedIpResolver {
    pub fn new(
        config: &Arc<crate::config::Config>,
        selector: fn(&crate::config::InnerConfig) -> &Vec<cidr::IpCidr>,
        context: &'static str,
    ) -> Self {
        let mut builder =
            TokioResolver::builder_tokio().expect("failed to create TokioResolver builder");
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

        Self {
            config: Arc::clone(config),
            selector,
            context,
            state: Arc::new(builder.build().expect("failed to build TokioResolver")),
        }
    }
}

impl Resolve for BlockedIpResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();

        Box::pin(async move {
            let lookup = resolver.state.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs::new(
                Arc::clone(&resolver.config),
                resolver.selector,
                resolver.context,
                lookup,
                |l| l.iter(),
            ));

            Ok(addrs)
        })
    }
}

#[ouroboros::self_referencing]
struct SocketAddrs {
    config: Arc<crate::config::Config>,
    selector: fn(&crate::config::InnerConfig) -> &Vec<cidr::IpCidr>,
    context: &'static str,
    lookup: LookupIp,

    #[borrows(mut lookup)]
    #[covariant]
    iter: LookupIpIter<'this>,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self
            .with_iter_mut(|iter| iter.next())
            .map(|ip_addr| SocketAddr::new(ip_addr, 0))?;

        let config = self.borrow_config().load();
        if is_blocked_ip((self.borrow_selector())(&config), &next.ip()) {
            tracing::warn!(
                "blocking internal IP address in {}: {}",
                self.borrow_context(),
                next.ip()
            );

            return self.next();
        }

        Some(next)
    }
}

#[cfg(target_os = "linux")]
pub fn tcp_congestion_control_supported(algorithm: &str) -> bool {
    use std::{collections::HashMap, sync::OnceLock};

    static CACHE: OnceLock<parking_lot::Mutex<HashMap<String, bool>>> = OnceLock::new();

    let cache = CACHE.get_or_init(Default::default);
    if let Some(&supported) = cache.lock().get(algorithm) {
        return supported;
    }

    let available = |algorithm: &str| {
        std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
            .is_ok_and(|contents| contents.split_whitespace().any(|entry| entry == algorithm))
    };

    let mut supported = available(algorithm);
    if !supported {
        std::process::Command::new("modprobe")
            .arg(format!("tcp_{algorithm}"))
            .output()
            .ok();

        supported = available(algorithm);
    }

    if !supported {
        tracing::warn!(
            algorithm = %algorithm,
            "the configured tcp congestion control algorithm is not available on this kernel, keeping the system default"
        );
    }

    cache.lock().insert(algorithm.to_string(), supported);

    supported
}

#[cfg(not(target_os = "linux"))]
pub fn tcp_congestion_control_supported(_algorithm: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn apply_socket_congestion_control<F: std::os::fd::AsFd>(
    listener: &F,
    config: &crate::config::Config,
) {
    let algorithm = config.load().system.tcp_congestion_control.clone();
    if algorithm.is_empty() || !tcp_congestion_control_supported(&algorithm) {
        return;
    }

    if let Err(err) = rustix::net::sockopt::set_tcp_congestion(listener, &algorithm) {
        tracing::debug!(
            algorithm = %algorithm,
            "failed to set tcp congestion control on listener: {}",
            err
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_socket_congestion_control<F>(_listener: &F, _config: &crate::config::Config) {}

pub struct CongestionControlProxy {
    address: std::net::SocketAddr,
    listener_task: tokio::task::JoinHandle<()>,
}

impl CongestionControlProxy {
    pub async fn start(
        config: &Arc<crate::config::Config>,
        target_host: String,
        target_port: u16,
    ) -> Option<Self> {
        let algorithm = config.load().system.tcp_congestion_control.clone();
        if algorithm.is_empty() || !tcp_congestion_control_supported(&algorithm) {
            return None;
        }

        let listener = match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await
        {
            Ok(listener) => listener,
            Err(err) => {
                tracing::debug!(
                    "failed to bind congestion control proxy listener, connecting directly: {}",
                    err
                );

                return None;
            }
        };
        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(_) => return None,
        };

        let listener_task = tokio::spawn({
            let config = Arc::clone(config);

            async move {
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        break;
                    };

                    tokio::spawn(Self::forward(
                        client,
                        target_host.clone(),
                        target_port,
                        Arc::clone(&config),
                    ));
                }
            }
        });

        Some(Self {
            address,
            listener_task,
        })
    }

    #[inline]
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    async fn forward(
        mut client: tokio::net::TcpStream,
        target_host: String,
        target_port: u16,
        config: Arc<crate::config::Config>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const MAX_HEAD_SIZE: usize = 8192;

        let mut head = Vec::with_capacity(512);
        let head_end = loop {
            if client.read_buf(&mut head).await.unwrap_or(0) == 0 || head.len() > MAX_HEAD_SIZE {
                return;
            }

            if let Some(position) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };

        let mut upstream =
            match tokio::net::TcpStream::connect((target_host.as_str(), target_port)).await {
                Ok(upstream) => upstream,
                Err(err) => {
                    tracing::debug!(
                        host = %target_host,
                        port = target_port,
                        "congestion control proxy failed to reach the target: {}",
                        err
                    );

                    return;
                }
            };
        apply_socket_congestion_control(&upstream, &config);
        upstream.set_nodelay(true).ok();

        if head.starts_with(b"CONNECT ") {
            let Ok(tunneled) = head.get_slice(head_end..) else {
                return;
            };

            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
                || upstream.write_all(tunneled).await.is_err()
            {
                return;
            }
        } else if upstream.write_all(&head).await.is_err() {
            return;
        }

        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .ok();
    }
}

impl Drop for CongestionControlProxy {
    fn drop(&mut self) {
        self.listener_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn echo_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    while let Ok(n) = socket.read(&mut buffer).await {
                        if n == 0 || socket.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        (address, task)
    }

    fn proxy_test_config() -> Arc<crate::config::Config> {
        let config = Arc::new(crate::config::Config::mock());
        // cubic is compiled into every linux kernel, unlike bbr
        config
            .mutate_in_place_for_testing()
            .system
            .tcp_congestion_control = "cubic".to_string();

        config
    }

    // CongestionControlProxy

    #[test]
    fn congestion_control_proxy_tunnels_connect_requests() {
        tokio_test::block_on(async {
            let (target, _target_task) = echo_target().await;
            let config = proxy_test_config();

            let proxy =
                CongestionControlProxy::start(&config, target.ip().to_string(), target.port())
                    .await
                    .expect("proxy should start with an always-available algorithm");

            let mut client =
                tokio::net::TcpStream::connect(proxy.url().strip_prefix("http://").unwrap())
                    .await
                    .unwrap();

            client
                .write_all(b"CONNECT ignored.example:443 HTTP/1.1\r\nHost: ignored.example\r\n\r\n")
                .await
                .unwrap();

            let mut response = [0u8; 39];
            client.read_exact(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));

            client.write_all(b"tunneled").await.unwrap();
            let mut echoed = [0u8; 8];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"tunneled");
        });
    }

    #[test]
    fn congestion_control_proxy_forwards_plain_http_transparently() {
        tokio_test::block_on(async {
            let (target, _target_task) = echo_target().await;
            let config = proxy_test_config();

            let proxy =
                CongestionControlProxy::start(&config, target.ip().to_string(), target.port())
                    .await
                    .unwrap();

            let mut client =
                tokio::net::TcpStream::connect(proxy.url().strip_prefix("http://").unwrap())
                    .await
                    .unwrap();

            let request =
                b"POST http://ignored.example/api HTTP/1.1\r\nHost: ignored.example\r\n\r\n";
            client.write_all(request).await.unwrap();

            let mut echoed = vec![0u8; request.len()];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, request);
        });
    }

    #[test]
    fn congestion_control_proxy_refuses_unavailable_algorithms() {
        tokio_test::block_on(async {
            let config = Arc::new(crate::config::Config::mock());
            config
                .mutate_in_place_for_testing()
                .system
                .tcp_congestion_control = "definitely-not-a-real-algorithm".to_string();

            assert!(
                CongestionControlProxy::start(&config, "127.0.0.1".to_string(), 1)
                    .await
                    .is_none()
            );
        });
    }
}
