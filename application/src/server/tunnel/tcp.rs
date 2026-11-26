use axum::extract::ws::WebSocket;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn tunnel(socket: WebSocket, target: SocketAddr) {
    let stream = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::debug!(%target, "internal tcp tunnel connect failed: {err}");
            return;
        }
    };

    let (read, write) = stream.into_split();
    super::stream::pipe(socket, read, write).await;
}
