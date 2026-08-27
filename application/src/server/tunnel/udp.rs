use axum::{
    body::Bytes,
    extract::ws::{Message, WebSocket},
};
use futures::{SinkExt, StreamExt};
use std::{io, net::SocketAddr, time::Duration};
use tokio::net::UdpSocket;

pub const RECV_BUFFER_SIZE: usize = 65536;
const RECV_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(30);

const REFUSED_SIGNAL: &str = "refused";

pub async fn tunnel(socket: WebSocket, target: SocketAddr) {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let udp = match UdpSocket::bind(bind).await {
        Ok(udp) => udp,
        Err(err) => {
            tracing::debug!(%target, "internal udp tunnel bind failed: {err}");
            return;
        }
    };
    if let Err(err) = udp.connect(target).await {
        tracing::debug!(%target, "internal udp tunnel connect failed: {err}");
        return;
    }

    let (mut ws_sink, mut ws_stream) = socket.split();

    let ws_to_udp = async {
        while let Some(Ok(message)) = ws_stream.next().await {
            match datagram_payload(&message) {
                Some(data) => {
                    let _ = udp.send(data).await;
                }
                None => {
                    if matches!(message, Message::Close(_)) {
                        break;
                    }
                }
            }
        }
    };

    let udp_to_ws = async {
        let mut buffer = vec![0; RECV_BUFFER_SIZE];
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                recv = tokio::time::timeout(RECV_TIMEOUT, udp.recv(&mut buffer)) => {
                    match recv {
                        Ok(Ok(bytes_read)) => {
                            if let Some(slice) = buffer.get(..bytes_read) && ws_sink
                                .send(Message::Binary(Bytes::copy_from_slice(slice)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
                            let _ = ws_sink.send(Message::Text(REFUSED_SIGNAL.into())).await;
                        }
                        Ok(Err(_)) | Err(_) => {}
                    }
                }
                _ = ping.tick() => {
                    if ws_sink.send(Message::Ping(Bytes::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = ws_to_udp => {}
        _ = udp_to_ws => {}
    }

    let _ = ws_sink.send(Message::Close(None)).await;
}

fn datagram_payload(message: &Message) -> Option<&[u8]> {
    match message {
        Message::Binary(data) => Some(data),
        _ => None,
    }
}
