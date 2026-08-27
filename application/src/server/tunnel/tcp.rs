use axum::{
    body::Bytes,
    extract::ws::{Message, WebSocket},
};
use futures::{SinkExt, StreamExt};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const PING_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_MESSAGE_SIZE: usize = crate::TRANSFER_BUFFER_SIZE;

pub async fn tunnel(socket: WebSocket, target: SocketAddr) {
    let stream = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::debug!(%target, "internal tcp tunnel connect failed: {err}");
            return;
        }
    };

    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let (mut ws_sink, mut ws_stream) = socket.split();

    let ws_to_tcp = async {
        while let Some(Ok(message)) = ws_stream.next().await {
            match message {
                Message::Binary(data) if tcp_write.write_all(&data).await.is_err() => {
                    break;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };

    let tcp_to_ws = async {
        let mut buffer = bytes::BytesMut::with_capacity(crate::BUFFER_SIZE);
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            buffer.reserve(crate::BUFFER_SIZE);

            tokio::select! {
                read = tcp_read.read_buf(&mut buffer) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if ws_sink
                            .send(Message::Binary(buffer.split().freeze()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                },
                _ = ping.tick() => {
                    if ws_sink.send(Message::Ping(Bytes::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = ws_to_tcp => {}
        _ = tcp_to_ws => {}
    }

    let _ = ws_sink.send(Message::Close(None)).await;
}
