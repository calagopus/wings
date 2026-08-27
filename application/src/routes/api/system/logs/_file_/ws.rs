use super::State;
use crate::{
    io::{
        SafeSliceExt, SafeSliceMutExt,
        compression::{CompressionType, reader::AsyncCompressionReader},
        line_buffer::LineBuffer,
    },
    routes::GetState,
};
use axum::{
    body::Bytes,
    extract::{
        Path, Query, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
    routing::any,
};
use serde::Deserialize;
use std::{io::SeekFrom, pin::Pin, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};
use utoipa_axum::router::OpenApiRouter;

#[derive(Deserialize)]
pub struct Params {
    lines: Option<usize>,
}

async fn send_lines(
    socket: &Mutex<WebSocket>,
    line_buffer: &mut LineBuffer,
) -> Result<(), anyhow::Error> {
    while let Some(line) = line_buffer.next_line() {
        let text = String::from_utf8_lossy(line).into_owned();
        socket.lock().await.send(Message::Text(text.into())).await?;
    }

    line_buffer.compact();

    Ok(())
}

pub async fn handle_ws(
    ws: WebSocketUpgrade,
    state: GetState,
    Path(file): Path<compact_str::CompactString>,
    Query(params): Query<Params>,
) -> Response {
    ws.read_buffer_size(crate::WS_READ_BUFFER_SIZE)
        .on_upgrade(move |socket| async move {
            let Some(path) = super::log_file_path(&state, &file) else {
                return;
            };

            let lines = params.lines.map(|n| n.min(crate::io::tail::LINES_CAP));
            let compression_type = CompressionType::from_file_name(&file);

            let Ok(mut file) = tokio::fs::File::open(path).await else {
                return;
            };

            let socket = Arc::new(Mutex::new(socket));

            type ReturnType = dyn Future<Output = Result<(), anyhow::Error>> + Send;
            let futures: [Pin<Box<ReturnType>>; 2] = [
                // Log Line Follower
                Box::pin({
                    let socket = Arc::clone(&socket);

                    async move {
                        let mut buf = vec![0; crate::BUFFER_SIZE];
                        let mut line_buffer = LineBuffer::new();

                        if !matches!(compression_type, CompressionType::None) {
                            let reader = AsyncCompressionReader::new(
                                file.into_std().await,
                                compression_type,
                            );
                            let mut reader: Box<dyn AsyncRead + Send + Unpin> = match lines {
                                Some(lines) => Box::new(
                                    crate::io::tail::async_tail_stream(reader, lines).await?,
                                ),
                                None => Box::new(reader),
                            };

                            loop {
                                let bytes_read = reader.read(&mut buf).await?;
                                if bytes_read == 0 {
                                    break;
                                }

                                line_buffer.extend(buf.get_slice(..bytes_read)?);
                                send_lines(&socket, &mut line_buffer).await?;
                            }

                            if let Some(line) = line_buffer.flush() {
                                let text = String::from_utf8_lossy(line).into_owned();
                                socket.lock().await.send(Message::Text(text.into())).await?;
                            }

                            return Ok(());
                        }

                        let mut pos = match lines {
                            Some(lines) => {
                                file = crate::io::tail::async_tail(file, lines).await?;
                                file.stream_position().await?
                            }
                            None => 0,
                        };

                        loop {
                            let len = file.seek(SeekFrom::End(0)).await?;
                            if len < pos {
                                pos = 0;
                                line_buffer = LineBuffer::new();
                            }

                            while pos < len {
                                let to_read =
                                    std::cmp::min(len - pos, crate::BUFFER_SIZE as u64) as usize;
                                file.seek(SeekFrom::Start(pos)).await?;

                                let chunk = buf.get_slice_mut(..to_read)?;
                                file.read_exact(chunk).await?;
                                pos += to_read as u64;

                                line_buffer.extend(chunk);
                                send_lines(&socket, &mut line_buffer).await?;
                            }

                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                }),
                // Pinger
                Box::pin(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                        socket
                            .lock()
                            .await
                            .send(Message::Ping(Bytes::from_static(&[1, 2, 3])))
                            .await?;
                    }
                }),
            ];

            if let Err(err) = futures::future::try_join_all(futures).await {
                tracing::debug!("error while serving log websocket: {:?}", err);
            }
        })
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .route("/", any(handle_ws))
        .with_state(state.clone())
}
