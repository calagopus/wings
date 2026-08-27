use super::State;
use crate::routes::GetState;
use axum::{
    body::Bytes,
    extract::{WebSocketUpgrade, ws::Message},
    response::Response,
    routing::any,
};
use std::{collections::BTreeMap, pin::Pin, sync::Arc, sync::atomic::Ordering};
use utoipa_axum::router::OpenApiRouter;

pub async fn handle_ws(ws: WebSocketUpgrade, state: GetState) -> Response {
    ws.read_buffer_size(crate::WS_READ_BUFFER_SIZE)
        .on_upgrade(move |socket| async move {
            let socket = Arc::new(tokio::sync::Mutex::new(socket));

            type ReturnType = dyn Future<Output = Result<(), anyhow::Error>> + Send;
            let futures: [Pin<Box<ReturnType>>; 2] = [
                // Transfer Status Listener
                Box::pin({
                    let state = Arc::clone(&state);
                    let socket = Arc::clone(&socket);

                    async move {
                        loop {
                            let mut transfers = BTreeMap::new();

                            for server in state.server_manager.get_servers().await.iter() {
                                if let Some(outgoing_transfer) =
                                    server.outgoing_transfer.read().await.as_ref()
                                {
                                    transfers.insert(
                                        server.uuid,
                                        crate::models::TransferProgress {
                                            archive_bytes_processed: outgoing_transfer
                                                .bytes_archived
                                                .load(Ordering::Relaxed),
                                            network_bytes_processed: outgoing_transfer
                                                .bytes_sent
                                                .load(Ordering::Relaxed),
                                            bytes_total: outgoing_transfer
                                                .bytes_total
                                                .load(Ordering::Relaxed),
                                            files_processed: outgoing_transfer
                                                .files_archived
                                                .load(Ordering::Relaxed),
                                        },
                                    );
                                }
                            }

                            let transfers_json = match serde_json::to_string(&transfers) {
                                Ok(json) => json,
                                Err(err) => {
                                    tracing::error!(
                                        "Failed to serialize transfers to JSON: {}",
                                        err
                                    );
                                    continue;
                                }
                            };

                            socket
                                .lock()
                                .await
                                .send(Message::Text(transfers_json.into()))
                                .await?;

                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                tracing::debug!("error while serving transfers websocket: {:?}", err);
            }
        })
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .route("/", any(handle_ws))
        .with_state(state.clone())
}
