use super::State;
use crate::{response::ApiResponse, routes::GetState};
use axum::{
    body::Bytes,
    extract::{WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use std::{pin::Pin, sync::Arc};
use utoipa_axum::router::OpenApiRouter;

pub async fn handle_ws(ws: WebSocketUpgrade, state: GetState) -> Response {
    if state.tundra.is_none() {
        return ApiResponse::error("tundra is not enabled on this node")
            .with_status(StatusCode::NOT_IMPLEMENTED)
            .into_response();
    }

    ws.read_buffer_size(crate::WS_READ_BUFFER_SIZE)
        .on_upgrade(move |socket| async move {
            let socket = Arc::new(tokio::sync::Mutex::new(socket));

            type ReturnType = dyn Future<Output = Result<(), anyhow::Error>> + Send;
            let futures: [Pin<Box<ReturnType>>; 2] = [
                // Metrics Listener
                Box::pin({
                    let state = Arc::clone(&state);
                    let socket = Arc::clone(&socket);

                    async move {
                        let Some(tundra) = state.tundra.as_ref() else {
                            return Ok(());
                        };

                        loop {
                            match tundra.hub.request_metrics().await {
                                Ok(metrics) => match serde_json::to_string(&metrics) {
                                    Ok(json) => {
                                        socket
                                            .lock()
                                            .await
                                            .send(Message::Text(json.into()))
                                            .await?;
                                    }
                                    Err(err) => tracing::error!(
                                        "failed to serialize tundra metrics to JSON: {}",
                                        err
                                    ),
                                },
                                Err(err) => {
                                    tracing::debug!("failed to request tundra metrics: {:#}", err)
                                }
                            }

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
                tracing::debug!("error while serving tundra metrics websocket: {:?}", err);
            }
        })
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .route("/", any(handle_ws))
        .with_state(state.clone())
}
