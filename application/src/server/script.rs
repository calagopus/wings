use crate::server::installation::InstallationScript;
use anyhow::Context;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub async fn script_server(
    server: &super::Server,
    executor: &Arc<dyn crate::server::executor::ServerExecutor>,
    container_script: InstallationScript,
) -> Result<crate::io::pipe::PipeReader, anyhow::Error> {
    let (handle, _) = executor
        .setup_script_process(server, &container_script)
        .await
        .context("Failed to setup script process")?;

    let mut stdout_rx = handle
        .subscribe_stdout_lines()
        .await
        .context("Failed to subscribe to stdout")?;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    handle
        .start()
        .await
        .context("Failed to start script container")?;

    let (buf_stdout_rx, mut buf_stdout_tx) = crate::io::pipe::pipe(crate::BUFFER_SIZE);

    tokio::spawn(async move {
        loop {
            match stdout_rx.recv().await {
                Ok(data) => {
                    if let Err(err) = buf_stdout_tx.write_all(data.as_bytes()).await {
                        tracing::error!("Failed to write to script stdout buffer: {}", err);
                        break;
                    }
                    if let Err(err) = buf_stdout_tx.write_all(b"\n").await {
                        tracing::error!("Failed to write to script stdout buffer: {}", err);
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    buf_stdout_tx.shutdown().await.ok();
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            }
        }
    });

    Ok(buf_stdout_rx)
}
