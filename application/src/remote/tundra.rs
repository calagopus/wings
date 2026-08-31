use super::{ResponseExt, client::Client};
use serde::Deserialize;
use serde_json::json;
use tundra_common::{hash::Hash32, state::Snapshot};

pub async fn get_state(client: &Client) -> Result<Snapshot, anyhow::Error> {
    super::into_json(
        client
            .client
            .get(format!("{}/tunnel/state", client.url))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )
}

pub async fn store_cert(client: &Client, cert_sha256: Hash32) -> Result<(), anyhow::Error> {
    client
        .client
        .post(format!("{}/tunnel/cert", client.url))
        .json(&json!({ "cert_sha256": cert_sha256 }))
        .send()
        .await?
        .error_for_remote_status()
        .await?;

    Ok(())
}

pub async fn get_connect_token(
    client: &Client,
    target: uuid::Uuid,
) -> Result<String, anyhow::Error> {
    let response: Response = super::into_json(
        client
            .client
            .get(format!(
                "{}/tunnel/connect-token?target={}",
                client.url, target
            ))
            .send()
            .await?
            .error_for_remote_status()
            .await?
            .text()
            .await?,
    )?;

    #[derive(Deserialize)]
    struct Response {
        jwt: String,
    }

    Ok(response.jwt)
}
