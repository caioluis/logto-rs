use reqwest::Client;

async fn fetch_oidc_config(
    client: &Client,
    endpoint: &str,
) -> Result<OidcConfigResponse, reqwest::Error> {
    let response = client.get(endpoint).send().await?;

    let config: OidcConfigResponse = response.json().await?;

    Ok(config)
}
