use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OidcConfigResponse {
    authorization_endpoint: String,
    token_endpoint: String,
    end_session_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    issuer: String,
}

async fn fetch_oidc_config(
    client: &Client,
    endpoint: &str,
) -> Result<OidcConfigResponse, reqwest::Error> {
    let response = client.get(endpoint).send().await?;

    let config: OidcConfigResponse = response.json().await?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_oidc_config() {
        let client = reqwest::Client::new();

        let res = fetch_oidc_config(
            &client,
            "http://localhost:3001/oidc/.well-known/openid-configuration",
        )
        .await;

        assert!(res.is_ok())
    }
}
