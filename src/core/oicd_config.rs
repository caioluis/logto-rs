use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, PartialEq, Deserialize)]
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
        let mut server = mockito::Server::new();
        let url = server.url();

        server
            .mock("GET", "/oidc/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "authorization_endpoint": "foo",
                    "token_endpoint": "foo",
                    "userinfo_endpoint": "foo",
                    "end_session_endpoint": "foo",
                    "revocation_endpoint": "foo",
                    "jwks_uri": "foo",
                    "issuer": "foo"
                }"#,
            )
            .create();

        let expected_config_response = OidcConfigResponse {
            authorization_endpoint: "foo".to_string(),
            token_endpoint: "foo".to_string(),
            end_session_endpoint: "foo".to_string(),
            revocation_endpoint: "foo".to_string(),
            jwks_uri: "foo".to_string(),
            issuer: "foo".to_string(),
        };

        let client = reqwest::Client::new();

        let response = fetch_oidc_config(
            &client,
            format!("{}/oidc/.well-known/openid-configuration", url).as_str(),
        )
        .await;

        match response {
            Ok(r) => {
                assert_eq!(r, expected_config_response)
            }
            Err(e) => panic!("Error in fetch_token_by_authorization_code: {}", e),
        }
    }
}
