use reqwest::Client;
use serde::Deserialize;

struct TokenByAuthorizationCodeParameters {
    token_endpoint: String,
    code: String,
    code_verifier: String,
    client_id: String,
    redirect_uri: String,
    resource: Option<String>,
}

#[derive(Debug, PartialEq, Deserialize)]
struct CodeTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
    scope: String,
    expires_in: i16,
}

async fn fetch_token_by_authorization_code(
    client: &Client,
    parameters: TokenByAuthorizationCodeParameters,
) -> Result<CodeTokenResponse, reqwest::Error> {
    let mut params = vec![
        ("client_id", &parameters.client_id),
        ("code", &parameters.code),
        ("code_verifier", &parameters.code_verifier),
        ("redirect_uri", &parameters.redirect_uri),
    ];

    if let Some(resource) = &parameters.resource {
        params.push(("resource", resource));
    }

    let response = client
        .post(&parameters.token_endpoint)
        .form(&params)
        .send()
        .await?
        .json::<CodeTokenResponse>()
        .await?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_token_by_auth_code() {
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/oidc/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "access_token": "access_token_value",
                    "refresh_token": "refresh_token_value",
                    "id_token": "id_token_value",
                    "scope": "read register",
                    "expires_in": 3600
                }"#,
            )
            .create();
        let url = server.url();

        let expected_token_response = CodeTokenResponse {
            access_token: "access_token_value".to_string(),
            refresh_token: Some("refresh_token_value".to_string()),
            id_token: "id_token_value".to_string(),
            scope: "read register".to_string(),
            expires_in: 3600,
        };

        let client = reqwest::Client::new();

        let params = TokenByAuthorizationCodeParameters {
            client_id: "client_id_value".to_string(),
            token_endpoint: format!("{}/oidc/token", url),
            redirect_uri: "https://localhost:3000/callback".to_string(),
            code_verifier: "code_verifier_value".to_string(),
            code: "code_value".to_string(),
            resource: Some("resource_value".to_string()),
        };

        let response = fetch_token_by_authorization_code(&client, params).await;

        match response {
            Ok(r) => assert_eq!(expected_token_response, r),
            Err(e) => panic!("Error in fetch_token_by_authorization_code: {}", e),
        }
    }
}
