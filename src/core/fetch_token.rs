use std::collections::HashMap;

use reqwest::Client;
use serde::Deserialize;

struct TokenByAuthorizationCodeParameters<'a> {
    token_endpoint: &'a str,
    code: &'a str,
    code_verifier: &'a str,
    client_id: &'a str,
    redirect_uri: &'a str,
    resource: Option<&'a str>,
}

struct TokenByRefreshTokenParameters {
    token_endpoint: &'static str,
    client_id: &'static str,
    refresh_token: &'static str,
    resource: Option<&'static str>,
    scopes: Option<Vec<&'static str>>,
}

// TODO: refactor this to a generic or something composed?

#[derive(Debug, PartialEq, Deserialize)]
struct CodeTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
    scope: String,
    expires_in: i16,
}

#[derive(Debug, PartialEq, Deserialize)]
struct RefreshTokenTokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: Option<String>,
    scope: String,
    expires_in: i16,
}

async fn fetch_token_by_authorization_code<'a>(
    client: &Client,
    parameters: TokenByAuthorizationCodeParameters<'a>,
) -> Result<CodeTokenResponse, reqwest::Error> {
    let mut params = HashMap::new();
    params.insert("client_id", parameters.client_id);
    params.insert("code", parameters.code);
    params.insert("code_verifier", parameters.code_verifier);
    params.insert("redirect_uri", parameters.redirect_uri);
    params.insert("grant_type", "authorization_code");

    if let Some(resource) = parameters.resource {
        params.insert("resource", resource);
    }

    let response = client
        .post(parameters.token_endpoint)
        .form(&params)
        .send()
        .await?
        .json::<CodeTokenResponse>()
        .await?;

    Ok(response)
}

async fn fetch_token_by_refresh_token(
    client: &Client,
    parameters: TokenByRefreshTokenParameters,
) -> Result<RefreshTokenTokenResponse, reqwest::Error> {
    let mut params = HashMap::new();
    params.insert("client_id", parameters.client_id);
    params.insert("refresh_token", parameters.refresh_token);
    params.insert("grant_type", "refresh_token");

    let scope = parameters
        .scopes
        .as_ref()
        .map(|val| val.join(" "))
        .unwrap_or_else(|| "".to_string());

    if scope.len() > 0 {
        params.insert("scope", scope.as_str());
    }

    if let Some(resource) = parameters.resource {
        params.insert("resource", resource);
    }

    let response = client
        .post(parameters.token_endpoint)
        .form(&params)
        .send()
        .await?
        .json::<RefreshTokenTokenResponse>()
        .await?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use mockito::Matcher;

    use super::*;

    #[tokio::test]
    async fn test_fetch_token_by_auth_code() {
        let mut server = mockito::Server::new();

        let body_matchers = vec![
            Matcher::UrlEncoded("client_id".into(), "client_id_value".into()),
            Matcher::UrlEncoded("code".into(), "code_value".into()),
            Matcher::UrlEncoded("code_verifier".into(), "code_verifier_value".into()),
            Matcher::UrlEncoded("resource".into(), "resource_value".into()),
            Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
        ];

        server
            .mock("POST", "/oidc/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(Matcher::AllOf(body_matchers))
            .with_status(201)
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

        let endpoint = format!("{}/oidc/token", url);

        let params = TokenByAuthorizationCodeParameters {
            client_id: "client_id_value",
            token_endpoint: endpoint.as_str(),
            redirect_uri: "https://localhost:3000/callback",
            code_verifier: "code_verifier_value",
            code: "code_value",
            resource: Some("resource_value"),
        };

        let response = fetch_token_by_authorization_code(&client, params).await;

        match response {
            Ok(r) => assert_eq!(expected_token_response, r),
            Err(e) => panic!("Error in fetch_token_by_authorization_code: {}", e),
        }
    }
}
