use reqwest::{header::CONTENT_TYPE, Client, Url};
use serde::Deserialize;

struct TokenByAuthorizationCodeParameters {
    token_endpoint: String,
    code: String,
    code_verifier: String,
    client_id: String,
    redirect_uri: String,
    resource: Option<String>,
}

#[derive(Deserialize)]
struct CodeTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    client_id: String,
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

    let response: CodeTokenResponse = client
        .post(&parameters.token_endpoint)
        .form(&params)
        .send()
        .await?
        .json()
        .await?;

    Ok(response)
}
