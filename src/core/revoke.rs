use std::collections::HashMap;

use reqwest::Client;

struct RevocationParams<'a> {
    revocation_endpoint: &'a str,
    client_id: &'a str,
    token: &'a str,
}

async fn revoke<'a>(
    client: &Client,
    parameters: RevocationParams<'a>,
) -> Result<(), reqwest::Error> {
    let mut params = HashMap::new();
    params.insert("client_id", parameters.client_id);
    params.insert("token", parameters.token);

    match client
        .post(parameters.revocation_endpoint)
        .form(&params)
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use mockito::Matcher;

    use super::*;

    #[tokio::test]
    async fn should_revoke() {
        let mut server = mockito::Server::new();
        let body_matcher = vec![
            Matcher::UrlEncoded("client_id".into(), "client_id_value".into()),
            Matcher::UrlEncoded("token".into(), "token".into()),
        ];

        server
            .mock("POST", "/oidc/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(Matcher::AllOf(body_matcher))
            .with_status(201)
            .with_header("content-type", "application/json")
            .expect(1)
            .create();

        let url = server.url();

        let client = reqwest::Client::new();
        let endpoint = format!("{}/oidc/token/revocation", url);

        let params = RevocationParams {
            revocation_endpoint: &endpoint,
            client_id: "client_id",
            token: "token",
        };

        let response = revoke(&client, params).await;

        assert!(response.is_ok())
    }
}
