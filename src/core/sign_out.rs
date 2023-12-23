use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignOutUriGenerationOptions {
    end_session_endpoint: String,
    client_id: String, // Docs convention says id_token, but other SDKs use client_id
    post_logout_redirect_uri: Option<String>,
}

pub fn generate_signout_uri(
    options: SignOutUriGenerationOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut url = Url::parse(&options.end_session_endpoint)?;

    url.query_pairs_mut()
        .append_pair("client_id", &options.client_id);

    if let Some(redirect_uri) = &options.post_logout_redirect_uri {
        url.query_pairs_mut()
            .append_pair("post_logout_redirect_uri", redirect_uri);
    }

    Ok(url.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_signin_uri() {
        let generated_uri = generate_signout_uri(SignOutUriGenerationOptions {
            end_session_endpoint: "http://logto.dev/oidc/session/end".to_string(),
            client_id: "clientId".to_string(),
            post_logout_redirect_uri: None,
        });

        if let Ok(uri) = generated_uri {
            assert_eq!(uri, "http://logto.dev/oidc/session/end?client_id=clientId")
        }
    }

    #[tokio::test]
    async fn test_generate_signin_uri_with_redirect() {
        let generated_uri = generate_signout_uri(SignOutUriGenerationOptions {
            end_session_endpoint: "http://logto.dev/oidc/session/end".to_string(),
            client_id: "clientId".to_string(),
            post_logout_redirect_uri: Some("http://example.com/callback".to_string()),
        });

        if let Ok(uri) = generated_uri {
            assert_eq!(
                uri,
                "http://logto.dev/oidc/session/end?client_id=clientId&post_logout_redirect_uri=http%3A%2F%2Fexample.com%2Fcallback"
            )
        }
    }
}
