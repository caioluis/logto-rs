use std::collections::HashSet;

use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignInUriGenerationOptions {
    authorization_endpoint: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    state: String,
    scopes: Option<Vec<String>>,
    resources: Option<Vec<String>>,
    prompt: Option<String>,
}

enum ReservedScopes {
    OfflineAccess,
    OpenId,
}

impl ReservedScopes {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OfflineAccess => "offline_access",
            Self::OpenId => "openid",
        }
    }
}

fn with_default_scopes(mut scopes: Option<Vec<String>>) -> Vec<String> {
    let default_scopes: Vec<String> = vec![
        ReservedScopes::OpenId.as_str().to_owned(),
        ReservedScopes::OfflineAccess.as_str().to_owned(),
    ];

    match scopes {
        None => default_scopes,
        Some(mut scopes) => {
            scopes.extend(default_scopes);
            scopes.sort_unstable();
            scopes.dedup();

            scopes
        }
    }
}

const CODE_CHALLENGE_METHOD: &str = "S256";
const RESPONSE_TYPE: &str = "code";

pub fn generate_signin_uri(
    options: SignInUriGenerationOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut url = Url::parse(&options.authorization_endpoint)?;

    url.query_pairs_mut()
        .append_pair("client_id", &options.client_id)
        .append_pair("redirect_uri", &options.redirect_uri)
        .append_pair("code_challenge", &options.code_challenge)
        .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD)
        .append_pair("state", &options.state)
        .append_pair("response_type", RESPONSE_TYPE)
        .append_pair(
            "scope",
            with_default_scopes(options.scopes).join(" ").as_str(),
        )
        .append_pair(
            "prompt",
            &options.prompt.unwrap_or("consent".to_string()).to_string(),
        );

    let mut resources = Vec::<String>::new();
    if let Some(resources_list) = options.resources {
        for resource in resources_list {
            if !resources.contains(&resource) {
                resources.push(resource);
            }
        }
        url.query_pairs_mut()
            .append_pair("resource", resources.join(" ").as_str());
    }

    Ok(url.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_signin_uri() {
        let generated_uri = generate_signin_uri(SignInUriGenerationOptions {
            authorization_endpoint: "http://localhost:3001/oidc/sign-in".to_string(),
            client_id: "clientId".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            code_challenge: "codeChallenge".to_string(),
            state: "state".to_string(),
            scopes: None,
            resources: None,
            prompt: None,
        });

        if let Ok(uri) = generated_uri {
            assert_eq!(
                uri,
                "http://localhost:3001/oidc/sign-in?client_id=clientId&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=codeChallenge&code_challenge_method=S256&state=state&response_type=code&scope=openid+offline_access+profile&prompt=consent"
            )
        }
    }
}
