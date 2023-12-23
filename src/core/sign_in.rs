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
    interaction_mode: Option<String>,
}

enum ReservedScopes {
    OfflineAccess,
    OpenId,
}

enum UserScopes {
    CustomData,
    Email,
    Identities,
    Phone,
    Profile,
}

impl UserScopes {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CustomData => "custom_data",
            Self::Email => "email",
            Self::Identities => "identities",
            Self::Phone => "phone",
            Self::Profile => "profile",
        }
    }
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
        ReservedScopes::OfflineAccess.as_str().to_owned(),
        ReservedScopes::OpenId.as_str().to_owned(),
        UserScopes::Profile.as_str().to_owned(),
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

    if let Some(interaction_mode) = options.interaction_mode {
        url.query_pairs_mut()
            .append_pair("interaction_mode", &interaction_mode);
    }

    Ok(url.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[tokio::test]
    async fn test_generate_signin_uri() {
        let generated_uri = generate_signin_uri(SignInUriGenerationOptions {
            authorization_endpoint: "http://logto.dev/oidc/sign-in".to_string(),
            client_id: "clientId".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            code_challenge: "codeChallenge".to_string(),
            state: "state".to_string(),
            scopes: None,
            resources: None,
            prompt: None,
            interaction_mode: None,
        });

        if let Ok(uri) = generated_uri {
            let url = Url::parse(uri.as_str());
            if let Ok(parsed_url) = url {
                let params: HashMap<String, String> =
                    parsed_url.query_pairs().into_owned().collect();

                let expected_params: HashMap<String, String> = [
                    ("client_id".to_string(), "clientId".to_string()),
                    (
                        "redirect_uri".to_string(),
                        "https://example.com/callback".to_string(),
                    ),
                    ("code_challenge".to_string(), "codeChallenge".to_string()),
                    ("code_challenge_method".to_string(), "S256".to_string()),
                    ("response_type".to_string(), "code".to_string()),
                    ("state".to_string(), "state".to_string()),
                    (
                        "scope".to_string(),
                        "offline_access openid profile".to_string(),
                    ),
                    ("prompt".to_string(), "consent".to_string()),
                ]
                .into_iter()
                .collect();

                assert_eq!(params, expected_params)
            }
        }
    }

    #[tokio::test]
    async fn test_generate_signin_uri_with_optionals() {
        let generated_uri = generate_signin_uri(SignInUriGenerationOptions {
            authorization_endpoint: "http://logto.dev/oidc/sign-in".to_string(),
            client_id: "clientId".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            code_challenge: "codeChallenge".to_string(),
            state: "state".to_string(),
            scopes: Some(vec![UserScopes::Email.as_str().to_owned()]),
            resources: Some(vec!["resource1".to_string(), "resource2".to_string()]),
            prompt: Some("login".to_string()),
            interaction_mode: None,
        });

        if let Ok(uri) = generated_uri {
            let url = Url::parse(uri.as_str());
            if let Ok(parsed_url) = url {
                let params: HashMap<String, String> =
                    parsed_url.query_pairs().into_owned().collect();

                let expected_params: HashMap<String, String> = [
                    ("client_id".to_string(), "clientId".to_string()),
                    (
                        "redirect_uri".to_string(),
                        "https://example.com/callback".to_string(),
                    ),
                    ("code_challenge".to_string(), "codeChallenge".to_string()),
                    ("code_challenge_method".to_string(), "S256".to_string()),
                    ("response_type".to_string(), "code".to_string()),
                    ("state".to_string(), "state".to_string()),
                    (
                        "scope".to_string(),
                        "email offline_access openid profile".to_string(),
                    ),
                    ("resource".to_string(), "resource1 resource2".to_string()),
                    ("prompt".to_string(), "login".to_string()),
                ]
                .into_iter()
                .collect();

                assert_eq!(params, expected_params)
            }
        }
    }

    #[tokio::test]
    async fn test_generate_signin_uri_with_interaction_mode() {
        let generated_uri = generate_signin_uri(SignInUriGenerationOptions {
            authorization_endpoint: "http://logto.dev/oidc/sign-in".to_string(),
            client_id: "clientId".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            code_challenge: "codeChallenge".to_string(),
            state: "state".to_string(),
            scopes: None,
            resources: None,
            prompt: None,
            interaction_mode: Some("signUp".to_string()),
        });

        if let Ok(uri) = generated_uri {
            let url = Url::parse(uri.as_str());
            if let Ok(parsed_url) = url {
                let params: HashMap<String, String> =
                    parsed_url.query_pairs().into_owned().collect();

                let expected_params: HashMap<String, String> = [
                    ("client_id".to_string(), "clientId".to_string()),
                    (
                        "redirect_uri".to_string(),
                        "https://example.com/callback".to_string(),
                    ),
                    ("code_challenge".to_string(), "codeChallenge".to_string()),
                    ("code_challenge_method".to_string(), "S256".to_string()),
                    ("response_type".to_string(), "code".to_string()),
                    ("state".to_string(), "state".to_string()),
                    (
                        "scope".to_string(),
                        "offline_access openid profile".to_string(),
                    ),
                    ("prompt".to_string(), "consent".to_string()),
                    ("interaction_mode".to_string(), "signUp".to_string()),
                ]
                .into_iter()
                .collect();

                assert_eq!(params, expected_params)
            }
        }
    }
}
