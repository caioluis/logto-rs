use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignInUriGenerationOptions<'a> {
    authorization_endpoint: String,
    client_id: &'a str,
    redirect_uri: &'a str,
    code_challenge: &'a str,
    state: &'a str,
    scopes: Option<Vec<&'a str>>,
    resources: Option<Vec<&'a str>>,
    prompt: Option<&'a str>,
    interaction_mode: Option<&'a str>,
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

fn with_default_scopes(mut scopes: Option<Vec<&str>>) -> Vec<&str> {
    let default_scopes: Vec<&str> = vec![
        ReservedScopes::OfflineAccess.as_str(),
        ReservedScopes::OpenId.as_str(),
        UserScopes::Profile.as_str(),
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
        .append_pair("prompt", &options.prompt.unwrap_or("consent"));

    let mut resources = Vec::<&str>::new();
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

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, os::macos::raw};

    use super::*;

    #[tokio::test]
    async fn test_generate_signin_uri() {
        let generated_uri = generate_signin_uri(SignInUriGenerationOptions {
            authorization_endpoint: "http://logto.dev/oidc/sign-in".to_string(),
            client_id: "clientId",
            redirect_uri: "https://example.com/callback",
            code_challenge: "codeChallenge",
            state: "state",
            scopes: None,
            resources: None,
            prompt: None,
            interaction_mode: None,
        });

        if let Ok(uri) = generated_uri {
            let url = Url::parse(uri.as_str());
            if let Ok(parsed_url) = url {
                let raw_params: HashMap<String, String> =
                    parsed_url.query_pairs().into_owned().collect();

                let params: HashMap<&str, &str> = raw_params
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();

                let expected_params: HashMap<&str, &str> = [
                    ("client_id", "clientId"),
                    ("redirect_uri", "https://example.com/callback"),
                    ("code_challenge", "codeChallenge"),
                    ("code_challenge_method", "S256"),
                    ("response_type", "code"),
                    ("state", "state"),
                    ("scope", "offline_access openid profile"),
                    ("prompt", "consent"),
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
            client_id: "clientId",
            redirect_uri: "https://example.com/callback",
            code_challenge: "codeChallenge",
            state: "state",
            scopes: Some(vec![UserScopes::Email.as_str()]),
            resources: Some(vec!["resource1", "resource2"]),
            prompt: Some("login"),
            interaction_mode: None,
        });

        if let Ok(uri) = generated_uri {
            let url = Url::parse(uri.as_str());
            if let Ok(parsed_url) = url {
                let raw_params: HashMap<String, String> =
                    parsed_url.query_pairs().into_owned().collect();

                let params: HashMap<&str, &str> = raw_params
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();

                let expected_params: HashMap<&str, &str> = [
                    ("client_id", "clientId"),
                    ("redirect_uri", "https://example.com/callback"),
                    ("code_challenge", "codeChallenge"),
                    ("code_challenge_method", "S256"),
                    ("response_type", "code"),
                    ("state", "state"),
                    ("scope", "email offline_access openid profile"),
                    ("resource", "resource1 resource2"),
                    ("prompt", "login"),
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
            client_id: "clientId",
            redirect_uri: "https://example.com/callback",
            code_challenge: "codeChallenge",
            state: "state",
            scopes: None,
            resources: None,
            prompt: None,
            interaction_mode: Some("signUp"),
        });

        if let Ok(uri) = generated_uri {
            let url = Url::parse(uri.as_str());
            if let Ok(parsed_url) = url {
                let raw_params: HashMap<String, String> =
                    parsed_url.query_pairs().into_owned().collect();

                let params: HashMap<&str, &str> = raw_params
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();

                let expected_params: HashMap<&str, &str> = [
                    ("client_id", "clientId"),
                    ("redirect_uri", "https://example.com/callback"),
                    ("code_challenge", "codeChallenge"),
                    ("code_challenge_method", "S256"),
                    ("response_type", "code"),
                    ("state", "state"),
                    ("scope", "offline_access openid profile"),
                    ("prompt", "consent"),
                    ("interaction_mode", "signUp"),
                ]
                .into_iter()
                .collect();

                assert_eq!(params, expected_params)
            }
        }
    }
}
