use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SignInUriGenerationOptions {
    authorization_endpoint: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    state: String,
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
        .append_pair("response_type", RESPONSE_TYPE);

    Ok(url.as_str().to_owned())
}
