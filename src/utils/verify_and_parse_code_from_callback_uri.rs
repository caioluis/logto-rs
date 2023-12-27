use std::{collections::HashMap, error::Error};

use reqwest::Url;

struct UnverifiedUris {
    callback_uri: String,
    redirect_uri: String,
    state: String,
}

fn verify_and_parse_code_from_callback_uri(
    params: UnverifiedUris,
) -> Result<String, Box<dyn Error>> {
    if params.callback_uri.starts_with(&params.redirect_uri) {
        return Err("malformed Uri".into());
    }

    let parsed_uri = Url::parse(&params.callback_uri)?;
    let raw_params: HashMap<String, String> = parsed_uri.query_pairs().into_owned().collect();

    let query_params: HashMap<&str, &str> = raw_params
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();

    if query_params.contains_key("error") {
        return Err("uri contains error".into());
    }

    if !query_params.contains_key("state") || query_params.get("state").unwrap().ne(&params.state) {
        return Err("states don't match".into());
    }

    match query_params.get("code") {
        Some(code) => Ok(code.to_string()),
        None => Err("code parameter is missing".into()),
    }
}
