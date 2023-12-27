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
    if !params.callback_uri.starts_with(&params.redirect_uri) {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Callback URI does not start with redirect URI",
        )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_verify_and_parse_code_from_callback_uri() -> Result<()> {
        let params = UnverifiedUris {
            callback_uri: "http://example.com/callback?state=123456&code=abcdef".to_string(),
            redirect_uri: "http://example.com/callback".to_string(),
            state: "123456".to_string(),
        };

        let result = verify_and_parse_code_from_callback_uri(params).unwrap_or_default();

        assert_eq!(result, "abcdef");

        Ok(())
    }

    #[test]
    fn wrong_uri_test_verify_and_parse_code_from_callback_uri() {
        let params = UnverifiedUris {
            callback_uri: "http://example.com/callback?state=123456&code=abcdef".to_string(),
            redirect_uri: "http://example.com/redirect".to_string(),
            state: "123456".to_string(),
        };

        let result = verify_and_parse_code_from_callback_uri(params);

        match result {
            Ok(_) => panic!("Expected error but got ok"),
            Err(e) => assert_eq!(
                &*e.to_string(),
                "Callback URI does not start with redirect URI"
            ),
        }
    }

    #[test]
    fn callback_uri_with_error() -> Result<()> {
        let params = UnverifiedUris {
            callback_uri: "http://example.com/callback?state=123456&code=abcdef&error=some_error"
                .to_string(),
            redirect_uri: "http://example.com/callback".to_string(),
            state: "123456".to_string(),
        };

        let result = verify_and_parse_code_from_callback_uri(params);

        match result {
            Ok(_) => panic!("Expected error but got ok"),
            Err(e) => assert_eq!(&*e.to_string(), "uri contains error"),
        }

        Ok(())
    }

    #[test]
    fn callback_uri_without_state() -> Result<()> {
        let params = UnverifiedUris {
            callback_uri: "http://example.com/callback?code=abcdef".to_string(),
            redirect_uri: "http://example.com/callback".to_string(),
            state: "123456".to_string(),
        };

        let result = verify_and_parse_code_from_callback_uri(params);

        match result {
            Ok(_) => panic!("Expected error but got ok"),
            Err(e) => assert_eq!(&*e.to_string(), "states don't match"),
        }

        Ok(())
    }

    #[test]
    fn callback_uri_with_mismatched_state() -> Result<()> {
        let params = UnverifiedUris {
            callback_uri: "http://example.com/callback?state=wrong&code=abcdef".to_string(),
            redirect_uri: "http://example.com/callback".to_string(),
            state: "123456".to_string(),
        };

        let result = verify_and_parse_code_from_callback_uri(params);

        match result {
            Ok(_) => panic!("Expected error but got ok"),
            Err(e) => assert_eq!(&*e.to_string(), "states don't match"),
        }

        Ok(())
    }

    #[test]
    fn callback_uri_without_code() -> Result<()> {
        let params = UnverifiedUris {
            callback_uri: "http://example.com/callback?state=123456".to_string(),
            redirect_uri: "http://example.com/callback".to_string(),
            state: "123456".to_string(),
        };

        let result = verify_and_parse_code_from_callback_uri(params);

        match result {
            Ok(_) => panic!("Expected error but got ok"),
            Err(e) => assert_eq!(&*e.to_string(), "code parameter is missing"),
        }

        Ok(())
    }
}
