use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    decode, decode_header,
    errors::ErrorKind,
    errors::{Error, Result},
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};

use crate::utils::decode_id_token::IdTokenClaims;

struct TokenInfoParameters {
    id_token: String,
    client_id: String,
    issuer: String,
    jwks: JwkSet,
}

// TODO: I need to find a way with the existent libs to
// mock the creation of the JWT and the JWK, so that I can
// be realiable in my testing.
// So far, I've tried with the following crates, but I haven't managed
// to find a solution
//
// jwt, josekit, jwt-simple, jsonwebtokens, jsonwebtoken_rustcrypto, jsonwebkey, aliri

fn verify_id_token(params: TokenInfoParameters) -> Result<()> {
    let header = decode_header(params.id_token.as_str())?;

    let kid = match header.kid {
        Some(k) => k,
        None => return Err(ErrorKind::InvalidToken.into()),
    };

    if let Some(j) = params.jwks.find(&kid) {
        match &j.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();

                let mut validation = Validation::new(Algorithm::RS256);

                validation.set_audience(&[params.client_id.as_str()]);
                validation.set_issuer(&[params.issuer.as_str()]);

                match decode::<IdTokenClaims>(&params.id_token, &decoding_key, &validation) {
                    Ok(token) => {
                        let start = SystemTime::now();
                        let since_the_epoch = start
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards");

                        match token.claims.iat
                            > (since_the_epoch + Duration::from_secs(60)).as_millis()
                            || token.claims.iat
                                < (since_the_epoch - Duration::from_secs(60)).as_millis()
                        {
                            true => return Err(ErrorKind::ExpiredSignature.into()),
                            false => Ok(()),
                        }
                    }
                    Err(_) => return Err(ErrorKind::InvalidSignature.into()),
                }
            }
            _ => unreachable!("This should be a RSA"),
        }
    } else {
        return Err(ErrorKind::InvalidSignature.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWKS: &str = r#"{"keys":[{
        "alg": "RS256",
        "e": "AQAB",
        "key_ops": [
          "verify"
        ],
        "kty": "RSA",
        "n": "wUt6EU-HrrtoTrTO9HUb5b1MWfmty1RoxuUf6v2Zs_zeC0aW39eObic7T6GZyahFnFFMJ6ET7f-V3ZoOa9hgqpHQJDa8UrgHz0sMh2c3iIY-ay2OSbJxtw1dL_RpqMelyv8887o7gRLvtFboJARINqpN1dFXofDhqHa6jliEHJ_gNxalcA540v2_jSNs9Ec7cSsaZ6_XwdwgmOHq10PkGeJv6L9pzvCdFQBtCF_lhx5Obp2W-AUOub5XEAJ-WtgfOrGQudtVl51kt5t0rlk7s-jNyFZNXFhXqDOXnq7kHubJtpvgIS7NHdQUcq59qVzNCG5IFvBSldJpsvQvqOo01w",
        "use": "sig",
        "kid": "416d11167f7781ea24212019b4c0b749"
    }]}"#;

    const JWT: &str = r#"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjQxNmQxMTE2N2Y3NzgxZWEyNDIxMjAxOWI0YzBiNzQ5In0.eyJpc3MiOiJmb28iLCJhdWQiOiJxdXgiLCJzdWIiOiJiYXIiLCJleHAiOjE3MDM2NTk5MzcsImlhdCI6MTcwMzY1OTYzN30.vI_VkJBJCmti5AF82pibpPmvn0vbaB5qf6okgxaBHnyxayKxlObu8ztIqC3YIcKDKZkRS4lo9BKjSZa1KLYvvMM9wSqi0H0DjBzCuDnAMDgH3NzrOmUqyKuLxAT0Hq2mXZruIqkW0CXnVgLhyKI5iGwniUrZqLLPXQ0aVAWzwX-V3pQpMzBZDcw4HTZO1NKtA9fLPdUjqwGt3Wx2Yxwp85VxIy_x8scd2MRylhsTDe116hXM0np7XJwYymhm-ji4RlUqrh0dORU0AXXiUHlLzV-FdM4Vos9iuGDJJd5AoS9CNpoSHmxTDJ2ITJ4DhKzqaXzSxac6aDZGDvlheGBvyA"#;

    #[test]
    fn verify_id_token_works() {
        assert!(verify_id_token(TokenInfoParameters {
            id_token: JWT.to_string(),
            client_id: "qux".to_string(),
            issuer: "foo".to_string(),
            jwks: serde_json::from_str(JWKS).unwrap()
        })
        .is_ok())
    }
}
