use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    decode, decode_header,
    errors::ErrorKind,
    errors::Result,
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

// // TODO: I need to find a way with the existent libs to
// // mock the creation of the JWT and the JWK, so that I can
// // be realiable in my testing.
// // So far, I've tried with the following crates, but I haven't managed
// // to find a solution
// //
// // jwt, josekit, jwt-simple, jsonwebtokens, jsonwebtoken_rustcrypto, jsonwebkey, aliri

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
                            true => {
                                return Err(ErrorKind::ExpiredSignature.into());
                            }
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
    use josekit::jwk::JwkSet;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use josekit::{
        jwk::alg::rsa::RsaKeyPair,
        jwk::Jwk,
        jws::{alg::rsassa::RsassaJwsAlgorithm::Rs256, JwsHeader},
    };

    use crate::utils::decode_id_token::IdTokenClaims;

    use super::*;

    #[test]
    fn verify_id_token_works() {
        let key_pair: RsaKeyPair = Rs256
            .generate_key_pair(2048)
            .expect("couldn't generate key pair");

        let mut jwk_keypair: Jwk = key_pair.to_jwk_key_pair();
        jwk_keypair.set_key_id("123");
        jwk_keypair.set_algorithm("RS256");

        let mut jwk_public: Jwk = jwk_keypair.to_public_key().unwrap();
        jwk_public.set_key_id("123");
        jwk_public.set_algorithm("RS256");

        let token_signer = Rs256.signer_from_jwk(&jwk_keypair).unwrap();

        let header = {
            let mut value = JwsHeader::new();
            value.set_key_id(jwk_public.key_id().unwrap_or_default());
            value.set_algorithm(key_pair.algorithm().unwrap_or_default());
            value
        };

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let claims = IdTokenClaims {
            sub: "bar".to_string(),
            iss: "foo".to_string(),
            aud: "qux".to_string(),
            exp: (since_the_epoch + Duration::from_millis(2000)).as_millis(),
            iat: (since_the_epoch + Duration::from_millis(100)).as_millis(),
            at_hash: None,
            username: None,
            name: None,
            avatar: None,
        };

        let token =
            josekit::jwt::encode_with_signer(&claims.to_payload(), &header, &token_signer).unwrap();

        let mut initial_map: josekit::Map<String, josekit::Value> = josekit::Map::new();
        initial_map.insert(
            "keys".to_string(),
            josekit::Value::from(Vec::<String>::new()),
        );

        let mut set = JwkSet::from_map(initial_map).unwrap();
        set.push_key(jwk_public);

        assert!(verify_id_token(TokenInfoParameters {
            id_token: token.to_string(),
            client_id: "qux".to_string(),
            issuer: "foo".to_string(),
            jwks: serde_json::from_str(&set.to_string()).unwrap()
        })
        .is_ok())
    }
}
