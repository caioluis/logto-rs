use josekit::jwt::JwtPayload;
use jsonwebtoken::{decode, errors::Error, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub aud: String,
    pub exp: u128,
    pub iat: u128,
    pub iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

impl IdTokenClaims {
    pub fn to_payload(&self) -> JwtPayload {
        let value = serde_json::to_value(self).unwrap();
        JwtPayload::from_map(value.as_object().unwrap().clone()).unwrap()
    }
}

fn decode_id_token(token: &str) -> Result<IdTokenClaims, Error> {
    let key = DecodingKey::from_secret(&[]);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.insecure_disable_signature_validation();

    match decode::<IdTokenClaims>(&token, &key, &validation) {
        Ok(decoded_token) => Ok(decoded_token.claims),
        Err(e) => Err(e),
    }
}

// TODO: improve testing add more cases for other types of error

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn decode_valid_jwt() {
        use openssl::rsa::Rsa;

        let rsa = Rsa::generate(2048).unwrap();

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_der(&rsa.private_key_to_der().unwrap()[..]);

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let expected_claims = IdTokenClaims {
            sub: "bar".to_string(),
            iss: "foo".to_string(),
            aud: "qux".to_string(),
            exp: (since_the_epoch + Duration::from_millis(2000)).as_millis(),
            iat: 1000,
            at_hash: None,
            username: None,
            name: None,
            avatar: None,
        };

        let token_str = encode(&header, &expected_claims, &key);
        match token_str {
            Ok(token_string) => {
                let access_token = decode_id_token(&token_string);
                match access_token {
                    Ok(claims) => {
                        assert_eq!(claims, expected_claims)
                    }
                    Err(e) => println!("Error:{}", e),
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    }

    #[test]
    fn fail_decode_invalid_jwt() {
        assert!(decode_id_token("invalidToken").is_err())
    }

    #[test]
    fn fail_decode_valid_jwt_wrong_payload() {
        assert!(decode_id_token("part1.invalidPayload.part3").is_err())
    }
}
