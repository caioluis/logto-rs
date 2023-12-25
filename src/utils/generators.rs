use base64::{engine::general_purpose, Engine as _};
use rand::distributions::{Alphanumeric, DistString};
use sha256::digest;

fn generate_code_verifier() -> String {
    generate_random_string()
}

fn generate_code_challenge(code_verifier: String) -> String {
    general_purpose::STANDARD.encode(digest(code_verifier))
}

fn generate_state() -> String {
    generate_random_string()
}

fn generate_random_string() -> String {
    general_purpose::STANDARD.encode(Alphanumeric.sample_string(&mut rand::thread_rng(), 64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_strings() {
        let first_code = generate_code_verifier();
        let second_code = generate_code_verifier();

        assert_ne!(first_code, second_code)
    }

    #[test]
    fn strings_are_shorter_than_128_characters() {
        let code = generate_code_verifier();
        println!("{}", code);
        assert!(code.chars().count() < 128)
    }
}
