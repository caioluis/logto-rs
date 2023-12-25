use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
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
    general_purpose::STANDARD.encode(
        rand::thread_rng()
            .sample_iter::<char, _>(rand::distributions::Standard)
            .take(64)
            .collect::<String>(),
    )
}
