use base64::{engine::general_purpose, Engine as _};
use rand::distributions::{Alphanumeric, DistString};
use sha2::{Digest, Sha256};

fn generate_code_verifier() -> String {
    generate_random_string()
}

fn generate_code_challenge(code_verifier: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&code_verifier.as_bytes());
    let result = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(&result)
}

fn generate_state() -> String {
    generate_random_string()
}

fn generate_random_string() -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(Alphanumeric.sample_string(&mut rand::thread_rng(), 64))
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
        assert!(code.chars().count() < 128)
    }

    #[test]
    fn different_verifier_different_string() {
        let first_verifier = generate_code_verifier();
        let first_challenge = generate_code_challenge(first_verifier);

        let second_verifier = generate_code_verifier();
        let second_challenge = generate_code_challenge(second_verifier);

        assert_ne!(first_challenge, second_challenge)
    }

    #[test]
    fn same_verifier_same_challenge() {
        let code_verifier = generate_code_verifier();

        let first_challenge = generate_code_challenge(code_verifier.clone());
        let second_challenge = generate_code_challenge(code_verifier);

        assert_eq!(first_challenge, second_challenge)
    }

    #[test]
    fn generate_correct_string() {
        assert_eq!(
            generate_code_challenge("tO6MabnMFRAatnlMa1DdSstypzzkgalL1-k8Hr_GdfTj-VXGiEACqAkSkDhFuAuD8FOU8lMishaXjt29Xt2Oww".to_string()),
            "0K3SLeGlNNzFswYJjcVzcN4C76m_8NZORxFJLBJWGwg"
        );
        assert_eq!(
            generate_code_challenge("ipK7uh7F41nJyYY4RZQzEwBwBTd-BlXSO4W8q0tK5VA".to_string()),
            "C51JGVPSnuLTTumLt6X5w2JAL_kBaeqHON3KPIviYaU"
        );
        assert_eq!(
            generate_code_challenge("Á".to_string()),
            "p3yvZiKYauPicLIDZ0W1peDz4Z9KFC-9uxtDfoO1KOQ"
        );
        assert_eq!(
            generate_code_challenge("🚀".to_string()),
            "67wLKHDrMj8rbP-lxJPO74GufrNq_HPU4DZzAWMdrsU"
        );
    }
}
