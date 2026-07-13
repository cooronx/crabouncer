use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub(crate) fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub(crate) fn token_matches(token: &str, expected: &[u8]) -> bool {
    let actual = hash_token(token);
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_are_unique_and_url_safe() {
        let first = random_token();
        let second = random_token();
        assert_ne!(first, second);
        assert!(!first.contains(['+', '/', '=']));
    }

    #[test]
    fn token_hash_comparison_rejects_other_values() {
        let expected = hash_token("secret");
        assert!(token_matches("secret", &expected));
        assert!(!token_matches("other", &expected));
    }
}
