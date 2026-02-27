use sha2::{Digest, Sha256};

/// Hash a one-time enrollment token for at-rest storage and comparison.
pub fn hash_enrollment_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::hash_enrollment_token;

    #[test]
    fn enrollment_token_hash_is_sha256_hex() {
        let hash = hash_enrollment_token("cset_example");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
