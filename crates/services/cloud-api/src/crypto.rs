use sha2::{Digest, Sha256};

/// Hash a one-time enrollment token for at-rest storage and comparison.
///
/// New token format: `cset_<salt>_<secret>` where both components are random.
/// We hash `salt || ":" || secret` so hash precomputation is impractical even
/// if token components become partially predictable in future formats.
///
/// Legacy compatibility: tokens that do not match the new format still hash as
/// plain SHA-256 of the full token string.
pub fn hash_enrollment_token(token: &str) -> String {
    if let Some((salt, secret)) = parse_salted_token(token) {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(b":");
        hasher.update(secret.as_bytes());
        return hex::encode(hasher.finalize());
    }

    legacy_hash(token)
}

fn parse_salted_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix("cset_")?;
    if rest.matches('_').count() != 1 {
        return None;
    }
    let (salt, secret) = rest.split_once('_')?;
    if salt.is_empty() || secret.is_empty() {
        return None;
    }
    Some((salt, secret))
}

fn legacy_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::hash_enrollment_token;
    use sha2::{Digest, Sha256};

    #[test]
    fn enrollment_token_hash_is_sha256_hex() {
        let hash = hash_enrollment_token("cset_example");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn salted_token_hash_changes_when_salt_changes() {
        let hash_a = hash_enrollment_token("cset_salt-a_secret");
        let hash_b = hash_enrollment_token("cset_salt-b_secret");
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn legacy_token_hash_is_still_supported() {
        let token = "csetlegacytokenwithoutseparator";
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let expected = hex::encode(hasher.finalize());
        assert_eq!(hash_enrollment_token(token), expected);
    }

    #[test]
    fn malformed_salted_token_with_extra_separator_uses_legacy_hash() {
        let token = "cset_salt_with_extra_separator_secret";
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let expected = hex::encode(hasher.finalize());
        assert_eq!(hash_enrollment_token(token), expected);
    }
}
