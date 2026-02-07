//! Hash normalization helpers.
//!
//! Spine uses `0x`-prefixed, lowercase hex strings for SHA-256 hashes in
//! envelopes and indexes.

/// Normalize a SHA-256 hash string to `0x`-prefixed, lowercase hex.
///
/// Accepts input with or without a `0x`/`0X` prefix. Returns `None` if the
/// input does not look like a 32-byte hex hash.
pub fn normalize_hash_hex(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let rest = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if rest.len() != 64 {
        return None;
    }
    if !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", rest.to_ascii_lowercase()))
}

/// Build a KV index key for a policy hash.
pub fn policy_index_key(policy_hash: &str) -> Option<String> {
    normalize_hash_hex(policy_hash).map(|h| format!("policy.{h}"))
}

/// Build a subject prefix for receipt verification lookups.
pub fn receipt_verification_prefix(target_envelope_hash: &str) -> Option<String> {
    normalize_hash_hex(target_envelope_hash).map(|h| format!("receipt_verification.{h}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_prefixed() {
        let h = "0xAABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        assert_eq!(
            normalize_hash_hex(h).unwrap(),
            "0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
    }

    #[test]
    fn normalize_accepts_uppercase_prefix() {
        let h = "0XAABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        assert_eq!(
            normalize_hash_hex(h).unwrap(),
            "0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
    }

    #[test]
    fn normalize_accepts_unprefixed() {
        let h = "aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        assert_eq!(
            normalize_hash_hex(h).unwrap(),
            "0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
    }

    #[test]
    fn normalize_rejects_invalid() {
        assert!(normalize_hash_hex("").is_none());
        assert!(normalize_hash_hex("0x1234").is_none());
        assert!(normalize_hash_hex(
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_none());
    }

    #[test]
    fn policy_key_normalizes() {
        let k = policy_index_key(
            "AABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00",
        );
        assert_eq!(
            k.unwrap(),
            "policy.0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
    }

    #[test]
    fn receipt_prefix_normalizes() {
        let k = receipt_verification_prefix(
            "0xAABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00",
        );
        assert_eq!(
            k.unwrap(),
            "receipt_verification.0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00."
        );
    }
}
