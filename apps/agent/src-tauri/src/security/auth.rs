use subtle::ConstantTimeEq;

/// Constant-time equality for byte slices.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

/// Constant-time equality for authentication tokens.
pub fn constant_time_eq_token(candidate: &str, expected: &str) -> bool {
    constant_time_eq(candidate.as_bytes(), expected.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_inputs() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq_token("token", "token"));
    }

    #[test]
    fn constant_time_eq_rejects_different_inputs() {
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq_token("token-a", "token-b"));
    }

    #[test]
    fn constant_time_eq_rejects_large_length_mismatches() {
        assert!(!constant_time_eq(&vec![0u8; 256], &vec![0u8; 512]));
    }
}
