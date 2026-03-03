/// Constant-time equality for byte slices.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for i in 0..max_len {
        let l = *left.get(i).unwrap_or(&0u8);
        let r = *right.get(i).unwrap_or(&0u8);
        diff |= usize::from(l ^ r);
    }

    diff == 0
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
