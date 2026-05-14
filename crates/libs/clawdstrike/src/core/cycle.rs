//! Cycle/depth detection for policy `extends` chains (no serde, no I/O).

use std::collections::HashSet;

pub const MAX_POLICY_EXTENDS_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CycleCheckResult {
    Ok,
    DepthExceeded { depth: usize, limit: usize },
    CycleDetected { key: String },
}

/// Check whether adding `key` at `depth` is safe. Does not mutate `visited`;
/// the caller must insert on success.
#[must_use]
pub fn check_extends_cycle(key: &str, visited: &HashSet<String>, depth: usize) -> CycleCheckResult {
    if depth > MAX_POLICY_EXTENDS_DEPTH {
        return CycleCheckResult::DepthExceeded {
            depth,
            limit: MAX_POLICY_EXTENDS_DEPTH,
        };
    }

    if visited.contains(key) {
        return CycleCheckResult::CycleDetected {
            key: key.to_string(),
        };
    }

    CycleCheckResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_visit_is_ok() {
        let visited = HashSet::new();
        assert_eq!(
            check_extends_cycle("base.yaml", &visited, 0),
            CycleCheckResult::Ok
        );
    }

    #[test]
    fn depth_exceeded() {
        let visited = HashSet::new();
        let result = check_extends_cycle("deep.yaml", &visited, MAX_POLICY_EXTENDS_DEPTH + 1);
        assert_eq!(
            result,
            CycleCheckResult::DepthExceeded {
                depth: MAX_POLICY_EXTENDS_DEPTH + 1,
                limit: MAX_POLICY_EXTENDS_DEPTH,
            }
        );
    }

    #[test]
    fn cycle_detected() {
        let mut visited = HashSet::new();
        visited.insert("a.yaml".to_string());
        visited.insert("b.yaml".to_string());

        let result = check_extends_cycle("a.yaml", &visited, 2);
        assert_eq!(
            result,
            CycleCheckResult::CycleDetected {
                key: "a.yaml".to_string(),
            }
        );
    }

    #[test]
    fn no_cycle_different_key() {
        let mut visited = HashSet::new();
        visited.insert("a.yaml".to_string());
        visited.insert("b.yaml".to_string());

        assert_eq!(
            check_extends_cycle("c.yaml", &visited, 2),
            CycleCheckResult::Ok
        );
    }

    #[test]
    fn depth_zero_is_ok() {
        let visited = HashSet::new();
        assert_eq!(
            check_extends_cycle("root.yaml", &visited, 0),
            CycleCheckResult::Ok
        );
    }

    #[test]
    fn depth_exactly_at_limit_is_ok() {
        let visited = HashSet::new();
        assert_eq!(
            check_extends_cycle("edge.yaml", &visited, MAX_POLICY_EXTENDS_DEPTH),
            CycleCheckResult::Ok
        );
    }

    #[test]
    fn depth_one_past_limit_fails() {
        let visited = HashSet::new();
        let result = check_extends_cycle("too_deep.yaml", &visited, MAX_POLICY_EXTENDS_DEPTH + 1);
        assert!(matches!(result, CycleCheckResult::DepthExceeded { .. }));
    }
}
