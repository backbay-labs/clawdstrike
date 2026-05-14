//! Aggregation logic for guard verdicts (no serde, no I/O).

use super::verdict::{severity_ord, CoreSeverity, CoreVerdict};

/// Select the index of the "winning" (worst) verdict from a non-empty slice.
///
/// Priority: blocking > non-blocking, then higher severity, then sanitized
/// over plain (among allowed results at equal severity).
///
/// Returns `None` if the input slice is empty. Callers with richer types
/// (e.g. `GuardResult`) can use the index to pick the winner from their array.
#[must_use]
pub fn aggregate_index(
    results: &[(bool, CoreSeverity, bool)], // (allowed, severity, sanitized)
) -> Option<usize> {
    if results.is_empty() {
        return None;
    }

    let mut best_idx: usize = 0;
    let mut best = &results[0];

    for (idx, r) in results.iter().enumerate().skip(1) {
        let best_blocks = !best.0;
        let r_blocks = !r.0;

        // Rule 1: blocking beats non-blocking
        if r_blocks && !best_blocks {
            best_idx = idx;
            best = r;
            continue;
        }

        // Rule 2: higher severity wins (within same blocking status)
        if r_blocks == best_blocks && severity_ord(r.1) > severity_ord(best.1) {
            best_idx = idx;
            best = r;
            continue;
        }

        // Rule 3: sanitize tiebreaker (among allowed results at same severity)
        if r_blocks == best_blocks
            && severity_ord(r.1) == severity_ord(best.1)
            && !r_blocks
            && r.2
            && !best.2
        {
            best_idx = idx;
            best = r;
        }
    }

    Some(best_idx)
}

/// Aggregate verdicts into a single overall verdict.
///
/// Returns `CoreVerdict::allow("engine")` if the input slice is empty.
#[must_use]
pub fn aggregate_overall(results: &[CoreVerdict]) -> CoreVerdict {
    let tuples: Vec<(bool, CoreSeverity, bool)> = results
        .iter()
        .map(|v| (v.allowed, v.severity, v.sanitized))
        .collect();

    match aggregate_index(&tuples) {
        Some(idx) => results[idx].clone(),
        None => CoreVerdict::allow("engine"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::verdict::CoreSeverity;

    #[test]
    fn empty_results_returns_allow() {
        let result = aggregate_overall(&[]);
        assert!(result.allowed);
        assert_eq!(result.guard, "engine");
    }

    #[test]
    fn single_allow() {
        let results = vec![CoreVerdict::allow("g1")];
        let overall = aggregate_overall(&results);
        assert!(overall.allowed);
        assert_eq!(overall.guard, "g1");
    }

    #[test]
    fn single_block() {
        let results = vec![CoreVerdict::block("g1", CoreSeverity::Error, "blocked")];
        let overall = aggregate_overall(&results);
        assert!(!overall.allowed);
        assert_eq!(overall.guard, "g1");
    }

    #[test]
    fn block_beats_allow() {
        let results = vec![
            CoreVerdict::allow("g1"),
            CoreVerdict::block("g2", CoreSeverity::Error, "blocked"),
        ];
        let overall = aggregate_overall(&results);
        assert!(!overall.allowed);
        assert_eq!(overall.guard, "g2");
    }

    #[test]
    fn higher_severity_wins() {
        let results = vec![
            CoreVerdict::block("g1", CoreSeverity::Warning, "low"),
            CoreVerdict::block("g2", CoreSeverity::Critical, "high"),
        ];
        let overall = aggregate_overall(&results);
        assert_eq!(overall.guard, "g2");
        assert_eq!(overall.severity, CoreSeverity::Critical);
    }

    #[test]
    fn sanitize_preferred_over_plain_warning_on_tie() {
        let plain = CoreVerdict::warn("warn_guard", "warning only");
        let sanitized = CoreVerdict::sanitize("sanitize_guard", "sanitized content");

        let overall = aggregate_overall(&[plain, sanitized]);

        assert!(overall.allowed);
        assert_eq!(overall.severity, CoreSeverity::Warning);
        assert_eq!(overall.guard, "sanitize_guard");
        assert!(overall.sanitized);
    }

    #[test]
    fn sanitize_not_preferred_when_blocked() {
        // If both block, sanitize flag is irrelevant -- severity wins.
        let block_err = CoreVerdict::block("g1", CoreSeverity::Error, "err");
        let block_crit = CoreVerdict::block("g2", CoreSeverity::Critical, "crit");

        let overall = aggregate_overall(&[block_err, block_crit]);
        assert_eq!(overall.guard, "g2");
    }

    #[test]
    fn block_beats_sanitize_allow() {
        let sanitized = CoreVerdict::sanitize("g1", "sanitized");
        let block = CoreVerdict::block("g2", CoreSeverity::Error, "blocked");

        let overall = aggregate_overall(&[sanitized, block]);
        assert!(!overall.allowed);
        assert_eq!(overall.guard, "g2");
    }

    #[test]
    fn first_result_wins_on_complete_tie() {
        let a = CoreVerdict::allow("g1");
        let b = CoreVerdict::allow("g2");

        let overall = aggregate_overall(&[a, b]);
        assert_eq!(overall.guard, "g1");
    }
}
