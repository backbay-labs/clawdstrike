//! Differential tests: cycle detection.
//!
//! Compares the reference specification's cycle/depth checking against the
//! production `clawdstrike::core::check_extends_cycle` on random scenarios.

use formal_diff_tests::generators::{
    arb_cycle_present_scenario, arb_cycle_scenario, arb_key, arb_visited_set,
};
use formal_diff_tests::harness::cycle_results_match;
use formal_diff_tests::spec::{check_extends_cycle_spec, MAX_DEPTH_SPEC};

use clawdstrike::core::{check_extends_cycle, CycleCheckResult, MAX_POLICY_EXTENDS_DEPTH};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

/// Read case count from `PROPTEST_CASES` env var, falling back to the given default.
fn case_count(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Build a `ProptestConfig` with the env-driven case count and tuned shrinking.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: case_count(256),
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

// ===========================================================================
// Differential tests: spec vs. impl
// ===========================================================================

proptest! {
    #![proptest_config(config())]
    /// Core differential test: cycle detection produces the same result.
    #[test]
    fn cycle_check_spec_matches_impl(
        (key, visited, depth) in arb_cycle_scenario()
    ) {
        let spec_result = check_extends_cycle_spec(&key, &visited, depth);
        let impl_result = check_extends_cycle(&key, &visited, depth);

        prop_assert!(
            cycle_results_match(&spec_result, &impl_result),
            "Cycle check mismatch!\n  key: {:?}\n  visited: {:?}\n  depth: {}\n  spec: {:?}\n  impl: {:?}",
            key, visited, depth, spec_result, impl_result
        );
    }

    /// Differential test specifically for cases where the key IS in visited.
    #[test]
    fn cycle_detected_matches(
        (key, visited, depth) in arb_cycle_present_scenario()
    ) {
        let spec_result = check_extends_cycle_spec(&key, &visited, depth);
        let impl_result = check_extends_cycle(&key, &visited, depth);

        prop_assert!(
            cycle_results_match(&spec_result, &impl_result),
            "Cycle-present check mismatch!\n  key: {:?}\n  visited: {:?}\n  depth: {}\n  spec: {:?}\n  impl: {:?}",
            key, visited, depth, spec_result, impl_result
        );
    }
}

// ===========================================================================
// Property tests: algebraic properties of cycle detection
// ===========================================================================

proptest! {
    #![proptest_config(config())]
    /// P1: Constants agree between spec and impl.
    #[test]
    fn max_depth_constants_agree(_dummy in 0u8..1) {
        prop_assert_eq!(MAX_DEPTH_SPEC, MAX_POLICY_EXTENDS_DEPTH);
    }

    /// P2: Fresh key at zero depth is always Ok.
    #[test]
    fn fresh_key_at_zero_is_ok(key in arb_key()) {
        let visited = std::collections::HashSet::new();
        let result = check_extends_cycle(&key, &visited, 0);
        prop_assert_eq!(result, CycleCheckResult::Ok);
    }

    /// P3: Any depth > MAX is DepthExceeded, regardless of visited set.
    #[test]
    fn depth_over_max_always_exceeds(
        key in arb_key(),
        visited in arb_visited_set(),
        extra in 1usize..100,
    ) {
        let depth = MAX_POLICY_EXTENDS_DEPTH + extra;
        let result = check_extends_cycle(&key, &visited, depth);
        match result {
            CycleCheckResult::DepthExceeded { depth: d, limit: l } => {
                prop_assert_eq!(d, depth);
                prop_assert_eq!(l, MAX_POLICY_EXTENDS_DEPTH);
            }
            other => prop_assert!(false, "Expected DepthExceeded, got {:?}", other),
        }
    }

    /// P4: Depth exactly at MAX is Ok (boundary test).
    #[test]
    fn depth_at_max_is_ok(key in arb_key()) {
        let visited = std::collections::HashSet::new();
        let result = check_extends_cycle(&key, &visited, MAX_POLICY_EXTENDS_DEPTH);
        prop_assert_eq!(result, CycleCheckResult::Ok);
    }

    /// P5: Key already visited (at valid depth) is CycleDetected.
    #[test]
    fn visited_key_detected((key, visited, depth) in arb_cycle_present_scenario()) {
        // depth is guaranteed <= MAX_POLICY_EXTENDS_DEPTH by the generator.
        let result = check_extends_cycle(&key, &visited, depth);
        match result {
            CycleCheckResult::CycleDetected { key: k } => {
                prop_assert_eq!(k, key);
            }
            other => prop_assert!(false, "Expected CycleDetected, got {:?}", other),
        }
    }

    /// P6: Key NOT in visited set, at valid depth, is Ok.
    #[test]
    fn unvisited_key_ok(
        visited in arb_visited_set(),
        depth in 0usize..=32,
    ) {
        // Construct a key that is definitely not in the visited set.
        let key = format!("unique_{}_never_visited.yaml", depth);
        let result = check_extends_cycle(&key, &visited, depth);
        prop_assert_eq!(result, CycleCheckResult::Ok);
    }

    /// P7: Depth check takes priority over cycle check.
    /// When depth > MAX AND key is in visited, depth should win (it is checked first).
    #[test]
    fn depth_check_priority(
        (key, visited, _depth) in arb_cycle_present_scenario(),
    ) {
        let deep = MAX_POLICY_EXTENDS_DEPTH + 1;
        let result = check_extends_cycle(&key, &visited, deep);
        // Depth check happens first in the implementation.
        match result {
            CycleCheckResult::DepthExceeded { .. } => { /* correct */ }
            other => prop_assert!(
                false,
                "Expected DepthExceeded when depth > MAX, got {:?}",
                other
            ),
        }
    }

    /// P8: Adding keys to visited never causes a previously-Ok check to become
    /// DepthExceeded (visited set doesn't affect depth).
    #[test]
    fn visited_growth_doesnt_affect_depth(
        key in arb_key(),
        base_visited in arb_visited_set(),
        extra_keys in prop::collection::vec(arb_key(), 0..5),
        depth in 0usize..=32,
    ) {
        // Skip if key is already visited.
        if base_visited.contains(&key) || extra_keys.contains(&key) {
            return Ok(());
        }

        let result_before = check_extends_cycle(&key, &base_visited, depth);

        let mut bigger_visited = base_visited;
        for k in extra_keys {
            bigger_visited.insert(k);
        }
        // Make sure our key is still not in there.
        bigger_visited.remove(&key);

        let result_after = check_extends_cycle(&key, &bigger_visited, depth);

        // Both should be Ok (key not visited, depth within range).
        prop_assert_eq!(result_before, CycleCheckResult::Ok);
        prop_assert_eq!(result_after, CycleCheckResult::Ok);
    }
}
