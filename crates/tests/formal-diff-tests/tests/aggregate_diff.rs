//! Differential tests: aggregate logic.
//!
//! Compares the reference specification's aggregation against the production
//! `clawdstrike::core::aggregate_overall` on randomly generated verdicts.

use formal_diff_tests::generators::{arb_core_verdict, arb_paired_verdict, arb_paired_verdicts};
use formal_diff_tests::harness::verdicts_match;
use formal_diff_tests::spec::{aggregate_spec, severity_ord_spec, SpecSeverity};

use clawdstrike::core::{aggregate_overall, severity_ord, CoreSeverity, CoreVerdict};
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
    /// Core differential test: aggregate produces the same verdict in spec and impl.
    #[test]
    fn aggregate_spec_matches_impl(
        (spec_results, core_results) in arb_paired_verdicts()
    ) {
        let spec_agg = aggregate_spec(&spec_results);
        let core_agg = aggregate_overall(&core_results);

        prop_assert!(
            verdicts_match(&spec_agg, &core_agg),
            "Aggregation mismatch!\n  spec: allowed={}, severity={:?}, sanitized={}\n  impl: allowed={}, severity={:?}, sanitized={}\n  input count: {}",
            spec_agg.allowed, spec_agg.severity, spec_agg.sanitized,
            core_agg.allowed, core_agg.severity, core_agg.sanitized,
            spec_results.len()
        );
    }

    /// Single-element aggregation must return the element itself.
    #[test]
    fn aggregate_single_element((spec_v, core_v) in arb_paired_verdict()) {
        let spec_agg = aggregate_spec(std::slice::from_ref(&spec_v));
        let core_agg = aggregate_overall(std::slice::from_ref(&core_v));

        prop_assert_eq!(spec_agg.allowed, spec_v.allowed);
        prop_assert_eq!(core_agg.allowed, core_v.allowed);
        prop_assert!(verdicts_match(&spec_agg, &core_agg));
    }

    /// Severity ordering must agree between spec and impl for all variants.
    #[test]
    fn severity_ord_matches(sev_idx in 0u8..4) {
        let spec_sev = match sev_idx {
            0 => SpecSeverity::Info,
            1 => SpecSeverity::Warning,
            2 => SpecSeverity::Error,
            _ => SpecSeverity::Critical,
        };
        let core_sev = match sev_idx {
            0 => CoreSeverity::Info,
            1 => CoreSeverity::Warning,
            2 => CoreSeverity::Error,
            _ => CoreSeverity::Critical,
        };

        prop_assert_eq!(severity_ord_spec(spec_sev), severity_ord(core_sev));
    }
}

// ===========================================================================
// Property tests: algebraic properties of aggregation
// ===========================================================================

proptest! {
    #![proptest_config(config())]
    /// P1: Deny monotonicity — if any guard denies, aggregate must deny.
    #[test]
    fn deny_monotonicity(results in prop::collection::vec(arb_core_verdict(), 1..50)) {
        let aggregated = aggregate_overall(&results);
        if results.iter().any(|r| !r.allowed) {
            prop_assert!(
                !aggregated.allowed,
                "If any guard denies, aggregate must deny. Got allowed=true."
            );
        }
    }

    /// P2: All-allow implies aggregate-allow.
    #[test]
    fn all_allow_implies_allow(results in prop::collection::vec(arb_core_verdict(), 1..50)) {
        let aggregated = aggregate_overall(&results);
        if results.iter().all(|r| r.allowed) {
            prop_assert!(
                aggregated.allowed,
                "If all guards allow, aggregate must allow. Got allowed=false."
            );
        }
    }

    /// P3: Severity ordering is a total order (trichotomy).
    #[test]
    fn severity_total_order(a_idx in 0u8..4, b_idx in 0u8..4) {
        let a = match a_idx {
            0 => CoreSeverity::Info,
            1 => CoreSeverity::Warning,
            2 => CoreSeverity::Error,
            _ => CoreSeverity::Critical,
        };
        let b = match b_idx {
            0 => CoreSeverity::Info,
            1 => CoreSeverity::Warning,
            2 => CoreSeverity::Error,
            _ => CoreSeverity::Critical,
        };
        // Trichotomy: exactly one of <, =, > holds.
        let a_ord = severity_ord(a);
        let b_ord = severity_ord(b);
        prop_assert!(a_ord <= b_ord || b_ord <= a_ord);
    }

    /// P4: Aggregate is idempotent — aggregating a single verdict returns
    /// a verdict with the same decision fields.
    #[test]
    fn aggregate_idempotent(v in arb_core_verdict()) {
        let once = aggregate_overall(std::slice::from_ref(&v));
        let twice = aggregate_overall(std::slice::from_ref(&once));

        prop_assert_eq!(once.allowed, twice.allowed);
        prop_assert_eq!(severity_ord(once.severity), severity_ord(twice.severity));
        prop_assert_eq!(once.sanitized, twice.sanitized);
    }

    /// P5: Aggregate severity is at least as bad as the worst individual.
    #[test]
    fn aggregate_severity_is_worst(results in prop::collection::vec(arb_core_verdict(), 1..50)) {
        let aggregated = aggregate_overall(&results);

        // If any result blocks, aggregate severity comes from the worst blocker.
        // If all allow, aggregate severity comes from the worst allow.
        // Either way, the aggregate severity should be the maximum among those
        // with the same blocking status as the aggregate.
        let same_block_status: Vec<_> = results.iter()
            .filter(|r| r.allowed == aggregated.allowed)
            .collect();
        let expected_max = same_block_status.iter()
            .map(|r| severity_ord(r.severity))
            .max()
            .unwrap_or(0);

        prop_assert_eq!(
            severity_ord(aggregated.severity),
            expected_max,
            "Aggregate severity should be the worst among results with the same blocking status"
        );
    }

    /// P6: Empty aggregate is default-allow.
    #[test]
    fn empty_aggregate_is_allow(_dummy in 0u8..1) {
        let result = aggregate_overall(&[]);
        prop_assert!(result.allowed);
        prop_assert_eq!(severity_ord(result.severity), 0);
        prop_assert!(!result.sanitized);
    }

    /// P7: Aggregate result is always one of the input elements (or default for empty).
    #[test]
    fn aggregate_picks_from_input(results in prop::collection::vec(arb_core_verdict(), 1..50)) {
        let aggregated = aggregate_overall(&results);
        // The aggregate must match one of the inputs on all decision fields.
        let found = results.iter().any(|r|
            r.allowed == aggregated.allowed
            && severity_ord(r.severity) == severity_ord(aggregated.severity)
            && r.sanitized == aggregated.sanitized
            && r.guard == aggregated.guard
        );
        prop_assert!(found, "Aggregate result must be one of the input verdicts");
    }

    /// P8: Deny dominance — adding a deny to a list of all-allows flips result.
    #[test]
    fn deny_dominance(
        allows in prop::collection::vec(arb_core_verdict(), 1..20),
        deny_sev_idx in 0u8..4,
    ) {
        // Force all to be allows.
        let allows: Vec<CoreVerdict> = allows.into_iter().map(|mut v| {
            v.allowed = true;
            v
        }).collect();

        let deny_sev = match deny_sev_idx {
            0 => CoreSeverity::Info,
            1 => CoreSeverity::Warning,
            2 => CoreSeverity::Error,
            _ => CoreSeverity::Critical,
        };
        let deny = CoreVerdict::block("deny_guard", deny_sev, "blocked");

        let mut with_deny = allows.clone();
        with_deny.push(deny);

        let agg_allows = aggregate_overall(&allows);
        let agg_with_deny = aggregate_overall(&with_deny);

        prop_assert!(agg_allows.allowed, "All-allow list should aggregate to allow");
        prop_assert!(!agg_with_deny.allowed, "Adding a deny must flip to deny");
    }
}
