#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::Receipt;
use serde_json::Value;

#[test]
fn receipt_posture_snapshot_vectors_parse_and_validate() {
    let fixtures: &[(&str, &str, bool)] = &[
        (
            "posture_allow",
            include_str!("../../../fixtures/receipts/posture_allow.json"),
            true,
        ),
        (
            "posture_deny_capability",
            include_str!("../../../fixtures/receipts/posture_deny_capability.json"),
            true,
        ),
        (
            "posture_deny_budget",
            include_str!("../../../fixtures/receipts/posture_deny_budget.json"),
            true,
        ),
        (
            "posture_transition",
            include_str!("../../../fixtures/receipts/posture_transition.json"),
            true,
        ),
        (
            "no_posture_legacy",
            include_str!("../../../fixtures/receipts/no_posture_legacy.json"),
            false,
        ),
    ];

    for (name, raw, has_posture) in fixtures {
        let receipt: Receipt = serde_json::from_str(raw).expect("fixture should parse as receipt");
        receipt
            .validate_version()
            .expect("fixture version should be valid");

        let metadata = receipt.metadata.clone().unwrap_or(Value::Null);
        let posture = metadata.pointer("/clawdstrike/posture");
        assert_eq!(
            posture.is_some(),
            *has_posture,
            "fixture {} posture metadata presence mismatch",
            name
        );

        if *has_posture {
            assert!(
                metadata
                    .pointer("/clawdstrike/posture/state_before")
                    .is_some(),
                "fixture {} missing state_before",
                name
            );
            assert!(
                metadata
                    .pointer("/clawdstrike/posture/state_after")
                    .is_some(),
                "fixture {} missing state_after",
                name
            );
            assert!(
                metadata
                    .pointer("/clawdstrike/posture/budgets_before")
                    .is_some(),
                "fixture {} missing budgets_before",
                name
            );
            assert!(
                metadata
                    .pointer("/clawdstrike/posture/budgets_after")
                    .is_some(),
                "fixture {} missing budgets_after",
                name
            );
            assert!(
                metadata
                    .pointer("/clawdstrike/posture/budget_deltas")
                    .is_some(),
                "fixture {} missing budget_deltas",
                name
            );
        }
    }
}
