#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct CanonicalVector {
    name: String,
    input: serde_json::Value,
    expected: String,
}

#[test]
fn canonical_json_golden_vectors() {
    let vectors: Vec<CanonicalVector> =
        serde_json::from_str(include_str!("../../../fixtures/canonical/jcs_vectors.json"))
            .expect("valid vector json");

    let mut seen = HashSet::with_capacity(vectors.len());

    for vector in vectors {
        assert!(
            seen.insert(vector.name.clone()),
            "duplicate vector name: {}",
            vector.name
        );

        let got = hush_core::canonical::canonicalize(&vector.input)
            .unwrap_or_else(|e| panic!("vector {} failed: {}", vector.name, e));

        // Ensure the output is still valid JSON.
        serde_json::from_str::<serde_json::Value>(&got)
            .unwrap_or_else(|e| panic!("vector {} produced invalid JSON: {}", vector.name, e));

        assert_eq!(got, vector.expected, "vector {}", vector.name);
    }
}
