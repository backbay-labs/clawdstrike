#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct VersionCase {
    name: String,
    version: String,
    supported: bool,
    #[serde(default)]
    error_contains: Option<String>,
}

#[test]
fn receipt_version_vectors() {
    let cases: Vec<VersionCase> = serde_json::from_str(include_str!(
        "../../../fixtures/receipts/version_cases.json"
    ))
    .expect("valid version_cases.json");

    let mut seen = HashSet::with_capacity(cases.len());

    for case in cases {
        assert!(
            seen.insert(case.name.clone()),
            "duplicate case name: {}",
            case.name
        );

        let result = hush_core::receipt::validate_receipt_version(&case.version);

        if case.supported {
            assert!(
                result.is_ok(),
                "case {} expected Ok, got {:?}",
                case.name,
                result
            );
            continue;
        }

        let err = result.unwrap_err();
        let err_s = err.to_string();
        let needle = case.error_contains.as_deref().unwrap_or("receipt version");
        assert!(
            err_s.contains(needle),
            "case {} expected error containing {:?}, got {:?}",
            case.name,
            needle,
            err_s
        );
    }
}
