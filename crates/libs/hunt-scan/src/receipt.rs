//! Signed scan receipt generation using `hush-core`.
//!
//! Each `hunt scan` invocation produces an Ed25519-signed receipt that attests
//! to the scan results. The receipt contains the SHA-256 hash of the canonical
//! JSON serialization of the scan data, plus optional policy metadata.

use hush_core::{sha256, Hash, Keypair, Provenance, Receipt, SignedReceipt, Verdict};
use serde::{Deserialize, Serialize};

use crate::models::ScanPathResult;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced when building or signing a scan receipt.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Signing error: {0}")]
    Signing(String),
}

impl From<hush_core::Error> for ReceiptError {
    fn from(e: hush_core::Error) -> Self {
        ReceiptError::Signing(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Receipt content
// ---------------------------------------------------------------------------

/// The logical content of a hunt scan receipt, serialized as the receipt's
/// metadata so that verifiers can reconstruct what was attested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntScanReceiptContent {
    pub command: &'static str,
    pub scan_results: Vec<ScanPathResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign a scan receipt over the given results.
///
/// 1. Builds a [`HuntScanReceiptContent`] from the scan results.
/// 2. Serialises it to JSON and computes a SHA-256 content hash.
/// 3. Determines the overall verdict (pass = no issues found).
/// 4. Creates a `hush_core::Receipt` and signs it with the provided keypair.
fn scan_error_is_failure(error: &crate::models::ScanError) -> bool {
    error.is_failure
        || error
            .category
            .as_ref()
            .is_some_and(crate::models::ErrorCategory::is_failure)
}

fn result_has_failure(result: &ScanPathResult) -> bool {
    result.error.as_ref().is_some_and(scan_error_is_failure)
        || result.servers.as_ref().is_some_and(|servers| {
            servers
                .iter()
                .any(|server| server.error.as_ref().is_some_and(scan_error_is_failure))
        })
}

pub fn sign_scan_receipt(
    results: &[ScanPathResult],
    keypair: &Keypair,
    policy_ref: Option<&str>,
) -> Result<SignedReceipt, ReceiptError> {
    let now = chrono::Utc::now();

    let content = HuntScanReceiptContent {
        command: "hunt scan",
        scan_results: results.to_vec(),
        policy_ref: policy_ref.map(|s| s.to_string()),
        timestamp: now,
    };

    // Serialize and hash.
    let json_bytes = serde_json::to_vec(&content)?;
    let content_hash: Hash = sha256(&json_bytes);

    // Determine verdict: fail on issues, policy violations, or scan failures.
    let has_issues = results.iter().any(|r| !r.issues.is_empty());
    let has_policy_violations = results.iter().any(|r| !r.policy_violations.is_empty());
    let has_failures = results.iter().any(result_has_failure);
    let verdict = if has_issues || has_policy_violations || has_failures {
        Verdict::fail_with_gate("hunt-scan")
    } else {
        Verdict::pass_with_gate("hunt-scan")
    };

    // Build provenance.
    let provenance = Provenance {
        clawdstrike_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        provider: Some("hunt-scan".to_string()),
        policy_hash: None,
        ruleset: policy_ref.map(|s| s.to_string()),
        violations: vec![],
    };

    let receipt = Receipt::new(content_hash, verdict)
        .with_provenance(provenance)
        .with_metadata(serde_json::to_value(&content)?);

    // Sign.
    let signed = SignedReceipt::sign(receipt, keypair)?;

    Ok(signed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::receipt::PublicKeySet;

    fn make_scan_result(path: &str, issue_count: usize) -> ScanPathResult {
        let issues = (0..issue_count)
            .map(|i| crate::models::Issue {
                code: format!("TEST_{i}"),
                message: format!("Test issue {i}"),
                reference: None,
                extra_data: None,
            })
            .collect();
        ScanPathResult {
            client: None,
            path: path.to_string(),
            servers: None,
            issues,
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }
    }

    #[test]
    fn test_sign_scan_receipt_no_issues() {
        let keypair = Keypair::generate();
        let results = vec![make_scan_result("/test/config.json", 0)];

        let signed = sign_scan_receipt(&results, &keypair, None).unwrap();

        // Verify signature.
        let keys = PublicKeySet::new(keypair.public_key());
        let vr = signed.verify(&keys);
        assert!(vr.valid);

        // Verdict should be passing.
        assert!(signed.receipt.verdict.passed);
        assert_eq!(signed.receipt.verdict.gate_id.as_deref(), Some("hunt-scan"));
    }

    #[test]
    fn test_sign_scan_receipt_with_issues() {
        let keypair = Keypair::generate();
        let results = vec![make_scan_result("/test/config.json", 2)];

        let signed = sign_scan_receipt(&results, &keypair, Some("strict")).unwrap();

        let keys = PublicKeySet::new(keypair.public_key());
        let vr = signed.verify(&keys);
        assert!(vr.valid);

        // Verdict should be failing.
        assert!(!signed.receipt.verdict.passed);
    }

    #[test]
    fn test_sign_scan_receipt_with_policy_violations_fails() {
        let keypair = Keypair::generate();
        let mut result = make_scan_result("/test/config.json", 0);
        result
            .policy_violations
            .push(crate::analysis::PolicyViolation {
                guard: "mcp_tool".to_string(),
                tool_name: "shell_exec".to_string(),
                allowed: false,
                severity: "error".to_string(),
                message: "Tool blocked by policy".to_string(),
            });

        let signed = sign_scan_receipt(&[result], &keypair, Some("strict")).unwrap();
        assert!(!signed.receipt.verdict.passed);
    }

    #[test]
    fn test_sign_scan_receipt_with_failure_error_fails() {
        let keypair = Keypair::generate();
        let mut result = make_scan_result("/test/config.json", 0);
        result.error = Some(crate::models::ScanError::server_startup(
            "failed to start",
            None,
        ));

        let signed = sign_scan_receipt(&[result], &keypair, None).unwrap();
        assert!(!signed.receipt.verdict.passed);
    }

    #[test]
    fn test_sign_scan_receipt_with_policy_ref() {
        let keypair = Keypair::generate();
        let results = vec![make_scan_result("/cfg.json", 0)];

        let signed = sign_scan_receipt(&results, &keypair, Some("ai-agent")).unwrap();

        let prov = signed.receipt.provenance.as_ref().unwrap();
        assert_eq!(prov.ruleset.as_deref(), Some("ai-agent"));
    }

    #[test]
    fn test_sign_scan_receipt_deterministic_hash() {
        let keypair = Keypair::generate();
        let results = vec![make_scan_result("/cfg.json", 0)];

        let signed1 = sign_scan_receipt(&results, &keypair, None).unwrap();
        let signed2 = sign_scan_receipt(&results, &keypair, None).unwrap();

        // The content hash should differ because timestamps differ, but both
        // should be valid.
        let keys = PublicKeySet::new(keypair.public_key());
        assert!(signed1.verify(&keys).valid);
        assert!(signed2.verify(&keys).valid);
    }

    #[test]
    fn test_receipt_roundtrip_json() {
        let keypair = Keypair::generate();
        let results = vec![make_scan_result("/cfg.json", 1)];
        let signed = sign_scan_receipt(&results, &keypair, None).unwrap();

        let json = signed.to_json().unwrap();
        let restored = SignedReceipt::from_json(&json).unwrap();

        let keys = PublicKeySet::new(keypair.public_key());
        assert!(restored.verify(&keys).valid);
    }
}
