//! Evidence report generation with Merkle-anchored integrity proofs.
//!
//! Builds tamper-evident reports from alerts, timeline events, and IOC matches.
//! Each evidence item is serialized to canonical JSON, hashed, and included in
//! a Merkle tree. The root can be optionally signed with an Ed25519 key.

use std::io::{self, Write};

use chrono::{DateTime, Utc};
use hush_core::merkle::MerkleTree;
use hush_core::signing::{Keypair, PublicKey, Signature};
use hush_core::{canonicalize_json, Hash};
use serde::Serialize;
use serde_json::Value;

use crate::engine::Alert;
use crate::error::{Error, Result};
use crate::ioc::IocMatch;
use hunt_query::timeline::TimelineEvent;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single piece of evidence included in a hunt report.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    /// Positional index within the report.
    pub index: usize,
    /// Source type: `"alert"`, `"event"`, `"ioc_match"`.
    pub source_type: String,
    /// Timestamp of the evidence.
    pub timestamp: DateTime<Utc>,
    /// Human-readable summary.
    pub summary: String,
    /// Full structured data.
    pub data: Value,
}

/// A complete hunt report with Merkle-anchored evidence.
#[derive(Debug, Clone, Serialize)]
pub struct HuntReport {
    /// Report title.
    pub title: String,
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Evidence items (leaves of the Merkle tree).
    pub evidence: Vec<EvidenceItem>,
    /// Hex-encoded Merkle root of the evidence tree.
    pub merkle_root: String,
    /// JSON-serialized Merkle inclusion proofs, one per evidence item.
    pub merkle_proofs: Vec<String>,
    /// Ed25519 signature over the Merkle root (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Hex-encoded public key of the signer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

/// Build a hunt report from evidence items.
///
/// Each item is serialized to canonical JSON (RFC 8785), then included as a
/// Merkle tree leaf. The resulting report contains the tree root and an
/// inclusion proof for every item.
pub fn build_report(title: &str, items: Vec<EvidenceItem>) -> Result<HuntReport> {
    if items.is_empty() {
        return Err(Error::ReportError("no evidence items provided".into()));
    }

    // Serialize each item to canonical JSON bytes.
    let canonical_leaves: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let val = serde_json::to_value(item).map_err(|e| Error::ReportError(e.to_string()))?;
            let canonical =
                canonicalize_json(&val).map_err(|e| Error::ReportError(e.to_string()))?;
            Ok(canonical.into_bytes())
        })
        .collect::<Result<Vec<_>>>()?;

    // Build the Merkle tree.
    let tree = MerkleTree::from_leaves(&canonical_leaves)
        .map_err(|e| Error::ReportError(e.to_string()))?;
    let root = tree.root();

    // Generate inclusion proofs.
    let proofs: Vec<String> = (0..items.len())
        .map(|i| {
            let proof = tree
                .inclusion_proof(i)
                .map_err(|e| Error::ReportError(e.to_string()))?;
            serde_json::to_string(&proof).map_err(|e| Error::ReportError(e.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(HuntReport {
        title: title.to_string(),
        generated_at: Utc::now(),
        evidence: items,
        merkle_root: root.to_hex(),
        merkle_proofs: proofs,
        signature: None,
        signer: None,
    })
}

// ---------------------------------------------------------------------------
// Signing / verification
// ---------------------------------------------------------------------------

/// Sign a report's Merkle root with an Ed25519 key (hex-encoded seed).
pub fn sign_report(report: &mut HuntReport, signing_key_hex: &str) -> Result<()> {
    let keypair =
        Keypair::from_hex(signing_key_hex).map_err(|e| Error::ReportError(e.to_string()))?;
    let root_bytes = hex::decode(&report.merkle_root)
        .map_err(|e| Error::ReportError(format!("invalid merkle_root hex: {e}")))?;
    let sig = keypair.sign(&root_bytes);
    report.signature = Some(sig.to_hex());
    report.signer = Some(keypair.public_key().to_hex());
    Ok(())
}

/// Verify a report's signature and Merkle proofs.
///
/// Returns `true` if:
/// 1. The signature over the Merkle root is valid (if present).
/// 2. Every evidence item's inclusion proof verifies against the root.
pub fn verify_report(report: &HuntReport) -> Result<bool> {
    let root =
        Hash::from_hex(&report.merkle_root).map_err(|e| Error::ReportError(e.to_string()))?;

    // Verify signature if present.  Reject when one of signature/signer is
    // present but the other is missing — that indicates a tampered report.
    match (&report.signature, &report.signer) {
        (Some(sig_hex), Some(pub_hex)) => {
            let pubkey =
                PublicKey::from_hex(pub_hex).map_err(|e| Error::ReportError(e.to_string()))?;
            let sig =
                Signature::from_hex(sig_hex).map_err(|e| Error::ReportError(e.to_string()))?;
            let root_bytes =
                hex::decode(&report.merkle_root).map_err(|e| Error::ReportError(e.to_string()))?;
            if !pubkey.verify(&root_bytes, &sig) {
                return Ok(false);
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            // Mismatched: one field present without the other.
            return Ok(false);
        }
        (None, None) => { /* unsigned report — nothing to verify */ }
    }

    // Verify each evidence item's Merkle proof.
    if report.merkle_proofs.len() != report.evidence.len() {
        return Err(Error::ReportError(
            "proof count does not match evidence count".into(),
        ));
    }

    for (i, item) in report.evidence.iter().enumerate() {
        let val = serde_json::to_value(item).map_err(|e| Error::ReportError(e.to_string()))?;
        let canonical = canonicalize_json(&val).map_err(|e| Error::ReportError(e.to_string()))?;
        let leaf_bytes = canonical.into_bytes();

        let proof: hush_core::MerkleProof = serde_json::from_str(&report.merkle_proofs[i])
            .map_err(|e| Error::ReportError(format!("invalid proof at index {i}: {e}")))?;

        if !proof.verify(&leaf_bytes, &root) {
            return Ok(false);
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Evidence conversion helpers
// ---------------------------------------------------------------------------

/// Convert an [`Alert`] and its bound evidence events into [`EvidenceItem`]s.
///
/// The alert itself becomes one item; each bound event becomes another.
pub fn evidence_from_alert(alert: &Alert, start_index: usize) -> Vec<EvidenceItem> {
    let mut items = Vec::with_capacity(1 + alert.evidence.len());

    items.push(EvidenceItem {
        index: start_index,
        source_type: "alert".to_string(),
        timestamp: alert.triggered_at,
        summary: format!(
            "[{:?}] {}: {}",
            alert.severity, alert.rule_name, alert.title
        ),
        data: serde_json::to_value(alert).unwrap_or(Value::Null),
    });

    for (i, event) in alert.evidence.iter().enumerate() {
        items.push(EvidenceItem {
            index: start_index + 1 + i,
            source_type: "event".to_string(),
            timestamp: event.timestamp,
            summary: format!("[{}] {}", event.source, event.summary),
            data: serde_json::to_value(event).unwrap_or(Value::Null),
        });
    }

    items
}

/// Convert timeline events into [`EvidenceItem`]s.
pub fn evidence_from_events(events: &[TimelineEvent], start_index: usize) -> Vec<EvidenceItem> {
    events
        .iter()
        .enumerate()
        .map(|(i, event)| EvidenceItem {
            index: start_index + i,
            source_type: "event".to_string(),
            timestamp: event.timestamp,
            summary: format!("[{}] {}", event.source, event.summary),
            data: serde_json::to_value(event).unwrap_or(Value::Null),
        })
        .collect()
}

/// Convert IOC matches into [`EvidenceItem`]s.
pub fn evidence_from_ioc_matches(matches: &[IocMatch], start_index: usize) -> Vec<EvidenceItem> {
    matches
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let ioc_names: Vec<&str> = m
                .matched_iocs
                .iter()
                .map(|e| e.indicator.as_str())
                .collect();
            EvidenceItem {
                index: start_index + i,
                source_type: "ioc_match".to_string(),
                timestamp: m.event.timestamp,
                summary: format!(
                    "IOC match in {}: {} ({})",
                    m.match_field,
                    ioc_names.join(", "),
                    m.event.summary,
                ),
                data: serde_json::to_value(m).unwrap_or(Value::Null),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a human-readable text report.
pub fn render_report(report: &HuntReport, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "=== Hunt Report: {} ===", report.title)?;
    writeln!(out, "Generated: {}", report.generated_at.to_rfc3339())?;
    writeln!(out, "Evidence items: {}", report.evidence.len())?;
    writeln!(out, "Merkle root: {}", report.merkle_root)?;

    if let Some(ref signer) = report.signer {
        writeln!(out, "Signed by: {}", signer)?;
    }

    writeln!(out)?;

    for item in &report.evidence {
        writeln!(
            out,
            "  [{}] ({}) {} — {}",
            item.index,
            item.source_type,
            item.timestamp.to_rfc3339(),
            item.summary,
        )?;
    }

    writeln!(out)?;
    Ok(())
}

/// Render the report as JSON.
pub fn render_report_json(report: &HuntReport, out: &mut dyn Write) -> io::Result<()> {
    let json = serde_json::to_string_pretty(report).map_err(io::Error::other)?;
    writeln!(out, "{json}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use hunt_query::query::EventSource;
    use hunt_query::timeline::{NormalizedVerdict, TimelineEventKind};

    use crate::ioc::{IocEntry, IocType};
    use crate::rules::RuleSeverity;

    fn sample_items() -> Vec<EvidenceItem> {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        vec![
            EvidenceItem {
                index: 0,
                source_type: "alert".to_string(),
                timestamp: ts,
                summary: "Suspicious file access".to_string(),
                data: serde_json::json!({"rule": "exfil", "severity": "high"}),
            },
            EvidenceItem {
                index: 1,
                source_type: "event".to_string(),
                timestamp: ts,
                summary: "read /etc/passwd".to_string(),
                data: serde_json::json!({"path": "/etc/passwd"}),
            },
            EvidenceItem {
                index: 2,
                source_type: "ioc_match".to_string(),
                timestamp: ts,
                summary: "IOC match: evil.com".to_string(),
                data: serde_json::json!({"domain": "evil.com"}),
            },
        ]
    }

    fn make_timeline_event(summary: &str, ts: DateTime<Utc>) -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: ts,
            source: EventSource::Receipt,
            kind: TimelineEventKind::GuardDecision,
            verdict: NormalizedVerdict::Deny,
            severity: Some("high".to_string()),
            summary: summary.to_string(),
            process: None,
            namespace: None,
            pod: None,
            action_type: Some("file".to_string()),
            signature_valid: None,
            raw: None,
        }
    }

    #[test]
    fn build_report_with_sample_evidence() {
        let items = sample_items();
        let report = build_report("Test Report", items).unwrap();

        assert_eq!(report.title, "Test Report");
        assert_eq!(report.evidence.len(), 3);
        assert!(!report.merkle_root.is_empty());
        assert_eq!(report.merkle_proofs.len(), 3);
        assert!(report.signature.is_none());
        assert!(report.signer.is_none());
    }

    #[test]
    fn build_report_with_single_item() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let items = vec![EvidenceItem {
            index: 0,
            source_type: "event".to_string(),
            timestamp: ts,
            summary: "single event".to_string(),
            data: serde_json::json!({"key": "value"}),
        }];

        let report = build_report("Single Item Report", items).unwrap();
        assert_eq!(report.evidence.len(), 1);
        assert!(!report.merkle_root.is_empty());
        assert_eq!(report.merkle_proofs.len(), 1);

        // Verify passes.
        assert!(verify_report(&report).unwrap());
    }

    #[test]
    fn build_report_empty_items_errors() {
        let result = build_report("Empty", vec![]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no evidence"), "got: {msg}");
    }

    #[test]
    fn verify_report_passes_unsigned() {
        let items = sample_items();
        let report = build_report("Test", items).unwrap();
        assert!(verify_report(&report).unwrap());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let items = sample_items();
        let mut report = build_report("Signed Report", items).unwrap();

        let keypair = Keypair::generate();
        let seed_hex = keypair.to_hex();

        sign_report(&mut report, &seed_hex).unwrap();
        assert!(report.signature.is_some());
        assert!(report.signer.is_some());

        assert!(verify_report(&report).unwrap());
    }

    #[test]
    fn verify_report_detects_tampered_signature() {
        let items = sample_items();
        let mut report = build_report("Tampered", items).unwrap();

        let keypair = Keypair::generate();
        sign_report(&mut report, &keypair.to_hex()).unwrap();

        // Tamper with the signature (flip a character).
        let mut sig = report.signature.take().unwrap();
        let bytes: Vec<u8> = sig.bytes().collect();
        if !bytes.is_empty() {
            let mut chars: Vec<char> = sig.chars().collect();
            chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
            sig = chars.into_iter().collect();
        }
        report.signature = Some(sig);

        // Verification should fail (either error or false).
        let result = verify_report(&report);
        if let Ok(valid) = result {
            assert!(!valid);
        }
        // Err is also acceptable — invalid hex parse.
    }

    #[test]
    fn verify_report_fails_signature_without_signer() {
        let items = sample_items();
        let mut report = build_report("Missing Signer", items).unwrap();

        // Add a signature but leave signer as None.
        let keypair = Keypair::generate();
        sign_report(&mut report, &keypair.to_hex()).unwrap();
        report.signer = None;

        let valid = verify_report(&report).unwrap();
        assert!(
            !valid,
            "signature present without signer should fail verification"
        );
    }

    #[test]
    fn verify_report_fails_signer_without_signature() {
        let items = sample_items();
        let mut report = build_report("Missing Signature", items).unwrap();

        // Add a signer but leave signature as None.
        let keypair = Keypair::generate();
        report.signer = Some(keypair.public_key().to_hex());

        let valid = verify_report(&report).unwrap();
        assert!(
            !valid,
            "signer present without signature should fail verification"
        );
    }

    #[test]
    fn evidence_from_alert_conversion() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = make_timeline_event("read /etc/passwd", ts);
        let alert = Alert {
            rule_name: "exfil_rule".to_string(),
            severity: RuleSeverity::High,
            title: "Data exfiltration".to_string(),
            triggered_at: ts,
            evidence: vec![event],
            description: "Test alert".to_string(),
        };

        let items = evidence_from_alert(&alert, 0);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].source_type, "alert");
        assert_eq!(items[0].index, 0);
        assert!(items[0].summary.contains("exfil_rule"));
        assert_eq!(items[1].source_type, "event");
        assert_eq!(items[1].index, 1);
        assert!(items[1].summary.contains("read /etc/passwd"));
    }

    #[test]
    fn evidence_from_events_conversion() {
        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 1, 0).unwrap();
        let events = vec![
            make_timeline_event("event one", ts1),
            make_timeline_event("event two", ts2),
        ];

        let items = evidence_from_events(&events, 5);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].index, 5);
        assert_eq!(items[1].index, 6);
        assert_eq!(items[0].source_type, "event");
        assert!(items[0].summary.contains("event one"));
        assert!(items[1].summary.contains("event two"));
    }

    #[test]
    fn evidence_from_ioc_matches_conversion() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = TimelineEvent {
            event_id: None,
            timestamp: ts,
            source: EventSource::Tetragon,
            kind: TimelineEventKind::ProcessExec,
            verdict: NormalizedVerdict::None,
            severity: None,
            summary: "curl evil.com".to_string(),
            process: Some("curl".to_string()),
            namespace: None,
            pod: None,
            action_type: None,
            signature_valid: None,
            raw: None,
        };

        let ioc_match = IocMatch {
            event,
            matched_iocs: vec![IocEntry {
                indicator: "evil.com".to_string(),
                ioc_type: IocType::Domain,
                description: Some("C2 domain".to_string()),
                source: None,
            }],
            match_field: "summary".to_string(),
        };

        let items = evidence_from_ioc_matches(&[ioc_match], 10);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].index, 10);
        assert_eq!(items[0].source_type, "ioc_match");
        assert!(items[0].summary.contains("evil.com"));
        assert!(items[0].summary.contains("summary"));
    }

    #[test]
    fn render_report_text_output() {
        let items = sample_items();
        let report = build_report("Render Test", items).unwrap();

        let mut buf = Vec::new();
        render_report(&report, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Render Test"));
        assert!(output.contains("Evidence items: 3"));
        assert!(output.contains("Suspicious file access"));
        assert!(output.contains("Merkle root:"));
    }

    #[test]
    fn render_report_json_output() {
        let items = sample_items();
        let report = build_report("JSON Test", items).unwrap();

        let mut buf = Vec::new();
        render_report_json(&report, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Validate it parses as JSON.
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["title"], "JSON Test");
        assert_eq!(parsed["evidence"].as_array().unwrap().len(), 3);
        assert!(parsed["merkle_root"].is_string());
    }

    #[test]
    fn full_pipeline_alerts_to_report() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = make_timeline_event("read /etc/shadow", ts);
        let alert = Alert {
            rule_name: "shadow_access".to_string(),
            severity: RuleSeverity::Critical,
            title: "Shadow file read".to_string(),
            triggered_at: ts,
            evidence: vec![event],
            description: "Shadow file access detected".to_string(),
        };

        let items = evidence_from_alert(&alert, 0);
        let report = build_report("Full Pipeline", items).unwrap();

        assert!(verify_report(&report).unwrap());

        // Sign and re-verify.
        let mut report = report;
        let kp = Keypair::generate();
        sign_report(&mut report, &kp.to_hex()).unwrap();
        assert!(verify_report(&report).unwrap());
    }
}
