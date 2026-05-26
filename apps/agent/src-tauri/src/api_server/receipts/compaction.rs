//! Compaction record helpers and timestamp/sequence accessors used by
//! receipt ledger maintenance and reporting.

use super::super::*;

pub(crate) fn receipt_compaction_record(
    receipt: &SignedReceipt,
    age_seconds: u64,
    removed: bool,
    reason: String,
) -> EdrReceiptCompactionRecord {
    EdrReceiptCompactionRecord {
        receipt_id: receipt.receipt.receipt_id.clone(),
        timestamp: receipt.receipt.timestamp.clone(),
        age_seconds,
        family: receipt_family(receipt).map(ToString::to_string),
        action: receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(ToString::to_string),
        finding_id: receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(ToString::to_string),
        rule_id: receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(ToString::to_string),
        graph_slice_id: receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(ToString::to_string),
        root_node_id: receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        removed,
        reason,
    }
}

pub(crate) fn receipt_age_seconds(
    receipt: &SignedReceipt,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp)
        .map(|timestamp| {
            now.signed_duration_since(timestamp.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0) as u64
        })
        .unwrap_or(0)
}

pub(crate) fn receipt_local_sequence(receipt: &SignedReceipt) -> Option<u64> {
    receipt
        .receipt
        .metadata
        .as_ref()?
        .get("endpointDecision")?
        .get("localSequence")?
        .as_u64()
}

pub(crate) fn receipt_family(receipt: &SignedReceipt) -> Option<&str> {
    receipt_endpoint_decision_str(receipt, &["receiptFamily"])
}
