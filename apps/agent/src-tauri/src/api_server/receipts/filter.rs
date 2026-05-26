//! Predicate helpers for matching signed endpoint receipts against
//! `EdrReceiptFilter` and inspecting evidence value hashes.

use super::super::*;

pub(crate) fn receipt_matches_filter(
    receipt: &SignedReceipt,
    filter: EdrReceiptFilter<'_>,
) -> bool {
    if let Some(expected) = filter.receipt_id {
        if !receipt
            .receipt
            .receipt_id
            .as_deref()
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.family {
        if !receipt_family(receipt)
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.action {
        if !receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.finding_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.rule_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.graph_slice_id {
        if !receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.root_node_id {
        if !receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.execution_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
            && !receipt_evidence_hash_matches(receipt, "executionId", expected)
        {
            return false;
        }
    }
    if let Some(expected) = filter.status {
        if !receipt_evidence_hash_matches(receipt, "executionStatus", expected) {
            return false;
        }
    }
    if let Some(expected) = filter.actor_endpoint_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_user_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "userId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_session_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "sessionId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_agent_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "agentId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_workload_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "workloadId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_approval_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "approvalId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.local_sequence {
        if receipt_local_sequence(receipt) != Some(expected) {
            return false;
        }
    }
    true
}

pub(crate) fn receipt_evidence_hash_matches(
    receipt: &SignedReceipt,
    key: &str,
    raw_value: &str,
) -> bool {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    receipt_evidence_hash_value(receipt, key) == Some(expected_hash.as_str())
}

pub(crate) fn receipt_evidence_hash_value<'a>(
    receipt: &'a SignedReceipt,
    key: &str,
) -> Option<&'a str> {
    receipt_endpoint_decision_value(receipt, &["evidence"])
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                if item.get("key").and_then(serde_json::Value::as_str) == Some(key) {
                    item.get("valueHash").and_then(serde_json::Value::as_str)
                } else {
                    None
                }
            })
        })
}
