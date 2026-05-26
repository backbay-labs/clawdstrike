//! On-disk receipt index records.
//!
//! The agent maintains an append-only JSON-Lines index next to its receipt
//! log. Each line is a serialized [`EndpointReceiptIndexRecord`] mapping a
//! receipt's identifying metadata to its byte range inside the log file.
//!
//! The schema lives in this crate so external readers (e.g. forensic tooling
//! or the workbench's local browser) can deserialize the index without
//! pulling in the agent's full dependency tree.

use serde::{Deserialize, Serialize};

/// One row of the agent's local receipt index ledger.
///
/// Fields default to `None`/`0` so older index files (predating any field
/// addition) deserialize cleanly. `#[serde(deny_unknown_fields)]` keeps
/// schema drift fail-closed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointReceiptIndexRecord {
    /// Receipt identifier as recorded on the underlying receipt.
    pub receipt_id: Option<String>,
    /// RFC 3339 timestamp from the receipt.
    pub timestamp: String,
    /// Receipt family tag (e.g. `"endpoint_decision"`, `"response_execution"`).
    pub family: Option<String>,
    /// Decision action string, when applicable.
    pub action: Option<String>,
    /// Finding identifier associated with this receipt.
    pub finding_id: Option<String>,
    /// Rule identifier associated with this receipt.
    pub rule_id: Option<String>,
    /// Identifier of the causal graph slice the receipt references.
    pub graph_slice_id: Option<String>,
    /// Root node ID inside the causal graph slice.
    pub root_node_id: Option<String>,
    /// Response execution identifier, for response_execution receipts.
    pub execution_id: Option<String>,
    /// Execution status (e.g. `"succeeded"`, `"failed"`).
    pub execution_status: Option<String>,
    /// Endpoint identifier for the actor.
    pub actor_endpoint_id: Option<String>,
    /// User identifier for the actor.
    pub actor_user_id: Option<String>,
    /// Session identifier for the actor.
    pub actor_session_id: Option<String>,
    /// Agent identifier for the actor.
    pub actor_agent_id: Option<String>,
    /// Workload identifier for the actor.
    pub actor_workload_id: Option<String>,
    /// Approval identifier for the actor.
    pub actor_approval_id: Option<String>,
    /// Monotonic local sequence assigned by the agent.
    pub local_sequence: Option<u64>,
    /// Byte offset of the receipt entry in the log file.
    pub byte_offset: u64,
    /// Byte length of the receipt entry in the log file.
    pub byte_len: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_record_defaults() {
        let record = EndpointReceiptIndexRecord::default();
        assert_eq!(record.byte_offset, 0);
        assert_eq!(record.byte_len, 0);
        assert!(record.receipt_id.is_none());
    }

    #[test]
    fn index_record_round_trips_with_camel_case() {
        let record = EndpointReceiptIndexRecord {
            receipt_id: Some("rcpt-1".to_string()),
            timestamp: "2026-05-26T00:00:00Z".to_string(),
            family: Some("endpoint_decision".to_string()),
            local_sequence: Some(42),
            byte_offset: 1024,
            byte_len: 256,
            ..Default::default()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"receiptId\""), "expected camelCase, got {json}");
        assert!(json.contains("\"localSequence\""));
        let back: EndpointReceiptIndexRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn index_record_rejects_unknown_fields() {
        let raw = r#"{"receiptId":"r","timestamp":"t","byteOffset":0,"byteLen":0,"surprise":42}"#;
        let err = serde_json::from_str::<EndpointReceiptIndexRecord>(raw).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected deny_unknown_fields error, got {err}"
        );
    }
}
