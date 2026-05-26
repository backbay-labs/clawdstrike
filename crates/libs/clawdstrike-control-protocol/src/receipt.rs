//! Receipt upload request bodies.
//!
//! These DTOs back `POST /api/v1/receipts` and `POST /api/v1/receipts/batch`
//! on the Control API. The agent is the only producer in the current fleet
//! and always emits a fully-populated payload (including
//! [`ControlStoreReceiptRequest::signed_receipt`]).
//!
//! ## Signature decision (`signed_receipt`)
//!
//! Prior to this crate, the agent declared `signed_receipt` as required
//! (`serde_json::Value`) while `control-api` declared it optional
//! (`Option<serde_json::Value>` with `#[serde(default)]`). The control-api
//! handler then turned around and ran
//! `req.signed_receipt.ok_or(BadRequest("signed_receipt is required"))?`
//! at the very top of `validate_store_request`. The "optional" half of the
//! schema was therefore unreachable.
//!
//! The unified contract makes `signed_receipt` required at the deserializer
//! level so missing-field requests are rejected before the handler runs.
//! This matches the canonical producer (agent) and tightens the runtime check
//! into a compile-time/deserialize-time guarantee on the receiver.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body for `POST /api/v1/receipts`.
///
/// The agent constructs one of these from a [`hush_core::SignedReceipt`] and
/// posts it to the Control API for durable storage. The Control API
/// re-verifies the signature against the embedded `signed_receipt` before
/// persisting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlStoreReceiptRequest {
    /// RFC 3339 timestamp from the original receipt.
    pub timestamp: String,
    /// Verdict string — one of `"allow"`, `"deny"`, `"warn"`.
    pub verdict: String,
    /// Guard family that produced the receipt (e.g. `"endpoint_decision"`).
    pub guard: String,
    /// Policy ruleset name or version identifier.
    pub policy_name: String,
    /// Hex-encoded Ed25519 signature of the canonical receipt bytes.
    pub signature: String,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key: String,
    /// Optional rolling chain hash (snake_case `chain_hash` on the wire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
    /// Optional evidence payload bundle attached to the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    /// Optional metadata payload (e.g. `receiptId`, source, policy hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// The full signed receipt envelope. Required — the control-api
    /// validation pipeline rejects payloads where this is missing, so we
    /// model the requirement at the type level.
    pub signed_receipt: Value,
}

/// Request body for `POST /api/v1/receipts/batch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlBatchStoreReceiptsRequest {
    /// Receipts to store, processed in order.
    pub receipts: Vec<ControlStoreReceiptRequest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_receipt_request_round_trips() {
        let req = ControlStoreReceiptRequest {
            timestamp: "2026-05-26T00:00:00Z".to_string(),
            verdict: "allow".to_string(),
            guard: "endpoint_decision".to_string(),
            policy_name: "default".to_string(),
            signature: "ab".repeat(64),
            public_key: "cd".repeat(32),
            chain_hash: None,
            evidence: None,
            metadata: None,
            signed_receipt: serde_json::json!({"signed": true}),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: ControlStoreReceiptRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.timestamp, req.timestamp);
        assert_eq!(back.signed_receipt, req.signed_receipt);
    }

    #[test]
    fn store_receipt_request_rejects_missing_signed_receipt() {
        let raw = serde_json::json!({
            "timestamp": "2026-05-26T00:00:00Z",
            "verdict": "allow",
            "guard": "endpoint_decision",
            "policy_name": "default",
            "signature": "ab",
            "public_key": "cd",
        });
        let err = serde_json::from_value::<ControlStoreReceiptRequest>(raw).unwrap_err();
        assert!(
            err.to_string().contains("signed_receipt"),
            "expected missing-field error to mention signed_receipt, got {err}"
        );
    }

    #[test]
    fn batch_store_receipts_request_round_trips() {
        let batch = ControlBatchStoreReceiptsRequest {
            receipts: vec![ControlStoreReceiptRequest {
                timestamp: "2026-05-26T00:00:00Z".to_string(),
                verdict: "deny".to_string(),
                guard: "ForbiddenPathGuard".to_string(),
                policy_name: "strict".to_string(),
                signature: "00".repeat(64),
                public_key: "11".repeat(32),
                chain_hash: Some("0xdeadbeef".to_string()),
                evidence: Some(serde_json::json!([])),
                metadata: Some(serde_json::json!({"receiptId": "abc"})),
                signed_receipt: serde_json::json!({}),
            }],
        };
        let bytes = serde_json::to_vec(&batch).unwrap();
        let back: ControlBatchStoreReceiptsRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.receipts.len(), 1);
        assert_eq!(back.receipts[0].guard, "ForbiddenPathGuard");
    }
}
