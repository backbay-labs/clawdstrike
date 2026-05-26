//! Response-action acknowledgement postback envelope.
//!
//! After the agent executes a control-plane response action it posts an
//! acknowledgement to the Control API. Historically the agent built the
//! payload inline with [`serde_json::json!`] while the Control API parsed it
//! into a typed `RecordResponseAckRequest`. This module hosts the shared
//! typed envelope so both sides agree on the schema.
//!
//! Wire path:
//! `POST /api/v1/response-actions/{id}/acks`
//! (and the agent-token-authenticated public ack route).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Acknowledgement of a control-plane response action.
///
/// Fields are camelCase on the wire. `deny_unknown_fields` keeps drift
/// fail-closed; today's known fields:
///
/// - `targetKind` — `"endpoint"`, `"runtime"`, `"session"`, `"principal"`,
///   `"grant"`, `"swarm"`, or `"project"`.
/// - `targetId` — opaque target identifier.
/// - `ackToken` — capability token issued with the response-action delivery.
/// - `status` — one of `"acknowledged"`, `"rejected"`, `"failed"`,
///   `"expired"`, `"rolled_back"`.
/// - `observedAt` — RFC 3339 timestamp the agent observed the terminal state.
/// - `message` — optional human-readable status line.
/// - `resultingState` — optional machine-friendly state code.
/// - `rawPayload` — optional opaque acknowledgement body (e.g. policy
///   rule-diff signed validation receipt).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlResponseActionAck {
    /// Target kind the ack is scoped to.
    pub target_kind: String,
    /// Target identifier.
    pub target_id: String,
    /// Capability token issued with the original response-action delivery.
    pub ack_token: String,
    /// Final status the agent is reporting.
    pub status: String,
    /// Optional observation timestamp; defaults to deserialize-time if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// Human-readable status message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Machine-friendly resulting state code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_state: Option<String>,
    /// Opaque raw payload (e.g. signed validation receipt or failure body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_round_trips_with_camel_case() {
        let ack = ControlResponseActionAck {
            target_kind: "endpoint".to_string(),
            target_id: "endpoint-1".to_string(),
            ack_token: "tok".to_string(),
            status: "acknowledged".to_string(),
            observed_at: Some(
                DateTime::parse_from_rfc3339("2026-05-26T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            message: Some("ok".to_string()),
            resulting_state: Some("policy_rule_diff_validation:succeeded".to_string()),
            raw_payload: Some(serde_json::json!({"k": "v"})),
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("\"targetKind\""));
        assert!(json.contains("\"resultingState\""));
        let back: ControlResponseActionAck = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target_kind, ack.target_kind);
        assert_eq!(back.raw_payload, ack.raw_payload);
    }

    #[test]
    fn ack_skips_none_fields_on_serialize() {
        let ack = ControlResponseActionAck {
            target_kind: "endpoint".to_string(),
            target_id: "endpoint-1".to_string(),
            ack_token: "tok".to_string(),
            status: "rejected".to_string(),
            observed_at: None,
            message: None,
            resulting_state: None,
            raw_payload: None,
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert!(!json.contains("observedAt"));
        assert!(!json.contains("message"));
        assert!(!json.contains("rawPayload"));
    }

    #[test]
    fn ack_rejects_unknown_fields() {
        let raw = r#"{"targetKind":"endpoint","targetId":"e","ackToken":"t","status":"acknowledged","surprise":1}"#;
        let err = serde_json::from_str::<ControlResponseActionAck>(raw).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
