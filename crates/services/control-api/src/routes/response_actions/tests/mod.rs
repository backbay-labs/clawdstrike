//! Unit tests for the response-actions routes (extracted from the inline module).
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub(super) use super::*;

pub(super) fn test_response_action(
    target_kind: ResponseTargetKind,
    action_type: &str,
) -> ResponseActionRecord {
    ResponseActionRecord {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        action_type: action_type.to_string(),
        target: ResponseTarget {
            kind: target_kind,
            id: "endpoint-1".to_string(),
        },
        requested_by: RequestedBy {
            actor_type: "user".to_string(),
            actor_id: "alice".to_string(),
        },
        requested_at: Utc::now(),
        expires_at: None,
        reason: "test".to_string(),
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: true,
        payload: json!({}),
        status: "published".to_string(),
        metadata: json!({}),
    }
}

pub(super) fn test_ack(status: &str, target_kind: &str) -> AckSubmission {
    parse_ack_submission(RecordResponseAckRequest {
        target_kind: target_kind.to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: status.to_string(),
        observed_at: None,
        message: None,
        resulting_state: None,
        raw_payload: Some(json!({ "status": status })),
    })
    .expect("test acknowledgement parses")
}

pub(super) fn policy_rule_diff_action_payload() -> Value {
    json!({
        "operation": "policy_rule_diff_validation",
        "proposalId": "proposal-test",
        "validationPlanSha256": "sha256:plan",
        "endpointAgentId": "endpoint-1",
        "request": {
            "method": "POST",
            "path": "/api/v1/edr/policy/event-impact",
            "body": {
                "limit": 10,
                "trackPosture": true
            }
        }
    })
}

pub(super) fn policy_rule_diff_error_ack(mut error_payload: Value) -> AckSubmission {
    error_payload["message"] = json!("local validation failed");
    parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "failed".to_string(),
        observed_at: None,
        message: Some("local validation failed".to_string()),
        resulting_state: Some("policy_rule_diff_validation:failed".to_string()),
        raw_payload: Some(json!({
            "policyRuleDiffValidationError": error_payload
        })),
    })
    .expect("test policy rule-diff failure acknowledgement parses")
}

mod ack_receipts;
mod create_validation;
mod delivery;
mod parse_ack;
