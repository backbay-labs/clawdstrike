//! Acknowledgement signed-receipt + policy-rule-diff contract tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn endpoint_terminal_ack_statuses_require_signed_receipts() {
    let action = test_response_action(
        ResponseTargetKind::Endpoint,
        ResponseActionType::TerminateSession.as_str(),
    );

    for status in [
        "acknowledged",
        "rolled_back",
        "failed",
        "rejected",
        "expired",
    ] {
        let ack = test_ack(status, "endpoint");
        assert!(
            requires_endpoint_ack_signed_receipt(&action, &ack),
            "endpoint {status} acknowledgements must be signed"
        );
    }
}

#[test]
fn policy_rule_diff_non_ack_terminal_statuses_require_signed_receipts() {
    let action = test_response_action(
        ResponseTargetKind::Endpoint,
        ResponseActionType::PolicyRuleDiffValidation.as_str(),
    );

    for status in ["failed", "rejected", "expired"] {
        let ack = test_ack(status, "endpoint");
        assert!(
                requires_endpoint_ack_signed_receipt(&action, &ack),
                "policy rule-diff {status} terminal acknowledgements must include an endpoint signed receipt"
            );
    }
}

#[test]
fn cloud_only_targets_do_not_require_endpoint_receipts() {
    let action = test_response_action(
        ResponseTargetKind::Principal,
        ResponseActionType::RevokePrincipal.as_str(),
    );
    let ack = test_ack("acknowledged", "principal");

    assert!(!requires_endpoint_ack_signed_receipt(&action, &ack));
}

#[test]
fn policy_rule_diff_error_payload_must_be_bound_to_dispatched_action() {
    fn bad_request_message(err: ApiError) -> String {
        match err {
            ApiError::BadRequest(message) => message,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    let action_payload = policy_rule_diff_action_payload();
    let empty_payload = parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "failed".to_string(),
        observed_at: None,
        message: Some("local validation failed".to_string()),
        resulting_state: Some("policy_rule_diff_validation:failed".to_string()),
        raw_payload: Some(json!({})),
    })
    .expect("empty raw payload parses");
    let message = bad_request_message(
        validate_policy_rule_diff_error_payload_matches_action(
            &empty_payload,
            &action_payload,
            "endpoint-1",
        )
        .unwrap_err(),
    );
    assert!(message.contains("must include policyRuleDiffValidationError"));

    let wrong_plan = policy_rule_diff_error_ack(json!({
        "proposalId": "proposal-test",
        "validationPlanSha256": "sha256:wrong-plan",
        "endpointAgentId": "endpoint-1",
        "request": action_payload["request"].clone()
    }));
    let message = bad_request_message(
        validate_policy_rule_diff_error_payload_matches_action(
            &wrong_plan,
            &action_payload,
            "endpoint-1",
        )
        .unwrap_err(),
    );
    assert!(message.contains("validationPlanSha256 does not match"));

    let wrong_request = policy_rule_diff_error_ack(json!({
        "proposalId": "proposal-test",
        "validationPlanSha256": "sha256:plan",
        "endpointAgentId": "endpoint-1",
        "request": {
            "method": "POST",
            "path": "/api/v1/edr/policy/event-impact",
            "body": {
                "limit": 999,
                "trackPosture": true
            }
        }
    }));
    let message = bad_request_message(
        validate_policy_rule_diff_error_payload_matches_action(
            &wrong_request,
            &action_payload,
            "endpoint-1",
        )
        .unwrap_err(),
    );
    assert!(message.contains("request does not match"));

    let valid = policy_rule_diff_error_ack(json!({
        "proposalId": "proposal-test",
        "validationPlanSha256": "sha256:plan",
        "endpointAgentId": "endpoint-1",
        "request": action_payload["request"].clone()
    }));
    validate_policy_rule_diff_error_payload_matches_action(&valid, &action_payload, "endpoint-1")
        .expect("bound policy rule-diff error payload should validate");
}

#[test]
fn policy_rule_diff_ack_payload_requires_receipt_and_impact_for_success() {
    fn bad_request_message(err: ApiError) -> String {
        match err {
            ApiError::BadRequest(message) => message,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    let missing_receipt = parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: None,
        resulting_state: None,
        raw_payload: Some(json!({
            "policyRuleDiffValidation": {
                "impact": {
                    "impactId": "impact-test"
                }
            }
        })),
    })
    .expect("ack payload parses");
    let message =
        bad_request_message(validate_policy_rule_diff_ack_payload(&missing_receipt).unwrap_err());
    assert!(message.contains("policyRuleDiffValidation acknowledgement must include receipt"));

    let complete = parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: None,
        resulting_state: None,
        raw_payload: Some(json!({
            "policyRuleDiffValidation": {
                "impact": {
                    "impactId": "impact-test"
                },
                "receipt": {
                    "receipt": {
                        "receipt_id": "receipt-test"
                    }
                }
            }
        })),
    })
    .expect("ack payload parses");
    validate_policy_rule_diff_ack_payload(&complete)
        .expect("complete policy rule-diff acknowledgement payload");

    let failed_without_receipt = parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "failed".to_string(),
        observed_at: None,
        message: Some("local validation failed".to_string()),
        resulting_state: None,
        raw_payload: Some(json!({
            "policyRuleDiffValidationError": {
                "message": "local validation failed"
            }
        })),
    })
    .expect("ack payload parses");
    validate_policy_rule_diff_ack_payload(&failed_without_receipt).expect(
        "error payload shape validation is separate from terminal signed-receipt enforcement",
    );
}

#[test]
fn policy_rule_diff_ack_binds_dispatched_expected_receipt() {
    fn bad_request_message(err: ApiError) -> String {
        match err {
            ApiError::BadRequest(message) => message,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    let expected_receipt = json!({
        "receiptFamily": "policy_event_impact",
        "ruleId": "endpoint.policy_event.impact",
        "graphProcessNodeId": "fleet-rule-diff",
        "proposedPolicyHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposedPolicyEpoch": 42,
        "requiredEvidenceKeys": [
            "impactId",
            "proposedPolicyHash",
            "proposedPolicyEpoch"
        ]
    });
    let action_payload = json!({
        "expectedReceipt": expected_receipt.clone()
    });
    let payload = json!({
        "endpointAgentId": "agent-1",
        "expectedReceipt": expected_receipt,
        "impact": {
            "proposedPolicyHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proposedPolicyEpoch": 42
        }
    });
    validate_policy_rule_diff_ack_matches_action_payload(&payload, &action_payload, "agent-1")
        .expect("expected receipt identity should match");

    let mut mutated_expected = payload.clone();
    mutated_expected["expectedReceipt"]["proposedPolicyHash"] =
        json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let message = bad_request_message(
        validate_policy_rule_diff_ack_matches_action_payload(
            &mutated_expected,
            &action_payload,
            "agent-1",
        )
        .unwrap_err(),
    );
    assert!(message.contains("expectedReceipt does not match"));

    let mut mutated_impact = payload.clone();
    mutated_impact["impact"]["proposedPolicyEpoch"] = json!(43);
    let message = bad_request_message(
        validate_policy_rule_diff_ack_matches_action_payload(
            &mutated_impact,
            &action_payload,
            "agent-1",
        )
        .unwrap_err(),
    );
    assert!(message.contains("impact proposedPolicyEpoch"));
}
