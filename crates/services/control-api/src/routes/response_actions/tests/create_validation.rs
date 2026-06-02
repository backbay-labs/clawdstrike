//! Create-request validation tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn create_validation_rejects_invalid_action_target_pairs() {
    let input = CreateResponseActionRequest {
        action_type: "request_policy_reload".to_string(),
        target: ResponseTargetInput {
            kind: "principal".to_string(),
            id: "p-1".to_string(),
        },
        reason: "reload".to_string(),
        expires_at: None,
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(false),
        payload: None,
    };
    let err = validate_create_request(
        &input,
        &ResponseActionType::RequestPolicyReload,
        &ResponseTargetKind::Principal,
        false,
    )
    .unwrap_err();
    assert!(matches!(err, ApiError::BadRequest(_)));
}

#[test]
fn create_validation_rejects_endpoint_actions_without_agent_executor() {
    let input = CreateResponseActionRequest {
        action_type: "request_policy_reload".to_string(),
        target: ResponseTargetInput {
            kind: "endpoint".to_string(),
            id: "agent-1".to_string(),
        },
        reason: "reload".to_string(),
        expires_at: None,
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(false),
        payload: None,
    };

    let err = validate_create_request(
        &input,
        &ResponseActionType::RequestPolicyReload,
        &ResponseTargetKind::Endpoint,
        false,
    )
    .unwrap_err();
    match err {
        ApiError::BadRequest(message) => {
            assert!(message.contains("policy_rule_diff_validation"));
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn create_validation_requires_policy_rule_diff_acknowledgement() {
    let input = CreateResponseActionRequest {
        action_type: "policy_rule_diff_validation".to_string(),
        target: ResponseTargetInput {
            kind: "endpoint".to_string(),
            id: "agent-1".to_string(),
        },
        reason: "validate proposal".to_string(),
        expires_at: None,
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(false),
        payload: Some(json!({"operation": "policy_rule_diff_validation"})),
    };

    let err = validate_create_request(
        &input,
        &ResponseActionType::PolicyRuleDiffValidation,
        &ResponseTargetKind::Endpoint,
        false,
    )
    .unwrap_err();
    match err {
        ApiError::BadRequest(message) => {
            assert!(message.contains("require acknowledgement"));
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn create_validation_accepts_policy_rule_diff_endpoint_contract() {
    let input = CreateResponseActionRequest {
        action_type: "policy_rule_diff_validation".to_string(),
        target: ResponseTargetInput {
            kind: "endpoint".to_string(),
            id: "agent-1".to_string(),
        },
        reason: "validate proposal".to_string(),
        expires_at: Some(Utc::now() + Duration::minutes(5)),
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(true),
        payload: Some(json!({"operation": "policy_rule_diff_validation"})),
    };

    validate_create_request(
        &input,
        &ResponseActionType::PolicyRuleDiffValidation,
        &ResponseTargetKind::Endpoint,
        true,
    )
    .expect("policy_rule_diff_validation endpoint command should be accepted");
}

#[test]
fn create_validation_rejects_acknowledgement_until_executor_support_exists() {
    let input = CreateResponseActionRequest {
        action_type: "request_policy_reload".to_string(),
        target: ResponseTargetInput {
            kind: "endpoint".to_string(),
            id: "agent-1".to_string(),
        },
        reason: "reload".to_string(),
        expires_at: None,
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(true),
        payload: None,
    };

    let err = validate_create_request(
        &input,
        &ResponseActionType::RequestPolicyReload,
        &ResponseTargetKind::Endpoint,
        true,
    )
    .unwrap_err();
    assert!(matches!(err, ApiError::BadRequest(_)));
}

#[test]
fn create_validation_rejects_unsupported_runtime_targets() {
    let input = CreateResponseActionRequest {
        action_type: "kill_switch".to_string(),
        target: ResponseTargetInput {
            kind: "runtime".to_string(),
            id: "runtime-1".to_string(),
        },
        reason: "contain".to_string(),
        expires_at: None,
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(false),
        payload: None,
    };

    let err = validate_create_request(
        &input,
        &ResponseActionType::KillSwitch,
        &ResponseTargetKind::Runtime,
        false,
    )
    .unwrap_err();
    assert!(matches!(err, ApiError::BadRequest(_)));
}

#[test]
fn create_validation_rejects_oversized_request_fields() {
    let oversized_target = match validate_create_request(
        &CreateResponseActionRequest {
            action_type: "request_policy_reload".to_string(),
            target: ResponseTargetInput {
                kind: "endpoint".to_string(),
                id: "e".repeat(257),
            },
            reason: "reload".to_string(),
            expires_at: None,
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: Some(false),
            payload: None,
        },
        &ResponseActionType::RequestPolicyReload,
        &ResponseTargetKind::Endpoint,
        false,
    ) {
        Ok(_) => panic!("oversized response-action target id was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_target, ApiError::BadRequest(_)));

    let oversized_reason = match validate_create_request(
        &CreateResponseActionRequest {
            action_type: "request_policy_reload".to_string(),
            target: ResponseTargetInput {
                kind: "endpoint".to_string(),
                id: "agent-1".to_string(),
            },
            reason: "r".repeat(2049),
            expires_at: None,
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: Some(false),
            payload: None,
        },
        &ResponseActionType::RequestPolicyReload,
        &ResponseTargetKind::Endpoint,
        false,
    ) {
        Ok(_) => panic!("oversized response-action reason was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_reason, ApiError::BadRequest(_)));

    let oversized_payload = match validate_create_request(
        &CreateResponseActionRequest {
            action_type: "request_policy_reload".to_string(),
            target: ResponseTargetInput {
                kind: "endpoint".to_string(),
                id: "agent-1".to_string(),
            },
            reason: "reload".to_string(),
            expires_at: None,
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: Some(false),
            payload: Some(json!({
                "blob": "p".repeat(65_536)
            })),
        },
        &ResponseActionType::RequestPolicyReload,
        &ResponseTargetKind::Endpoint,
        false,
    ) {
        Ok(_) => panic!("oversized response-action payload was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_payload, ApiError::BadRequest(_)));
}

#[test]
fn control_discriminator_errors_do_not_echo_oversized_values() {
    fn bad_request_message(err: ApiError) -> String {
        match err {
            ApiError::BadRequest(message) => message,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    let oversized_action_type = "a".repeat(2048);
    let action_message =
        bad_request_message(ResponseActionType::from_str(&oversized_action_type).unwrap_err());
    assert!(!action_message.contains(&oversized_action_type));
    assert!(action_message.len() < 256);

    let oversized_target_kind = "t".repeat(2048);
    let target_message =
        bad_request_message(ResponseTargetKind::from_str(&oversized_target_kind).unwrap_err());
    assert!(!target_message.contains(&oversized_target_kind));
    assert!(target_message.len() < 256);

    let oversized_ack_status = "s".repeat(2048);
    let status_message =
        bad_request_message(normalize_ack_status(&oversized_ack_status).unwrap_err());
    assert!(!status_message.contains(&oversized_ack_status));
    assert!(status_message.len() < 256);
}

#[test]
fn control_discriminators_reject_oversized_values_with_length_errors() {
    fn bad_request_message(err: ApiError) -> String {
        match err {
            ApiError::BadRequest(message) => message,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    let action_message =
        bad_request_message(ResponseActionType::from_str(&"a".repeat(65)).unwrap_err());
    assert!(action_message.contains("action_type"));
    assert!(action_message.contains("at most"));

    let target_message =
        bad_request_message(ResponseTargetKind::from_str(&"t".repeat(65)).unwrap_err());
    assert!(target_message.contains("target.kind"));
    assert!(target_message.contains("at most"));

    let status_message = bad_request_message(normalize_ack_status(&"s".repeat(65)).unwrap_err());
    assert!(status_message.contains("status"));
    assert!(status_message.contains("at most"));
}

#[test]
fn response_action_requests_reject_unknown_fields() {
    let create_err = serde_json::from_value::<CreateResponseActionRequest>(json!({
        "actionType": "request_policy_reload",
        "target": {
            "kind": "endpoint",
            "id": "agent-1"
        },
        "reason": "reload",
        "dryRun": true
    }))
    .expect_err("unknown create request field should be rejected");
    assert!(create_err.to_string().contains("unknown field"));

    let target_err = serde_json::from_value::<CreateResponseActionRequest>(json!({
        "actionType": "request_policy_reload",
        "target": {
            "kind": "endpoint",
            "id": "agent-1",
            "displayName": "Endpoint One"
        },
        "reason": "reload"
    }))
    .expect_err("unknown target field should be rejected");
    assert!(target_err.to_string().contains("unknown field"));

    let ack_err = serde_json::from_value::<RecordResponseAckRequest>(json!({
        "targetKind": "endpoint",
        "targetId": "agent-1",
        "ackToken": "ack-token",
        "status": "acknowledged",
        "receiptHash": "abc123"
    }))
    .expect_err("unknown acknowledgement field should be rejected");
    assert!(ack_err.to_string().contains("unknown field"));
}
