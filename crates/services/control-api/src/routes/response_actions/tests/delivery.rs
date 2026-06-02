//! Delivery-plan / subject-derivation / metadata-scrub tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn delivery_plan_uses_response_subject_for_supported_endpoint_actions() {
    let action = ResponseActionRecord {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        action_type: "policy_rule_diff_validation".to_string(),
        target: ResponseTarget {
            kind: ResponseTargetKind::Endpoint,
            id: "agent-123".to_string(),
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
        payload: json!({"operation": "policy_rule_diff_validation"}),
        status: "queued".to_string(),
        metadata: json!({}),
    };

    let plan = delivery_plan(&action, "acme");
    assert_eq!(
        plan.delivery_subject.as_deref(),
        Some("tenant-acme.clawdstrike.response.command.endpoint.agent-123")
    );
    assert!(plan.metadata["compat_mirror_subject"].is_null());
    assert_eq!(
        plan.metadata["canonical_subject"],
        "tenant-acme.clawdstrike.response.command.endpoint.agent-123"
    );
    assert!(plan.metadata["ack_token"].is_string());
}

#[test]
fn publish_contract_rejects_legacy_endpoint_actions() {
    let action = ResponseActionRecord {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        action_type: "request_policy_reload".to_string(),
        target: ResponseTarget {
            kind: ResponseTargetKind::Endpoint,
            id: "agent-123".to_string(),
        },
        requested_by: RequestedBy {
            actor_type: "user".to_string(),
            actor_id: "alice".to_string(),
        },
        requested_at: Utc::now(),
        expires_at: None,
        reason: "reload".to_string(),
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: false,
        payload: json!({}),
        status: "queued".to_string(),
        metadata: json!({}),
    };

    let err = validate_publish_delivery_contract(&action).unwrap_err();
    match err {
        ApiError::BadRequest(message) => {
            assert!(message.contains("policy_rule_diff_validation"));
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn cloud_only_targets_skip_transport_subject() {
    let action = ResponseActionRecord {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        action_type: "revoke_principal".to_string(),
        target: ResponseTarget {
            kind: ResponseTargetKind::Principal,
            id: "principal-1".to_string(),
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
        require_acknowledgement: false,
        payload: json!({}),
        status: "queued".to_string(),
        metadata: json!({}),
    };

    let plan = delivery_plan(&action, "acme");
    assert!(plan.delivery_subject.is_none());
    assert_eq!(plan.executor_kind, "cloud_only");
}

#[test]
fn transition_posture_requires_target_state_in_payload() {
    let input = CreateResponseActionRequest {
        action_type: "transition_posture".to_string(),
        target: ResponseTargetInput {
            kind: "project".to_string(),
            id: "agent-1".to_string(),
        },
        reason: "contain".to_string(),
        expires_at: None,
        case_id: None,
        source_detection_id: None,
        source_approval_id: None,
        require_acknowledgement: Some(false),
        payload: Some(json!({})),
    };

    let err = validate_create_request(
        &input,
        &ResponseActionType::TransitionPosture,
        &ResponseTargetKind::Project,
        false,
    )
    .unwrap_err();
    match err {
        ApiError::BadRequest(message) => {
            assert!(message.contains("payload.toState"));
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn scrub_delivery_metadata_hides_ack_token() {
    let scrubbed = scrub_delivery_metadata(json!({
        "ack_token": "secret",
        "compat_mirror_subject": "tenant-acme.clawdstrike.posture.command.agent-123",
    }));

    assert!(scrubbed.get("ack_token").is_none());
    assert_eq!(
        scrubbed["compat_mirror_subject"],
        "tenant-acme.clawdstrike.posture.command.agent-123"
    );
}
