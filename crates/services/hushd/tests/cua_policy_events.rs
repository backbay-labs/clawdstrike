#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Integration tests verifying CUA policy events flow through the hushd mapping pipeline.

use chrono::Utc;
use hushd::policy_event::{
    map_policy_event, CuaEventData, FileEventData, MappedGuardAction, PolicyEvent, PolicyEventData,
    PolicyEventType,
};

fn cua_event(event_type_str: &str, cua_data: CuaEventData) -> PolicyEvent {
    PolicyEvent {
        event_id: format!("integ-{}", event_type_str),
        event_type: serde_json::from_value(serde_json::Value::String(event_type_str.to_string()))
            .unwrap(),
        timestamp: Utc::now(),
        session_id: Some("integ-session-001".to_string()),
        data: PolicyEventData::Cua(cua_data),
        metadata: None,
        context: None,
    }
}

fn base_cua_data(action: &str) -> CuaEventData {
    CuaEventData {
        cua_action: action.to_string(),
        direction: None,
        continuity_prev_session_hash: None,
        postcondition_probe_hash: None,
        extra: serde_json::Map::new(),
    }
}

/// CUA events reach the guard pipeline via the Custom action path.
#[test]
fn cua_events_map_to_custom_guard_action() {
    let cases = vec![
        ("remote.session.connect", "connect"),
        ("remote.session.disconnect", "disconnect"),
        ("remote.session.reconnect", "reconnect"),
        ("input.inject", "inject"),
        ("remote.clipboard", "clipboard"),
        ("remote.file_transfer", "file_transfer"),
        ("remote.audio", "audio"),
        ("remote.drive_mapping", "drive_mapping"),
        ("remote.printing", "printing"),
        ("remote.session_share", "session_share"),
    ];

    for (event_type, cua_action) in cases {
        let event = cua_event(event_type, base_cua_data(cua_action));
        let mapped = map_policy_event(&event).unwrap_or_else(|_| {
            panic!("map_policy_event should succeed for {}", event_type)
        });

        match &mapped.action {
            MappedGuardAction::Custom { custom_type, .. } => {
                assert_eq!(
                    custom_type, event_type,
                    "custom_type should match event_type for {}",
                    event_type
                );
            }
            other => panic!("expected Custom action for {}, got {:?}", event_type, other),
        }

        // Verify the action_type() and target() methods work correctly.
        assert_eq!(mapped.action.action_type(), "custom");
        assert_eq!(mapped.action.target(), Some(event_type.to_string()));
    }
}

/// Session continuity fields are preserved through the mapping.
#[test]
fn session_continuity_fields_preserved() {
    let mut data = base_cua_data("reconnect");
    data.continuity_prev_session_hash = Some("sha256:continuity_abc".to_string());

    let event = cua_event("remote.session.reconnect", data);
    let mapped = map_policy_event(&event).unwrap();

    match &mapped.action {
        MappedGuardAction::Custom { data, .. } => {
            assert_eq!(
                data["continuityPrevSessionHash"], "sha256:continuity_abc",
                "continuity hash must survive mapping"
            );
        }
        other => panic!("expected Custom, got {:?}", other),
    }

    // Session ID should be propagated to the guard context.
    assert_eq!(
        mapped.context.session_id.as_deref(),
        Some("integ-session-001")
    );
}

/// Post-condition probe results are captured in the mapped data.
#[test]
fn postcondition_probe_preserved() {
    let mut data = base_cua_data("inject");
    data.postcondition_probe_hash = Some("sha256:probe_xyz".to_string());

    let event = cua_event("input.inject", data);
    let mapped = map_policy_event(&event).unwrap();

    match &mapped.action {
        MappedGuardAction::Custom { data, .. } => {
            assert_eq!(
                data["postconditionProbeHash"], "sha256:probe_xyz",
                "postcondition probe hash must survive mapping"
            );
        }
        other => panic!("expected Custom, got {:?}", other),
    }
}

/// Unknown CUA event types (not matching the 6 defined) fall into Other(String)
/// and are rejected by map_policy_event (fail closed).
#[test]
fn unknown_cua_event_types_fail_closed() {
    // Create an event with an unrecognized event type string that will
    // deserialize to Other(String).
    let event = PolicyEvent {
        event_id: "integ-unknown".to_string(),
        event_type: PolicyEventType::Other("remote.session.unknown_action".to_string()),
        timestamp: Utc::now(),
        session_id: None,
        data: PolicyEventData::Cua(base_cua_data("unknown")),
        metadata: None,
        context: None,
    };

    let err = map_policy_event(&event).unwrap_err();
    assert!(
        err.to_string().contains("unsupported eventType"),
        "unknown event types should fail closed: {}",
        err
    );
}

/// CUA event type with wrong data type fails validation.
#[test]
fn cua_event_type_with_wrong_data_rejects() {
    let event = PolicyEvent {
        event_id: "integ-mismatch".to_string(),
        event_type: PolicyEventType::InputInject,
        timestamp: Utc::now(),
        session_id: None,
        data: PolicyEventData::File(FileEventData {
            path: "/tmp/test".to_string(),
            operation: None,
            content_base64: None,
            content: None,
            content_hash: None,
        }),
        metadata: None,
        context: None,
    };

    let err = map_policy_event(&event).unwrap_err();
    assert!(
        err.to_string().contains("does not match"),
        "mismatched event type + data should fail: {}",
        err
    );
}

/// Full JSON deserialization of a CUA policy event.
#[test]
fn cua_event_full_json_deserialization() {
    let json = serde_json::json!({
        "eventId": "json-001",
        "eventType": "remote.clipboard",
        "timestamp": "2026-02-18T12:00:00Z",
        "sessionId": "sess-json",
        "data": {
            "type": "cua",
            "cuaAction": "clipboard",
            "direction": "write"
        }
    });

    let event: PolicyEvent = serde_json::from_value(json).unwrap();
    assert_eq!(event.event_type, PolicyEventType::ClipboardTransfer);

    let mapped = map_policy_event(&event).unwrap();
    match &mapped.action {
        MappedGuardAction::Custom { custom_type, data } => {
            assert_eq!(custom_type, "remote.clipboard");
            assert_eq!(data["direction"], "write");
        }
        other => panic!("expected Custom, got {:?}", other),
    }
}
