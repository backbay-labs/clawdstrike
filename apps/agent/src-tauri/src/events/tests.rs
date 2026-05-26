#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::dedupe::EventDeduper;
use super::types::should_publish_polled_event;
use super::{DaemonEvent, EventManager, PolicyEvent};

#[test]
fn test_policy_event_deserialize() {
    let json = r#"{
        "id": "123",
        "timestamp": "2024-01-01T00:00:00Z",
        "action_type": "file_access",
        "target": "/etc/passwd",
        "decision": "blocked",
        "guard": "fs_blocklist",
        "severity": "high"
    }"#;

    let event: PolicyEvent = match serde_json::from_str(json) {
        Ok(value) => value,
        Err(err) => panic!("failed to parse event fixture: {err}"),
    };
    assert_eq!(event.id, "123");
    assert!(event.normalized_decision().is_blocked());
}

#[test]
fn daemon_event_policy_updated_deserializes() {
    let json = r#"{"type":"policy_updated","version":"1.2.0"}"#;
    let event: DaemonEvent = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => panic!("failed to parse policy_updated event: {err}"),
    };
    assert!(matches!(event, DaemonEvent::PolicyUpdated { .. }));
}

#[test]
fn daemon_event_violation_deserializes() {
    let json = r#"{"type":"violation","guard":"fs_blocklist","severity":"high","target":"/etc/shadow","session_id":"s-1","agent_id":"a-1"}"#;
    let event: DaemonEvent = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => panic!("failed to parse violation event: {err}"),
    };
    match event {
        DaemonEvent::Violation {
            guard,
            session_id,
            agent_id,
            ..
        } => {
            assert_eq!(guard.as_deref(), Some("fs_blocklist"));
            assert_eq!(session_id.as_deref(), Some("s-1"));
            assert_eq!(agent_id.as_deref(), Some("a-1"));
        }
        other => panic!("expected Violation, got {:?}", other),
    }
}

#[test]
fn daemon_event_violation_deserializes_without_attribution() {
    let json = r#"{"type":"violation","guard":"fs_blocklist","severity":"high"}"#;
    let event: DaemonEvent = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => panic!("failed to parse violation event: {err}"),
    };
    match event {
        DaemonEvent::Violation {
            session_id,
            agent_id,
            ..
        } => {
            assert!(session_id.is_none());
            assert!(agent_id.is_none());
        }
        other => panic!("expected Violation, got {:?}", other),
    }
}

#[test]
fn daemon_event_posture_transition_deserializes() {
    let json = r#"{"type":"session_posture_transition","session_id":"s-1","from":"standard","to":"restricted"}"#;
    let event: DaemonEvent = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => panic!("failed to parse posture transition event: {err}"),
    };
    assert!(matches!(
        event,
        DaemonEvent::SessionPostureTransition { .. }
    ));
}

#[test]
fn daemon_event_agent_heartbeat_deserializes() {
    let json = r#"{"type":"agent_heartbeat","endpoint_agent_id":"agent-1","runtime_agent_id":"runtime-1","runtime_agent_kind":"desktop","session_id":"s-1","posture":"standard","policy_version":"1.0.0","daemon_version":"0.2.7","timestamp":"2026-03-06T03:49:39Z"}"#;
    let event: DaemonEvent = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => panic!("failed to parse agent heartbeat event: {err}"),
    };
    assert!(matches!(
        event,
        DaemonEvent::AgentHeartbeat {
            endpoint_agent_id: Some(ref agent_id),
            runtime_agent_id: Some(ref runtime_id),
            ..
        } if agent_id == "agent-1" && runtime_id == "runtime-1"
    ));
}

/// Verify that handle_sse_message dispatches daemon events using the SSE event-type
/// field (how hushd actually sends them) rather than requiring "type" in the JSON data.
#[tokio::test]
async fn sse_event_field_dispatches_daemon_events() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut daemon_rx = mgr.subscribe_daemon_events();
    let mut events_rx = mgr.subscribe();

    // hushd sends: event: policy_updated\ndata: {"version":"2.0.0"}
    // Note: no "type" key in the JSON payload.
    mgr.handle_sse_message_for_test("policy_updated", r#"{"version":"2.0.0"}"#)
        .await
        .expect("should dispatch policy_updated");

    let evt = daemon_rx
        .try_recv()
        .expect("should have received daemon event");
    assert!(matches!(evt, DaemonEvent::PolicyUpdated { version: Some(v) } if v == "2.0.0"));

    // violation with SSE event field — should produce both a PolicyEvent and a DaemonEvent
    mgr.handle_sse_message_for_test(
        "violation",
        r#"{"event_id":"ev-v7","guard":"fs_blocklist","severity":"high","allowed":false,"action_type":"file_access","target":"/etc/shadow","session_id":"s-1","agent_id":"a-1"}"#,
    )
    .await
    .expect("should dispatch violation");

    // Violation should produce a PolicyEvent via the unified path.
    let policy_evt = events_rx
        .try_recv()
        .expect("violation should produce a PolicyEvent");
    assert_eq!(policy_evt.id, "ev-v7");
    assert_eq!(policy_evt.session_id.as_deref(), Some("s-1"));
    assert_eq!(policy_evt.agent_id.as_deref(), Some("a-1"));
    assert!(policy_evt.normalized_decision().is_blocked());

    // Violation should also produce a DaemonEvent for logging.
    let evt = daemon_rx
        .try_recv()
        .expect("should have received violation event");
    assert!(
        matches!(evt, DaemonEvent::Violation { guard: Some(g), session_id: Some(s), .. } if g == "fs_blocklist" && s == "s-1")
    );

    mgr.handle_sse_message_for_test(
        "agent_heartbeat",
        r#"{"endpoint_agent_id":"agent-1","runtime_agent_id":"runtime-1","runtime_agent_kind":"desktop","session_id":"s-1","posture":"standard","policy_version":"1.0.0","daemon_version":"0.2.7","timestamp":"2026-03-06T03:49:39Z"}"#,
    )
    .await
    .expect("should dispatch agent heartbeat");

    let evt = daemon_rx
        .try_recv()
        .expect("should have received agent heartbeat event");
    assert!(matches!(
        evt,
        DaemonEvent::AgentHeartbeat {
            endpoint_agent_id: Some(ref agent_id),
            posture: Some(ref posture),
            ..
        } if agent_id == "agent-1" && posture == "standard"
    ));
}

/// Verify that audit events (no special SSE event field) still parse correctly.
#[tokio::test]
async fn sse_default_event_dispatches_audit() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    let data = r#"{"id":"ev-1","timestamp":"2024-01-01T00:00:00Z","action_type":"file_access","decision":"blocked"}"#;
    mgr.handle_sse_message_for_test("message", data)
        .await
        .expect("should dispatch audit event");

    let evt = events_rx
        .try_recv()
        .expect("should have received policy event");
    assert_eq!(evt.id, "ev-1");
}

/// Malformed JSON in a known daemon event type must return an error,
/// not silently create a phantom event with all-None fields.
#[tokio::test]
async fn sse_malformed_json_returns_error() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut daemon_rx = mgr.subscribe_daemon_events();

    let result = mgr
        .handle_sse_message_for_test("violation", "not valid json{{{")
        .await;
    assert!(result.is_err(), "malformed JSON should be an error");

    // No phantom event should have been emitted.
    assert!(daemon_rx.try_recv().is_err());
}

/// Non-object JSON payloads (arrays, strings) for check/violation must be rejected
/// rather than producing a phantom PolicyEvent with action_type="unknown".
#[tokio::test]
async fn sse_non_object_json_rejects_for_check_and_violation() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    for event_type in &["check", "violation"] {
        let result = mgr
            .handle_sse_message_for_test(event_type, r#"[1, 2, 3]"#)
            .await;
        assert!(
            result.is_err(),
            "non-object JSON should be rejected for {event_type}"
        );

        let result = mgr
            .handle_sse_message_for_test(event_type, r#""just a string""#)
            .await;
        assert!(
            result.is_err(),
            "string JSON should be rejected for {event_type}"
        );
    }

    // No phantom events should have been emitted.
    assert!(events_rx.try_recv().is_err());
}

#[test]
fn deduper_drops_replays() {
    let mut deduper = EventDeduper::new(3);
    assert!(deduper.insert_if_new("a"));
    assert!(!deduper.insert_if_new("a"));
    assert!(deduper.insert_if_new("b"));
    assert!(deduper.insert_if_new("c"));
    assert!(deduper.insert_if_new("d"));
    // "a" falls out of the dedupe window and can re-appear if needed.
    assert!(deduper.insert_if_new("a"));
}

#[test]
fn policy_event_with_session_and_agent_ids() {
    let json = r#"{
        "id": "ev-100",
        "timestamp": "2024-01-01T00:00:00Z",
        "action_type": "file_access",
        "target": "/etc/passwd",
        "decision": "blocked",
        "guard": "fs_blocklist",
        "severity": "high",
        "session_id": "sess-abc",
        "agent_id": "agent-xyz"
    }"#;

    let event: PolicyEvent = serde_json::from_str(json).expect("should parse with ids");
    assert_eq!(event.session_id.as_deref(), Some("sess-abc"));
    assert_eq!(event.agent_id.as_deref(), Some("agent-xyz"));
}

#[test]
fn policy_event_without_session_and_agent_ids() {
    let json = r#"{
        "id": "ev-101",
        "timestamp": "2024-01-01T00:00:00Z",
        "action_type": "egress",
        "decision": "allowed"
    }"#;

    let event: PolicyEvent = serde_json::from_str(json).expect("should parse without ids");
    assert!(event.session_id.is_none());
    assert!(event.agent_id.is_none());
}

#[tokio::test]
async fn sse_check_event_propagates_session_agent_ids() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    let data = r#"{"action_type":"file_access","target":"/etc/shadow","allowed":false,"guard":"fs_blocklist","policy_hash":"abc123","session_id":"s-42","agent_id":"a-7"}"#;
    mgr.handle_sse_message_for_test("check", data)
        .await
        .expect("should handle check with ids");

    let evt = events_rx.try_recv().expect("should have received event");
    assert_eq!(evt.session_id.as_deref(), Some("s-42"));
    assert_eq!(evt.agent_id.as_deref(), Some("a-7"));
    assert_eq!(evt.decision, "blocked");
}

#[tokio::test]
async fn sse_allowed_check_event_is_not_published() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    let data =
        r#"{"action_type":"file_access","target":"/tmp/x","allowed":true,"guard":"fs_allow"}"#;
    mgr.handle_sse_message_for_test("check", data)
        .await
        .expect("should handle allowed check event");

    assert!(
        events_rx.try_recv().is_err(),
        "allowed check should not be published to policy channel"
    );
}

#[tokio::test]
async fn sse_allowed_warning_check_event_is_published_as_warn() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    let data = r#"{"action_type":"file_access","target":"/tmp/x","allowed":true,"guard":"fs_allow","severity":"warning"}"#;
    mgr.handle_sse_message_for_test("check", data)
        .await
        .expect("should handle warning check event");

    let evt = events_rx
        .try_recv()
        .expect("warning check should be published");
    assert_eq!(evt.decision, "warn");
}

/// Verify that SSE events with a stable event_id from hushd are deduped against the same
/// events arriving via poll_once().
#[tokio::test]
async fn sse_and_poll_dedup_with_stable_event_id() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    // Simulate SSE check event with stable event_id (as hushd now sends).
    let data = r#"{"event_id":"019abc-v7","action_type":"file_access","target":"/etc/shadow","allowed":false,"guard":"fs_blocklist","session_id":"s-1","agent_id":"a-1"}"#;
    mgr.handle_sse_message_for_test("check", data)
        .await
        .expect("should handle check event");

    let evt = events_rx
        .try_recv()
        .expect("should have received policy event");
    assert_eq!(evt.id, "019abc-v7", "should use stable ID from hushd");

    // Simulate the same event arriving via poll_once (audit API returns same ID).
    let poll_event = PolicyEvent {
        id: "019abc-v7".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        action_type: "file_access".to_string(),
        target: Some("/etc/shadow".to_string()),
        decision: "blocked".to_string(),
        guard: Some("fs_blocklist".to_string()),
        severity: Some("high".to_string()),
        message: None,
        details: serde_json::Value::Null,
        session_id: Some("s-1".to_string()),
        agent_id: Some("a-1".to_string()),
    };
    mgr.publish_event_if_new_for_test(poll_event).await;

    // Should be deduped — no new event on the channel.
    assert!(
        events_rx.try_recv().is_err(),
        "duplicate event should be deduped"
    );
}

#[tokio::test]
async fn poll_filter_suppresses_allowed_events_and_keeps_blocks() {
    let mgr = EventManager::new("http://localhost:0".to_string(), None);
    let mut events_rx = mgr.subscribe();

    for i in 0..500usize {
        let allowed = PolicyEvent {
            id: format!("allow-{i}"),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            action_type: "file_access".to_string(),
            target: Some(format!("/tmp/allowed-{i}")),
            decision: "allowed".to_string(),
            guard: Some("fs_allow".to_string()),
            severity: None,
            message: None,
            details: serde_json::Value::Null,
            session_id: None,
            agent_id: None,
        };
        if should_publish_polled_event(&allowed) {
            mgr.publish_event_if_new_for_test(allowed).await;
        }
    }

    let blocked = PolicyEvent {
        id: "blocked-1".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        action_type: "file_access".to_string(),
        target: Some("/etc/shadow".to_string()),
        decision: "blocked".to_string(),
        guard: Some("fs_blocklist".to_string()),
        severity: Some("high".to_string()),
        message: None,
        details: serde_json::Value::Null,
        session_id: None,
        agent_id: None,
    };
    if should_publish_polled_event(&blocked) {
        mgr.publish_event_if_new_for_test(blocked).await;
    }

    let evt = events_rx
        .try_recv()
        .expect("blocked event should still be published");
    assert_eq!(evt.id, "blocked-1");
    assert!(
        events_rx.try_recv().is_err(),
        "allowed poll events should be suppressed"
    );
}
