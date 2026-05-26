//! Offline fail-closed audit event enqueueing for policy checks.

use serde_json::Value;
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub(super) async fn enqueue_offline_audit_event(
    audit_queue: Option<&Arc<crate::daemon::AuditQueue>>,
    action_type: &str,
    target: &str,
    guard: &str,
    severity: &str,
    message: &str,
    session_id: Option<&str>,
    endpoint_agent_id: &str,
    runtime_agent_id: Option<&str>,
    runtime_agent_kind: Option<&str>,
    details: Option<&Value>,
) {
    let Some(queue) = audit_queue else {
        return;
    };

    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "reason".to_string(),
        Value::String("offline_fail_closed".to_string()),
    );
    if let Some(runtime_agent_id) = runtime_agent_id {
        metadata.insert(
            "runtime_agent_id".to_string(),
            Value::String(runtime_agent_id.to_string()),
        );
    }
    if let Some(runtime_agent_kind) = runtime_agent_kind {
        metadata.insert(
            "runtime_agent_kind".to_string(),
            Value::String(runtime_agent_kind.to_string()),
        );
    }
    if let Some(details) = details {
        metadata.insert("details".to_string(), details.clone());
    }

    queue
        .enqueue(serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "violation",
            "action_type": action_type,
            "target": target,
            "decision": "blocked",
            "guard": guard,
            "severity": severity,
            "message": message,
            "session_id": session_id,
            "agent_id": endpoint_agent_id,
            "metadata": Value::Object(metadata),
        }))
        .await;
}
