//! Event payload types: `PolicyEvent`, `DaemonEvent`, and decision helpers.

use crate::decision::NormalizedDecision;
use serde::{Deserialize, Serialize};

/// A policy check event from hushd.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvent {
    /// Event ID.
    pub id: String,
    /// Timestamp.
    pub timestamp: String,
    /// Action type (e.g., "file_access", "file_write", "egress", "shell", "mcp_tool", "patch").
    pub action_type: String,
    /// Target (file path, URL, command).
    pub target: Option<String>,
    /// Decision (allow/allowed, block/blocked, warn).
    pub decision: String,
    /// Guard that made the decision.
    pub guard: Option<String>,
    /// Severity level.
    pub severity: Option<String>,
    /// Human-readable message.
    pub message: Option<String>,
    /// Additional details.
    #[serde(default)]
    pub details: serde_json::Value,
    /// Session that triggered this event.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Agent that triggered this event.
    #[serde(default)]
    pub agent_id: Option<String>,
}

impl PolicyEvent {
    pub fn normalized_decision(&self) -> NormalizedDecision {
        NormalizedDecision::from_str(&self.decision)
    }
}

pub(super) fn should_publish_polled_event(event: &PolicyEvent) -> bool {
    !matches!(event.normalized_decision(), NormalizedDecision::Allowed)
}

pub(super) fn decision_from_allowed_and_severity(
    allowed: bool,
    severity: Option<&str>,
) -> &'static str {
    if !allowed {
        return "blocked";
    }

    let is_warning = severity
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| matches!(value.as_str(), "warn" | "warning" | "medium"))
        .unwrap_or(false);

    if is_warning {
        "warn"
    } else {
        "allowed"
    }
}

/// Daemon-level SSE event types beyond audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonEvent {
    /// Policy was updated on hushd; local cache should refresh.
    PolicyUpdated {
        #[serde(default)]
        version: Option<String>,
    },
    /// A security violation was detected.
    Violation {
        #[serde(default)]
        guard: Option<String>,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        severity: Option<String>,
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        agent_id: Option<String>,
    },
    /// Session posture transitioned (e.g., standard -> restricted).
    SessionPostureTransition {
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        from: Option<String>,
        #[serde(default)]
        to: Option<String>,
    },
    /// Endpoint/runtime heartbeat update from hushd.
    AgentHeartbeat {
        #[serde(default)]
        endpoint_agent_id: Option<String>,
        #[serde(default)]
        runtime_agent_id: Option<String>,
        #[serde(default)]
        runtime_agent_kind: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        posture: Option<String>,
        #[serde(default)]
        policy_version: Option<String>,
        #[serde(default)]
        daemon_version: Option<String>,
        #[serde(default)]
        timestamp: Option<String>,
    },
}
