//! Wire types for the hushd session API.

use serde::Deserialize;

/// Inner session object matching hushd's `SessionContext` (snake_case).
/// We only deserialize the fields the agent cares about; serde ignores the rest.
#[derive(Debug, Deserialize)]
pub(super) struct HushdSessionInfo {
    pub(super) session_id: String,
    /// Posture may live in the `state` map; extracted after deserialization.
    #[serde(default)]
    state: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl HushdSessionInfo {
    /// Extract the posture state name from the nested `PostureRuntimeState` object.
    /// hushd stores `state["posture"]` as `{ "current_state": "...", "budgets": {...}, ... }`.
    pub(super) fn posture(&self) -> Option<String> {
        self.state
            .as_ref()
            .and_then(|s| s.get("posture"))
            .and_then(|v| v.get("current_state"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Sum the budget limits across all posture budget counters.
    /// hushd stores budgets at `state["posture"]["budgets"]` as `{ "<name>": { "used": N, "limit": M } }`.
    pub(super) fn budget_limit(&self) -> Option<u64> {
        let budgets = self
            .state
            .as_ref()
            .and_then(|s| s.get("posture"))
            .and_then(|v| v.get("budgets"))
            .and_then(|v| v.as_object())?;
        let total: u64 = budgets
            .values()
            .filter_map(|b| b.get("limit").and_then(|v| v.as_u64()))
            .sum();
        Some(total)
    }

    /// Sum the budget usage across all posture budget counters.
    pub(super) fn budget_used(&self) -> Option<u64> {
        let budgets = self
            .state
            .as_ref()
            .and_then(|s| s.get("posture"))
            .and_then(|v| v.get("budgets"))
            .and_then(|v| v.as_object())?;
        let total: u64 = budgets
            .values()
            .filter_map(|b| b.get("used").and_then(|v| v.as_u64()))
            .sum();
        Some(total)
    }
}

/// hushd session creation response — wraps session in an envelope.
#[derive(Debug, Deserialize)]
pub(super) struct CreateSessionResponse {
    pub(super) session: HushdSessionInfo,
}

/// hushd session status/heartbeat response — same envelope.
#[derive(Debug, Deserialize)]
pub(super) struct GetSessionResponse {
    pub(super) session: HushdSessionInfo,
}
