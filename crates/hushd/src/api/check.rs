//! Action checking endpoint

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use hushclaw::guards::{GuardContext, GuardResult};

use crate::audit::AuditEvent;
use crate::state::{AppState, DaemonEvent};

#[derive(Clone, Debug, Deserialize)]
pub struct CheckRequest {
    /// Action type: file_access, file_write, egress, shell, mcp_tool, patch
    pub action_type: String,
    /// Target (path, host:port, tool name)
    pub target: String,
    /// Optional content (for file_write, patch)
    #[serde(default)]
    pub content: Option<String>,
    /// Optional arguments (for mcp_tool)
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    /// Optional session ID
    #[serde(default)]
    pub session_id: Option<String>,
    /// Optional agent ID
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckResponse {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl From<GuardResult> for CheckResponse {
    fn from(result: GuardResult) -> Self {
        Self {
            allowed: result.allowed,
            guard: result.guard,
            severity: format!("{:?}", result.severity),
            message: result.message,
            details: result.details,
        }
    }
}

/// POST /api/v1/check
pub async fn check_action(
    State(state): State<AppState>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let engine = state.engine.read().await;

    let context = GuardContext::new()
        .with_session_id(request.session_id.clone().unwrap_or_else(|| state.session_id.clone()));

    let result = match request.action_type.as_str() {
        "file_access" => engine.check_file_access(&request.target, &context).await,
        "file_write" => {
            let content = request.content.as_deref().unwrap_or("").as_bytes();
            engine
                .check_file_write(&request.target, content, &context)
                .await
        }
        "egress" => {
            let parts: Vec<&str> = request.target.split(':').collect();
            let host = parts[0];
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
            engine.check_egress(host, port, &context).await
        }
        "shell" => engine.check_shell(&request.target, &context).await,
        "mcp_tool" => {
            let args = request.args.clone().unwrap_or(serde_json::json!({}));
            engine.check_mcp_tool(&request.target, &args, &context).await
        }
        "patch" => {
            let diff = request.content.as_deref().unwrap_or("");
            engine.check_patch(&request.target, diff, &context).await
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unknown action type: {}", request.action_type),
            ));
        }
    };

    let result = result.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Record to audit ledger
    let audit_event = AuditEvent::from_guard_result(
        &request.action_type,
        Some(&request.target),
        &result,
        request.session_id.as_deref(),
        request.agent_id.as_deref(),
    );

    if let Err(e) = state.ledger.record(&audit_event) {
        tracing::warn!(error = %e, "Failed to record audit event");
    }

    // Broadcast event
    state.broadcast(DaemonEvent {
        event_type: if result.allowed { "check" } else { "violation" }.to_string(),
        data: serde_json::json!({
            "action_type": request.action_type,
            "target": request.target,
            "allowed": result.allowed,
            "guard": result.guard,
        }),
    });

    Ok(Json(result.into()))
}
