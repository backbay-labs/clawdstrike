//! Audit log endpoints

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::audit::{AuditEvent, AuditFilter, ExportFormat};
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize)]
pub struct AuditQuery {
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by action type
    pub action_type: Option<String>,
    /// Filter by decision (allowed, blocked)
    pub decision: Option<String>,
    /// Filter by session ID
    pub session_id: Option<String>,
    /// Maximum events to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Export format (json, csv, jsonl)
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditResponse {
    pub events: Vec<AuditEvent>,
    pub total: usize,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditStatsResponse {
    pub total_events: usize,
    pub violations: usize,
    pub allowed: usize,
    pub session_id: String,
    pub uptime_secs: i64,
}

/// GET /api/v1/audit
pub async fn query_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let filter = AuditFilter {
        event_type: query.event_type,
        action_type: query.action_type,
        decision: query.decision,
        session_id: query.session_id,
        limit: query.limit,
        offset: query.offset,
        ..Default::default()
    };

    // Handle export formats
    if let Some(format_str) = query.format {
        let required_action = match format_str.to_lowercase().as_str() {
            "csv" | "jsonl" => Action::Export,
            _ => Action::Read,
        };

        require_api_key_scope_or_user_permission(
            actor.as_ref().map(|e| &e.0),
            &state.rbac,
            Scope::Read,
            ResourceType::AuditLog,
            required_action,
        )?;

        let format = match format_str.to_lowercase().as_str() {
            "csv" => ExportFormat::Csv,
            "jsonl" => ExportFormat::Jsonl,
            _ => ExportFormat::Json,
        };

        let data = state
            .ledger
            .export(&filter, format.clone())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let content_type = match format {
            ExportFormat::Csv => "text/csv",
            ExportFormat::Jsonl => "application/x-ndjson",
            ExportFormat::Json => "application/json",
        };

        return Ok(([(header::CONTENT_TYPE, content_type)], data).into_response());
    }

    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let events = state
        .ledger
        .query(&filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut count_filter = filter.clone();
    count_filter.limit = None;
    count_filter.offset = None;
    let total = state
        .ledger
        .count_filtered(&count_filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuditResponse {
        events,
        total,
        limit: query.limit,
        offset: query.offset,
    })
    .into_response())
}

/// GET /api/v1/audit/stats
pub async fn audit_stats(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<AuditStatsResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let total = state
        .ledger
        .count()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Count violations
    let violations = state
        .ledger
        .count_filtered(&AuditFilter {
            decision: Some("blocked".to_string()),
            ..Default::default()
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let allowed = state
        .ledger
        .count_filtered(&AuditFilter {
            decision: Some("allowed".to_string()),
            ..Default::default()
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuditStatsResponse {
        total_events: total,
        violations,
        allowed,
        session_id: state.session_id.clone(),
        uptime_secs: state.uptime_secs(),
    }))
}
