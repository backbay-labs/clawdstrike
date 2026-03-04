//! Audit log endpoints

use axum::{
    extract::{Query, State},
    http::header,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::api::v1::V1Error;
use crate::audit::{serialize_events, AuditError, AuditEvent, AuditFilter, ExportFormat};
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::AppState;

const DEFAULT_AUDIT_LIMIT: usize = 50;
const MAX_AUDIT_LIMIT: usize = 500;

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
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter by runtime agent ID (metadata-backed)
    pub runtime_agent_id: Option<String>,
    /// Filter by runtime agent kind (metadata-backed)
    pub runtime_agent_kind: Option<String>,
    /// Maximum events to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Opaque cursor for pagination (preferred over offset when provided)
    pub cursor: Option<String>,
    /// Export format (json, csv, jsonl)
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditResponse {
    pub events: Vec<AuditEvent>,
    pub total: usize,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditBatchRequest {
    pub events: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditBatchResponse {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditStatsResponse {
    pub total_events: usize,
    pub violations: usize,
    pub allowed: usize,
    pub session_id: String,
    pub uptime_secs: i64,
}

fn normalize_runtime_query(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn metadata_string<'a>(event: &'a AuditEvent, snake_key: &str, camel_key: &str) -> Option<&'a str> {
    let metadata = event.metadata.as_ref()?;
    let obj = metadata.as_object()?;
    obj.get(snake_key)
        .or_else(|| obj.get(camel_key))
        .and_then(|value| value.as_str())
}

fn matches_runtime_filters(
    event: &AuditEvent,
    runtime_id: Option<&str>,
    runtime_kind: Option<&str>,
) -> bool {
    let id_matches = match runtime_id {
        Some(expected) => metadata_string(event, "runtime_agent_id", "runtimeAgentId")
            .map(|value| value.eq_ignore_ascii_case(expected))
            .unwrap_or(false),
        None => true,
    };

    let kind_matches = match runtime_kind {
        Some(expected) => metadata_string(event, "runtime_agent_kind", "runtimeAgentKind")
            .map(|value| value.eq_ignore_ascii_case(expected))
            .unwrap_or(false),
        None => true,
    };

    id_matches && kind_matches
}

fn decode_cursor(raw: Option<&str>) -> Option<usize> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| {
            value
                .strip_prefix("off_")
                .unwrap_or(value)
                .parse::<usize>()
                .ok()
        })
}

fn encode_cursor(offset: usize) -> String {
    format!("off_{offset}")
}

fn is_duplicate_audit_error(err: &AuditError) -> bool {
    match err {
        AuditError::Database(db) => {
            let text = db.to_string();
            text.contains("UNIQUE constraint failed: audit_events.id")
                || text.contains("PRIMARY KEY")
                || text.contains("constraint failed")
        }
        _ => false,
    }
}

/// POST /api/v1/audit/batch
pub async fn ingest_audit_batch(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<AuditBatchRequest>,
) -> Result<Json<AuditBatchResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::AuditLog,
        Action::Create,
    )?;

    if request.events.len() > 5_000 {
        return Err(V1Error::bad_request(
            "AUDIT_BATCH_TOO_LARGE",
            "batch exceeds maximum size of 5000 events",
        ));
    }

    let mut accepted = 0usize;
    let mut duplicates = 0usize;
    let mut rejected = 0usize;

    for raw in request.events {
        let event: AuditEvent = match serde_json::from_value(raw) {
            Ok(event) => event,
            Err(_) => {
                rejected += 1;
                continue;
            }
        };

        match state.ledger.record_async(event.clone()).await {
            Ok(()) => {
                accepted += 1;
                state.metrics.inc_audit_event();
                if let Some(forwarder) = &state.audit_forwarder {
                    forwarder.try_enqueue(event);
                }
            }
            Err(err) if is_duplicate_audit_error(&err) => {
                duplicates += 1;
            }
            Err(err) => {
                rejected += 1;
                state.metrics.inc_audit_write_failure();
                tracing::warn!(error = %err, "Failed to ingest audit batch event");
            }
        }
    }

    Ok(Json(AuditBatchResponse {
        accepted,
        duplicates,
        rejected,
    }))
}

/// GET /api/v1/audit
pub async fn query_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, V1Error> {
    let runtime_agent_id = normalize_runtime_query(query.runtime_agent_id.as_deref());
    let runtime_agent_kind = normalize_runtime_query(query.runtime_agent_kind.as_deref());
    let use_runtime_filters = runtime_agent_id.is_some() || runtime_agent_kind.is_some();
    let limit = query
        .limit
        .unwrap_or(DEFAULT_AUDIT_LIMIT)
        .clamp(1, MAX_AUDIT_LIMIT);
    let cursor_offset = decode_cursor(query.cursor.as_deref());
    let offset = cursor_offset.unwrap_or_else(|| query.offset.unwrap_or(0));

    let filter = AuditFilter {
        event_type: query.event_type,
        action_type: query.action_type,
        decision: query.decision,
        session_id: query.session_id,
        agent_id: query.agent_id,
        limit: Some(limit),
        offset: Some(offset),
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

        let export_filter = AuditFilter {
            limit: None,
            offset: None,
            ..filter.clone()
        };
        let data = if use_runtime_filters {
            let mut events = state
                .ledger
                .query_async(export_filter)
                .await
                .map_err(|e| V1Error::internal("AUDIT_EXPORT_ERROR", e.to_string()))?;
            events.retain(|event| {
                matches_runtime_filters(
                    event,
                    runtime_agent_id.as_deref(),
                    runtime_agent_kind.as_deref(),
                )
            });
            serialize_events(&events, &format)
                .map_err(|e| V1Error::internal("AUDIT_EXPORT_ERROR", e.to_string()))?
        } else {
            state
                .ledger
                .export_async(export_filter, format.clone())
                .await
                .map_err(|e| V1Error::internal("AUDIT_EXPORT_ERROR", e.to_string()))?
        };

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

    let (events, total) = if use_runtime_filters {
        let mut all = state
            .ledger
            .query_async(AuditFilter {
                limit: None,
                offset: None,
                ..filter.clone()
            })
            .await
            .map_err(|e| V1Error::internal("AUDIT_QUERY_ERROR", e.to_string()))?;
        all.retain(|event| {
            matches_runtime_filters(
                event,
                runtime_agent_id.as_deref(),
                runtime_agent_kind.as_deref(),
            )
        });
        let total = all.len();
        let page = all.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
        (page, total)
    } else {
        let count_filter = AuditFilter {
            limit: None,
            offset: None,
            ..filter.clone()
        };
        let events = state
            .ledger
            .query_async(filter)
            .await
            .map_err(|e| V1Error::internal("AUDIT_QUERY_ERROR", e.to_string()))?;
        let total = state
            .ledger
            .count_filtered_async(count_filter)
            .await
            .map_err(|e| V1Error::internal("AUDIT_COUNT_ERROR", e.to_string()))?;
        (events, total)
    };
    let next_offset = offset.saturating_add(events.len());
    let has_more = next_offset < total;
    let next_cursor = if has_more {
        Some(encode_cursor(next_offset))
    } else {
        None
    };

    Ok(Json(AuditResponse {
        events,
        total,
        limit: Some(limit),
        offset: Some(offset),
        next_cursor,
        has_more: Some(has_more),
    })
    .into_response())
}

/// GET /api/v1/audit/stats
pub async fn audit_stats(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<AuditStatsResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let total = state
        .ledger
        .count_async()
        .await
        .map_err(|e| V1Error::internal("AUDIT_COUNT_ERROR", e.to_string()))?;

    // Count violations
    let violations = state
        .ledger
        .count_filtered_async(AuditFilter {
            decision: Some("blocked".to_string()),
            ..Default::default()
        })
        .await
        .map_err(|e| V1Error::internal("AUDIT_COUNT_ERROR", e.to_string()))?;

    let allowed = state
        .ledger
        .count_filtered_async(AuditFilter {
            decision: Some("allowed".to_string()),
            ..Default::default()
        })
        .await
        .map_err(|e| V1Error::internal("AUDIT_COUNT_ERROR", e.to_string()))?;

    Ok(Json(AuditStatsResponse {
        total_events: total,
        violations,
        allowed,
        session_id: state.session_id.clone(),
        uptime_secs: state.uptime_secs(),
    }))
}
