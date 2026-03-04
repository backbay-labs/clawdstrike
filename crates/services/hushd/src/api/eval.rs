//! Canonical PolicyEvent evaluation endpoint.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::{decision_taxonomy::summarize_decision, GuardReport, GuardResult, Severity};
use hush_certification::audit::NewAuditEventV2;

use crate::api::v1::V1Error;
use crate::audit::AuditEvent;
use crate::policy_event::{map_policy_event, PolicyEvent};
use crate::state::{AppState, DaemonEvent};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EvalRequest {
    Wrapped { event: PolicyEvent },
    Direct(PolicyEvent),
}

#[derive(Clone, Debug, Serialize)]
pub struct DecisionJson {
    pub allowed: bool,
    pub denied: bool,
    pub warn: bool,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GuardResultJson {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GuardReportJson {
    pub overall: GuardResultJson,
    pub per_guard: Vec<GuardResultJson>,
}

impl GuardReportJson {
    pub fn from_report(report: &GuardReport) -> Self {
        Self {
            overall: GuardResultJson::from_result(&report.overall),
            per_guard: report
                .per_guard
                .iter()
                .map(GuardResultJson::from_result)
                .collect(),
        }
    }
}

impl GuardResultJson {
    fn from_result(result: &GuardResult) -> Self {
        Self {
            allowed: result.allowed,
            guard: result.guard.clone(),
            severity: canonical_guard_severity(&result.severity).to_string(),
            message: result.message.clone(),
            details: result.details.clone(),
        }
    }
}

fn canonical_guard_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

fn normalize_identity_component(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn extract_metadata_string_with_aliases(
    value: Option<&serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    let serde_json::Value::Object(obj) = value? else {
        return None;
    };
    for key in keys {
        if let Some(serde_json::Value::String(text)) = obj.get(*key) {
            return Some(text.clone());
        }
    }
    None
}

fn extract_eval_identity(
    metadata: Option<&serde_json::Value>,
    context_agent_id: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let endpoint_agent_id = normalize_identity_component(
        extract_metadata_string_with_aliases(
            metadata,
            &[
                "endpointAgentId",
                "endpoint_agent_id",
                "agentId",
                "agent_id",
            ],
        )
        .as_deref()
        .or(context_agent_id),
    );

    let runtime_agent_id = normalize_identity_component(
        extract_metadata_string_with_aliases(metadata, &["runtimeAgentId", "runtime_agent_id"])
            .as_deref(),
    );
    let runtime_agent_kind = normalize_identity_component(
        extract_metadata_string_with_aliases(metadata, &["runtimeAgentKind", "runtime_agent_kind"])
            .as_deref(),
    )
    .map(|value| value.to_ascii_lowercase());

    (endpoint_agent_id, runtime_agent_id, runtime_agent_kind)
}

type AgentIdentity = (Option<String>, Option<String>, Option<String>);

fn validate_eval_identity(
    endpoint_agent_id: Option<String>,
    runtime_agent_id: Option<String>,
    runtime_agent_kind: Option<String>,
) -> Result<AgentIdentity, V1Error> {
    if runtime_agent_id.is_some() ^ runtime_agent_kind.is_some() {
        return Err(V1Error::bad_request(
            "INVALID_EVENT",
            "runtime_agent_id and runtime_agent_kind must be provided together",
        ));
    }
    if runtime_agent_id.is_some() && endpoint_agent_id.is_none() {
        return Err(V1Error::bad_request(
            "INVALID_EVENT",
            "endpoint_agent_id is required when runtime attribution is present",
        ));
    }
    Ok((endpoint_agent_id, runtime_agent_id, runtime_agent_kind))
}

fn decision_from_report(report: &GuardReport, reason_override: Option<String>) -> DecisionJson {
    let overall = &report.overall;
    let summary = summarize_decision(overall, reason_override.as_deref());

    DecisionJson {
        allowed: overall.allowed,
        denied: summary.denied,
        warn: summary.warn,
        reason_code: summary.reason_code,
        guard: if overall.allowed && overall.severity == Severity::Info {
            None
        } else {
            Some(overall.guard.clone())
        },
        severity: summary.severity,
        message: Some(overall.message.clone()),
        reason: reason_override,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyEvalResponse {
    pub version: u8,
    pub command: &'static str,
    pub decision: DecisionJson,
    pub report: GuardReportJson,
}

/// POST /api/v1/eval
pub async fn eval_policy_event(
    State(state): State<AppState>,
    Json(req): Json<EvalRequest>,
) -> Result<Json<PolicyEvalResponse>, V1Error> {
    let event = match req {
        EvalRequest::Wrapped { event } => event,
        EvalRequest::Direct(event) => event,
    };

    let mapped = map_policy_event(&event)
        .map_err(|e| V1Error::bad_request("INVALID_EVENT", e.to_string()))?;
    let (identity_endpoint, identity_runtime_id, identity_runtime_kind) = extract_eval_identity(
        mapped.context.metadata.as_ref(),
        mapped.context.agent_id.as_deref(),
    );
    let (endpoint_agent_id, runtime_agent_id, runtime_agent_kind) = validate_eval_identity(
        identity_endpoint,
        identity_runtime_id,
        identity_runtime_kind,
    )?;

    let engine = state.engine.read().await;
    let report = engine
        .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
        .await
        .map_err(|e| V1Error::internal("ENGINE_ERROR", e.to_string()))?;

    let decision = decision_from_report(&report, mapped.decision_reason.clone());

    state
        .metrics
        .observe_eval_outcome(decision.allowed, decision.warn);

    // Record to audit ledger (best-effort).
    let target = mapped.action.target();
    let audit_event = AuditEvent::from_guard_result(
        mapped.action.action_type(),
        target.as_deref(),
        &report.overall,
        mapped.context.session_id.as_deref(),
        endpoint_agent_id.as_deref(),
    );
    if let Err(e) = state.ledger.record(&audit_event) {
        state.metrics.inc_audit_write_failure();
        tracing::warn!(error = %e, "Failed to record audit event");
    }

    // Record to audit ledger v2 (best-effort).
    {
        let policy_hash = match engine.policy_hash() {
            Ok(hash) => format!("sha256:{}", hash.to_hex()),
            Err(err) => {
                state.metrics.inc_audit_write_failure();
                tracing::warn!(
                    error = %err,
                    "Failed to derive policy hash for eval audit_v2 event"
                );
                "sha256:unavailable".to_string()
            }
        };

        let organization_id = mapped
            .context
            .organization
            .as_ref()
            .map(|o| o.id.clone())
            .or_else(|| {
                mapped
                    .context
                    .identity
                    .as_ref()
                    .and_then(|p| p.organization_id.clone())
            });

        let provenance = mapped.context.request.as_ref().map(|r| {
            serde_json::json!({
                "requestId": r.request_id,
                "sourceIp": r.source_ip,
                "userAgent": r.user_agent,
                "timestamp": r.timestamp,
            })
        });

        let action_parameters = match serde_json::to_value(&event) {
            Ok(value) => Some(value),
            Err(err) => {
                state.metrics.inc_audit_write_failure();
                tracing::warn!(
                    error = %err,
                    "Failed to serialize eval event for audit_v2 action_parameters"
                );
                None
            }
        };

        let action_resource = mapped
            .action
            .target()
            .unwrap_or_else(|| "<none>".to_string());

        let mut extensions = serde_json::Map::new();
        if let Some(endpoint) = endpoint_agent_id.as_ref() {
            extensions.insert(
                "endpointAgentId".to_string(),
                serde_json::Value::String(endpoint.clone()),
            );
        }
        if let Some(runtime_id) = runtime_agent_id.as_ref() {
            extensions.insert(
                "runtimeAgentId".to_string(),
                serde_json::Value::String(runtime_id.clone()),
            );
        }
        if let Some(runtime_kind) = runtime_agent_kind.as_ref() {
            extensions.insert(
                "runtimeAgentKind".to_string(),
                serde_json::Value::String(runtime_kind.clone()),
            );
        }

        if let Err(err) = state.audit_v2.record(NewAuditEventV2 {
            session_id: mapped
                .context
                .session_id
                .clone()
                .unwrap_or_else(|| state.session_id.clone()),
            agent_id: endpoint_agent_id.clone(),
            organization_id,
            correlation_id: None,
            action_type: mapped.action.action_type().to_string(),
            action_resource,
            action_parameters,
            action_result: None,
            decision_allowed: report.overall.allowed,
            decision_guard: Some(report.overall.guard.clone()),
            decision_severity: Some(canonical_guard_severity(&report.overall.severity).to_string()),
            decision_reason: Some(report.overall.message.clone()),
            decision_policy_hash: policy_hash,
            provenance,
            extensions: (!extensions.is_empty()).then_some(serde_json::Value::Object(extensions)),
        }) {
            state.metrics.inc_audit_write_failure();
            tracing::warn!(error = %err, "Failed to record eval audit_v2 event");
        }
    }

    // Publish to Spine (best-effort, non-blocking).
    if let Some(ref publisher) = state.spine_publisher {
        let decision_json = match serde_json::to_value(&decision) {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "Skipping Spine eval publish: failed to serialize decision payload"
                );
                None
            }
        };
        let event_json = match serde_json::to_value(&event) {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "Skipping Spine eval publish: failed to serialize event payload"
                );
                None
            }
        };
        if let (Some(decision_json), Some(event_json)) = (decision_json, event_json) {
            let policy_ref = engine.policy().name.clone();
            let session_id_ref = mapped.context.session_id.clone();
            let publisher = publisher.clone();
            tokio::spawn(async move {
                if let Err(e) = publisher
                    .publish_eval_receipt(
                        &decision_json,
                        &event_json,
                        &policy_ref,
                        session_id_ref.as_deref(),
                    )
                    .await
                {
                    tracing::warn!(error = %e, "Failed to publish eval receipt to Spine");
                }
            });
        }
    }

    // Broadcast event (SSE) for real-time monitoring + attribution.
    //
    // Keep the payload close to `/api/v1/check` so clients can build a unified
    // attribution stream across both endpoints.
    let action_type = mapped.action.action_type();
    let target = mapped
        .action
        .target()
        .unwrap_or_else(|| "<none>".to_string());
    let session_id = mapped.context.session_id.clone();
    let agent_id = endpoint_agent_id.clone();

    state.broadcast(DaemonEvent {
        event_type: if decision.allowed {
            "eval"
        } else {
            "violation"
        }
        .to_string(),
        data: serde_json::json!({
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "action_type": action_type,
            "target": target,
            "event_type": event.event_type.as_str(),
            "allowed": decision.allowed,
            "guard": report.overall.guard,
            "severity": canonical_guard_severity(&report.overall.severity),
            "message": report.overall.message,
            "session_id": session_id,
            "endpoint_agent_id": agent_id,
            "agent_id": agent_id,
            "runtime_agent_id": runtime_agent_id,
            "runtime_agent_kind": runtime_agent_kind,
        }),
    });

    Ok(Json(PolicyEvalResponse {
        version: 1,
        command: "policy_eval",
        decision,
        report: GuardReportJson::from_report(&report),
    }))
}
