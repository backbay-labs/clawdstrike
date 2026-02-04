//! Canonical PolicyEvent evaluation endpoint.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::{GuardReport, GuardResult, Severity};
use hush_certification::audit::NewAuditEventV2;

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

fn canonical_severity_for_decision(result: &GuardResult) -> Option<String> {
    if result.allowed && result.severity == Severity::Info {
        return None;
    }

    Some(
        match result.severity {
            Severity::Info => "low",
            Severity::Warning => "medium",
            Severity::Error => "high",
            Severity::Critical => "critical",
        }
        .to_string(),
    )
}

fn decision_from_report(report: &GuardReport, reason_override: Option<String>) -> DecisionJson {
    let overall = &report.overall;
    let warn = overall.allowed && overall.severity == Severity::Warning;
    let denied = !overall.allowed;

    DecisionJson {
        allowed: overall.allowed,
        denied,
        warn,
        guard: if overall.allowed && overall.severity == Severity::Info {
            None
        } else {
            Some(overall.guard.clone())
        },
        severity: canonical_severity_for_decision(overall),
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
) -> Result<Json<PolicyEvalResponse>, (StatusCode, String)> {
    let event = match req {
        EvalRequest::Wrapped { event } => event,
        EvalRequest::Direct(event) => event,
    };

    let mapped = map_policy_event(&event).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let engine = state.engine.read().await;
    let report = engine
        .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
        mapped.context.agent_id.as_deref(),
    );
    if let Err(e) = state.ledger.record(&audit_event) {
        state.metrics.inc_audit_write_failure();
        tracing::warn!(error = %e, "Failed to record audit event");
    }

    // Record to audit ledger v2 (best-effort).
    {
        let policy_yaml = engine.policy().to_yaml().unwrap_or_default();
        let policy_hash = format!("sha256:{}", hush_core::sha256(policy_yaml.as_bytes()).to_hex());

        let organization_id = mapped
            .context
            .organization
            .as_ref()
            .map(|o| o.id.clone())
            .or_else(|| mapped.context.identity.as_ref().and_then(|p| p.organization_id.clone()));

        let provenance = mapped.context.request.as_ref().map(|r| {
            serde_json::json!({
                "requestId": r.request_id,
                "sourceIp": r.source_ip,
                "userAgent": r.user_agent,
                "timestamp": r.timestamp,
            })
        });

        let _ = state.audit_v2.record(NewAuditEventV2 {
            session_id: mapped
                .context
                .session_id
                .clone()
                .unwrap_or_else(|| state.session_id.clone()),
            agent_id: mapped.context.agent_id.clone(),
            organization_id,
            correlation_id: None,
            action_type: mapped.action.action_type().to_string(),
            action_resource: mapped.action.target().unwrap_or_default(),
            action_parameters: Some(serde_json::to_value(&event).unwrap_or(serde_json::Value::Null)),
            action_result: None,
            decision_allowed: report.overall.allowed,
            decision_guard: Some(report.overall.guard.clone()),
            decision_severity: Some(canonical_guard_severity(&report.overall.severity).to_string()),
            decision_reason: Some(report.overall.message.clone()),
            decision_policy_hash: policy_hash,
            provenance,
            extensions: None,
        });
    }

    // Broadcast event
    state.broadcast(DaemonEvent {
        event_type: if decision.allowed {
            "eval"
        } else {
            "violation"
        }
        .to_string(),
        data: serde_json::json!({
            "event_id": event.event_id,
            "event_type": event.event_type.as_str(),
            "allowed": decision.allowed,
            "guard": report.overall.guard,
        }),
    });

    Ok(Json(PolicyEvalResponse {
        version: 1,
        command: "policy_eval",
        decision,
        report: GuardReportJson::from_report(&report),
    }))
}
