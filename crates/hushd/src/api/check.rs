//! Action checking endpoint

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::guards::{GuardContext, GuardResult, Severity};
use clawdstrike::{HushEngine, RequestContext};
use hush_certification::audit::NewAuditEventV2;

use crate::audit::AuditEvent;
use crate::auth::AuthenticatedActor;
use crate::certification_webhooks::emit_webhook_event;
use crate::identity_rate_limit::IdentityRateLimitError;
use crate::siem::types::SecurityEvent;
use crate::state::{AppState, DaemonEvent};

fn parse_egress_target(target: &str) -> Result<(String, u16), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target is empty".to_string());
    }

    // RFC 3986-style IPv6 literal in brackets: "[::1]:443".
    if let Some(rest) = target.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "invalid egress target: missing closing ']'".to_string())?;
        let host = &rest[..end];
        if host.is_empty() {
            return Err("invalid egress target: empty IPv6 host".to_string());
        }
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            443
        } else if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid egress target: invalid port {}", port_str))?
        } else {
            return Err(format!(
                "invalid egress target: unexpected suffix after ']': {}",
                after
            ));
        };
        return Ok((host.to_string(), port));
    }

    // Split on the last ':'; if the suffix is numeric, treat as port.
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if !host.is_empty() && !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit())
        {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid egress target: invalid port {}", port_str))?;
            return Ok((host.to_string(), port));
        }
    }

    Ok((target.to_string(), 443))
}

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
            severity: canonical_guard_severity(&result.severity).to_string(),
            message: result.message,
            details: result.details,
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

/// POST /api/v1/check
pub async fn check_action(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let (default_policy, keypair) = {
        let engine = state.engine.read().await;
        (engine.policy().clone(), engine.keypair().cloned())
    };

    let request_context = RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        source_ip: Some(addr.ip().to_string()),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geo_location: headers
            .get("X-Hush-Country")
            .and_then(|v| v.to_str().ok())
            .map(|c| clawdstrike::GeoLocation {
                country: Some(c.to_string()),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
            }),
        is_vpn: None,
        is_corporate_network: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let mut context = GuardContext::new().with_request(request_context.clone());
    let mut session_for_audit: Option<clawdstrike::SessionContext> = None;
    let mut principal_for_audit: Option<clawdstrike::IdentityPrincipal> = None;
    let mut roles_for_audit: Option<Vec<String>> = None;
    let mut permissions_for_audit: Option<Vec<String>> = None;

    if let Some(session_id) = request.session_id.clone() {
        // Validate session existence + liveness.
        let validation = state
            .sessions
            .validate_session(&session_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !validation.valid {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "invalid_session: {}",
                    validation
                        .reason
                        .as_ref()
                        .map(|r| format!("{r:?}"))
                        .unwrap_or_else(|| "unknown".to_string())
                ),
            ));
        }

        let session = validation.session.ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_validation_missing_session".to_string(),
            )
        })?;

        // Enforce that user sessions can only be used by the same authenticated user.
        if let Some(ext) = actor.as_ref() {
            match &ext.0 {
                AuthenticatedActor::User(principal) => {
                    if principal.id != session.identity.id
                        || principal.issuer != session.identity.issuer
                    {
                        return Err((
                            StatusCode::FORBIDDEN,
                            "session_identity_mismatch".to_string(),
                        ));
                    }
                }
                AuthenticatedActor::ApiKey(key) => {
                    // Allow service accounts to use sessions only when the session is explicitly bound.
                    let bound = session
                        .state
                        .as_ref()
                        .and_then(|s| s.get("bound_api_key_id"))
                        .and_then(|v| v.as_str());
                    let Some(bound_id) = bound else {
                        return Err((
                            StatusCode::FORBIDDEN,
                            "api_key_cannot_use_unbound_sessions".to_string(),
                        ));
                    };
                    if bound_id != key.id.as_str() {
                        return Err((
                            StatusCode::FORBIDDEN,
                            "api_key_session_binding_mismatch".to_string(),
                        ));
                    }
                }
            }
        }

        state
            .sessions
            .validate_session_binding(&session, &request_context)
            .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;

        context = state
            .sessions
            .create_guard_context(&session, Some(&request_context));
        session_for_audit = Some(session);
    } else if let Some(ext) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = &ext.0 {
            let roles = state.rbac.effective_roles_for_identity(principal);
            let perms = state
                .rbac
                .effective_permission_strings_for_roles(&roles)
                .unwrap_or_default();
            principal_for_audit = Some(principal.clone());
            roles_for_audit = Some(roles.clone());
            permissions_for_audit = Some(perms.clone());
            context = context
                .with_identity(principal.clone())
                .with_roles(roles)
                .with_permissions(perms);
        }
    }

    if let Some(agent_id) = request.agent_id.clone() {
        context = context.with_agent_id(agent_id);
    }

    // Identity-based rate limiting (per-user/per-org sliding window).
    let identity_for_rate_limit: Option<&clawdstrike::IdentityPrincipal> = session_for_audit
        .as_ref()
        .map(|s| &s.identity)
        .or(principal_for_audit.as_ref());

    if let Some(identity) = identity_for_rate_limit {
        if let Err(err) = state
            .identity_rate_limiter
            .check_and_increment(identity, request.action_type.as_str())
        {
            return match err {
                IdentityRateLimitError::RateLimited { retry_after_secs } => Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("identity_rate_limited_retry_after_secs={retry_after_secs}"),
                )),
                other => Err((StatusCode::INTERNAL_SERVER_ERROR, other.to_string())),
            };
        }
    }

    // Resolve identity-scoped policy for this request and get a compiled engine for it.
    let resolved = state
        .policy_resolver
        .resolve_policy(&default_policy, &context)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resolved_yaml = resolved
        .policy
        .to_yaml()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let policy_hash = hush_core::sha256(resolved_yaml.as_bytes()).to_hex();

    let engine: Arc<HushEngine> = match keypair {
        Some(keypair) => state
            .policy_engine_cache
            .get_or_insert_with(&policy_hash, || {
                Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_keypair(keypair))
            }),
        None => Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_generated_keypair()),
    };

    let result = match request.action_type.as_str() {
        "file_access" => engine.check_file_access(&request.target, &context).await,
        "file_write" => {
            let content = request.content.as_deref().unwrap_or("").as_bytes();
            engine
                .check_file_write(&request.target, content, &context)
                .await
        }
        "egress" => {
            let (host, port) =
                parse_egress_target(&request.target).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            engine.check_egress(&host, port, &context).await
        }
        "shell" => engine.check_shell(&request.target, &context).await,
        "mcp_tool" => {
            let args = request.args.clone().unwrap_or(serde_json::json!({}));
            engine
                .check_mcp_tool(&request.target, &args, &context)
                .await
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

    let warn = result.allowed && result.severity == Severity::Warning;
    state.metrics.observe_check_outcome(result.allowed, warn);

    // Record to audit ledger
    let mut audit_event = AuditEvent::from_guard_result(
        &request.action_type,
        Some(&request.target),
        &result,
        request.session_id.as_deref(),
        request.agent_id.as_deref(),
    );

    // Policy resolver metadata.
    {
        let mut obj = match audit_event.metadata.take() {
            Some(serde_json::Value::Object(obj)) => obj,
            Some(other) => {
                let mut obj = serde_json::Map::new();
                obj.insert("details".to_string(), other);
                obj
            }
            None => serde_json::Map::new(),
        };

        obj.insert(
            "policy_hash".to_string(),
            serde_json::Value::String(policy_hash.clone()),
        );
        obj.insert(
            "contributing_policies".to_string(),
            serde_json::to_value(&resolved.contributing_policies)
                .unwrap_or(serde_json::Value::Null),
        );

        audit_event.metadata = Some(serde_json::Value::Object(obj));
    }

    // Enrich audit metadata with identity/session context when available.
    if let Some(session) = session_for_audit.as_ref() {
        let mut obj = match audit_event.metadata.take() {
            Some(serde_json::Value::Object(obj)) => obj,
            Some(other) => {
                let mut obj = serde_json::Map::new();
                obj.insert("details".to_string(), other);
                obj
            }
            None => serde_json::Map::new(),
        };

        obj.insert(
            "principal".to_string(),
            serde_json::to_value(&session.identity).unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "user_session_id".to_string(),
            serde_json::Value::String(session.session_id.clone()),
        );
        obj.insert(
            "roles".to_string(),
            serde_json::to_value(&session.effective_roles).unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "permissions".to_string(),
            serde_json::to_value(&session.effective_permissions).unwrap_or(serde_json::Value::Null),
        );

        audit_event.metadata = Some(serde_json::Value::Object(obj));
    }

    // If there's an authenticated principal but no session, still attribute the action.
    if session_for_audit.is_none() && principal_for_audit.is_some() {
        let mut obj = match audit_event.metadata.take() {
            Some(serde_json::Value::Object(obj)) => obj,
            Some(other) => {
                let mut obj = serde_json::Map::new();
                obj.insert("details".to_string(), other);
                obj
            }
            None => serde_json::Map::new(),
        };

        obj.insert(
            "principal".to_string(),
            serde_json::to_value(principal_for_audit.as_ref()).unwrap_or(serde_json::Value::Null),
        );
        if let Some(roles) = roles_for_audit.as_ref() {
            obj.insert(
                "roles".to_string(),
                serde_json::to_value(roles).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(perms) = permissions_for_audit.as_ref() {
            obj.insert(
                "permissions".to_string(),
                serde_json::to_value(perms).unwrap_or(serde_json::Value::Null),
            );
        }

        audit_event.metadata = Some(serde_json::Value::Object(obj));
    }

    // Emit canonical SecurityEvent for exporters.
    {
        let ctx = state.security_ctx.read().await.clone();
        let event = SecurityEvent::from_audit_event(&audit_event, &ctx);
        if let Err(err) = event.validate() {
            tracing::warn!(error = %err, "Generated invalid SecurityEvent");
        } else {
            state.emit_security_event(event);
        }
    }

    state.record_audit_event(audit_event);

    let policy_hash_sha256 = format!("sha256:{policy_hash}");

    // Record to audit ledger v2 (best-effort).
    {
        let organization_id = session_for_audit
            .as_ref()
            .and_then(|s| s.identity.organization_id.clone())
            .or_else(|| principal_for_audit.as_ref().and_then(|p| p.organization_id.clone()));

        let provenance = serde_json::json!({
            "sourceIp": request_context.source_ip.clone(),
            "userAgent": request_context.user_agent.clone(),
            "requestId": request_context.request_id.clone(),
            "timestamp": request_context.timestamp.clone(),
        });

        let mut extensions = serde_json::Map::new();
        if let Some(details) = result.details.clone() {
            extensions.insert("guardDetails".to_string(), details);
        }

        if let Some(session) = session_for_audit.as_ref() {
            extensions.insert(
                "userSessionId".to_string(),
                serde_json::Value::String(session.session_id.clone()),
            );
        }

        let _ = state.audit_v2.record(NewAuditEventV2 {
            session_id: request
                .session_id
                .clone()
                .unwrap_or_else(|| state.session_id.clone()),
            agent_id: request.agent_id.clone(),
            organization_id,
            correlation_id: None,
            action_type: request.action_type.clone(),
            action_resource: request.target.clone(),
            action_parameters: request.args.clone(),
            action_result: None,
            decision_allowed: result.allowed,
            decision_guard: Some(result.guard.clone()),
            decision_severity: Some(canonical_guard_severity(&result.severity).to_string()),
            decision_reason: Some(result.message.clone()),
            decision_policy_hash: policy_hash_sha256.clone(),
            provenance: Some(provenance),
            extensions: Some(serde_json::Value::Object(extensions)),
        });
    }

    let action_type = request.action_type.clone();
    let target = request.target.clone();
    let session_id = request.session_id.clone();
    let agent_id = request.agent_id.clone();

    // Broadcast event
    state.broadcast(DaemonEvent {
        event_type: if result.allowed { "check" } else { "violation" }.to_string(),
        data: serde_json::json!({
            "action_type": &action_type,
            "target": &target,
            "allowed": result.allowed,
            "guard": &result.guard,
            "policy_hash": &policy_hash,
        }),
    });

    if !result.allowed {
        emit_webhook_event(
            state.clone(),
            "violation.detected",
            serde_json::json!({
                "actionType": &action_type,
                "target": &target,
                "guard": &result.guard,
                "severity": canonical_guard_severity(&result.severity),
                "policyHash": &policy_hash_sha256,
                "sessionId": &session_id,
                "agentId": &agent_id,
            }),
        );
    }

    Ok(Json(result.into()))
}
