//! Action checking endpoint

use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};

use crate::api::v1::V1Error;
use serde::{Deserialize, Serialize};

use clawdstrike::guards::{GuardAction, GuardContext, GuardResult, Severity};
use clawdstrike::{
    EnclaveResolver, HushEngine, OriginContext, OriginRuntimeState, PostureRuntimeState,
    PostureTransitionRecord, RequestContext,
};
use hush_certification::audit::NewAuditEventV2;

use crate::audit::AuditEvent;
use crate::auth::AuthenticatedActor;
use crate::certification_webhooks::emit_webhook_event;
use crate::identity_rate_limit::IdentityRateLimitError;
use crate::session::{
    origin_state_from_session, origin_state_patch, posture_state_from_session, posture_state_patch,
};
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
    /// Action type: file_access, file_write, egress, shell, mcp_tool, patch, output_send
    pub action_type: String,
    /// Target (path, host:port, tool name)
    pub target: String,
    /// Optional content (for file_write, patch)
    #[serde(default)]
    pub content: Option<String>,
    /// Optional arguments (for mcp_tool)
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    /// Optional origin context for origin-aware enforcement.
    #[serde(default, alias = "originContext")]
    pub origin: Option<OriginContext>,
    /// Optional session ID
    #[serde(default)]
    pub session_id: Option<String>,
    /// Canonical endpoint agent ID.
    #[serde(default, alias = "agent_id")]
    pub endpoint_agent_id: Option<String>,
    /// Optional runtime agent ID (nested AI/runtime process on endpoint agent)
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    /// Optional runtime agent kind (claude_code, openclaw, mcp, etc.)
    #[serde(default)]
    pub runtime_agent_kind: Option<String>,
}

type AgentIdentity = (Option<String>, Option<String>, Option<String>);

fn normalize_identity_component(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn normalize_and_validate_agent_identity(
    endpoint_agent_id: Option<&str>,
    runtime_agent_id: Option<&str>,
    runtime_agent_kind: Option<&str>,
) -> Result<AgentIdentity, V1Error> {
    let endpoint_agent_id = normalize_identity_component(endpoint_agent_id);
    let runtime_agent_id = normalize_identity_component(runtime_agent_id);
    let runtime_agent_kind =
        normalize_identity_component(runtime_agent_kind).map(|value| value.to_ascii_lowercase());

    if runtime_agent_id.is_some() ^ runtime_agent_kind.is_some() {
        return Err(V1Error::bad_request(
            "INVALID_AGENT_IDENTITY",
            "runtime_agent_id and runtime_agent_kind must be provided together",
        ));
    }

    if runtime_agent_id.is_some() && endpoint_agent_id.is_none() {
        return Err(V1Error::bad_request(
            "INVALID_AGENT_IDENTITY",
            "endpoint_agent_id is required when runtime attribution is present",
        ));
    }

    Ok((endpoint_agent_id, runtime_agent_id, runtime_agent_kind))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckResponse {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureInfo {
    pub state: String,
    pub budgets: HashMap<String, PostureBudgetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<PostureTransitionInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureBudgetInfo {
    pub used: u64,
    pub limit: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureTransitionInfo {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub at: String,
}

impl From<GuardResult> for CheckResponse {
    fn from(result: GuardResult) -> Self {
        Self {
            allowed: result.allowed,
            guard: result.guard,
            severity: canonical_guard_severity(&result.severity).to_string(),
            message: result.message,
            details: result.details,
            posture: None,
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

fn posture_info_from_runtime(
    posture: &PostureRuntimeState,
    transition: Option<&PostureTransitionRecord>,
) -> PostureInfo {
    let budgets = posture
        .budgets
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                PostureBudgetInfo {
                    used: v.used,
                    limit: v.limit,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    PostureInfo {
        state: posture.current_state.clone(),
        budgets,
        transition: transition.map(|record| PostureTransitionInfo {
            from: record.from.clone(),
            to: record.to.clone(),
            trigger: record.trigger.clone(),
            at: record.at.clone(),
        }),
    }
}

fn resolve_request_origin_enclave(
    request: &CheckRequest,
    policy: &clawdstrike::Policy,
) -> Option<clawdstrike::ResolvedEnclave> {
    request
        .origin
        .as_ref()
        .and_then(|origin| policy.origins.as_ref().map(|origins| (origin, origins)))
        .and_then(|(origin, origins)| EnclaveResolver::resolve(origin, origins).ok())
}

fn origin_budget_session_required(
    request: &CheckRequest,
    enclave: Option<&clawdstrike::ResolvedEnclave>,
) -> bool {
    let budget_key = match request.action_type.as_str() {
        "mcp_tool" => Some("mcp_tool_calls"),
        "egress" => Some("egress_calls"),
        "shell" => Some("shell_commands"),
        _ => None,
    };

    request.session_id.is_none()
        && budget_key
            .and_then(|key| {
                enclave
                    .and_then(|resolved| resolved.budgets.as_ref())
                    .and_then(|budgets| match key {
                        "mcp_tool_calls" => budgets.mcp_tool_calls,
                        "egress_calls" => budgets.egress_calls,
                        "shell_commands" => budgets.shell_commands,
                        _ => None,
                    })
            })
            .is_some()
}

fn deep_merge_json(target: &mut serde_json::Value, patch: serde_json::Value) {
    let serde_json::Value::Object(patch_obj) = patch else {
        *target = patch;
        return;
    };

    let serde_json::Value::Object(target_obj) = target else {
        *target = serde_json::Value::Object(serde_json::Map::new());
        deep_merge_json(target, serde_json::Value::Object(patch_obj));
        return;
    };

    for (key, value) in patch_obj {
        match (target_obj.get_mut(&key), value) {
            (Some(existing), serde_json::Value::Object(new_obj)) => {
                if existing.is_object() {
                    deep_merge_json(existing, serde_json::Value::Object(new_obj));
                } else {
                    *existing = serde_json::Value::Object(new_obj);
                }
            }
            (_, new_value) => {
                target_obj.insert(key, new_value);
            }
        }
    }
}

/// POST /api/v1/check
pub async fn check_action(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, V1Error> {
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

    let session_lock = if let Some(session_id) = request.session_id.as_deref() {
        Some(state.sessions.acquire_session_lock(session_id).await)
    } else {
        None
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
            .map_err(|e| {
                tracing::error!(error = %e, "session validation failed");
                V1Error::internal("INTERNAL_ERROR", "internal server error")
            })?;

        if !validation.valid {
            return Err(V1Error::forbidden(
                "INVALID_SESSION",
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
            V1Error::internal(
                "SESSION_VALIDATION_ERROR",
                "session_validation_missing_session",
            )
        })?;

        // Enforce that user sessions can only be used by the same authenticated user.
        if let Some(ext) = actor.as_ref() {
            match &ext.0 {
                AuthenticatedActor::User(principal) => {
                    if principal.id != session.identity.id
                        || principal.issuer != session.identity.issuer
                    {
                        return Err(V1Error::forbidden(
                            "SESSION_IDENTITY_MISMATCH",
                            "session_identity_mismatch",
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
                        return Err(V1Error::forbidden(
                            "API_KEY_UNBOUND_SESSION",
                            "api_key_cannot_use_unbound_sessions",
                        ));
                    };
                    if bound_id != key.id.as_str() {
                        return Err(V1Error::forbidden(
                            "API_KEY_SESSION_BINDING_MISMATCH",
                            "api_key_session_binding_mismatch",
                        ));
                    }
                }
            }
        }

        state
            .sessions
            .validate_session_binding(&session, &request_context)
            .map_err(|e| V1Error::forbidden("FORBIDDEN", e.to_string()))?;

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
                .map_err(|e| {
                    tracing::error!(error = %e, "RBAC permission resolution failed");
                    V1Error::internal("RBAC_RESOLUTION_ERROR", "internal server error")
                })?;
            principal_for_audit = Some(principal.clone());
            roles_for_audit = Some(roles.clone());
            permissions_for_audit = Some(perms.clone());
            context = context
                .with_identity(principal.clone())
                .with_roles(roles)
                .with_permissions(perms);
        }
    }

    let (endpoint_agent_id, runtime_agent_id, runtime_agent_kind) =
        normalize_and_validate_agent_identity(
            request.endpoint_agent_id.as_deref(),
            request.runtime_agent_id.as_deref(),
            request.runtime_agent_kind.as_deref(),
        )?;

    if let Some(agent_id) = endpoint_agent_id.clone() {
        context = context.with_agent_id(agent_id);
    }

    if let Some(origin) = request.origin.clone() {
        context = context.with_origin(origin);
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
                IdentityRateLimitError::RateLimited { retry_after_secs } => Err(V1Error::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "IDENTITY_RATE_LIMITED",
                    format!("identity_rate_limited_retry_after_secs={retry_after_secs}"),
                )
                .with_retry_after(retry_after_secs)),
                other => {
                    tracing::error!(error = %other, "identity rate limit check failed");
                    Err(V1Error::internal("INTERNAL_ERROR", "internal server error"))
                }
            };
        }
    }

    // Resolve identity-scoped policy for this request and get a compiled engine for it.
    let resolved = state
        .policy_resolver
        .resolve_policy(&default_policy, &context)
        .map_err(|e| {
            tracing::error!(error = %e, "policy resolution failed");
            V1Error::internal("INTERNAL_ERROR", "internal server error")
        })?;

    let resolved_yaml = resolved
        .policy
        .to_yaml()
        .map_err(|e| {
            tracing::error!(error = %e, "policy YAML serialization failed");
            V1Error::internal("INTERNAL_ERROR", "internal server error")
        })?;
    let policy_hash = hush_core::sha256(resolved_yaml.as_bytes()).to_hex();

    let resolved_origin_enclave = resolve_request_origin_enclave(&request, &resolved.policy);

    if let Some(enclave) = resolved_origin_enclave.clone() {
        if origin_budget_session_required(&request, Some(&enclave)) {
            return Err(V1Error::bad_request(
                "SESSION_ID_REQUIRED",
                "session_id_required_for_origin_budgets",
            ));
        }
        context = context.with_enclave(enclave);
    }

    let engine: Arc<HushEngine> = match keypair {
        Some(keypair) => state
            .policy_engine_cache
            .get_or_insert_with(&policy_hash, || {
                Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_keypair(keypair))
            }),
        None => Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_generated_keypair()),
    };

    let posture_enabled = resolved.policy.posture.is_some();
    if posture_enabled && request.session_id.is_none() {
        return Err(V1Error::bad_request(
            "SESSION_ID_REQUIRED",
            "session_id_required_for_posture_policy",
        ));
    }

    let mut posture_runtime = session_for_audit
        .as_ref()
        .and_then(posture_state_from_session);
    let mut origin_runtime: Option<OriginRuntimeState> = session_for_audit
        .as_ref()
        .and_then(origin_state_from_session);

    let posture_report = match request.action_type.as_str() {
        "file_access" => {
            let action = GuardAction::FileAccess(&request.target);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        "file_write" => {
            let content = request.content.as_deref().unwrap_or("").as_bytes();
            let action = GuardAction::FileWrite(&request.target, content);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        "egress" => {
            let (host, port) = parse_egress_target(&request.target)
                .map_err(|e| V1Error::bad_request("INVALID_EGRESS_TARGET", e))?;
            let action = GuardAction::NetworkEgress(&host, port);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        "shell" => {
            let action = GuardAction::ShellCommand(&request.target);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        "mcp_tool" => {
            let args = request.args.clone().unwrap_or(serde_json::json!({}));
            let action = GuardAction::McpTool(&request.target, &args);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        "patch" => {
            let diff = request.content.as_deref().unwrap_or("");
            let action = GuardAction::Patch(&request.target, diff);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        "output_send" => {
            let text = request.content.clone().ok_or_else(|| {
                V1Error::bad_request("INVALID_OUTPUT_SEND", "content is required for output_send")
            })?;
            let payload = serde_json::json!({
                "text": text,
                "target": request.target.clone(),
                "mime_type": request
                    .args
                    .as_ref()
                    .and_then(|args| args.get("mime_type"))
                    .and_then(|value| value.as_str()),
                "metadata": request.args.clone(),
            });
            let action = GuardAction::Custom("origin.output_send", &payload);
            engine
                .check_action_report_with_runtime(
                    &action,
                    &context,
                    &mut posture_runtime,
                    &mut origin_runtime,
                )
                .await
        }
        _ => {
            return Err(V1Error::bad_request(
                "UNKNOWN_ACTION_TYPE",
                format!("Unknown action type: {}", request.action_type),
            ));
        }
    }
    .map_err(|e| {
        tracing::error!(error = %e, "guard evaluation failed");
        V1Error::internal("INTERNAL_ERROR", "internal server error")
    })?;

    let result = posture_report.guard_report.overall.clone();
    let mut response_posture: Option<PostureInfo> = posture_runtime
        .as_ref()
        .map(|state| posture_info_from_runtime(state, posture_report.transition.as_ref()));

    if let Some(session_id) = request.session_id.as_deref() {
        let mut combined_patch: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(posture) = posture_runtime.as_ref() {
            combined_patch.extend(
                posture_state_patch(posture)
                    .map_err(|e| {
                        tracing::error!(error = %e, "posture state patch failed");
                        V1Error::internal("INTERNAL_ERROR", "internal server error")
                    })?,
            );
        }
        if let Some(origin) = origin_runtime.as_ref() {
            combined_patch.extend(
                origin_state_patch(origin)
                    .map_err(|e| {
                        tracing::error!(error = %e, "origin state patch failed");
                        V1Error::internal("INTERNAL_ERROR", "internal server error")
                    })?,
            );
        }

        if !combined_patch.is_empty() {
            let updated = state
                .sessions
                .merge_state(session_id, combined_patch)
                .map_err(|e| {
                    tracing::error!(error = %e, "session state merge failed");
                    V1Error::internal("INTERNAL_ERROR", "internal server error")
                })?;

            let updated_session = updated.ok_or_else(|| {
                V1Error::not_found(
                    "SESSION_NOT_FOUND",
                    "session_not_found_during_posture_update",
                )
            })?;
            session_for_audit = Some(updated_session.clone());
            response_posture =
                posture_state_from_session(&updated_session)
                    .as_ref()
                    .map(|runtime| {
                        posture_info_from_runtime(runtime, posture_report.transition.as_ref())
                    });
        }

        state
            .sessions
            .touch_session(session_id)
            .map_err(|e| {
                tracing::error!(error = %e, "session touch failed");
                V1Error::internal("INTERNAL_ERROR", "internal server error")
            })?;
    }
    drop(session_lock);

    let warn = result.allowed && result.severity == Severity::Warning;
    state.metrics.observe_check_outcome(result.allowed, warn);
    // Record to audit ledger
    let mut audit_event = AuditEvent::from_guard_result(
        &request.action_type,
        Some(&request.target),
        &result,
        request.session_id.as_deref(),
        endpoint_agent_id.as_deref(),
    );
    let stable_event_id = audit_event.id.clone();
    let stable_timestamp = audit_event.timestamp.to_rfc3339();

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
        if let Some(endpoint_id) = endpoint_agent_id.as_ref() {
            obj.insert(
                "endpoint_agent_id".to_string(),
                serde_json::Value::String(endpoint_id.clone()),
            );
            obj.insert(
                "endpointAgentId".to_string(),
                serde_json::Value::String(endpoint_id.clone()),
            );
        }
        if let Some(runtime_id) = runtime_agent_id.as_ref() {
            obj.insert(
                "runtime_agent_id".to_string(),
                serde_json::Value::String(runtime_id.clone()),
            );
            obj.insert(
                "runtimeAgentId".to_string(),
                serde_json::Value::String(runtime_id.clone()),
            );
        }
        if let Some(runtime_kind) = runtime_agent_kind.as_ref() {
            obj.insert(
                "runtime_agent_kind".to_string(),
                serde_json::Value::String(runtime_kind.clone()),
            );
            obj.insert(
                "runtimeAgentKind".to_string(),
                serde_json::Value::String(runtime_kind.clone()),
            );
        }

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

    if posture_enabled {
        let mut metadata = match audit_event.metadata.take() {
            Some(value) if value.is_object() => value,
            Some(other) => serde_json::json!({ "details": other }),
            None => serde_json::json!({}),
        };
        deep_merge_json(
            &mut metadata,
            serde_json::json!({
                "clawdstrike": {
                    "posture": {
                        "state_before": posture_report.posture_before,
                        "state_after": posture_report.posture_after,
                        "budgets_before": posture_report.budgets_before,
                        "budgets_after": posture_report.budgets_after,
                        "budget_deltas": posture_report.budget_deltas,
                        "transition": posture_report.transition,
                    }
                }
            }),
        );
        audit_event.metadata = Some(metadata);
    }

    if let Some(metadata) = posture_report.guard_report.metadata.as_ref() {
        let mut audit_metadata = match audit_event.metadata.take() {
            Some(value) if value.is_object() => value,
            Some(other) => serde_json::json!({ "details": other }),
            None => serde_json::json!({}),
        };

        if let Some(origin) = metadata.origin.as_ref() {
            deep_merge_json(
                &mut audit_metadata,
                serde_json::json!({
                    "clawdstrike": {
                        "origin": origin,
                    }
                }),
            );
        }

        if let Some(enclave) = metadata.enclave.as_ref() {
            deep_merge_json(
                &mut audit_metadata,
                serde_json::json!({
                    "clawdstrike": {
                        "enclave": enclave,
                    }
                }),
            );
        }

        audit_event.metadata = Some(audit_metadata);
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

    state.record_audit_event_async(audit_event).await;

    let policy_hash_sha256 = format!("sha256:{policy_hash}");

    // Record to audit ledger v2 (best-effort).
    {
        let organization_id = session_for_audit
            .as_ref()
            .and_then(|s| s.identity.organization_id.clone())
            .or_else(|| {
                principal_for_audit
                    .as_ref()
                    .and_then(|p| p.organization_id.clone())
            });

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
        if let Some(origin) = posture_report
            .guard_report
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.origin.as_ref())
        {
            extensions.insert(
                "origin".to_string(),
                serde_json::to_value(origin).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(enclave) = posture_report
            .guard_report
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.enclave.as_ref())
        {
            extensions.insert(
                "enclave".to_string(),
                serde_json::to_value(enclave).unwrap_or(serde_json::Value::Null),
            );
        }

        if let Some(session) = session_for_audit.as_ref() {
            extensions.insert(
                "userSessionId".to_string(),
                serde_json::Value::String(session.session_id.clone()),
            );
        }
        if let Some(endpoint_id) = endpoint_agent_id.as_ref() {
            extensions.insert(
                "endpointAgentId".to_string(),
                serde_json::Value::String(endpoint_id.clone()),
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
            session_id: request
                .session_id
                .clone()
                .unwrap_or_else(|| state.session_id.clone()),
            agent_id: endpoint_agent_id.clone(),
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
        }) {
            state.metrics.inc_audit_write_failure();
            tracing::warn!(error = %err, "Failed to record check audit_v2 event");
        }
    }

    let action_type = request.action_type.clone();
    let target = request.target.clone();
    let session_id = request.session_id.clone();
    let agent_id = endpoint_agent_id.clone();

    // Broadcast event
    state.broadcast(DaemonEvent {
        event_type: if result.allowed { "check" } else { "violation" }.to_string(),
        data: serde_json::json!({
            "event_id": &stable_event_id,
            "timestamp": &stable_timestamp,
            "action_type": &action_type,
            "target": &target,
            "allowed": result.allowed,
            "guard": &result.guard,
            "severity": canonical_guard_severity(&result.severity),
            "message": &result.message,
            "policy_hash": &policy_hash,
            "session_id": &session_id,
            "origin": posture_report.guard_report.metadata.as_ref().and_then(|metadata| metadata.origin.as_ref()),
            "enclave": posture_report.guard_report.metadata.as_ref().and_then(|metadata| metadata.enclave.as_ref()),
            "endpoint_agent_id": &agent_id,
            "agent_id": &agent_id,
            "runtime_agent_id": &runtime_agent_id,
            "runtime_agent_kind": &runtime_agent_kind,
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
                "origin": posture_report.guard_report.metadata.as_ref().and_then(|metadata| metadata.origin.as_ref()),
                "enclave": posture_report.guard_report.metadata.as_ref().and_then(|metadata| metadata.enclave.as_ref()),
                "endpointAgentId": &agent_id,
                "agentId": &agent_id,
                "runtimeAgentId": &runtime_agent_id,
                "runtimeAgentKind": &runtime_agent_kind,
            }),
        );
    }

    let mut response: CheckResponse = result.into();
    response.posture = response_posture.or_else(|| {
        session_for_audit
            .as_ref()
            .and_then(posture_state_from_session)
            .as_ref()
            .map(|runtime| posture_info_from_runtime(runtime, None))
    });

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike::policy::{
        OriginBudgets, OriginDefaultBehavior, OriginMatch, OriginProfile, OriginsConfig,
    };
    use clawdstrike::{OriginProvider, Policy};

    fn policy_with_budgeted_origin() -> Policy {
        let mut policy = Policy::new();
        policy.version = "1.4.0".to_string();
        policy.name = "budgeted-origin".to_string();
        policy.origins = Some(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-budgeted".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(OriginBudgets {
                    mcp_tool_calls: Some(1),
                    ..Default::default()
                }),
                bridge_policy: None,
                explanation: None,
            }],
        });
        policy
    }

    #[test]
    fn check_request_accepts_origin_context_alias() {
        let request: CheckRequest = serde_json::from_value(serde_json::json!({
            "action_type": "mcp_tool",
            "target": "safe_tool",
            "originContext": {
                "provider": "slack",
                "tenantId": "T123",
                "spaceId": "C123",
                "externalParticipants": true,
                "tags": ["provider:slack"]
            }
        }))
        .expect("request should deserialize");

        let origin = request.origin.expect("origin should be present");
        assert_eq!(origin.provider, OriginProvider::Slack);
        assert_eq!(origin.tenant_id.as_deref(), Some("T123"));
        assert_eq!(origin.space_id.as_deref(), Some("C123"));
        assert_eq!(origin.external_participants, Some(true));
    }

    #[test]
    fn budgeted_origin_requires_session_id() {
        let request = CheckRequest {
            action_type: "mcp_tool".to_string(),
            target: "safe_tool".to_string(),
            content: None,
            args: None,
            origin: Some(OriginContext {
                provider: OriginProvider::Slack,
                tags: vec!["provider:slack".to_string()],
                ..OriginContext::default()
            }),
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
        };

        let enclave = resolve_request_origin_enclave(&request, &policy_with_budgeted_origin())
            .expect("origin should resolve");
        assert!(origin_budget_session_required(&request, Some(&enclave)));

        let mut request_with_session = request;
        request_with_session.session_id = Some("sess-123".to_string());
        assert!(!origin_budget_session_required(
            &request_with_session,
            Some(&enclave)
        ));
    }

    #[test]
    fn unbudgeted_origin_action_does_not_require_session_id() {
        let request = CheckRequest {
            action_type: "file_access".to_string(),
            target: "safe_tool".to_string(),
            content: None,
            args: None,
            origin: Some(OriginContext {
                provider: OriginProvider::Slack,
                tags: vec!["provider:slack".to_string()],
                ..OriginContext::default()
            }),
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
        };

        let enclave = resolve_request_origin_enclave(&request, &policy_with_budgeted_origin())
            .expect("origin should resolve");
        assert!(!origin_budget_session_required(&request, Some(&enclave)));
    }

    #[test]
    fn empty_origin_budgets_do_not_require_session_id() {
        let request = CheckRequest {
            action_type: "mcp_tool".to_string(),
            target: "safe_tool".to_string(),
            content: None,
            args: None,
            origin: Some(OriginContext {
                provider: OriginProvider::Slack,
                tags: vec!["provider:slack".to_string()],
                ..OriginContext::default()
            }),
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
        };

        let mut policy = policy_with_budgeted_origin();
        policy.origins.as_mut().expect("origins").profiles[0].budgets =
            Some(OriginBudgets::default());

        let enclave =
            resolve_request_origin_enclave(&request, &policy).expect("origin should resolve");
        assert!(!origin_budget_session_required(&request, Some(&enclave)));
    }
}
