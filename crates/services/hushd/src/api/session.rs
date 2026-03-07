//! Session management endpoints.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Json,
};

use crate::api::v1::V1Error;
use clawdstrike::{AuthMethod, IdentityPrincipal, IdentityProvider, RequestContext};
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::auth::AuthenticatedActor;
use crate::auth::Scope;
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::session::CreateSessionOptions;
use crate::session::PostureBudgetCounter;
use crate::session::SessionError;
use crate::session::{posture_state_from_session, posture_state_patch, PostureTransitionRecord};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    pub session: clawdstrike::SessionContext,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionResponse {
    pub session: clawdstrike::SessionContext,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TerminateSessionRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminateSessionResponse {
    pub success: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionSessionPostureRequest {
    pub to_state: String,
    pub trigger: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionSessionPostureResponse {
    pub success: bool,
    pub from_state: String,
    pub to_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPostureResponse {
    pub state: String,
    pub entered_at: String,
    pub budgets: std::collections::HashMap<String, PostureBudgetInfo>,
    pub transition_history: Vec<PostureTransitionInfo>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureBudgetInfo {
    pub used: u64,
    pub limit: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureTransitionInfo {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub at: String,
}

fn local_service_principal(request: &RequestContext) -> IdentityPrincipal {
    let mut attributes = HashMap::new();
    if let Some(source_ip) = request.source_ip.as_ref() {
        attributes.insert(
            "source_ip".to_string(),
            serde_json::Value::String(source_ip.clone()),
        );
    }
    if let Some(user_agent) = request.user_agent.as_ref() {
        attributes.insert(
            "user_agent".to_string(),
            serde_json::Value::String(user_agent.clone()),
        );
    }

    IdentityPrincipal {
        id: "local-service".to_string(),
        provider: IdentityProvider::Custom,
        issuer: "hushd://local".to_string(),
        display_name: Some("Local Service".to_string()),
        email: None,
        email_verified: None,
        organization_id: None,
        teams: Vec::new(),
        roles: vec!["local-service".to_string()],
        attributes,
        authenticated_at: chrono::Utc::now().to_rfc3339(),
        auth_method: Some(AuthMethod::ServiceAccount),
        expires_at: None,
    }
}

fn resolve_session_identity(
    auth_enabled: bool,
    actor: Option<AuthenticatedActor>,
    request_ctx: &RequestContext,
) -> Result<IdentityPrincipal, V1Error> {
    match actor {
        Some(AuthenticatedActor::User(principal)) => Ok(principal),
        Some(AuthenticatedActor::ApiKey(_)) => Err(V1Error::forbidden(
            "API_KEY_CANNOT_CREATE_USER_SESSION",
            "api_key_cannot_create_user_session",
        )),
        None if !auth_enabled => Ok(local_service_principal(request_ctx)),
        None => Err(V1Error::unauthorized("UNAUTHENTICATED", "unauthenticated")),
    }
}

/// POST /api/v1/session
pub async fn create_session(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: Option<Json<CreateSessionOptions>>,
) -> Result<Json<CreateSessionResponse>, V1Error> {
    let request_ctx = RequestContext {
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
    let principal =
        resolve_session_identity(state.auth_enabled(), actor.map(|ext| ext.0), &request_ctx)?;

    let mut options = body.map(|Json(v)| v).unwrap_or_default();
    if options.request.is_none() {
        options.request = Some(request_ctx.clone());
    }

    let session = match state.sessions.create_session(principal, Some(options)) {
        Ok(session) => session,
        Err(SessionError::InvalidBinding(_)) => {
            return Err(V1Error::bad_request(
                "INVALID_SESSION_BINDING",
                "invalid_session_binding",
            ));
        }
        Err(err) => return Err(V1Error::internal("SESSION_ERROR", err.to_string())),
    };

    // Audit: session created.
    let principal = session.identity.clone();
    let roles = session.effective_roles.clone();
    let permissions = session.effective_permissions.clone();
    let mut audit = AuditEvent::session_start(&session.session_id, None);
    let is_local_service = matches!(principal.auth_method, Some(AuthMethod::ServiceAccount));
    audit.event_type = if is_local_service {
        "local_service_session_created".to_string()
    } else {
        "user_session_created".to_string()
    };
    audit.message = Some(if is_local_service {
        "Local service session created".to_string()
    } else {
        "User session created".to_string()
    });
    audit.metadata = Some(serde_json::json!({
        "principal": principal,
        "roles": roles,
        "permissions": permissions,
    }));
    if let Err(err) = state.ledger.record(&audit) {
        tracing::warn!(error = %err, "Failed to record audit event");
    }

    Ok(Json(CreateSessionResponse { session }))
}

/// GET /api/v1/session/:id
pub async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<GetSessionResponse>, V1Error> {
    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
        .ok_or_else(|| V1Error::not_found("SESSION_NOT_FOUND", "session_not_found"))?;

    // Users can always fetch their own sessions; otherwise enforce RBAC/scope.
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        match actor {
            AuthenticatedActor::User(principal) => {
                if principal.id == session.identity.id
                    && principal.issuer == session.identity.issuer
                {
                    return Ok(Json(GetSessionResponse { session }));
                }

                // Tenant isolation: avoid cross-org session reads unless super-admin.
                let is_super_admin = state
                    .rbac
                    .effective_roles_for_identity(principal)
                    .iter()
                    .any(|r| r == "super-admin");
                if !is_super_admin {
                    let actor_org = principal.organization_id.as_deref();
                    let session_org = session.identity.organization_id.as_deref();
                    if actor_org.is_some() && session_org.is_some() && actor_org != session_org {
                        return Err(V1Error::forbidden(
                            "CROSS_ORG_SESSION_ACCESS_DENIED",
                            "cross_org_session_access_denied",
                        ));
                    }
                }
            }
            AuthenticatedActor::ApiKey(_) => {}
        }
    }

    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Session,
        Action::Read,
    )?;

    Ok(Json(GetSessionResponse { session }))
}

/// DELETE /api/v1/session/:id
pub async fn terminate_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    body: Option<Json<TerminateSessionRequest>>,
) -> Result<Json<TerminateSessionResponse>, V1Error> {
    let reason = body.and_then(|Json(v)| v.reason);

    // Users can always terminate their own sessions; otherwise enforce RBAC/scope.
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        match actor {
            AuthenticatedActor::User(principal) => {
                if let Some(existing) = state
                    .sessions
                    .get_session(&session_id)
                    .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
                {
                    if principal.id == existing.identity.id
                        && principal.issuer == existing.identity.issuer
                    {
                        let deleted = state
                            .sessions
                            .terminate_session(&session_id, reason.as_deref())
                            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
                        if !deleted {
                            return Err(V1Error::not_found(
                                "SESSION_NOT_FOUND",
                                "session_not_found",
                            ));
                        }

                        let mut audit = AuditEvent::session_start(&session_id, None);
                        audit.event_type = "user_session_terminated".to_string();
                        audit.action_type = "session".to_string();
                        audit.target = Some(session_id.clone());
                        audit.message = Some("User session terminated".to_string());
                        audit.metadata = Some(serde_json::json!({
                            "principal": principal,
                            "reason": reason,
                        }));
                        if let Err(err) = state.ledger.record(&audit) {
                            tracing::warn!(error = %err, "Failed to record audit event");
                        }

                        return Ok(Json(TerminateSessionResponse { success: true }));
                    }
                }

                // Tenant isolation: avoid cross-org session termination unless super-admin.
                let is_super_admin = state
                    .rbac
                    .effective_roles_for_identity(principal)
                    .iter()
                    .any(|r| r == "super-admin");
                if !is_super_admin {
                    if let Some(existing) = state
                        .sessions
                        .get_session(&session_id)
                        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
                    {
                        let actor_org = principal.organization_id.as_deref();
                        let session_org = existing.identity.organization_id.as_deref();
                        if actor_org.is_some() && session_org.is_some() && actor_org != session_org
                        {
                            return Err(V1Error::forbidden(
                                "CROSS_ORG_SESSION_ACCESS_DENIED",
                                "cross_org_session_access_denied",
                            ));
                        }
                    }
                }
            }
            AuthenticatedActor::ApiKey(_) => {}
        }
    }

    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Session,
        Action::Delete,
    )?;

    let deleted = state
        .sessions
        .terminate_session(&session_id, reason.as_deref())
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;

    if !deleted {
        return Err(V1Error::not_found("SESSION_NOT_FOUND", "session_not_found"));
    }

    let mut audit = AuditEvent::session_start(&session_id, None);
    audit.event_type = "user_session_terminated".to_string();
    audit.action_type = "session".to_string();
    audit.target = Some(session_id.clone());
    audit.message = Some("User session terminated".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor.as_ref().map(|e| match &e.0 {
            AuthenticatedActor::ApiKey(key) => serde_json::json!({"type": "api_key", "id": key.id.clone(), "name": key.name.clone()}),
            AuthenticatedActor::User(user) => serde_json::json!({"type": "user", "id": user.id.clone(), "issuer": user.issuer.clone()}),
        }),
        "reason": reason,
    }));
    if let Err(err) = state.ledger.record(&audit) {
        tracing::warn!(error = %err, "Failed to record audit event");
    }

    Ok(Json(TerminateSessionResponse { success: true }))
}

fn to_posture_budget_info(
    budgets: std::collections::HashMap<String, PostureBudgetCounter>,
) -> std::collections::HashMap<String, PostureBudgetInfo> {
    budgets
        .into_iter()
        .map(|(name, counter)| {
            (
                name,
                PostureBudgetInfo {
                    used: counter.used,
                    limit: counter.limit,
                },
            )
        })
        .collect()
}

fn to_posture_transition_info(records: Vec<PostureTransitionRecord>) -> Vec<PostureTransitionInfo> {
    records
        .into_iter()
        .map(|r| PostureTransitionInfo {
            from: r.from,
            to: r.to,
            trigger: r.trigger,
            at: r.at,
        })
        .collect()
}

/// GET /api/v1/session/:id/posture
pub async fn get_session_posture(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<SessionPostureResponse>, V1Error> {
    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
        .ok_or_else(|| V1Error::not_found("SESSION_NOT_FOUND", "session_not_found"))?;

    if let Some(axum::extract::Extension(auth_actor)) = actor.as_ref() {
        match auth_actor {
            AuthenticatedActor::User(principal) => {
                if principal.id != session.identity.id
                    || principal.issuer != session.identity.issuer
                {
                    let is_super_admin = state
                        .rbac
                        .effective_roles_for_identity(principal)
                        .iter()
                        .any(|r| r == "super-admin");
                    if !is_super_admin {
                        let actor_org = principal.organization_id.as_deref();
                        let session_org = session.identity.organization_id.as_deref();
                        if actor_org.is_some() && session_org.is_some() && actor_org != session_org
                        {
                            return Err(V1Error::forbidden(
                                "CROSS_ORG_SESSION_ACCESS_DENIED",
                                "cross_org_session_access_denied",
                            ));
                        }
                    }
                    require_api_key_scope_or_user_permission(
                        actor.as_ref().map(|e| &e.0),
                        &state.rbac,
                        Scope::Read,
                        ResourceType::Session,
                        Action::Read,
                    )?;
                }
            }
            AuthenticatedActor::ApiKey(_) => {
                require_api_key_scope_or_user_permission(
                    actor.as_ref().map(|e| &e.0),
                    &state.rbac,
                    Scope::Read,
                    ResourceType::Session,
                    Action::Read,
                )?;
            }
        }
    }

    let posture = posture_state_from_session(&session)
        .ok_or_else(|| V1Error::not_found("POSTURE_STATE_NOT_FOUND", "posture_state_not_found"))?;

    Ok(Json(SessionPostureResponse {
        state: posture.current_state,
        entered_at: posture.entered_at,
        budgets: to_posture_budget_info(posture.budgets),
        transition_history: to_posture_transition_info(posture.transition_history),
    }))
}

/// POST /api/v1/session/:id/transition
pub async fn transition_session_posture(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<TransitionSessionPostureRequest>,
) -> Result<Json<TransitionSessionPostureResponse>, V1Error> {
    if request.to_state.trim().is_empty() {
        return Err(V1Error::bad_request(
            "TO_STATE_REQUIRED",
            "to_state_required",
        ));
    }
    if request.trigger != "user_approval" && request.trigger != "user_denial" {
        return Err(V1Error::bad_request(
            "INVALID_TRIGGER",
            "trigger_must_be_user_approval_or_user_denial",
        ));
    }

    let _session_guard = state.sessions.acquire_session_lock(&session_id).await;

    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
        .ok_or_else(|| V1Error::not_found("SESSION_NOT_FOUND", "session_not_found"))?;

    let mut owner_allowed = false;
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        match actor {
            AuthenticatedActor::User(principal) => {
                owner_allowed = principal.id == session.identity.id
                    && principal.issuer == session.identity.issuer;
                if !owner_allowed {
                    let is_super_admin = state
                        .rbac
                        .effective_roles_for_identity(principal)
                        .iter()
                        .any(|r| r == "super-admin");
                    if !is_super_admin {
                        let actor_org = principal.organization_id.as_deref();
                        let session_org = session.identity.organization_id.as_deref();
                        if actor_org.is_some() && session_org.is_some() && actor_org != session_org
                        {
                            return Err(V1Error::forbidden(
                                "CROSS_ORG_SESSION_ACCESS_DENIED",
                                "cross_org_session_access_denied",
                            ));
                        }
                    }
                }
            }
            AuthenticatedActor::ApiKey(_) => {}
        }
    }

    if !owner_allowed {
        require_api_key_scope_or_user_permission(
            actor.as_ref().map(|e| &e.0),
            &state.rbac,
            Scope::Admin,
            ResourceType::Session,
            Action::Update,
        )?;
    }

    let mut posture = posture_state_from_session(&session).ok_or_else(|| {
        V1Error::bad_request(
            "POSTURE_STATE_NOT_INITIALIZED",
            "posture_state_not_initialized",
        )
    })?;

    let from_state = posture.current_state.clone();
    let now = chrono::Utc::now().to_rfc3339();
    posture.current_state = request.to_state.clone();
    posture.entered_at = now.clone();
    posture.transition_history.push(PostureTransitionRecord {
        from: from_state.clone(),
        to: request.to_state.clone(),
        trigger: request.trigger.clone(),
        at: now,
    });

    let patch = posture_state_patch(&posture)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    let updated = state
        .sessions
        .merge_state(&session_id, patch)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    if updated.is_none() {
        return Err(V1Error::not_found("SESSION_NOT_FOUND", "session_not_found"));
    }

    let mut audit = AuditEvent::session_start(&session_id, None);
    audit.event_type = "session_posture_transition".to_string();
    audit.action_type = "session_transition".to_string();
    audit.target = Some(session_id.clone());
    audit.message = Some("Session posture transition applied".to_string());
    audit.metadata = Some(serde_json::json!({
        "from_state": from_state,
        "to_state": request.to_state,
        "trigger": request.trigger,
    }));
    if let Err(err) = state.ledger.record(&audit) {
        tracing::warn!(error = %err, "Failed to record audit event");
    }

    Ok(Json(TransitionSessionPostureResponse {
        success: true,
        from_state,
        to_state: posture.current_state,
        message: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> RequestContext {
        RequestContext {
            request_id: "req-1".to_string(),
            source_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("agent-test".to_string()),
            geo_location: None,
            is_vpn: None,
            is_corporate_network: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn resolve_session_identity_uses_local_service_when_auth_disabled() {
        let principal =
            resolve_session_identity(false, None, &sample_request()).expect("principal");

        assert_eq!(principal.id, "local-service");
        assert_eq!(principal.issuer, "hushd://local");
        assert_eq!(principal.auth_method, Some(AuthMethod::ServiceAccount));
    }

    #[test]
    fn resolve_session_identity_rejects_missing_actor_when_auth_enabled() {
        let err = resolve_session_identity(true, None, &sample_request())
            .expect_err("missing actor should be unauthorized");

        assert_eq!(err.code, "UNAUTHENTICATED");
    }
}
