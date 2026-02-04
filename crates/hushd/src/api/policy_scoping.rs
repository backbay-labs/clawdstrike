//! Identity-based policy scoping endpoints.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use clawdstrike::{guards::GuardContext, Policy};
use clawdstrike::policy::MergeStrategy;

use crate::audit::AuditEvent;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::AppState;

use crate::policy_scoping::{
    PolicyAssignment, PolicyAssignmentTarget, PolicyMetadata, PolicyScope, PolicyScopeType, ResolvedPolicy,
    ScopedPolicy,
};

fn actor_string(actor: Option<&AuthenticatedActor>) -> String {
    match actor {
        Some(AuthenticatedActor::ApiKey(key)) => format!("api_key:{}", key.id),
        Some(AuthenticatedActor::User(principal)) => format!("user:{}:{}", principal.issuer, principal.id),
        None => "system".to_string(),
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateScopedPolicyRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub scope: PolicyScope,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub merge_strategy: MergeStrategy,
    pub policy_yaml: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateScopedPolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub scope: Option<PolicyScope>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub merge_strategy: Option<MergeStrategy>,
    #[serde(default)]
    pub policy_yaml: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListScopedPoliciesResponse {
    pub policies: Vec<ScopedPolicy>,
}

/// POST /api/v1/scoped-policies
pub async fn create_scoped_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<CreateScopedPolicyRequest>,
) -> Result<Json<ScopedPolicy>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Policy,
        Action::Create,
    )?;

    // Validate policy yaml eagerly.
    Policy::from_yaml(&request.policy_yaml)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid policy_yaml: {e}")))?;

    // Basic scope validation.
    if request.scope.scope_type != PolicyScopeType::Global && request.scope.id.as_deref().unwrap_or("").is_empty() {
        return Err((StatusCode::BAD_REQUEST, "scope.id_required".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let id = request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let created_by = actor_string(actor.as_ref().map(|e| &e.0));

    let policy = ScopedPolicy {
        id: id.clone(),
        name: request.name,
        scope: request.scope,
        priority: request.priority,
        merge_strategy: request.merge_strategy,
        policy_yaml: request.policy_yaml,
        enabled: request.enabled,
        metadata: Some(PolicyMetadata {
            created_at: now.clone(),
            updated_at: now.clone(),
            created_by,
            description: request.description,
            tags: request.tags,
        }),
    };

    state
        .policy_resolver
        .store()
        .insert_scoped_policy(&policy)
        .map_err(|e| {
            if let crate::policy_scoping::PolicyScopingError::Database(db) = &e {
                if let rusqlite::Error::SqliteFailure(err, _) = db {
                    if matches!(
                        err.code,
                        rusqlite::ErrorCode::ConstraintViolation
                    ) {
                        return (StatusCode::CONFLICT, "scoped_policy_already_exists".to_string());
                    }
                }
            }
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    state.policy_engine_cache.clear();

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "scoped_policy_created".to_string();
    audit.action_type = "scoped_policy".to_string();
    audit.target = Some(id.clone());
    audit.message = Some("Scoped policy created".to_string());
    audit.metadata = Some(serde_json::json!({ "policy": policy }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "scoped_policy_created".to_string(),
        data: serde_json::json!({ "id": id }),
    });

    Ok(Json(policy))
}

/// GET /api/v1/scoped-policies
pub async fn list_scoped_policies(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<ListScopedPoliciesResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Policy,
        Action::Read,
    )?;

    let policies = state
        .policy_resolver
        .store()
        .list_scoped_policies()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ListScopedPoliciesResponse { policies }))
}

/// PATCH /api/v1/scoped-policies/:id
pub async fn update_scoped_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateScopedPolicyRequest>,
) -> Result<Json<ScopedPolicy>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Policy,
        Action::Update,
    )?;

    let Some(mut existing) = state
        .policy_resolver
        .store()
        .get_scoped_policy(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    else {
        return Err((StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string()));
    };

    if let Some(name) = request.name {
        existing.name = name;
    }
    if let Some(scope) = request.scope {
        if scope.scope_type != PolicyScopeType::Global && scope.id.as_deref().unwrap_or("").is_empty() {
            return Err((StatusCode::BAD_REQUEST, "scope.id_required".to_string()));
        }
        existing.scope = scope;
    }
    if let Some(priority) = request.priority {
        existing.priority = priority;
    }
    if let Some(ms) = request.merge_strategy {
        existing.merge_strategy = ms;
    }
    if let Some(yaml) = request.policy_yaml {
        Policy::from_yaml(&yaml).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid policy_yaml: {e}")))?;
        existing.policy_yaml = yaml;
    }
    if let Some(enabled) = request.enabled {
        existing.enabled = enabled;
    }

    let now = chrono::Utc::now().to_rfc3339();
    existing.metadata = Some(match existing.metadata.take() {
        Some(mut meta) => {
            meta.updated_at = now.clone();
            if request.description.is_some() {
                meta.description = request.description;
            }
            if request.tags.is_some() {
                meta.tags = request.tags;
            }
            meta
        }
        None => PolicyMetadata {
            created_at: now.clone(),
            updated_at: now.clone(),
            created_by: actor_string(actor.as_ref().map(|e| &e.0)),
            description: request.description,
            tags: request.tags,
        },
    });

    state
        .policy_resolver
        .store()
        .update_scoped_policy(&existing)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.policy_engine_cache.clear();

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "scoped_policy_updated".to_string();
    audit.action_type = "scoped_policy".to_string();
    audit.target = Some(id.clone());
    audit.message = Some("Scoped policy updated".to_string());
    audit.metadata = Some(serde_json::json!({ "policy": existing }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "scoped_policy_updated".to_string(),
        data: serde_json::json!({ "id": id }),
    });

    Ok(Json(existing))
}

/// DELETE /api/v1/scoped-policies/:id
pub async fn delete_scoped_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Policy,
        Action::Delete,
    )?;

    let deleted = state
        .policy_resolver
        .store()
        .delete_scoped_policy(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string()));
    }

    state.policy_engine_cache.clear();

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "scoped_policy_deleted".to_string();
    audit.action_type = "scoped_policy".to_string();
    audit.target = Some(id.clone());
    audit.message = Some("Scoped policy deleted".to_string());
    audit.metadata = Some(serde_json::json!({ "id": id }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "scoped_policy_deleted".to_string(),
        data: serde_json::json!({ "id": id }),
    });

    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateAssignmentRequest {
    pub policy_id: String,
    pub target: PolicyAssignmentTarget,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub effective_from: Option<String>,
    #[serde(default)]
    pub effective_until: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListAssignmentsResponse {
    pub assignments: Vec<PolicyAssignment>,
}

/// POST /api/v1/policy-assignments
pub async fn create_assignment(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<CreateAssignmentRequest>,
) -> Result<Json<PolicyAssignment>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::PolicyAssignment,
        Action::Assign,
    )?;

    // Ensure policy exists.
    let exists = state
        .policy_resolver
        .store()
        .get_scoped_policy(&request.policy_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    if !exists {
        return Err((StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string()));
    }

    let assigned_at = chrono::Utc::now().to_rfc3339();
    let assignment = PolicyAssignment {
        id: uuid::Uuid::new_v4().to_string(),
        policy_id: request.policy_id,
        target: request.target,
        priority: request.priority,
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        assigned_by: actor_string(actor.as_ref().map(|e| &e.0)),
        assigned_at,
        reason: request.reason,
    };

    state
        .policy_resolver
        .store()
        .insert_assignment(&assignment)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.policy_engine_cache.clear();

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "policy_assignment_created".to_string();
    audit.action_type = "policy_assignment".to_string();
    audit.target = Some(assignment.id.clone());
    audit.message = Some("Policy assignment created".to_string());
    audit.metadata = Some(serde_json::json!({ "assignment": assignment }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "policy_assignment_created".to_string(),
        data: serde_json::json!({ "id": assignment.id }),
    });

    Ok(Json(assignment))
}

/// GET /api/v1/policy-assignments
pub async fn list_assignments(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<ListAssignmentsResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::PolicyAssignment,
        Action::Read,
    )?;

    let assignments = state
        .policy_resolver
        .store()
        .list_assignments()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ListAssignmentsResponse { assignments }))
}

/// DELETE /api/v1/policy-assignments/:id
pub async fn delete_assignment(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::PolicyAssignment,
        Action::Unassign,
    )?;

    let deleted = state
        .policy_resolver
        .store()
        .delete_assignment(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, "policy_assignment_not_found".to_string()));
    }

    state.policy_engine_cache.clear();

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "policy_assignment_deleted".to_string();
    audit.action_type = "policy_assignment".to_string();
    audit.target = Some(id.clone());
    audit.message = Some("Policy assignment deleted".to_string());
    audit.metadata = Some(serde_json::json!({ "id": id }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "policy_assignment_deleted".to_string(),
        data: serde_json::json!({ "id": id }),
    });

    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResolvePolicyQuery {
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvePolicyResponse {
    pub resolved: ResolvedPolicy,
    pub policy_yaml: String,
    pub policy_hash: String,
}

/// GET /api/v1/policy/resolve
pub async fn resolve_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Query(query): Query<ResolvePolicyQuery>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Json<ResolvePolicyResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Policy,
        Action::Read,
    )?;

    let (default_policy, keypair) = {
        let engine = state.engine.read().await;
        (engine.policy().clone(), engine.keypair().cloned())
    };

    let mut ctx = GuardContext::new();

    // Request context is optional but helps condition evaluation.
    let request_ctx = clawdstrike::RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        source_ip: Some(addr.ip().to_string()),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geo_location: None,
        is_vpn: None,
        is_corporate_network: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    ctx = ctx.with_request(request_ctx);

    if let Some(session_id) = query.session_id.as_deref() {
        let validation = state
            .sessions
            .validate_session(session_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !validation.valid {
            return Err((StatusCode::FORBIDDEN, "invalid_session".to_string()));
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
                    if principal.id != session.identity.id || principal.issuer != session.identity.issuer {
                        return Err((StatusCode::FORBIDDEN, "session_identity_mismatch".to_string()));
                    }
                }
                AuthenticatedActor::ApiKey(key) => {
                    let bound = session
                        .state
                        .as_ref()
                        .and_then(|s| s.get("bound_api_key_id"))
                        .and_then(|v| v.as_str());
                    let Some(bound_id) = bound else {
                        return Err((StatusCode::FORBIDDEN, "api_key_cannot_use_unbound_sessions".to_string()));
                    };
                    if bound_id != key.id.as_str() {
                        return Err((StatusCode::FORBIDDEN, "api_key_session_binding_mismatch".to_string()));
                    }
                }
            }
        }

        ctx = state.sessions.create_guard_context(&session, ctx.request.as_ref());
    } else if let Some(ext) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = &ext.0 {
            let roles = state.rbac.effective_roles_for_identity(principal);
            let perms = state
                .rbac
                .effective_permission_strings_for_roles(&roles)
                .unwrap_or_default();
            ctx = ctx
                .with_identity(principal.clone())
                .with_roles(roles)
                .with_permissions(perms);
        }
    }

    let resolved = state
        .policy_resolver
        .resolve_policy(&default_policy, &ctx)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let policy_yaml = resolved
        .policy
        .to_yaml()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let policy_hash = hush_core::sha256(policy_yaml.as_bytes()).to_hex();

    // Prime cache (optional).
    if let Some(keypair) = keypair {
        let engine = state.policy_engine_cache.get_or_insert_with(&policy_hash, || {
            Arc::new(clawdstrike::HushEngine::with_policy(resolved.policy.clone()).with_keypair(keypair))
        });
        drop(engine);
    }

    Ok(Json(ResolvePolicyResponse {
        resolved,
        policy_yaml,
        policy_hash,
    }))
}
