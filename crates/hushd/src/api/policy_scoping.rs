//! Identity-based policy scoping endpoints.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use clawdstrike::policy::MergeStrategy;
use clawdstrike::{guards::GuardContext, Policy};

use crate::audit::AuditEvent;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::{
    require_api_key_scope_or_user_permission, require_api_key_scope_or_user_permission_with_context,
};
use crate::rbac::{
    Action, ResourceRef, ResourceType, RoleScope as RbacRoleScope, ScopeType as RbacScopeType,
};
use crate::state::AppState;

use crate::policy_scoping::{
    PolicyAssignment, PolicyAssignmentTarget, PolicyMetadata, PolicyScope, PolicyScopeType,
    ResolvedPolicy, ScopedPolicy,
};

fn actor_string(actor: Option<&AuthenticatedActor>) -> String {
    match actor {
        Some(AuthenticatedActor::ApiKey(key)) => format!("api_key:{}", key.id),
        Some(AuthenticatedActor::User(principal)) => {
            format!("user:{}:{}", principal.issuer, principal.id)
        }
        None => "system".to_string(),
    }
}

fn actor_is_super_admin(state: &AppState, actor: Option<&AuthenticatedActor>) -> bool {
    let Some(AuthenticatedActor::User(principal)) = actor else {
        return false;
    };
    state
        .rbac
        .effective_roles_for_identity(principal)
        .iter()
        .any(|r| r == "super-admin")
}

fn scope_org_id(scope: &PolicyScope) -> Option<&str> {
    if scope.scope_type == PolicyScopeType::Organization {
        return scope.id.as_deref();
    }
    scope.parent.as_deref().and_then(scope_org_id)
}

fn rbac_scope_for_policy_scope(scope: &PolicyScope) -> Option<RbacRoleScope> {
    let scope_type = match scope.scope_type {
        PolicyScopeType::Global => RbacScopeType::Global,
        PolicyScopeType::Organization => RbacScopeType::Organization,
        PolicyScopeType::Team => RbacScopeType::Team,
        PolicyScopeType::Project => RbacScopeType::Project,
        PolicyScopeType::User => RbacScopeType::User,
        PolicyScopeType::Role => {
            // RBAC doesn't treat "role" as a tenant scope; fail closed for scoped roles.
            return None;
        }
    };

    Some(RbacRoleScope {
        scope_type,
        scope_id: scope.id.clone(),
        include_children: false,
    })
}

fn rbac_scope_for_assignment_target(target: &PolicyAssignmentTarget) -> RbacRoleScope {
    let scope_type = match target.target_type {
        crate::policy_scoping::PolicyAssignmentTargetType::Organization => {
            RbacScopeType::Organization
        }
        crate::policy_scoping::PolicyAssignmentTargetType::Team => RbacScopeType::Team,
        crate::policy_scoping::PolicyAssignmentTargetType::Project => RbacScopeType::Project,
        crate::policy_scoping::PolicyAssignmentTargetType::User => RbacScopeType::User,
    };

    RbacRoleScope {
        scope_type,
        scope_id: Some(target.id.clone()),
        include_children: false,
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
    // RBAC does not currently have a first-class "role" scope type.
    // Fail closed: only super-admin users may mutate role-scoped policies.
    let actor_ref = actor.as_ref().map(|e| &e.0);
    if request.scope.scope_type == PolicyScopeType::Role
        && matches!(actor_ref, Some(AuthenticatedActor::User(_)))
        && !actor_is_super_admin(&state, actor_ref)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "role_scoped_policy_requires_super_admin".to_string(),
        ));
    }

    require_api_key_scope_or_user_permission_with_context(
        actor_ref,
        &state.rbac,
        Scope::Admin,
        ResourceRef {
            resource_type: ResourceType::Policy,
            id: None,
            attributes: None,
        },
        Action::Create,
        rbac_scope_for_policy_scope(&request.scope),
    )?;

    // Validate policy yaml eagerly.
    Policy::from_yaml(&request.policy_yaml)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid policy_yaml: {e}")))?;

    // Basic scope validation.
    if request.scope.scope_type != PolicyScopeType::Global
        && request.scope.id.as_deref().unwrap_or("").is_empty()
    {
        return Err((StatusCode::BAD_REQUEST, "scope.id_required".to_string()));
    }

    // Tenant scoping: non-super-admin users can only create policies in their org.
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = actor {
            if !actor_is_super_admin(&state, Some(actor)) {
                let policy_org = scope_org_id(&request.scope);
                let actor_org = principal.organization_id.as_deref();

                if let Some(policy_org) = policy_org {
                    if actor_org.is_some() && actor_org != Some(policy_org) {
                        return Err((StatusCode::FORBIDDEN, "cross_org_policy_denied".to_string()));
                    }
                    if actor_org.is_none() {
                        return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                    }
                } else if request.scope.scope_type != PolicyScopeType::Global {
                    return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                }
            }
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let id = request
        .id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let actor_id = actor_string(actor.as_ref().map(|e| &e.0));

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
            created_by: actor_id.clone(),
            description: request.description,
            tags: request.tags,
        }),
    };

    state
        .policy_resolver
        .store()
        .insert_scoped_policy(&policy)
        .map_err(|e| {
            if let crate::policy_scoping::PolicyScopingError::Database(
                rusqlite::Error::SqliteFailure(err, _),
            ) = &e
            {
                if matches!(err.code, rusqlite::ErrorCode::ConstraintViolation) {
                    return (
                        StatusCode::CONFLICT,
                        "scoped_policy_already_exists".to_string(),
                    );
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
    audit.metadata = Some(serde_json::json!({
        "actor": actor_id,
        "policy": policy.clone(),
    }));
    state.record_audit_event(audit);

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

    let actor_ref = actor.as_ref().map(|e| &e.0);
    let is_super_admin = actor_is_super_admin(&state, actor_ref);

    let policies = match actor_ref {
        Some(AuthenticatedActor::User(principal)) if !is_super_admin => {
            let actor_org = principal.organization_id.as_deref();
            policies
                .into_iter()
                .filter(|p| {
                    let policy_org = scope_org_id(&p.scope);
                    match (actor_org, policy_org) {
                        (Some(a), Some(o)) => a == o,
                        (None, Some(_)) => false,
                        (_, None) => p.scope.scope_type == PolicyScopeType::Global,
                    }
                })
                .collect()
        }
        _ => policies,
    };

    Ok(Json(ListScopedPoliciesResponse { policies }))
}

/// PATCH /api/v1/scoped-policies/:id
pub async fn update_scoped_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateScopedPolicyRequest>,
) -> Result<Json<ScopedPolicy>, (StatusCode, String)> {
    let actor_ref = actor.as_ref().map(|e| &e.0);
    let Some(mut existing) = state
        .policy_resolver
        .store()
        .get_scoped_policy(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    else {
        return Err((StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string()));
    };

    let before = existing.clone();

    if let Some(name) = request.name {
        existing.name = name;
    }
    if let Some(scope) = request.scope {
        if scope.scope_type != PolicyScopeType::Global
            && scope.id.as_deref().unwrap_or("").is_empty()
        {
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
        Policy::from_yaml(&yaml)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid policy_yaml: {e}")))?;
        existing.policy_yaml = yaml;
    }
    if let Some(enabled) = request.enabled {
        existing.enabled = enabled;
    }

    // Tenant scoping: non-super-admin users can only modify policies in their org.
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = actor {
            if !actor_is_super_admin(&state, Some(actor)) {
                let policy_org = scope_org_id(&existing.scope);
                let actor_org = principal.organization_id.as_deref();
                if let Some(policy_org) = policy_org {
                    if actor_org.is_some() && actor_org != Some(policy_org) {
                        return Err((StatusCode::FORBIDDEN, "cross_org_policy_denied".to_string()));
                    }
                    if actor_org.is_none() {
                        return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                    }
                } else if existing.scope.scope_type != PolicyScopeType::Global {
                    return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                }
            }
        }
    }

    // RBAC: apply scope constraints using the updated policy scope.
    if existing.scope.scope_type == PolicyScopeType::Role
        && matches!(actor_ref, Some(AuthenticatedActor::User(_)))
        && !actor_is_super_admin(&state, actor_ref)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "role_scoped_policy_requires_super_admin".to_string(),
        ));
    }

    require_api_key_scope_or_user_permission_with_context(
        actor_ref,
        &state.rbac,
        Scope::Admin,
        ResourceRef {
            resource_type: ResourceType::Policy,
            id: Some(id.clone()),
            attributes: None,
        },
        Action::Update,
        rbac_scope_for_policy_scope(&existing.scope),
    )?;

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

    let after = existing.clone();
    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "scoped_policy_updated".to_string();
    audit.action_type = "scoped_policy".to_string();
    audit.target = Some(id.clone());
    audit.message = Some("Scoped policy updated".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_string(actor.as_ref().map(|e| &e.0)),
        "before": before,
        "after": after,
    }));
    state.record_audit_event(audit);

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
    let actor_ref = actor.as_ref().map(|e| &e.0);
    let existing = state
        .policy_resolver
        .store()
        .get_scoped_policy(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string()))?;

    if existing.scope.scope_type == PolicyScopeType::Role
        && matches!(actor_ref, Some(AuthenticatedActor::User(_)))
        && !actor_is_super_admin(&state, actor_ref)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "role_scoped_policy_requires_super_admin".to_string(),
        ));
    }

    require_api_key_scope_or_user_permission_with_context(
        actor_ref,
        &state.rbac,
        Scope::Admin,
        ResourceRef {
            resource_type: ResourceType::Policy,
            id: Some(id.clone()),
            attributes: None,
        },
        Action::Delete,
        rbac_scope_for_policy_scope(&existing.scope),
    )?;

    // Tenant scoping.
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = actor {
            if !actor_is_super_admin(&state, Some(actor)) {
                let policy_org = scope_org_id(&existing.scope);
                let actor_org = principal.organization_id.as_deref();
                if let Some(policy_org) = policy_org {
                    if actor_org.is_some() && actor_org != Some(policy_org) {
                        return Err((StatusCode::FORBIDDEN, "cross_org_policy_denied".to_string()));
                    }
                    if actor_org.is_none() {
                        return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                    }
                } else if existing.scope.scope_type != PolicyScopeType::Global {
                    return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                }
            }
        }
    }

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
    audit.metadata = Some(serde_json::json!({
        "actor": actor_string(actor.as_ref().map(|e| &e.0)),
        "policy": existing,
    }));
    state.record_audit_event(audit);

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
    require_api_key_scope_or_user_permission_with_context(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceRef {
            resource_type: ResourceType::PolicyAssignment,
            id: None,
            attributes: None,
        },
        Action::Assign,
        Some(rbac_scope_for_assignment_target(&request.target)),
    )?;

    // Ensure policy exists.
    let policy = state
        .policy_resolver
        .store()
        .get_scoped_policy(&request.policy_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string()))?;

    // Tenant scoping: policy and target must remain within the actor's org (unless super-admin).
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = actor {
            if !actor_is_super_admin(&state, Some(actor)) {
                let policy_org = scope_org_id(&policy.scope);
                let actor_org = principal.organization_id.as_deref();
                if let Some(policy_org) = policy_org {
                    if actor_org.is_some() && actor_org != Some(policy_org) {
                        return Err((StatusCode::FORBIDDEN, "cross_org_policy_denied".to_string()));
                    }
                    if actor_org.is_none() {
                        return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                    }
                    if request.target.target_type
                        == crate::policy_scoping::PolicyAssignmentTargetType::Organization
                        && request.target.id != policy_org
                    {
                        return Err((
                            StatusCode::FORBIDDEN,
                            "cross_org_assignment_denied".to_string(),
                        ));
                    }
                } else if policy.scope.scope_type != PolicyScopeType::Global {
                    return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                }
            }
        }
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
    audit.metadata = Some(serde_json::json!({ "assignment": assignment.clone() }));
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
    // API keys still require explicit scope; user principals are filtered by RBAC below.
    if matches!(
        actor.as_ref().map(|e| &e.0),
        Some(AuthenticatedActor::ApiKey(_))
    ) {
        require_api_key_scope_or_user_permission(
            actor.as_ref().map(|e| &e.0),
            &state.rbac,
            Scope::Read,
            ResourceType::PolicyAssignment,
            Action::Read,
        )?;
    }

    let assignments = state
        .policy_resolver
        .store()
        .list_assignments()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let actor_ref = actor.as_ref().map(|e| &e.0);
    let is_super_admin = actor_is_super_admin(&state, actor_ref);

    let assignments = match actor_ref {
        Some(AuthenticatedActor::User(principal)) if !is_super_admin => {
            let actor_org = principal.organization_id.as_deref();
            let mut out = Vec::new();
            for a in assignments {
                let Some(policy) = state
                    .policy_resolver
                    .store()
                    .get_scoped_policy(&a.policy_id)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                else {
                    continue;
                };
                let policy_org = scope_org_id(&policy.scope);
                match (actor_org, policy_org) {
                    (Some(aorg), Some(porg)) if aorg == porg => {
                        let scope = rbac_scope_for_assignment_target(&a.target);
                        let allowed = state
                            .rbac
                            .check_permission_for_identity_with_context(
                                principal,
                                ResourceRef {
                                    resource_type: ResourceType::PolicyAssignment,
                                    id: Some(a.id.clone()),
                                    attributes: None,
                                },
                                Action::Read,
                                Some(scope),
                            )
                            .map(|r| r.allowed)
                            .unwrap_or(false);
                        if allowed {
                            out.push(a);
                        }
                    }
                    (Some(_), Some(_)) => {}
                    (None, Some(_)) => {}
                    (_, None) => {
                        let scope = rbac_scope_for_assignment_target(&a.target);
                        let allowed = state
                            .rbac
                            .check_permission_for_identity_with_context(
                                principal,
                                ResourceRef {
                                    resource_type: ResourceType::PolicyAssignment,
                                    id: Some(a.id.clone()),
                                    attributes: None,
                                },
                                Action::Read,
                                Some(scope),
                            )
                            .map(|r| r.allowed)
                            .unwrap_or(false);
                        if allowed {
                            out.push(a);
                        }
                    }
                }
            }
            out
        }
        _ => assignments,
    };

    Ok(Json(ListAssignmentsResponse { assignments }))
}

/// DELETE /api/v1/policy-assignments/:id
pub async fn delete_assignment(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let existing = state
        .policy_resolver
        .store()
        .get_assignment(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "policy_assignment_not_found".to_string(),
            )
        })?;

    require_api_key_scope_or_user_permission_with_context(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceRef {
            resource_type: ResourceType::PolicyAssignment,
            id: Some(id.clone()),
            attributes: None,
        },
        Action::Unassign,
        Some(rbac_scope_for_assignment_target(&existing.target)),
    )?;

    // Tenant scoping.
    if let Some(axum::extract::Extension(actor)) = actor.as_ref() {
        if let AuthenticatedActor::User(principal) = actor {
            if !actor_is_super_admin(&state, Some(actor)) {
                let actor_org = principal.organization_id.as_deref();
                let policy = state
                    .policy_resolver
                    .store()
                    .get_scoped_policy(&existing.policy_id)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                    .ok_or_else(|| {
                        (StatusCode::NOT_FOUND, "scoped_policy_not_found".to_string())
                    })?;

                let policy_org = scope_org_id(&policy.scope);
                if let Some(policy_org) = policy_org {
                    if actor_org.is_some() && actor_org != Some(policy_org) {
                        return Err((StatusCode::FORBIDDEN, "cross_org_policy_denied".to_string()));
                    }
                    if actor_org.is_none() {
                        return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                    }
                } else if policy.scope.scope_type != PolicyScopeType::Global {
                    return Err((StatusCode::FORBIDDEN, "organization_required".to_string()));
                }
            }
        }
    }

    let deleted = state
        .policy_resolver
        .store()
        .delete_assignment(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !deleted {
        return Err((
            StatusCode::NOT_FOUND,
            "policy_assignment_not_found".to_string(),
        ));
    }

    state.policy_engine_cache.clear();

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "policy_assignment_deleted".to_string();
    audit.action_type = "policy_assignment".to_string();
    audit.target = Some(id.clone());
    audit.message = Some("Policy assignment deleted".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_string(actor.as_ref().map(|e| &e.0)),
        "assignment": existing,
    }));
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
    ctx = ctx.with_request(request_ctx.clone());

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
            .validate_session_binding(&session, &request_ctx)
            .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;

        ctx = state
            .sessions
            .create_guard_context(&session, ctx.request.as_ref());
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
        let engine = state
            .policy_engine_cache
            .get_or_insert_with(&policy_hash, || {
                Arc::new(
                    clawdstrike::HushEngine::with_policy(resolved.policy.clone())
                        .with_keypair(keypair),
                )
            });
        drop(engine);
    }

    Ok(Json(ResolvePolicyResponse {
        resolved,
        policy_yaml,
        policy_hash,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::State;
    use axum::Json;

    fn test_policy_admin(org_id: &str) -> AuthenticatedActor {
        AuthenticatedActor::User(clawdstrike::IdentityPrincipal {
            id: "user-1".to_string(),
            provider: clawdstrike::IdentityProvider::Oidc,
            issuer: "https://issuer.example".to_string(),
            display_name: None,
            email: None,
            email_verified: None,
            organization_id: Some(org_id.to_string()),
            teams: Vec::new(),
            roles: vec!["policy-admin".to_string()],
            attributes: std::collections::HashMap::new(),
            authenticated_at: chrono::Utc::now().to_rfc3339(),
            auth_method: None,
            expires_at: None,
        })
    }

    #[tokio::test]
    async fn role_scoped_policy_mutation_requires_super_admin() {
        let test_dir =
            std::env::temp_dir().join(format!("hushd-role-scope-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("create temp dir");

        let config = crate::config::Config {
            cors_enabled: false,
            audit_db: test_dir.join("audit.db"),
            control_db: Some(test_dir.join("control.db")),
            ..Default::default()
        };
        let state = AppState::new(config).await.expect("state");

        let role_scope = PolicyScope {
            scope_type: PolicyScopeType::Role,
            id: Some("role-1".to_string()),
            name: Some("Role 1".to_string()),
            parent: Some(Box::new(PolicyScope {
                scope_type: PolicyScopeType::Organization,
                id: Some("org-1".to_string()),
                name: None,
                parent: None,
                conditions: Vec::new(),
            })),
            conditions: Vec::new(),
        };

        let request = CreateScopedPolicyRequest {
            id: None,
            name: "role-scoped".to_string(),
            scope: role_scope,
            priority: 0,
            merge_strategy: MergeStrategy::Merge,
            policy_yaml: Policy::new().to_yaml().expect("serialize default policy"),
            enabled: true,
            description: None,
            tags: None,
        };

        let res = create_scoped_policy(
            State(state),
            Some(axum::extract::Extension(test_policy_admin("org-1"))),
            Json(request),
        )
        .await;

        let (status, msg) = res.expect_err("expected forbidden");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(msg, "role_scoped_policy_requires_super_admin");

        let _ = std::fs::remove_dir_all(&test_dir);
    }
}
