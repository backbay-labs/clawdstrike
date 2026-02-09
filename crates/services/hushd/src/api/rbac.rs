//! RBAC management endpoints (roles and role assignments).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, Principal, PrincipalType, ResourceType, Role, RoleScope};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRolesResponse {
    pub roles: Vec<Role>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRoleResponse {
    pub role: Role,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<crate::rbac::Permission>,
    #[serde(default)]
    pub inherits: Vec<String>,
    #[serde(default)]
    pub scope: Option<RoleScope>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateRoleRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Option<Vec<crate::rbac::Permission>>,
    #[serde(default)]
    pub inherits: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<Option<RoleScope>>,
    #[serde(default)]
    pub metadata: Option<Option<serde_json::Value>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertRoleResponse {
    pub role: Role,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRoleResponse {
    pub deleted: bool,
}

/// GET /api/v1/rbac/roles
pub async fn list_roles(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<ListRolesResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Role,
        Action::Read,
    )?;

    let roles = state
        .rbac
        .list_roles()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(ListRolesResponse { roles }))
}

/// GET /api/v1/rbac/roles/{id}
pub async fn get_role(
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<GetRoleResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Role,
        Action::Read,
    )?;

    let role = state
        .rbac
        .get_role(&role_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "role_not_found".to_string()))?;

    Ok(Json(GetRoleResponse { role }))
}

/// POST /api/v1/rbac/roles
pub async fn create_role(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<UpsertRoleResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Role,
        Action::Create,
    )?;

    if let Some(existing) = state
        .rbac
        .get_role(&req.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        if existing.builtin {
            return Err((
                StatusCode::FORBIDDEN,
                "cannot_modify_builtin_role".to_string(),
            ));
        }
        return Err((StatusCode::CONFLICT, "role_already_exists".to_string()));
    }

    let role = Role {
        id: req.id,
        name: req.name,
        description: req.description,
        permissions: req.permissions,
        inherits: req.inherits,
        scope: req.scope,
        builtin: false,
        metadata: req.metadata,
        created_at: String::new(),
        updated_at: String::new(),
    };

    let role = state
        .rbac
        .upsert_role(role)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let role_for_audit = role.clone();
    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "rbac_role_created".to_string();
    audit.action_type = "rbac".to_string();
    audit.target = Some(role.id.clone());
    audit.message = Some("RBAC role created".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_name(actor.as_ref().map(|e| &e.0)),
        "role": role_for_audit,
    }));
    let _ = state.ledger.record(&audit);

    Ok(Json(UpsertRoleResponse { role }))
}

/// PATCH /api/v1/rbac/roles/{id}
pub async fn update_role(
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<UpsertRoleResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Role,
        Action::Update,
    )?;

    let mut role = state
        .rbac
        .get_role(&role_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "role_not_found".to_string()))?;

    if role.builtin {
        return Err((
            StatusCode::FORBIDDEN,
            "cannot_modify_builtin_role".to_string(),
        ));
    }

    let before = role.clone();
    if let Some(name) = req.name {
        role.name = name;
    }
    if let Some(description) = req.description {
        role.description = description;
    }
    if let Some(perms) = req.permissions {
        role.permissions = perms;
    }
    if let Some(inherits) = req.inherits {
        role.inherits = inherits;
    }
    if let Some(scope) = req.scope {
        role.scope = scope;
    }
    if let Some(metadata) = req.metadata {
        role.metadata = metadata;
    }

    let role = state
        .rbac
        .upsert_role(role)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let after = role.clone();
    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "rbac_role_updated".to_string();
    audit.action_type = "rbac".to_string();
    audit.target = Some(role.id.clone());
    audit.message = Some("RBAC role updated".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_name(actor.as_ref().map(|e| &e.0)),
        "before": before,
        "after": after,
    }));
    let _ = state.ledger.record(&audit);

    Ok(Json(UpsertRoleResponse { role }))
}

/// DELETE /api/v1/rbac/roles/{id}
pub async fn delete_role(
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<DeleteRoleResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Role,
        Action::Delete,
    )?;

    let existing = state
        .rbac
        .get_role(&role_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "role_not_found".to_string()))?;

    if existing.builtin {
        return Err((
            StatusCode::FORBIDDEN,
            "cannot_delete_builtin_role".to_string(),
        ));
    }

    let before = existing.clone();
    let deleted = state
        .rbac
        .delete_role(&role_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if deleted {
        let mut audit = AuditEvent::session_start(&state.session_id, None);
        audit.event_type = "rbac_role_deleted".to_string();
        audit.action_type = "rbac".to_string();
        audit.target = Some(before.id.clone());
        audit.message = Some("RBAC role deleted".to_string());
        audit.metadata = Some(serde_json::json!({
            "actor": actor_name(actor.as_ref().map(|e| &e.0)),
            "role": before,
        }));
        let _ = state.ledger.record(&audit);
    }

    Ok(Json(DeleteRoleResponse { deleted }))
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateRoleAssignmentRequest {
    #[serde(rename = "principal")]
    pub principal: CreateAssignmentPrincipal,
    #[serde(rename = "roleId")]
    pub role_id: String,
    pub scope: RoleScope,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateAssignmentPrincipal {
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoleAssignmentResponse {
    pub assignment: crate::rbac::RoleAssignment,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListRoleAssignmentsQuery {
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub principal_type: Option<PrincipalType>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRoleAssignmentsResponse {
    pub assignments: Vec<crate::rbac::RoleAssignment>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRoleAssignmentResponse {
    pub deleted: bool,
}

/// POST /api/v1/rbac/assignments
pub async fn create_role_assignment(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(req): Json<CreateRoleAssignmentRequest>,
) -> Result<Json<CreateRoleAssignmentResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Role,
        Action::Assign,
    )?;

    if req.scope.scope_type != crate::rbac::ScopeType::Global && req.scope.scope_id.is_none() {
        return Err((StatusCode::BAD_REQUEST, "scope_id_required".to_string()));
    }

    // Role must exist.
    state
        .rbac
        .get_role(&req.role_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown_role".to_string()))?;

    // Tenant scoping: non-super-admin users can only grant roles within their org.
    if let Some(axum::extract::Extension(AuthenticatedActor::User(principal))) = actor.as_ref() {
        let is_super_admin = state
            .rbac
            .effective_roles_for_identity(principal)
            .iter()
            .any(|r| r == "super-admin");
        if !is_super_admin {
            match req.scope.scope_type {
                crate::rbac::ScopeType::Organization => {
                    let Some(scope_id) = req.scope.scope_id.as_deref() else {
                        return Err((StatusCode::BAD_REQUEST, "scope_id_required".to_string()));
                    };
                    if principal.organization_id.as_deref() != Some(scope_id) {
                        return Err((
                            StatusCode::FORBIDDEN,
                            "cross_org_role_assignment_denied".to_string(),
                        ));
                    }
                }
                crate::rbac::ScopeType::Team => {
                    let Some(scope_id) = req.scope.scope_id.as_deref() else {
                        return Err((StatusCode::BAD_REQUEST, "scope_id_required".to_string()));
                    };
                    if !principal.teams.iter().any(|t| t == scope_id) {
                        return Err((StatusCode::FORBIDDEN, "team_scope_required".to_string()));
                    }
                }
                crate::rbac::ScopeType::Project => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "project_scope_not_supported".to_string(),
                    ));
                }
                crate::rbac::ScopeType::Global | crate::rbac::ScopeType::User => {
                    return Err((StatusCode::FORBIDDEN, "scope_not_allowed".to_string()));
                }
            }
        }
    }

    let assignment = state
        .rbac
        .assign_role(
            Principal {
                principal_type: req.principal.principal_type,
                id: req.principal.id,
            },
            req.role_id,
            req.scope,
            actor_name(actor.as_ref().map(|e| &e.0)),
            req.expires_at,
            req.reason,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let assignment_for_audit = assignment.clone();
    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "rbac_role_assigned".to_string();
    audit.action_type = "rbac".to_string();
    audit.target = Some(assignment.id.clone());
    audit.message = Some("RBAC role assigned".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_name(actor.as_ref().map(|e| &e.0)),
        "assignment": assignment_for_audit,
    }));
    let _ = state.ledger.record(&audit);

    Ok(Json(CreateRoleAssignmentResponse { assignment }))
}

/// GET /api/v1/rbac/assignments?principal_id=...&principal_type=...
pub async fn list_role_assignments(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Query(query): Query<ListRoleAssignmentsQuery>,
) -> Result<Json<ListRoleAssignmentsResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Role,
        Action::Read,
    )?;

    let principal = match (query.principal_id, query.principal_type) {
        (Some(id), Some(t)) => Principal {
            principal_type: t,
            id,
        },
        (Some(id), None) => Principal {
            principal_type: PrincipalType::User,
            id,
        },
        (None, _) => {
            return Err((StatusCode::BAD_REQUEST, "principal_id_required".to_string()));
        }
    };

    // Tenant scoping: non-super-admin users can only list their own assignments.
    if let Some(axum::extract::Extension(AuthenticatedActor::User(user))) = actor.as_ref() {
        let is_super_admin = state
            .rbac
            .effective_roles_for_identity(user)
            .iter()
            .any(|r| r == "super-admin");
        if !is_super_admin
            && principal.principal_type == PrincipalType::User
            && principal.id != user.id
        {
            return Err((
                StatusCode::FORBIDDEN,
                "cannot_list_other_principals".to_string(),
            ));
        }
    }

    let assignments = state
        .rbac
        .list_role_assignments_for_principal(&principal)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ListRoleAssignmentsResponse { assignments }))
}

/// DELETE /api/v1/rbac/assignments/{id}
pub async fn delete_role_assignment(
    State(state): State<AppState>,
    Path(assignment_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<DeleteRoleAssignmentResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Role,
        Action::Unassign,
    )?;

    let deleted = state
        .rbac
        .revoke_role_assignment(&assignment_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !deleted {
        return Err((StatusCode::NOT_FOUND, "assignment_not_found".to_string()));
    }

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "rbac_role_unassigned".to_string();
    audit.action_type = "rbac".to_string();
    audit.target = Some(assignment_id.clone());
    audit.message = Some("RBAC role unassigned".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_name(actor.as_ref().map(|e| &e.0)),
        "assignment_id": assignment_id,
    }));
    let _ = state.ledger.record(&audit);

    Ok(Json(DeleteRoleAssignmentResponse { deleted }))
}

fn actor_name(actor: Option<&AuthenticatedActor>) -> String {
    match actor {
        Some(AuthenticatedActor::ApiKey(key)) => format!("api_key:{}", key.id),
        Some(AuthenticatedActor::User(user)) => format!("user:{}:{}", user.issuer, user.id),
        None => "system".to_string(),
    }
}
