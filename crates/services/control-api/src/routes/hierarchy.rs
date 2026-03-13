use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::hierarchy::{
    CreateHierarchyNodeRequest, DeleteHierarchyNodeQuery, DeleteHierarchyNodeResponse,
    HierarchyNode, HierarchyTreeResponse, NullableField, UpdateHierarchyNodeRequest,
};
use crate::services::hierarchy as hierarchy_service;
use crate::state::AppState;
use crate::validation;

/// Query parameters for listing hierarchy nodes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListNodesQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/hierarchy/nodes", get(list_nodes).post(create_node))
        .route(
            "/hierarchy/nodes/{id}",
            get(get_node).put(update_node).delete(delete_node),
        )
        .route("/hierarchy/tree", get(get_tree))
}

/// GET /api/v1/hierarchy/nodes — list hierarchy nodes for the tenant (paginated).
async fn list_nodes(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ListNodesQuery>,
) -> Result<Json<Vec<HierarchyNode>>, ApiError> {
    let offset = query.offset.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let nodes = hierarchy_service::list_nodes(&state.db, auth.tenant_id, offset, limit).await?;
    Ok(Json(nodes))
}

/// GET /api/v1/hierarchy/nodes/{id} — get a single hierarchy node.
async fn get_node(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<HierarchyNode>, ApiError> {
    let node = hierarchy_service::get_node(&state.db, auth.tenant_id, id).await?;
    Ok(Json(node))
}

/// POST /api/v1/hierarchy/nodes — create a hierarchy node.
async fn create_node(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateHierarchyNodeRequest>,
) -> Result<Json<HierarchyNode>, ApiError> {
    ensure_write_access(&auth)?;

    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_string()));
    }

    // Input length validation
    validation::validate_name(&req.name)?;
    validation::validate_string_length("node_type", &req.node_type, 32)?;
    validation::validate_external_id(req.external_id.as_deref())?;
    validation::validate_policy_name(req.policy_name.as_deref())?;
    validation::validate_metadata(req.metadata.as_ref())?;

    let metadata = req.metadata.unwrap_or(serde_json::json!({}));

    let node = hierarchy_service::create_node(
        &state.db,
        &hierarchy_service::CreateNodeParams {
            tenant_id: auth.tenant_id,
            name: &req.name,
            node_type: &req.node_type,
            parent_id: req.parent_id,
            external_id: req.external_id.as_deref(),
            policy_id: req.policy_id,
            policy_name: req.policy_name.as_deref(),
            metadata: &metadata,
        },
    )
    .await?;

    tracing::info!(
        tenant = %auth.slug,
        node_id = %node.id,
        node_type = %node.node_type,
        parent_id = ?node.parent_id,
        "Hierarchy node created"
    );

    Ok(Json(node))
}

/// PUT /api/v1/hierarchy/nodes/{id} — update a hierarchy node.
async fn update_node(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHierarchyNodeRequest>,
) -> Result<Json<HierarchyNode>, ApiError> {
    ensure_write_access(&auth)?;

    if let Some(ref name) = req.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest("name must not be empty".to_string()));
        }
        validation::validate_name(name)?;
    }

    // Validate node_type length if provided
    if let Some(ref nt) = req.node_type {
        validation::validate_string_length("node_type", nt, 32)?;
    }

    // Input length validation for optional/nullable fields
    if let NullableField::Set(ref external_id) = req.external_id {
        validation::validate_external_id(Some(external_id.as_str()))?;
    }
    if let NullableField::Set(ref policy_name) = req.policy_name {
        validation::validate_policy_name(Some(policy_name.as_str()))?;
    }
    if let NullableField::Set(ref metadata) = req.metadata {
        validation::validate_metadata(Some(metadata))?;
    }

    let node = hierarchy_service::update_node(
        &state.db,
        &hierarchy_service::UpdateNodeParams {
            tenant_id: auth.tenant_id,
            node_id: id,
            name: req.name.as_deref(),
            node_type: req.node_type.as_deref(),
            parent_id: req.parent_id,
            external_id: req.external_id.as_ref().map(|s| s.as_str()),
            policy_id: req.policy_id,
            policy_name: req.policy_name.as_ref().map(|name| name.as_str()),
            metadata: req.metadata.as_ref(),
        },
    )
    .await?;

    tracing::info!(
        tenant = %auth.slug,
        node_id = %node.id,
        "Hierarchy node updated"
    );

    Ok(Json(node))
}

/// DELETE /api/v1/hierarchy/nodes/{id} — delete a hierarchy node.
///
/// Query parameter `reparent=true` moves children to the deleted node's parent
/// instead of cascade-deleting them.
async fn delete_node(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Query(query): Query<DeleteHierarchyNodeQuery>,
) -> Result<Json<DeleteHierarchyNodeResponse>, ApiError> {
    ensure_write_access(&auth)?;

    let reparent = query.reparent.unwrap_or(false);
    let result = hierarchy_service::delete_node(&state.db, auth.tenant_id, id, reparent).await?;

    tracing::info!(
        tenant = %auth.slug,
        node_id = %id,
        deleted = result.deleted_count,
        reparented = result.reparented_count,
        "Hierarchy node deleted"
    );

    Ok(Json(result))
}

/// GET /api/v1/hierarchy/tree — get the full hierarchy as a tree.
async fn get_tree(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<HierarchyTreeResponse>, ApiError> {
    let tree = hierarchy_service::get_tree(&state.db, auth.tenant_id).await?;
    Ok(Json(tree))
}

/// Only owners and admins may mutate the hierarchy.
fn ensure_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth(role: &str) -> AuthenticatedTenant {
        AuthenticatedTenant {
            tenant_id: Uuid::new_v4(),
            slug: "test-tenant".to_string(),
            plan: "enterprise".to_string(),
            agent_limit: 100,
            user_id: None,
            api_key_id: None,
            role: role.to_string(),
            auth_source: crate::auth::AuthSource::Jwt,
        }
    }

    #[test]
    fn write_access_allows_owner_and_admin() {
        assert!(ensure_write_access(&make_auth("owner")).is_ok());
        assert!(ensure_write_access(&make_auth("admin")).is_ok());
    }

    #[test]
    fn write_access_rejects_member_and_viewer() {
        assert!(matches!(
            ensure_write_access(&make_auth("member")),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            ensure_write_access(&make_auth("viewer")),
            Err(ApiError::Forbidden)
        ));
    }
}
