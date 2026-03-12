use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
use crate::models::hierarchy::{
    DeleteHierarchyNodeResponse, HierarchyNode, HierarchyNodeType, HierarchyTreeNode,
    HierarchyTreeResponse, NullableField,
};

// ---------------------------------------------------------------------------
// Parameter structs (to satisfy clippy::too_many_arguments)
// ---------------------------------------------------------------------------

pub struct CreateNodeParams<'a> {
    pub tenant_id: Uuid,
    pub name: &'a str,
    pub node_type: &'a str,
    pub parent_id: Option<Uuid>,
    pub external_id: Option<&'a str>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<&'a str>,
    pub metadata: &'a serde_json::Value,
}

pub struct UpdateNodeParams<'a> {
    pub tenant_id: Uuid,
    pub node_id: Uuid,
    pub name: Option<&'a str>,
    pub node_type: Option<&'a str>,
    pub parent_id: NullableField<Uuid>,
    pub external_id: NullableField<&'a str>,
    pub policy_id: NullableField<Uuid>,
    pub policy_name: NullableField<&'a str>,
    pub metadata: NullableField<&'a serde_json::Value>,
}

// ---------------------------------------------------------------------------
// List all nodes
// ---------------------------------------------------------------------------

pub async fn list_nodes(
    db: &PgPool,
    tenant_id: Uuid,
    offset: i64,
    limit: i64,
) -> Result<Vec<HierarchyNode>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM hierarchy_nodes
           WHERE tenant_id = $1
           ORDER BY created_at ASC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(HierarchyNode::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)
}

// ---------------------------------------------------------------------------
// Get single node
// ---------------------------------------------------------------------------

pub async fn get_node(
    db: &PgPool,
    tenant_id: Uuid,
    node_id: Uuid,
) -> Result<HierarchyNode, ApiError> {
    let row = sqlx::query::query("SELECT * FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2")
        .bind(node_id)
        .bind(tenant_id)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;

    HierarchyNode::from_row(row).map_err(ApiError::Database)
}

// ---------------------------------------------------------------------------
// Create node
// ---------------------------------------------------------------------------

pub async fn create_node(
    db: &PgPool,
    params: &CreateNodeParams<'_>,
) -> Result<HierarchyNode, ApiError> {
    // Validate node_type
    let node_type = parse_node_type(params.node_type)?;
    ensure_parentless_node_allowed(node_type, params.parent_id)?;

    // Resolve the stored node_type string — map legacy "agent" to "endpoint"
    // so new rows always use the canonical type.
    let stored_node_type = match node_type {
        HierarchyNodeType::Agent => HierarchyNodeType::Endpoint.as_str(),
        other => other.as_str(),
    };

    // Use a transaction so that the parent validation and INSERT are atomic,
    // preventing TOCTOU races where the parent is deleted between the check
    // and the insert.
    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    // If a parent_id is provided, ensure it exists in the same tenant and
    // validate the parent-child type relationship.
    if let Some(pid) = params.parent_id {
        let parent_row = sqlx::query::query(
            "SELECT node_type FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2",
        )
        .bind(pid)
        .bind(params.tenant_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

        let parent_row = parent_row.ok_or_else(|| {
            ApiError::BadRequest(format!("parent node {pid} does not exist in this tenant"))
        })?;

        let parent_type_str: String = parent_row
            .try_get("node_type")
            .map_err(ApiError::Database)?;
        if let Some(parent_type) = HierarchyNodeType::from_str(&parent_type_str) {
            validate_parent_child_types(parent_type, node_type)?;
        }
    }

    let row = sqlx::query::query(
        r#"INSERT INTO hierarchy_nodes (
               tenant_id, name, node_type, parent_id, external_id, policy_id, policy_name, metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING *"#,
    )
    .bind(params.tenant_id)
    .bind(params.name)
    .bind(stored_node_type)
    .bind(params.parent_id)
    .bind(params.external_id)
    .bind(params.policy_id)
    .bind(params.policy_name)
    .bind(params.metadata)
    .fetch_one(tx.as_mut())
    .await
    .map_err(map_unique_violation)?;

    let node = HierarchyNode::from_row(row).map_err(ApiError::Database)?;
    tx.commit().await.map_err(ApiError::Database)?;
    Ok(node)
}

// ---------------------------------------------------------------------------
// Update node
// ---------------------------------------------------------------------------

pub async fn update_node(
    db: &PgPool,
    params: &UpdateNodeParams<'_>,
) -> Result<HierarchyNode, ApiError> {
    // Use a transaction so that the initial read, validation, cycle check, and
    // UPDATE are all atomic — preventing TOCTOU races.
    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    // Read the current node inside the transaction (SELECT ... FOR UPDATE)
    // so the row is locked and consistent with the subsequent UPDATE.
    let current_row = sqlx::query::query(
        "SELECT * FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(params.node_id)
    .bind(params.tenant_id)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let current_node = HierarchyNode::from_row(current_row).map_err(ApiError::Database)?;

    // Validate node_type if provided
    let current_node_type = parse_node_type(&current_node.node_type)?;
    let next_node_type = match params.node_type {
        Some(node_type) => parse_node_type(node_type)?,
        None => current_node_type,
    };
    let next_parent_id = resolved_parent_id(params.parent_id, current_node.parent_id);
    ensure_parentless_node_allowed(next_node_type, next_parent_id)?;

    // Validate parent_id if provided — prevent self-parenting and cross-tenant refs
    if let NullableField::Set(pid) = params.parent_id {
        if pid == params.node_id {
            return Err(ApiError::BadRequest(
                "a node cannot be its own parent".to_string(),
            ));
        }

        let parent_row = sqlx::query::query(
            "SELECT node_type FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2",
        )
        .bind(pid)
        .bind(params.tenant_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

        let parent_row = parent_row.ok_or_else(|| {
            ApiError::BadRequest(format!("parent node {pid} does not exist in this tenant"))
        })?;

        // Validate parent-child type compatibility with the new parent.
        let parent_type_str: String = parent_row
            .try_get("node_type")
            .map_err(ApiError::Database)?;
        if let Some(parent_type) = HierarchyNodeType::from_str(&parent_type_str) {
            validate_parent_child_types(parent_type, next_node_type)?;
        }

        // Prevent cycles: ensure the proposed parent is not a descendant of this node.
        if is_descendant_tx(tx.as_mut(), params.tenant_id, pid, params.node_id).await? {
            return Err(ApiError::BadRequest(
                "cannot set parent: would create a cycle in the hierarchy".to_string(),
            ));
        }
    } else if params.node_type.is_some() {
        // node_type is changing but parent_id is not — validate the new type is
        // compatible with the existing parent.
        if let Some(existing_parent_id) = current_node.parent_id {
            let parent_row = sqlx::query::query(
                "SELECT node_type FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2",
            )
            .bind(existing_parent_id)
            .bind(params.tenant_id)
            .fetch_optional(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;

            if let Some(parent_row) = parent_row {
                let parent_type_str: String = parent_row
                    .try_get("node_type")
                    .map_err(ApiError::Database)?;
                if let Some(parent_type) = HierarchyNodeType::from_str(&parent_type_str) {
                    validate_parent_child_types(parent_type, next_node_type)?;
                }
            }
        }
    }

    if params.node_type.is_some() {
        validate_existing_children_for_node_type(
            &mut tx,
            params.tenant_id,
            params.node_id,
            next_node_type,
        )
        .await?;
    }

    let metadata_update = normalized_metadata_update(params.metadata);

    let row = sqlx::query::query(
        r#"UPDATE hierarchy_nodes
           SET name = COALESCE($3, name),
               node_type = COALESCE($4, node_type),
               parent_id = CASE WHEN $5 THEN $6 ELSE parent_id END,
               external_id = CASE WHEN $7 THEN $8 ELSE external_id END,
               policy_id = CASE WHEN $9 THEN $10 ELSE policy_id END,
               policy_name = CASE WHEN $11 THEN $12 ELSE policy_name END,
               metadata = CASE WHEN $13 THEN $14 ELSE metadata END,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2
           RETURNING *"#,
    )
    .bind(params.node_id)
    .bind(params.tenant_id)
    .bind(params.name)
    .bind(params.node_type)
    .bind(!matches!(params.parent_id, NullableField::Missing))
    .bind(params.parent_id.into_option())
    .bind(!matches!(params.external_id, NullableField::Missing))
    .bind(params.external_id.into_option())
    .bind(!matches!(params.policy_id, NullableField::Missing))
    .bind(params.policy_id.into_option())
    .bind(!matches!(params.policy_name, NullableField::Missing))
    .bind(params.policy_name.into_option())
    .bind(!matches!(params.metadata, NullableField::Missing))
    .bind(metadata_update)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(map_unique_violation)?
    .ok_or(ApiError::NotFound)?;

    let node = HierarchyNode::from_row(row).map_err(ApiError::Database)?;
    tx.commit().await.map_err(ApiError::Database)?;
    Ok(node)
}

fn normalized_metadata_update(
    metadata: NullableField<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match metadata {
        NullableField::Set(value) => Some(value.clone()),
        // `metadata` is stored as NOT NULL JSONB with `{}` as its empty-state value.
        NullableField::Clear => Some(serde_json::json!({})),
        NullableField::Missing => None,
    }
}

fn parse_node_type(node_type: &str) -> Result<HierarchyNodeType, ApiError> {
    let parsed = HierarchyNodeType::from_str(node_type).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "invalid node_type '{node_type}': must be one of org, team, project, endpoint, runtime"
        ))
    })?;

    // Warn on legacy "agent" usage — from_str already maps it to Endpoint,
    // but we log so operators know to update their tooling.
    if node_type == "agent" {
        tracing::warn!(
            requested_type = "agent",
            resolved_type = "endpoint",
            "Deprecated node_type 'agent' used — use 'endpoint' instead"
        );
    }

    Ok(parsed)
}

fn ensure_parentless_node_allowed(
    node_type: HierarchyNodeType,
    parent_id: Option<Uuid>,
) -> Result<(), ApiError> {
    if parent_id.is_none() && node_type != HierarchyNodeType::Org {
        return Err(ApiError::BadRequest(format!(
            "{node_type} nodes must specify a parent_id"
        )));
    }
    Ok(())
}

/// Validate that the child node type is allowed under the given parent type.
///
/// Enforced hierarchy:
///   org -> team | project
///   team -> endpoint | project
///   endpoint -> runtime
///   runtime -> (no children)
fn validate_parent_child_types(
    parent_type: HierarchyNodeType,
    child_type: HierarchyNodeType,
) -> Result<(), ApiError> {
    let allowed = match parent_type {
        HierarchyNodeType::Org => matches!(
            child_type,
            HierarchyNodeType::Team | HierarchyNodeType::Project
        ),
        HierarchyNodeType::Team => matches!(
            child_type,
            HierarchyNodeType::Endpoint | HierarchyNodeType::Project
        ),
        HierarchyNodeType::Project => false,
        HierarchyNodeType::Agent | HierarchyNodeType::Endpoint => {
            matches!(child_type, HierarchyNodeType::Runtime)
        }
        HierarchyNodeType::Runtime => false,
    };

    if !allowed {
        return Err(ApiError::BadRequest(format!(
            "a {child_type} node cannot be a child of a {parent_type} node"
        )));
    }
    Ok(())
}

fn resolved_parent_id(
    parent_id: NullableField<Uuid>,
    current_parent_id: Option<Uuid>,
) -> Option<Uuid> {
    match parent_id {
        NullableField::Missing => current_parent_id,
        NullableField::Set(parent_id) => Some(parent_id),
        NullableField::Clear => None,
    }
}

async fn validate_existing_children_for_node_type(
    tx: &mut sqlx::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    node_id: Uuid,
    node_type: HierarchyNodeType,
) -> Result<(), ApiError> {
    let child_rows = sqlx::query::query(
        "SELECT node_type FROM hierarchy_nodes WHERE parent_id = $1 AND tenant_id = $2",
    )
    .bind(node_id)
    .bind(tenant_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    let mut invalid_types = Vec::new();
    for child_row in &child_rows {
        let child_type_str: String = child_row.try_get("node_type").map_err(ApiError::Database)?;
        if let Some(child_type) = HierarchyNodeType::from_str(&child_type_str) {
            if validate_parent_child_types(node_type, child_type).is_err() {
                invalid_types.push(child_type_str);
            }
        }
    }

    if !invalid_types.is_empty() {
        invalid_types.sort();
        invalid_types.dedup();
        return Err(ApiError::BadRequest(format!(
            "cannot change node_type: children of type [{}] are not allowed under a {node_type} node",
            invalid_types.join(", ")
        )));
    }

    Ok(())
}

fn map_unique_violation(err: sqlx::error::Error) -> ApiError {
    if let sqlx::error::Error::Database(ref db_err) = err {
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("");
            if constraint == "idx_hierarchy_nodes_runtime_unique" {
                return ApiError::Conflict(
                    "a runtime with this external_id already exists under the same parent endpoint"
                        .to_string(),
                );
            }
            return ApiError::Conflict(
                "a root org node already exists for this tenant".to_string(),
            );
        }
    }
    ApiError::Database(err)
}

// ---------------------------------------------------------------------------
// Delete node
// ---------------------------------------------------------------------------

pub async fn delete_node(
    db: &PgPool,
    tenant_id: Uuid,
    node_id: Uuid,
    reparent: bool,
) -> Result<DeleteHierarchyNodeResponse, ApiError> {
    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    // Verify the node exists and fetch its parent_id and node_type.
    let node_row = sqlx::query::query(
        "SELECT parent_id, node_type FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2",
    )
    .bind(node_id)
    .bind(tenant_id)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let node_parent_id: Option<Uuid> = node_row.try_get("parent_id").map_err(ApiError::Database)?;

    let mut reparented_count = 0_i64;
    let mut deleted_count = 0_i64;
    let mut descendant_count = 0_i64;

    if reparent {
        // If the deleted node is a root (parent_id IS NULL), reparenting would
        // make its children root nodes.  Only org nodes may be roots.
        if node_parent_id.is_none() {
            let non_org_children = sqlx::query_scalar::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM hierarchy_nodes WHERE parent_id = $1 AND node_type != 'org' AND tenant_id = $2",
            )
            .bind(node_id)
            .bind(tenant_id)
            .fetch_one(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;

            if non_org_children > 0 {
                return Err(ApiError::BadRequest(
                    "cannot reparent: non-org children would become root nodes".to_string(),
                ));
            }
        }

        // Validate parent-child type compatibility: ensure each child's type
        // is allowed under the grandparent's type before reparenting.
        if let Some(grandparent_id) = node_parent_id {
            let grandparent_row = sqlx::query::query(
                "SELECT node_type FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2",
            )
            .bind(grandparent_id)
            .bind(tenant_id)
            .fetch_optional(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;

            if let Some(grandparent_row) = grandparent_row {
                let grandparent_type_str: String = grandparent_row
                    .try_get("node_type")
                    .map_err(ApiError::Database)?;

                if let Some(grandparent_type) = HierarchyNodeType::from_str(&grandparent_type_str) {
                    // Fetch the node_type of each child that would be reparented.
                    let child_rows = sqlx::query::query(
                        "SELECT node_type FROM hierarchy_nodes WHERE parent_id = $1 AND tenant_id = $2",
                    )
                    .bind(node_id)
                    .bind(tenant_id)
                    .fetch_all(tx.as_mut())
                    .await
                    .map_err(ApiError::Database)?;

                    let mut invalid_types = Vec::new();
                    for child_row in &child_rows {
                        let child_type_str: String =
                            child_row.try_get("node_type").map_err(ApiError::Database)?;
                        if let Some(child_type) = HierarchyNodeType::from_str(&child_type_str) {
                            if validate_parent_child_types(grandparent_type, child_type).is_err() {
                                invalid_types.push(child_type_str);
                            }
                        }
                    }

                    if !invalid_types.is_empty() {
                        invalid_types.sort();
                        invalid_types.dedup();
                        return Err(ApiError::BadRequest(format!(
                            "cannot reparent: children of type [{}] are not allowed under a {grandparent_type} node",
                            invalid_types.join(", ")
                        )));
                    }
                }
            }
        }

        // Move children to the deleted node's parent
        let result = sqlx::query::query(
            r#"UPDATE hierarchy_nodes
               SET parent_id = $3, updated_at = now()
               WHERE parent_id = $1 AND tenant_id = $2"#,
        )
        .bind(node_id)
        .bind(tenant_id)
        .bind(node_parent_id)
        .execute(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

        reparented_count = result.rows_affected() as i64;
    } else {
        // Cascade delete all descendants using a recursive CTE
        let result = sqlx::query::query(
            r#"WITH RECURSIVE descendants AS (
                   SELECT id FROM hierarchy_nodes
                   WHERE parent_id = $1 AND tenant_id = $2
                   UNION ALL
                   SELECT hn.id
                   FROM hierarchy_nodes hn
                   JOIN descendants d ON hn.parent_id = d.id
                   WHERE hn.tenant_id = $2
               )
               DELETE FROM hierarchy_nodes
               WHERE id IN (SELECT id FROM descendants)
                 AND tenant_id = $2"#,
        )
        .bind(node_id)
        .bind(tenant_id)
        .execute(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

        descendant_count = result.rows_affected() as i64;
        deleted_count += descendant_count;
    }

    // Delete the node itself
    let result = sqlx::query::query("DELETE FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2")
        .bind(node_id)
        .bind(tenant_id)
        .execute(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

    deleted_count += result.rows_affected() as i64;

    tracing::info!(
        node_id = %node_id,
        tenant_id = %tenant_id,
        deleted_count,
        descendant_count,
        reparented_count,
        "Hierarchy node deleted with descendants"
    );

    tx.commit().await.map_err(ApiError::Database)?;

    Ok(DeleteHierarchyNodeResponse {
        deleted_count,
        reparented_count,
        descendant_count,
    })
}

// ---------------------------------------------------------------------------
// Get full tree
// ---------------------------------------------------------------------------

pub async fn get_tree(db: &PgPool, tenant_id: Uuid) -> Result<HierarchyTreeResponse, ApiError> {
    const TREE_HARD_LIMIT: i64 = 10_001;

    let rows = sqlx::query::query(
        r#"SELECT *
           FROM hierarchy_nodes
           WHERE tenant_id = $1
           ORDER BY created_at ASC
           LIMIT $2"#,
    )
    .bind(tenant_id)
    .bind(TREE_HARD_LIMIT)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    if rows.len() as i64 >= TREE_HARD_LIMIT {
        return Err(ApiError::BadRequest(
            "hierarchy too large: tenant has more than 10000 nodes; use the paginated list endpoint instead".to_string(),
        ));
    }

    let nodes: Vec<HierarchyNode> = rows
        .into_iter()
        .map(HierarchyNode::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    let root_id = select_root_id(&nodes);

    // Build a map of parent_id -> ordered children IDs
    let mut children_map: std::collections::HashMap<Uuid, Vec<Uuid>> =
        std::collections::HashMap::new();

    for node in &nodes {
        if let Some(pid) = node.parent_id {
            children_map.entry(pid).or_default().push(node.id);
        }
    }

    let tree_nodes: Vec<HierarchyTreeNode> = nodes
        .into_iter()
        .map(|n| {
            let children = children_map.get(&n.id).cloned().unwrap_or_default();
            HierarchyTreeNode {
                id: n.id,
                name: n.name,
                node_type: n.node_type,
                parent_id: n.parent_id,
                external_id: n.external_id,
                policy_id: n.policy_id,
                policy_name: n.policy_name,
                metadata: n.metadata,
                children,
                created_at: n.created_at,
                updated_at: n.updated_at,
            }
        })
        .collect();

    Ok(HierarchyTreeResponse {
        root_id,
        nodes: tree_nodes,
    })
}

fn select_root_id(nodes: &[HierarchyNode]) -> Option<Uuid> {
    let mut first_top_level = None;

    for node in nodes {
        if node.parent_id.is_some() {
            continue;
        }

        first_top_level.get_or_insert(node.id);

        if node.node_type == HierarchyNodeType::Org.as_str() {
            return Some(node.id);
        }
    }

    first_top_level
}

// ---------------------------------------------------------------------------
// Cycle detection helper
// ---------------------------------------------------------------------------

/// Returns true if `candidate_descendant_id` is a descendant of `ancestor_id`.
/// Uses a pool connection (for standalone checks).
#[allow(dead_code)]
async fn is_descendant(
    db: &PgPool,
    tenant_id: Uuid,
    candidate_descendant_id: Uuid,
    ancestor_id: Uuid,
) -> Result<bool, ApiError> {
    let result = sqlx::query_scalar::query_scalar::<_, bool>(
        r#"WITH RECURSIVE ancestors AS (
               SELECT id, parent_id FROM hierarchy_nodes
               WHERE id = $1 AND tenant_id = $3
               UNION ALL
               SELECT hn.id, hn.parent_id
               FROM hierarchy_nodes hn
               JOIN ancestors a ON hn.id = a.parent_id
               WHERE hn.tenant_id = $3
           )
           SELECT EXISTS (
               SELECT 1 FROM ancestors WHERE id = $2
           )"#,
    )
    .bind(candidate_descendant_id)
    .bind(ancestor_id)
    .bind(tenant_id)
    .fetch_one(db)
    .await
    .map_err(ApiError::Database)?;

    Ok(result)
}

/// Returns true if `candidate_descendant_id` is a descendant of `ancestor_id`.
/// Runs within an existing transaction to avoid TOCTOU races.
async fn is_descendant_tx(
    conn: &mut sqlx_postgres::PgConnection,
    tenant_id: Uuid,
    candidate_descendant_id: Uuid,
    ancestor_id: Uuid,
) -> Result<bool, ApiError> {
    let result = sqlx::query_scalar::query_scalar::<_, bool>(
        r#"WITH RECURSIVE ancestors AS (
               SELECT id, parent_id FROM hierarchy_nodes
               WHERE id = $1 AND tenant_id = $3
               UNION ALL
               SELECT hn.id, hn.parent_id
               FROM hierarchy_nodes hn
               JOIN ancestors a ON hn.id = a.parent_id
               WHERE hn.tenant_id = $3
           )
           SELECT EXISTS (
               SELECT 1 FROM ancestors WHERE id = $2
           )"#,
    )
    .bind(candidate_descendant_id)
    .bind(ancestor_id)
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(ApiError::Database)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn normalized_metadata_update_preserves_explicit_value() {
        let metadata = serde_json::json!({ "tier": "prod" });

        assert_eq!(
            normalized_metadata_update(NullableField::Set(&metadata)),
            Some(metadata)
        );
    }

    #[test]
    fn normalized_metadata_update_clears_to_empty_object() {
        assert_eq!(
            normalized_metadata_update(NullableField::Clear),
            Some(serde_json::json!({}))
        );
    }

    #[test]
    fn normalized_metadata_update_skips_missing_field() {
        assert_eq!(normalized_metadata_update(NullableField::Missing), None);
    }

    #[test]
    fn ensure_parentless_node_allowed_rejects_non_org_roots() {
        assert!(matches!(
            ensure_parentless_node_allowed(HierarchyNodeType::Team, None),
            Err(ApiError::BadRequest(message)) if message == "team nodes must specify a parent_id"
        ));
        assert!(matches!(
            ensure_parentless_node_allowed(HierarchyNodeType::Endpoint, None),
            Err(ApiError::BadRequest(message)) if message == "endpoint nodes must specify a parent_id"
        ));
        assert!(matches!(
            ensure_parentless_node_allowed(HierarchyNodeType::Runtime, None),
            Err(ApiError::BadRequest(message)) if message == "runtime nodes must specify a parent_id"
        ));
    }

    #[test]
    fn ensure_parentless_node_allowed_accepts_org_root() {
        assert!(ensure_parentless_node_allowed(HierarchyNodeType::Org, None).is_ok());
    }

    #[test]
    fn parse_node_type_maps_agent_to_endpoint() {
        let nt = parse_node_type("agent").expect("should parse");
        assert_eq!(nt, HierarchyNodeType::Endpoint);
    }

    #[test]
    fn parse_node_type_accepts_endpoint_and_runtime() {
        assert_eq!(
            parse_node_type("endpoint").expect("should parse"),
            HierarchyNodeType::Endpoint
        );
        assert_eq!(
            parse_node_type("runtime").expect("should parse"),
            HierarchyNodeType::Runtime
        );
    }

    #[test]
    fn parse_node_type_error_message_lists_new_types() {
        let err = parse_node_type("bogus").expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("endpoint"),
            "error should mention endpoint: {msg}"
        );
        assert!(
            msg.contains("runtime"),
            "error should mention runtime: {msg}"
        );
    }

    #[test]
    fn validate_parent_child_types_allows_valid_hierarchy() {
        // org -> team
        assert!(
            validate_parent_child_types(HierarchyNodeType::Org, HierarchyNodeType::Team).is_ok()
        );
        // org -> project
        assert!(
            validate_parent_child_types(HierarchyNodeType::Org, HierarchyNodeType::Project).is_ok()
        );
        // team -> endpoint
        assert!(
            validate_parent_child_types(HierarchyNodeType::Team, HierarchyNodeType::Endpoint)
                .is_ok()
        );
        // team -> project
        assert!(
            validate_parent_child_types(HierarchyNodeType::Team, HierarchyNodeType::Project)
                .is_ok()
        );
        // endpoint -> runtime
        assert!(validate_parent_child_types(
            HierarchyNodeType::Endpoint,
            HierarchyNodeType::Runtime
        )
        .is_ok());
    }

    #[test]
    fn validate_parent_child_types_rejects_invalid_hierarchy() {
        // runtime cannot have children
        assert!(validate_parent_child_types(
            HierarchyNodeType::Runtime,
            HierarchyNodeType::Runtime
        )
        .is_err());
        assert!(validate_parent_child_types(
            HierarchyNodeType::Runtime,
            HierarchyNodeType::Endpoint
        )
        .is_err());
        // endpoint cannot have endpoint children
        assert!(validate_parent_child_types(
            HierarchyNodeType::Endpoint,
            HierarchyNodeType::Endpoint
        )
        .is_err());
        // project cannot have children
        assert!(validate_parent_child_types(
            HierarchyNodeType::Project,
            HierarchyNodeType::Runtime
        )
        .is_err());
        // org cannot directly contain endpoint
        assert!(
            validate_parent_child_types(HierarchyNodeType::Org, HierarchyNodeType::Endpoint)
                .is_err()
        );
        // org cannot directly contain runtime
        assert!(
            validate_parent_child_types(HierarchyNodeType::Org, HierarchyNodeType::Runtime)
                .is_err()
        );
        // team cannot directly contain runtime
        assert!(
            validate_parent_child_types(HierarchyNodeType::Team, HierarchyNodeType::Runtime)
                .is_err()
        );
    }

    fn make_node(
        node_type: HierarchyNodeType,
        parent_id: Option<Uuid>,
        created_at: chrono::DateTime<Utc>,
    ) -> HierarchyNode {
        HierarchyNode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: format!("{node_type} node"),
            node_type: node_type.as_str().to_string(),
            parent_id,
            external_id: None,
            policy_id: None,
            policy_name: None,
            metadata: serde_json::json!({}),
            created_at,
            updated_at: created_at,
        }
    }

    #[test]
    fn select_root_id_prefers_top_level_org_node() {
        let now = Utc::now();
        let orphan_project = make_node(HierarchyNodeType::Project, None, now);
        let org_root = make_node(
            HierarchyNodeType::Org,
            None,
            now + chrono::TimeDelta::seconds(1),
        );

        let selected = select_root_id(&[orphan_project, org_root.clone()]);
        assert_eq!(selected, Some(org_root.id));
    }

    #[test]
    fn select_root_id_falls_back_to_first_top_level_node() {
        let now = Utc::now();
        let project_root = make_node(HierarchyNodeType::Project, None, now);
        let team_root = make_node(
            HierarchyNodeType::Team,
            None,
            now + chrono::TimeDelta::seconds(1),
        );

        let selected = select_root_id(&[project_root.clone(), team_root]);
        assert_eq!(selected, Some(project_root.id));
    }
}
