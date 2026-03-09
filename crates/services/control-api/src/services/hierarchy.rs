use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
use crate::models::hierarchy::{
    DeleteHierarchyNodeResponse, HierarchyNode, HierarchyNodeType, HierarchyTreeNode,
    HierarchyTreeResponse,
};

// ---------------------------------------------------------------------------
// Parameter structs (to satisfy clippy::too_many_arguments)
// ---------------------------------------------------------------------------

pub struct CreateNodeParams<'a> {
    pub tenant_id: Uuid,
    pub name: &'a str,
    pub node_type: &'a str,
    pub parent_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<&'a str>,
    pub metadata: &'a serde_json::Value,
}

pub struct UpdateNodeParams<'a> {
    pub tenant_id: Uuid,
    pub node_id: Uuid,
    pub name: Option<&'a str>,
    pub node_type: Option<&'a str>,
    pub parent_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<&'a str>,
    pub metadata: Option<&'a serde_json::Value>,
}

// ---------------------------------------------------------------------------
// List all nodes
// ---------------------------------------------------------------------------

pub async fn list_nodes(db: &PgPool, tenant_id: Uuid) -> Result<Vec<HierarchyNode>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM hierarchy_nodes
           WHERE tenant_id = $1
           ORDER BY created_at ASC"#,
    )
    .bind(tenant_id)
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
    HierarchyNodeType::from_str(params.node_type).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "invalid node_type '{}': must be one of org, team, project, agent",
            params.node_type
        ))
    })?;

    // If a parent_id is provided, ensure it exists in the same tenant
    if let Some(pid) = params.parent_id {
        let exists =
            sqlx::query::query("SELECT 1 FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2")
                .bind(pid)
                .bind(params.tenant_id)
                .fetch_optional(db)
                .await
                .map_err(ApiError::Database)?;

        if exists.is_none() {
            return Err(ApiError::BadRequest(format!(
                "parent node {pid} does not exist in this tenant"
            )));
        }
    }

    let row = sqlx::query::query(
        r#"INSERT INTO hierarchy_nodes (
               tenant_id, name, node_type, parent_id, policy_id, policy_name, metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING *"#,
    )
    .bind(params.tenant_id)
    .bind(params.name)
    .bind(params.node_type)
    .bind(params.parent_id)
    .bind(params.policy_id)
    .bind(params.policy_name)
    .bind(params.metadata)
    .fetch_one(db)
    .await
    .map_err(|err| {
        // Unique constraint on root org per tenant
        if let sqlx::error::Error::Database(ref db_err) = err {
            if db_err.code().as_deref() == Some("23505") {
                return ApiError::Conflict(
                    "a root org node already exists for this tenant".to_string(),
                );
            }
        }
        ApiError::Database(err)
    })?;

    HierarchyNode::from_row(row).map_err(ApiError::Database)
}

// ---------------------------------------------------------------------------
// Update node
// ---------------------------------------------------------------------------

pub async fn update_node(
    db: &PgPool,
    params: &UpdateNodeParams<'_>,
) -> Result<HierarchyNode, ApiError> {
    // Validate node_type if provided
    if let Some(nt) = params.node_type {
        HierarchyNodeType::from_str(nt).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "invalid node_type '{nt}': must be one of org, team, project, agent"
            ))
        })?;
    }

    // Validate parent_id if provided — prevent self-parenting and cross-tenant refs
    if let Some(pid) = params.parent_id {
        if pid == params.node_id {
            return Err(ApiError::BadRequest(
                "a node cannot be its own parent".to_string(),
            ));
        }

        let exists =
            sqlx::query::query("SELECT 1 FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2")
                .bind(pid)
                .bind(params.tenant_id)
                .fetch_optional(db)
                .await
                .map_err(ApiError::Database)?;

        if exists.is_none() {
            return Err(ApiError::BadRequest(format!(
                "parent node {pid} does not exist in this tenant"
            )));
        }

        // Prevent cycles: ensure the proposed parent is not a descendant of this node.
        if is_descendant(db, params.tenant_id, pid, params.node_id).await? {
            return Err(ApiError::BadRequest(
                "cannot set parent: would create a cycle in the hierarchy".to_string(),
            ));
        }
    }

    let row = sqlx::query::query(
        r#"UPDATE hierarchy_nodes
           SET name = COALESCE($3, name),
               node_type = COALESCE($4, node_type),
               parent_id = COALESCE($5, parent_id),
               policy_id = COALESCE($6, policy_id),
               policy_name = COALESCE($7, policy_name),
               metadata = COALESCE($8, metadata),
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2
           RETURNING *"#,
    )
    .bind(params.node_id)
    .bind(params.tenant_id)
    .bind(params.name)
    .bind(params.node_type)
    .bind(params.parent_id)
    .bind(params.policy_id)
    .bind(params.policy_name)
    .bind(params.metadata)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    HierarchyNode::from_row(row).map_err(ApiError::Database)
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

    // Verify the node exists
    let node_row = sqlx::query::query(
        "SELECT parent_id FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2",
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

    if reparent {
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

        deleted_count += result.rows_affected() as i64;
    }

    // Delete the node itself
    let result = sqlx::query::query("DELETE FROM hierarchy_nodes WHERE id = $1 AND tenant_id = $2")
        .bind(node_id)
        .bind(tenant_id)
        .execute(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

    deleted_count += result.rows_affected() as i64;

    tx.commit().await.map_err(ApiError::Database)?;

    Ok(DeleteHierarchyNodeResponse {
        deleted_count,
        reparented_count,
    })
}

// ---------------------------------------------------------------------------
// Get full tree
// ---------------------------------------------------------------------------

pub async fn get_tree(db: &PgPool, tenant_id: Uuid) -> Result<HierarchyTreeResponse, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM hierarchy_nodes
           WHERE tenant_id = $1
           ORDER BY created_at ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let nodes: Vec<HierarchyNode> = rows
        .into_iter()
        .map(HierarchyNode::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    // Build a map of parent_id -> ordered children IDs
    let mut children_map: std::collections::HashMap<Uuid, Vec<Uuid>> =
        std::collections::HashMap::new();
    let mut root_id: Option<Uuid> = None;

    for node in &nodes {
        if let Some(pid) = node.parent_id {
            children_map.entry(pid).or_default().push(node.id);
        } else {
            // Root node (no parent)
            root_id = Some(node.id);
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

// ---------------------------------------------------------------------------
// Cycle detection helper
// ---------------------------------------------------------------------------

/// Returns true if `candidate_descendant_id` is a descendant of `ancestor_id`.
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
