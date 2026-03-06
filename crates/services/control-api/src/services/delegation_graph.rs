use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{DateTime, TimeZone, Utc};
use hush_multi_agent::{
    AgentCapability, AgentId, DelegationClaims, DelegationGraphEdgeKind, DelegationGraphNodeKind,
    GrantLineageFacts, InMemoryRevocationStore, SignedDelegationToken, DELEGATION_AUDIENCE,
};
use serde_json::json;
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;

use super::delegation_graph_models::{
    DelegationGraphEdge, DelegationGraphNode, DelegationGraphSnapshot, FleetGrant,
    GrantExerciseRequest, IngestGrantRequest, ListGrantsQuery, RevokeGrantRequest,
    RevokeGrantResponse,
};

struct TenantGraphData {
    grants: BTreeMap<Uuid, FleetGrant>,
    nodes: BTreeMap<String, DelegationGraphNode>,
    edges: Vec<DelegationGraphEdge>,
}

pub async fn list_grants(
    db: &PgPool,
    tenant_id: Uuid,
    query: &ListGrantsQuery,
) -> Result<Vec<FleetGrant>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM fleet_grants
           WHERE tenant_id = $1
             AND ($2::text IS NULL
                  OR issuer_principal_id = $2
                  OR subject_principal_id = $2)
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR token_jti = $4)
           ORDER BY issued_at DESC, created_at DESC"#,
    )
    .bind(tenant_id)
    .bind(query.principal_id.as_deref())
    .bind(query.status.as_deref())
    .bind(query.token_jti.as_deref())
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(FleetGrant::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

pub async fn get_grant(db: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<FleetGrant, ApiError> {
    let row = sqlx::query::query("SELECT * FROM fleet_grants WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;

    FleetGrant::from_row(row).map_err(ApiError::Database)
}

pub async fn ingest_grant(
    db: &PgPool,
    tenant_id: Uuid,
    request: IngestGrantRequest,
) -> Result<FleetGrant, ApiError> {
    let token = request.token;
    verify_signed_token(&token, request.issuer_public_key.as_deref())?;
    reject_revoked_chain(db, tenant_id, &token.claims).await?;

    let lineage = GrantLineageFacts::from_claims(&token.claims);
    let grant_type = request
        .grant_type
        .unwrap_or_else(|| "delegation".to_string());
    validate_grant_type(&grant_type)?;

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let parent_grant = if let Some(parent_token_jti) = lineage.parent_token_jti.as_deref() {
        fetch_grant_by_token(&mut tx, tenant_id, parent_token_jti).await?
    } else {
        None
    };
    if let Some(parent_grant) = parent_grant.as_ref() {
        validate_child_grant_against_parent(&token.claims, parent_grant)?;
    }

    let now = Utc::now();
    let status = if token.claims.exp <= now.timestamp() {
        "expired"
    } else {
        "active"
    };
    let lineage_chain = serde_json::to_value(&lineage.chain).map_err(|err| {
        ApiError::Internal(format!(
            "failed to serialize lineage chain for grant ingest: {err}"
        ))
    })?;
    let capabilities = serde_json::to_value(&token.claims.cap).map_err(|err| {
        ApiError::Internal(format!("failed to serialize grant capabilities: {err}"))
    })?;
    let capability_ceiling =
        serde_json::to_value(token.claims.effective_ceiling()).map_err(|err| {
            ApiError::Internal(format!(
                "failed to serialize grant capability ceiling: {err}"
            ))
        })?;
    let context = token.claims.ctx.clone().unwrap_or_else(|| json!({}));
    let issued_at = unix_to_utc(token.claims.iat)?;
    let not_before = token.claims.nbf.map(unix_to_utc).transpose()?;
    let expires_at = unix_to_utc(token.claims.exp)?;

    let row = sqlx::query::query(
        r#"INSERT INTO fleet_grants (
               tenant_id,
               issuer_principal_id,
               subject_principal_id,
               grant_type,
               audience,
               token_jti,
               parent_grant_id,
               parent_token_jti,
               delegation_depth,
               lineage_chain,
               lineage_resolved,
               capabilities,
               capability_ceiling,
               purpose,
               context,
               source_approval_id,
               source_session_id,
               issued_at,
               not_before,
               expires_at,
               status,
               updated_at
           ) VALUES (
               $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
               $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, now()
           )
           ON CONFLICT (tenant_id, token_jti)
           DO UPDATE SET
               issuer_principal_id = EXCLUDED.issuer_principal_id,
               subject_principal_id = EXCLUDED.subject_principal_id,
               grant_type = EXCLUDED.grant_type,
               audience = EXCLUDED.audience,
               parent_grant_id = EXCLUDED.parent_grant_id,
               parent_token_jti = EXCLUDED.parent_token_jti,
               delegation_depth = EXCLUDED.delegation_depth,
               lineage_chain = EXCLUDED.lineage_chain,
               lineage_resolved = EXCLUDED.lineage_resolved,
               capabilities = EXCLUDED.capabilities,
               capability_ceiling = EXCLUDED.capability_ceiling,
               purpose = EXCLUDED.purpose,
               context = EXCLUDED.context,
               source_approval_id = COALESCE(EXCLUDED.source_approval_id, fleet_grants.source_approval_id),
               source_session_id = COALESCE(EXCLUDED.source_session_id, fleet_grants.source_session_id),
               issued_at = EXCLUDED.issued_at,
               not_before = EXCLUDED.not_before,
               expires_at = EXCLUDED.expires_at,
               status = CASE
                   WHEN fleet_grants.status = 'revoked' THEN fleet_grants.status
                   ELSE EXCLUDED.status
               END,
               updated_at = now()
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(token.claims.iss.as_str())
    .bind(token.claims.sub.as_str())
    .bind(&grant_type)
    .bind(&token.claims.aud)
    .bind(&token.claims.jti)
    .bind(parent_grant.as_ref().map(|grant| grant.id))
    .bind(lineage.parent_token_jti.as_deref())
    .bind(i32::try_from(lineage.depth).map_err(|err| {
        ApiError::BadRequest(format!("delegation depth exceeds supported range: {err}"))
    })?)
    .bind(lineage_chain)
    .bind(parent_grant.is_some() || lineage.parent_token_jti.is_none())
    .bind(capabilities)
    .bind(capability_ceiling)
    .bind(token.claims.pur.as_deref())
    .bind(context)
    .bind(request.source_approval_id.as_deref())
    .bind(request.source_session_id.as_deref())
    .bind(issued_at)
    .bind(not_before)
    .bind(expires_at)
    .bind(status)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    let grant = FleetGrant::from_row(row).map_err(ApiError::Database)?;
    let issuer_node_id = DelegationGraphNodeKind::Principal.node_id(&grant.issuer_principal_id);
    let subject_node_id = DelegationGraphNodeKind::Principal.node_id(&grant.subject_principal_id);
    let grant_node_id = DelegationGraphNodeKind::Grant.node_id(&grant.id.to_string());

    upsert_node(
        &mut tx,
        tenant_id,
        &issuer_node_id,
        DelegationGraphNodeKind::Principal.as_str(),
        &grant.issuer_principal_id,
        Some("active"),
        json!({ "principal_id": &grant.issuer_principal_id }),
    )
    .await?;
    upsert_node(
        &mut tx,
        tenant_id,
        &subject_node_id,
        DelegationGraphNodeKind::Principal.as_str(),
        &grant.subject_principal_id,
        Some("active"),
        json!({ "principal_id": &grant.subject_principal_id }),
    )
    .await?;
    upsert_node(
        &mut tx,
        tenant_id,
        &grant_node_id,
        DelegationGraphNodeKind::Grant.as_str(),
        &grant_label(&grant),
        Some(grant.status.as_str()),
        json!({
            "grant_id": grant.id.to_string(),
            "token_jti": &grant.token_jti,
            "delegation_depth": grant.delegation_depth,
            "lineage_resolved": grant.lineage_resolved,
        }),
    )
    .await?;
    upsert_edge(
        &mut tx,
        tenant_id,
        &issuer_node_id,
        &grant_node_id,
        DelegationGraphEdgeKind::IssuedGrant.as_str(),
        json!({ "token_jti": &grant.token_jti }),
    )
    .await?;
    upsert_edge(
        &mut tx,
        tenant_id,
        &grant_node_id,
        &subject_node_id,
        DelegationGraphEdgeKind::ReceivedGrant.as_str(),
        json!({ "token_jti": &grant.token_jti }),
    )
    .await?;

    if let Some(parent) = parent_grant {
        let parent_node_id = DelegationGraphNodeKind::Grant.node_id(&parent.id.to_string());
        upsert_node(
            &mut tx,
            tenant_id,
            &parent_node_id,
            DelegationGraphNodeKind::Grant.as_str(),
            &grant_label(&parent),
            Some(parent.status.as_str()),
            json!({ "grant_id": parent.id.to_string(), "token_jti": &parent.token_jti }),
        )
        .await?;
        upsert_edge(
            &mut tx,
            tenant_id,
            &parent_node_id,
            &grant_node_id,
            DelegationGraphEdgeKind::DerivedFromGrant.as_str(),
            json!({
                "parent_token_jti": grant.parent_token_jti.clone(),
                "delegation_depth": grant.delegation_depth,
            }),
        )
        .await?;
    }

    if let Some(source_approval_id) = grant.source_approval_id.as_deref() {
        let approval_node_id = DelegationGraphNodeKind::Approval.node_id(source_approval_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &approval_node_id,
            DelegationGraphNodeKind::Approval.as_str(),
            source_approval_id,
            Some("observed"),
            json!({ "approval_id": source_approval_id }),
        )
        .await?;
        upsert_edge(
            &mut tx,
            tenant_id,
            &approval_node_id,
            &grant_node_id,
            DelegationGraphEdgeKind::ApprovedBy.as_str(),
            json!({ "approval_id": source_approval_id }),
        )
        .await?;
    }

    if let Some(source_session_id) = grant.source_session_id.as_deref() {
        let session_node_id = DelegationGraphNodeKind::Session.node_id(source_session_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &session_node_id,
            DelegationGraphNodeKind::Session.as_str(),
            source_session_id,
            Some("observed"),
            json!({ "session_id": source_session_id }),
        )
        .await?;
        upsert_edge(
            &mut tx,
            tenant_id,
            &grant_node_id,
            &session_node_id,
            DelegationGraphEdgeKind::ExercisedInSession.as_str(),
            json!({ "session_id": source_session_id }),
        )
        .await?;
    }

    tx.commit().await.map_err(ApiError::Database)?;
    Ok(grant)
}

pub async fn exercise_grant(
    db: &PgPool,
    tenant_id: Uuid,
    grant_id: Uuid,
    request: GrantExerciseRequest,
) -> Result<DelegationGraphSnapshot, ApiError> {
    let grant = get_grant(db, tenant_id, grant_id).await?;
    let grant_node_id = DelegationGraphNodeKind::Grant.node_id(&grant.id.to_string());
    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    if let Some(session_id) = request.session_id.as_deref() {
        let session_node_id = DelegationGraphNodeKind::Session.node_id(session_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &session_node_id,
            DelegationGraphNodeKind::Session.as_str(),
            request.session_label.as_deref().unwrap_or(session_id),
            request.session_state.as_deref(),
            request
                .session_metadata
                .unwrap_or_else(|| json!({ "session_id": session_id })),
        )
        .await?;
        upsert_edge(
            &mut tx,
            tenant_id,
            &grant_node_id,
            &session_node_id,
            DelegationGraphEdgeKind::ExercisedInSession.as_str(),
            json!({ "session_id": session_id }),
        )
        .await?;
    }

    let mut event_node_id = None;
    if let Some(event_id) = request.event_id.as_deref() {
        let node_id = DelegationGraphNodeKind::Event.node_id(event_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &node_id,
            DelegationGraphNodeKind::Event.as_str(),
            request.event_label.as_deref().unwrap_or(event_id),
            request.event_state.as_deref(),
            request
                .event_metadata
                .unwrap_or_else(|| json!({ "event_id": event_id })),
        )
        .await?;
        upsert_edge(
            &mut tx,
            tenant_id,
            &grant_node_id,
            &node_id,
            DelegationGraphEdgeKind::ExercisedInEvent.as_str(),
            json!({ "event_id": event_id, "token_jti": &grant.token_jti }),
        )
        .await?;
        event_node_id = Some(node_id);
    }

    if let Some(response_action_id) = request.response_action_id.as_deref() {
        let response_node_id = DelegationGraphNodeKind::ResponseAction.node_id(response_action_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &response_node_id,
            DelegationGraphNodeKind::ResponseAction.as_str(),
            request
                .response_action_label
                .as_deref()
                .unwrap_or(response_action_id),
            request.response_action_state.as_deref(),
            request
                .response_action_metadata
                .unwrap_or_else(|| json!({ "response_action_id": response_action_id })),
        )
        .await?;
        let from_node_id = event_node_id.as_deref().unwrap_or(grant_node_id.as_str());
        upsert_edge(
            &mut tx,
            tenant_id,
            from_node_id,
            &response_node_id,
            DelegationGraphEdgeKind::TriggeredResponseAction.as_str(),
            json!({ "response_action_id": response_action_id }),
        )
        .await?;
    }

    tx.commit().await.map_err(ApiError::Database)?;
    grant_lineage_snapshot(db, tenant_id, grant_id).await
}

pub async fn revoke_grant(
    db: &PgPool,
    tenant_id: Uuid,
    grant_id: Uuid,
    request: RevokeGrantRequest,
) -> Result<RevokeGrantResponse, ApiError> {
    if request.reason.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "revoke reason must not be empty".to_string(),
        ));
    }

    let revoked_by = request
        .revoked_by
        .clone()
        .unwrap_or_else(|| "control-api".to_string());
    let data = load_tenant_graph_data(db, tenant_id).await?;
    if !data.grants.contains_key(&grant_id) {
        return Err(ApiError::NotFound);
    }
    let grant_ids = if request.revoke_descendants.unwrap_or(true) {
        descendant_grant_ids(&data.grants, grant_id)
    } else {
        let mut only_self = BTreeSet::new();
        only_self.insert(grant_id);
        only_self
    };
    let revoked_ids = grant_ids.iter().copied().collect::<Vec<_>>();

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let now = Utc::now();
    for current_grant_id in &revoked_ids {
        let row = sqlx::query::query(
            r#"UPDATE fleet_grants
               SET status = 'revoked',
                   revoked_at = $3,
                   revoked_by = $4,
                   revoke_reason = $5,
                   updated_at = now()
               WHERE tenant_id = $1 AND id = $2
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(current_grant_id)
        .bind(now)
        .bind(&revoked_by)
        .bind(&request.reason)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::Database)?;

        let current_grant = FleetGrant::from_row(row).map_err(ApiError::Database)?;
        let node_id = DelegationGraphNodeKind::Grant.node_id(&current_grant.id.to_string());
        upsert_node(
            &mut tx,
            tenant_id,
            &node_id,
            DelegationGraphNodeKind::Grant.as_str(),
            &grant_label(&current_grant),
            Some("revoked"),
            json!({
                "grant_id": current_grant.id.to_string(),
                "revoked_by": &revoked_by,
                "revoke_reason": &request.reason,
            }),
        )
        .await?;
    }

    if let Some(response_action_id) = request.response_action_id.as_deref() {
        let response_node_id = DelegationGraphNodeKind::ResponseAction.node_id(response_action_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &response_node_id,
            DelegationGraphNodeKind::ResponseAction.as_str(),
            request
                .response_action_label
                .as_deref()
                .unwrap_or(response_action_id),
            request.response_action_state.as_deref(),
            request
                .response_action_metadata
                .unwrap_or_else(|| json!({ "response_action_id": response_action_id })),
        )
        .await?;
        let target_node_id = DelegationGraphNodeKind::Grant.node_id(&grant_id.to_string());
        upsert_edge(
            &mut tx,
            tenant_id,
            &response_node_id,
            &target_node_id,
            DelegationGraphEdgeKind::RevokedBy.as_str(),
            json!({ "reason": &request.reason, "revoked_by": &revoked_by }),
        )
        .await?;
    }

    tx.commit().await.map_err(ApiError::Database)?;
    let grant = get_grant(db, tenant_id, grant_id).await?;
    Ok(RevokeGrantResponse {
        grant,
        revoked_grant_ids: revoked_ids,
    })
}

pub async fn grant_lineage_snapshot(
    db: &PgPool,
    tenant_id: Uuid,
    grant_id: Uuid,
) -> Result<DelegationGraphSnapshot, ApiError> {
    let data = load_tenant_graph_data(db, tenant_id).await?;
    if !data.grants.contains_key(&grant_id) {
        return Err(ApiError::NotFound);
    }

    let grant_ids = lineage_grant_ids(&data.grants, grant_id);
    let root_node_id = Some(DelegationGraphNodeKind::Grant.node_id(&grant_id.to_string()));
    Ok(snapshot_for_grant_ids(
        &data,
        &grant_ids,
        root_node_id,
        true,
    ))
}

pub async fn principal_graph_snapshot(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: &str,
    include_context: bool,
) -> Result<DelegationGraphSnapshot, ApiError> {
    let principal_aliases = resolve_principal_aliases(db, tenant_id, principal_id).await?;
    let data = load_tenant_graph_data(db, tenant_id).await?;
    let mut starting_grants = BTreeSet::new();
    for (grant_id, grant) in &data.grants {
        if principal_aliases.matches(&grant.issuer_principal_id)
            || principal_aliases.matches(&grant.subject_principal_id)
        {
            starting_grants.insert(*grant_id);
        }
    }

    let mut expanded = BTreeSet::new();
    for grant_id in &starting_grants {
        expanded.extend(lineage_grant_ids(&data.grants, *grant_id));
    }

    let root_node_id =
        Some(DelegationGraphNodeKind::Principal.node_id(&principal_aliases.canonical_id));
    Ok(snapshot_for_grant_ids(
        &data,
        &expanded,
        root_node_id,
        include_context,
    ))
}

struct PrincipalAliases {
    canonical_id: String,
    aliases: BTreeSet<String>,
}

impl PrincipalAliases {
    fn matches(&self, candidate: &str) -> bool {
        self.aliases.contains(candidate)
    }
}

async fn resolve_principal_aliases(
    db: &PgPool,
    tenant_id: Uuid,
    principal_identifier: &str,
) -> Result<PrincipalAliases, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT id::text AS id_text, stable_ref
           FROM principals
           WHERE tenant_id = $1
             AND (id::text = $2 OR stable_ref = $2)
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(principal_identifier)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?;

    let mut aliases = BTreeSet::new();
    aliases.insert(principal_identifier.to_string());

    let canonical_id = if let Some(row) = row {
        let id_text = row
            .try_get::<String, _>("id_text")
            .map_err(ApiError::Database)?;
        let stable_ref = row
            .try_get::<String, _>("stable_ref")
            .map_err(ApiError::Database)?;
        aliases.insert(id_text.clone());
        aliases.insert(stable_ref);
        id_text
    } else {
        principal_identifier.to_string()
    };

    Ok(PrincipalAliases {
        canonical_id,
        aliases,
    })
}

pub async fn graph_path_snapshot(
    db: &PgPool,
    tenant_id: Uuid,
    from: &str,
    to: &str,
) -> Result<DelegationGraphSnapshot, ApiError> {
    let data = load_tenant_graph_data(db, tenant_id).await?;
    let mut adjacency = BTreeMap::<String, Vec<&DelegationGraphEdge>>::new();
    for edge in &data.edges {
        adjacency.entry(edge.from.clone()).or_default().push(edge);
    }

    if !data.nodes.contains_key(from) || !data.nodes.contains_key(to) {
        return Ok(empty_snapshot(Some(from.to_string())));
    }

    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();
    let mut previous = BTreeMap::<String, (String, Uuid)>::new();

    queue.push_back(from.to_string());
    visited.insert(from.to_string());

    while let Some(node_id) = queue.pop_front() {
        if node_id == to {
            break;
        }
        if let Some(edges) = adjacency.get(&node_id) {
            for edge in edges {
                if visited.insert(edge.to.clone()) {
                    previous.insert(edge.to.clone(), (node_id.clone(), edge.id));
                    queue.push_back(edge.to.clone());
                }
            }
        }
    }

    if !visited.contains(to) {
        return Ok(empty_snapshot(Some(from.to_string())));
    }

    let mut node_ids = BTreeSet::new();
    let mut edge_ids = BTreeSet::new();
    let mut cursor = to.to_string();
    node_ids.insert(cursor.clone());
    while let Some((prior, edge_id)) = previous.get(&cursor) {
        edge_ids.insert(*edge_id);
        node_ids.insert(prior.clone());
        cursor = prior.clone();
    }

    let mut nodes = node_ids
        .into_iter()
        .filter_map(|node_id| data.nodes.get(&node_id).cloned())
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));

    let mut edges = data
        .edges
        .iter()
        .filter(|edge| edge_ids.contains(&edge.id))
        .cloned()
        .collect::<Vec<_>>();
    edges.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(DelegationGraphSnapshot {
        root_node_id: Some(from.to_string()),
        nodes,
        edges,
        generated_at: Utc::now(),
    })
}

async fn load_tenant_graph_data(db: &PgPool, tenant_id: Uuid) -> Result<TenantGraphData, ApiError> {
    let grant_rows = sqlx::query::query("SELECT * FROM fleet_grants WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_all(db)
        .await
        .map_err(ApiError::Database)?;
    let node_rows = sqlx::query::query(
        "SELECT id, kind, label, state, metadata FROM delegation_graph_nodes WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;
    let edge_rows = sqlx::query::query(
        "SELECT id, from_node_id, to_node_id, kind, metadata FROM delegation_graph_edges WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let grants = grant_rows
        .into_iter()
        .map(FleetGrant::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;
    let nodes = node_rows
        .into_iter()
        .map(DelegationGraphNode::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;
    let edges = edge_rows
        .into_iter()
        .map(DelegationGraphEdge::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;

    let grants_by_id = grants
        .into_iter()
        .map(|grant| (grant.id, grant))
        .collect::<BTreeMap<_, _>>();
    let nodes_by_id = nodes
        .into_iter()
        .map(|node| (node.id.clone(), node))
        .collect::<BTreeMap<_, _>>();

    Ok(TenantGraphData {
        grants: grants_by_id,
        nodes: nodes_by_id,
        edges,
    })
}

fn lineage_grant_ids(grants: &BTreeMap<Uuid, FleetGrant>, grant_id: Uuid) -> BTreeSet<Uuid> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(grant_id);

    while let Some(current_id) = queue.pop_front() {
        if !visited.insert(current_id) {
            continue;
        }
        if let Some(parent_id) = grants
            .get(&current_id)
            .and_then(|grant| grant.parent_grant_id)
        {
            queue.push_back(parent_id);
        }
        for child_id in grants
            .values()
            .filter(|grant| grant.parent_grant_id == Some(current_id))
            .map(|grant| grant.id)
        {
            queue.push_back(child_id);
        }
    }

    visited
}

fn descendant_grant_ids(grants: &BTreeMap<Uuid, FleetGrant>, grant_id: Uuid) -> BTreeSet<Uuid> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(grant_id);

    while let Some(current_id) = queue.pop_front() {
        if !visited.insert(current_id) {
            continue;
        }
        for child_id in grants
            .values()
            .filter(|grant| grant.parent_grant_id == Some(current_id))
            .map(|grant| grant.id)
        {
            queue.push_back(child_id);
        }
    }

    visited
}

fn snapshot_for_grant_ids(
    data: &TenantGraphData,
    grant_ids: &BTreeSet<Uuid>,
    root_node_id: Option<String>,
    include_context: bool,
) -> DelegationGraphSnapshot {
    let mut included_node_ids = BTreeSet::new();
    for grant_id in grant_ids {
        included_node_ids.insert(DelegationGraphNodeKind::Grant.node_id(&grant_id.to_string()));
    }

    let mut included_edges = Vec::new();
    for edge in &data.edges {
        let touches_grant =
            included_node_ids.contains(&edge.from) || included_node_ids.contains(&edge.to);
        let both_included =
            included_node_ids.contains(&edge.from) && included_node_ids.contains(&edge.to);
        if both_included || (include_context && touches_grant) {
            included_node_ids.insert(edge.from.clone());
            included_node_ids.insert(edge.to.clone());
            included_edges.push(edge.clone());
        }
    }

    if let Some(root) = root_node_id.as_deref() {
        included_node_ids.insert(root.to_string());
    }

    let mut nodes = included_node_ids
        .into_iter()
        .filter_map(|node_id| data.nodes.get(&node_id).cloned())
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    included_edges.sort_by(|left, right| left.id.cmp(&right.id));

    DelegationGraphSnapshot {
        root_node_id,
        nodes,
        edges: included_edges,
        generated_at: Utc::now(),
    }
}

fn empty_snapshot(root_node_id: Option<String>) -> DelegationGraphSnapshot {
    DelegationGraphSnapshot {
        root_node_id,
        nodes: Vec::new(),
        edges: Vec::new(),
        generated_at: Utc::now(),
    }
}

async fn reject_revoked_chain(
    db: &PgPool,
    tenant_id: Uuid,
    claims: &DelegationClaims,
) -> Result<(), ApiError> {
    let row = if claims.chn.is_empty() {
        sqlx::query::query(
            r#"SELECT token_jti
               FROM fleet_grants
               WHERE tenant_id = $1
                 AND status = 'revoked'
                 AND token_jti = $2
               ORDER BY issued_at DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(&claims.jti)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
    } else {
        sqlx::query::query(
            r#"SELECT token_jti
               FROM fleet_grants
               WHERE tenant_id = $1
                 AND status = 'revoked'
                 AND (token_jti = $2 OR token_jti = ANY($3))
               ORDER BY issued_at DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(&claims.jti)
        .bind(&claims.chn)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
    };

    if let Some(row) = row {
        let token_jti: String = row.try_get("token_jti").map_err(ApiError::Database)?;
        return Err(ApiError::BadRequest(format!(
            "grant chain contains revoked token {token_jti}"
        )));
    }

    Ok(())
}

fn verify_signed_token(
    token: &SignedDelegationToken,
    issuer_public_key: Option<&str>,
) -> Result<(), ApiError> {
    let public_key = if let Some(encoded) = issuer_public_key {
        hush_core::PublicKey::from_hex(encoded)
            .map_err(|_| ApiError::BadRequest("issuer_public_key must be valid hex".to_string()))?
    } else if let Some(public_key) = token.public_key.clone() {
        public_key
    } else {
        return Err(ApiError::BadRequest(
            "signed delegation token must include an embedded public key or issuer_public_key"
                .to_string(),
        ));
    };

    let revocations = InMemoryRevocationStore::default();
    token
        .verify_and_validate(
            &public_key,
            Utc::now().timestamp(),
            &revocations,
            DELEGATION_AUDIENCE,
            None,
        )
        .map_err(|err| ApiError::BadRequest(format!("invalid delegation token: {err}")))
}

fn validate_child_grant_against_parent(
    child_claims: &DelegationClaims,
    parent_grant: &FleetGrant,
) -> Result<(), ApiError> {
    if parent_grant.status == "revoked" {
        return Err(ApiError::BadRequest(format!(
            "parent grant {} is revoked",
            parent_grant.token_jti
        )));
    }

    let parent_claims = claims_from_grant(parent_grant)?;
    child_claims
        .validate_redelegation_from(&parent_claims)
        .map_err(|err| {
            ApiError::BadRequest(format!(
                "invalid delegation token for parent {}: {err}",
                parent_grant.token_jti
            ))
        })
}

fn claims_from_grant(grant: &FleetGrant) -> Result<DelegationClaims, ApiError> {
    let iss = AgentId::new(grant.issuer_principal_id.clone()).map_err(|err| {
        ApiError::Internal(format!(
            "stored fleet grant {} has invalid issuer principal id: {err}",
            grant.id
        ))
    })?;
    let sub = AgentId::new(grant.subject_principal_id.clone()).map_err(|err| {
        ApiError::Internal(format!(
            "stored fleet grant {} has invalid subject principal id: {err}",
            grant.id
        ))
    })?;
    let cap: Vec<AgentCapability> =
        serde_json::from_value(grant.capabilities.clone()).map_err(|err| {
            ApiError::Internal(format!(
                "stored fleet grant {} has invalid capabilities: {err}",
                grant.id
            ))
        })?;
    let cel: Vec<AgentCapability> = serde_json::from_value(grant.capability_ceiling.clone())
        .map_err(|err| {
            ApiError::Internal(format!(
                "stored fleet grant {} has invalid capability ceiling: {err}",
                grant.id
            ))
        })?;
    let ctx = if grant.context.as_object().is_some_and(|map| map.is_empty()) {
        None
    } else {
        Some(grant.context.clone())
    };
    let claims = DelegationClaims {
        iss,
        sub,
        aud: grant.audience.clone(),
        iat: grant.issued_at.timestamp(),
        exp: grant.expires_at.timestamp(),
        nbf: grant.not_before.map(|value| value.timestamp()),
        jti: grant.token_jti.clone(),
        cap,
        chn: grant.lineage_chain.clone(),
        cel,
        pur: grant.purpose.clone(),
        ctx,
    };
    claims.validate_basic().map_err(|err| {
        ApiError::Internal(format!(
            "stored fleet grant {} could not be reconstructed as valid claims: {err}",
            grant.id
        ))
    })?;
    Ok(claims)
}

fn validate_grant_type(grant_type: &str) -> Result<(), ApiError> {
    if matches!(grant_type, "delegation" | "approval" | "session_override") {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "unsupported grant_type '{grant_type}'"
        )))
    }
}

fn unix_to_utc(unix_seconds: i64) -> Result<DateTime<Utc>, ApiError> {
    Utc.timestamp_opt(unix_seconds, 0)
        .single()
        .ok_or_else(|| ApiError::BadRequest(format!("invalid unix timestamp {unix_seconds}")))
}

fn grant_label(grant: &FleetGrant) -> String {
    grant
        .purpose
        .clone()
        .unwrap_or_else(|| format!("grant {}", grant.token_jti))
}

async fn fetch_grant_by_token(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    token_jti: &str,
) -> Result<Option<FleetGrant>, ApiError> {
    let row =
        sqlx::query::query("SELECT * FROM fleet_grants WHERE tenant_id = $1 AND token_jti = $2")
            .bind(tenant_id)
            .bind(token_jti)
            .fetch_optional(&mut **tx)
            .await
            .map_err(ApiError::Database)?;

    row.map(FleetGrant::from_row)
        .transpose()
        .map_err(ApiError::Database)
}

async fn upsert_node(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    id: &str,
    kind: &str,
    label: &str,
    state: Option<&str>,
    metadata: serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"INSERT INTO delegation_graph_nodes (
               tenant_id, id, kind, label, state, metadata
           ) VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (tenant_id, id)
           DO UPDATE SET
               kind = EXCLUDED.kind,
               label = EXCLUDED.label,
               state = COALESCE(EXCLUDED.state, delegation_graph_nodes.state),
               metadata = delegation_graph_nodes.metadata || EXCLUDED.metadata,
               updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(id)
    .bind(kind)
    .bind(label)
    .bind(state)
    .bind(metadata)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    Ok(())
}

async fn upsert_edge(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    from_node_id: &str,
    to_node_id: &str,
    kind: &str,
    metadata: serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"INSERT INTO delegation_graph_edges (
               tenant_id, from_node_id, to_node_id, kind, metadata
           ) VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (tenant_id, from_node_id, to_node_id, kind)
           DO UPDATE SET
               metadata = delegation_graph_edges.metadata || EXCLUDED.metadata,
               updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(from_node_id)
    .bind(to_node_id)
    .bind(kind)
    .bind(metadata)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant(id: Uuid, parent_grant_id: Option<Uuid>, token_jti: &str) -> FleetGrant {
        let now = Utc::now();
        FleetGrant {
            id,
            tenant_id: Uuid::new_v4(),
            issuer_principal_id: "agent:issuer".to_string(),
            subject_principal_id: "agent:subject".to_string(),
            grant_type: "delegation".to_string(),
            audience: DELEGATION_AUDIENCE.to_string(),
            token_jti: token_jti.to_string(),
            parent_grant_id,
            parent_token_jti: None,
            delegation_depth: 0,
            lineage_chain: Vec::new(),
            lineage_resolved: true,
            capabilities: json!([]),
            capability_ceiling: json!([]),
            purpose: None,
            context: json!({}),
            source_approval_id: None,
            source_session_id: None,
            issued_at: now,
            not_before: None,
            expires_at: now,
            status: "active".to_string(),
            revoked_at: None,
            revoked_by: None,
            revoke_reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn lineage_walk_collects_ancestors_and_descendants() {
        let root_id = Uuid::new_v4();
        let child_id = Uuid::new_v4();
        let grandchild_id = Uuid::new_v4();
        let grants = [
            sample_grant(root_id, None, "root"),
            sample_grant(child_id, Some(root_id), "child"),
            sample_grant(grandchild_id, Some(child_id), "grandchild"),
        ]
        .into_iter()
        .map(|grant| (grant.id, grant))
        .collect::<BTreeMap<_, _>>();

        let lineage = lineage_grant_ids(&grants, child_id);
        assert!(lineage.contains(&root_id));
        assert!(lineage.contains(&child_id));
        assert!(lineage.contains(&grandchild_id));
    }

    #[test]
    fn empty_path_snapshot_is_stable() {
        let snapshot = empty_snapshot(Some("principal:agent:test".to_string()));
        assert_eq!(
            snapshot.root_node_id.as_deref(),
            Some("principal:agent:test")
        );
        assert!(snapshot.nodes.is_empty());
        assert!(snapshot.edges.is_empty());
    }
}
