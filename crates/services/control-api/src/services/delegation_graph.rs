use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeZone, Utc};
use hush_multi_agent::{
    AgentCapability, AgentId, DelegationClaims, DelegationGraphEdgeKind, DelegationGraphNodeKind,
    GrantLineageFacts, InMemoryRevocationStore, SignedDelegationToken, DELEGATION_AUDIENCE,
};
use serde_json::{json, Value};
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
use crate::models::delegation_graph::{
    DelegationGraphEdge, DelegationGraphNode, DelegationGraphSnapshot, FleetGrant,
    GrantExerciseRequest, IngestGrantRequest, ListGrantsQuery, RevokeGrantRequest,
    RevokeGrantResponse,
};
use crate::services::principal_resolution;

struct TenantGraphData {
    grants: BTreeMap<Uuid, FleetGrant>,
    nodes: BTreeMap<String, DelegationGraphNode>,
    edges: Vec<DelegationGraphEdge>,
}

pub struct RevokePrincipalGrantsRequest {
    pub principal_id: Uuid,
    pub principal_stable_ref: String,
    pub reason: String,
    pub revoked_by: Option<String>,
    pub response_action_id: Option<String>,
    pub response_action_label: Option<String>,
    pub response_action_state: Option<String>,
    pub response_action_metadata: Option<Value>,
}

struct PreparedGrantIngest {
    issuer_principal_id: String,
    subject_principal_id: String,
    grant_type: String,
    audience: String,
    token_jti: String,
    parent_token_jti: Option<String>,
    delegation_depth: i32,
    lineage_chain: Vec<String>,
    capabilities: Value,
    capability_ceiling: Value,
    purpose: Option<String>,
    context: Value,
    source_approval_id: Option<String>,
    source_session_id: Option<String>,
    issued_at: DateTime<Utc>,
    not_before: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    status: String,
}

struct GrantExerciseEvent {
    event_id: String,
    summary: String,
    source: String,
    session_id: Option<String>,
    response_action_id: Option<String>,
    grant_id: Option<String>,
    timestamp: DateTime<Utc>,
}

struct ResponseActionNode {
    id: String,
    label: String,
    state: String,
    metadata: Value,
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
    let IngestGrantRequest {
        token,
        grant_type,
        source_approval_id,
        source_session_id,
        issuer_public_key,
    } = request;
    let trusted_issuer_key = resolve_trusted_issuer_public_key(
        db,
        tenant_id,
        token.claims.iss.as_str(),
        issuer_public_key.as_deref(),
    )
    .await?;
    verify_signed_token(&token, &trusted_issuer_key)?;
    reject_revoked_chain(db, tenant_id, &token.claims).await?;
    reject_blocked_principal_authority(db, tenant_id, token.claims.iss.as_str(), "issuer").await?;
    reject_blocked_principal_authority(db, tenant_id, token.claims.sub.as_str(), "subject").await?;

    let lineage = GrantLineageFacts::from_claims(&token.claims);
    let grant_type = grant_type.unwrap_or_else(|| "delegation".to_string());
    validate_grant_type(&grant_type)?;
    validate_grant_source_refs(db, tenant_id, source_approval_id.as_deref()).await?;

    let prepared = prepare_grant_ingest(
        &token.claims,
        &lineage,
        &grant_type,
        source_approval_id,
        source_session_id,
    )?;
    if let Some(existing) = get_grant_by_token_optional(db, tenant_id, &prepared.token_jti).await? {
        return ensure_matching_grant_ingest(existing, &prepared);
    }

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let parent_grant = if let Some(parent_token_jti) = prepared.parent_token_jti.as_deref() {
        fetch_grant_by_token(&mut tx, tenant_id, parent_token_jti).await?
    } else {
        None
    };
    if let Some(parent_grant) = parent_grant.as_ref() {
        validate_child_grant_against_parent(db, tenant_id, &token.claims, parent_grant).await?;
    }

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
           DO NOTHING
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(&prepared.issuer_principal_id)
    .bind(&prepared.subject_principal_id)
    .bind(&prepared.grant_type)
    .bind(&prepared.audience)
    .bind(&prepared.token_jti)
    .bind(parent_grant.as_ref().map(|grant| grant.id))
    .bind(prepared.parent_token_jti.as_deref())
    .bind(prepared.delegation_depth)
    .bind(
        serde_json::to_value(&prepared.lineage_chain).map_err(|err| {
            ApiError::Internal(format!(
                "failed to serialize lineage chain for grant ingest: {err}"
            ))
        })?,
    )
    .bind(parent_grant.is_some() || lineage.parent_token_jti.is_none())
    .bind(prepared.capabilities.clone())
    .bind(prepared.capability_ceiling.clone())
    .bind(prepared.purpose.as_deref())
    .bind(prepared.context.clone())
    .bind(prepared.source_approval_id.as_deref())
    .bind(prepared.source_session_id.as_deref())
    .bind(prepared.issued_at)
    .bind(prepared.not_before)
    .bind(prepared.expires_at)
    .bind(&prepared.status)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    let Some(row) = row else {
        let existing = fetch_grant_by_token(&mut tx, tenant_id, &prepared.token_jti)
            .await?
            .ok_or_else(|| {
                ApiError::Conflict(format!(
                    "grant ingest conflict: token_jti '{}' already exists",
                    prepared.token_jti
                ))
            })?;
        tx.rollback().await.map_err(ApiError::Database)?;
        return ensure_matching_grant_ingest(existing, &prepared);
    };

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

fn prepare_grant_ingest(
    claims: &DelegationClaims,
    lineage: &GrantLineageFacts,
    grant_type: &str,
    source_approval_id: Option<String>,
    source_session_id: Option<String>,
) -> Result<PreparedGrantIngest, ApiError> {
    let now = Utc::now();
    let status = if claims.exp <= now.timestamp() {
        "expired".to_string()
    } else {
        "active".to_string()
    };
    let capabilities = serde_json::to_value(&claims.cap).map_err(|err| {
        ApiError::Internal(format!("failed to serialize grant capabilities: {err}"))
    })?;
    let capability_ceiling = serde_json::to_value(claims.effective_ceiling()).map_err(|err| {
        ApiError::Internal(format!(
            "failed to serialize grant capability ceiling: {err}"
        ))
    })?;

    Ok(PreparedGrantIngest {
        issuer_principal_id: claims.iss.as_str().to_string(),
        subject_principal_id: claims.sub.as_str().to_string(),
        grant_type: grant_type.to_string(),
        audience: claims.aud.clone(),
        token_jti: claims.jti.clone(),
        parent_token_jti: lineage.parent_token_jti.clone(),
        delegation_depth: i32::try_from(lineage.depth).map_err(|err| {
            ApiError::BadRequest(format!("delegation depth exceeds supported range: {err}"))
        })?,
        lineage_chain: lineage.chain.clone(),
        capabilities,
        capability_ceiling,
        purpose: claims.pur.clone(),
        context: claims.ctx.clone().unwrap_or_else(|| json!({})),
        source_approval_id,
        source_session_id,
        issued_at: unix_to_utc(claims.iat)?,
        not_before: claims.nbf.map(unix_to_utc).transpose()?,
        expires_at: unix_to_utc(claims.exp)?,
        status,
    })
}

fn ensure_matching_grant_ingest(
    existing: FleetGrant,
    prepared: &PreparedGrantIngest,
) -> Result<FleetGrant, ApiError> {
    let matches = existing.issuer_principal_id == prepared.issuer_principal_id
        && existing.subject_principal_id == prepared.subject_principal_id
        && existing.grant_type == prepared.grant_type
        && existing.audience == prepared.audience
        && existing.token_jti == prepared.token_jti
        && existing.parent_token_jti == prepared.parent_token_jti
        && existing.delegation_depth == prepared.delegation_depth
        && existing.lineage_chain == prepared.lineage_chain
        && existing.capabilities == prepared.capabilities
        && existing.capability_ceiling == prepared.capability_ceiling
        && existing.purpose == prepared.purpose
        && existing.context == prepared.context
        && existing.source_approval_id == prepared.source_approval_id
        && existing.source_session_id == prepared.source_session_id
        && existing.issued_at == prepared.issued_at
        && existing.not_before == prepared.not_before
        && existing.expires_at == prepared.expires_at;

    if matches {
        Ok(existing)
    } else {
        Err(ApiError::Conflict(format!(
            "grant ingest conflict: token_jti '{}' already exists with different contents",
            prepared.token_jti
        )))
    }
}

async fn validate_grant_source_refs(
    db: &PgPool,
    tenant_id: Uuid,
    source_approval_id: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(source_approval_id) = source_approval_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM approvals
                   WHERE tenant_id = $1
                     AND id::text = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(source_approval_id)
        .fetch_one(db)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }
    Ok(())
}

async fn get_grant_by_token_optional(
    db: &PgPool,
    tenant_id: Uuid,
    token_jti: &str,
) -> Result<Option<FleetGrant>, ApiError> {
    let row =
        sqlx::query::query("SELECT * FROM fleet_grants WHERE tenant_id = $1 AND token_jti = $2")
            .bind(tenant_id)
            .bind(token_jti)
            .fetch_optional(db)
            .await
            .map_err(ApiError::Database)?;

    row.map(FleetGrant::from_row)
        .transpose()
        .map_err(ApiError::Database)
}

pub async fn exercise_grant(
    db: &PgPool,
    tenant_id: Uuid,
    grant_id: Uuid,
    request: GrantExerciseRequest,
) -> Result<DelegationGraphSnapshot, ApiError> {
    let grant = get_grant(db, tenant_id, grant_id).await?;
    let event = load_grant_exercise_event(db, tenant_id, grant_id, &request).await?;
    ensure_grant_is_exercisable(&grant)?;
    let grant_node_id = DelegationGraphNodeKind::Grant.node_id(&grant.id.to_string());
    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    if let Some(session_id) = event.session_id.as_deref() {
        let session_node_id = DelegationGraphNodeKind::Session.node_id(session_id);
        upsert_node(
            &mut tx,
            tenant_id,
            &session_node_id,
            DelegationGraphNodeKind::Session.as_str(),
            session_id,
            Some("observed"),
            json!({
                "session_id": session_id,
                "grant_id": grant.id.to_string(),
            }),
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

    let event_node_id = DelegationGraphNodeKind::Event.node_id(&event.event_id);
    upsert_node(
        &mut tx,
        tenant_id,
        &event_node_id,
        DelegationGraphNodeKind::Event.as_str(),
        &event.summary,
        Some("observed"),
        json!({
            "event_id": event.event_id,
            "grant_id": grant.id.to_string(),
            "source": event.source,
            "session_id": event.session_id,
            "response_action_id": event.response_action_id,
            "timestamp": event.timestamp.to_rfc3339(),
        }),
    )
    .await?;
    upsert_edge(
        &mut tx,
        tenant_id,
        &grant_node_id,
        &event_node_id,
        DelegationGraphEdgeKind::ExercisedInEvent.as_str(),
        json!({ "event_id": event.event_id, "token_jti": &grant.token_jti }),
    )
    .await?;

    if let Some(response_action) = load_exercise_response_action_node(
        &mut tx,
        tenant_id,
        event.response_action_id.as_deref(),
        &request,
    )
    .await?
    {
        let response_node_id = DelegationGraphNodeKind::ResponseAction.node_id(&response_action.id);
        upsert_node(
            &mut tx,
            tenant_id,
            &response_node_id,
            DelegationGraphNodeKind::ResponseAction.as_str(),
            &response_action.label,
            Some(&response_action.state),
            response_action.metadata,
        )
        .await?;
        upsert_edge(
            &mut tx,
            tenant_id,
            &event_node_id,
            &response_node_id,
            DelegationGraphEdgeKind::TriggeredResponseAction.as_str(),
            json!({ "response_action_id": response_action.id }),
        )
        .await?;
    }

    tx.commit().await.map_err(ApiError::Database)?;
    grant_lineage_snapshot(db, tenant_id, grant_id).await
}

fn ensure_grant_is_exercisable(grant: &FleetGrant) -> Result<(), ApiError> {
    if grant.status != "active" {
        return Err(ApiError::Conflict(format!(
            "grant {} is not active",
            grant.id
        )));
    }

    let now = Utc::now();
    if grant.not_before.is_some_and(|not_before| now < not_before) {
        return Err(ApiError::Conflict(format!(
            "grant {} is not active yet",
            grant.id
        )));
    }
    if now >= grant.expires_at {
        return Err(ApiError::Conflict(format!(
            "grant {} has expired",
            grant.id
        )));
    }
    Ok(())
}

async fn load_grant_exercise_event(
    db: &PgPool,
    tenant_id: Uuid,
    grant_id: Uuid,
    request: &GrantExerciseRequest,
) -> Result<GrantExerciseEvent, ApiError> {
    let event_id = request.event_id.as_deref().ok_or_else(|| {
        ApiError::BadRequest("grant exercise requires an existing event_id".to_string())
    })?;

    let row = sqlx::query::query(
        r#"SELECT event_id,
                  summary,
                  source,
                  session_id,
                  response_action_id,
                  grant_id,
                  timestamp
           FROM hunt_events
           WHERE tenant_id = $1 AND event_id = $2"#,
    )
    .bind(tenant_id)
    .bind(event_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let recorded_grant_id: Option<String> = row.try_get("grant_id").map_err(ApiError::Database)?;
    if recorded_grant_id.as_deref() != Some(&grant_id.to_string()) {
        return Err(ApiError::BadRequest(
            "event_id does not belong to the requested grant".to_string(),
        ));
    }

    let session_id: Option<String> = row.try_get("session_id").map_err(ApiError::Database)?;
    if let Some(expected_session_id) = request.session_id.as_deref() {
        if session_id.as_deref() != Some(expected_session_id) {
            return Err(ApiError::BadRequest(
                "session_id does not match the verified event session".to_string(),
            ));
        }
    }

    let response_action_id: Option<String> = row
        .try_get("response_action_id")
        .map_err(ApiError::Database)?;
    if let Some(expected_response_action_id) = request.response_action_id.as_deref() {
        if response_action_id.as_deref() != Some(expected_response_action_id) {
            return Err(ApiError::BadRequest(
                "response_action_id does not match the verified event".to_string(),
            ));
        }
    }

    Ok(GrantExerciseEvent {
        event_id: row.try_get("event_id").map_err(ApiError::Database)?,
        summary: row.try_get("summary").map_err(ApiError::Database)?,
        source: row.try_get("source").map_err(ApiError::Database)?,
        session_id,
        response_action_id,
        grant_id: recorded_grant_id,
        timestamp: row.try_get("timestamp").map_err(ApiError::Database)?,
    })
}

async fn load_exercise_response_action_node(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    response_action_id: Option<&str>,
    request: &GrantExerciseRequest,
) -> Result<Option<ResponseActionNode>, ApiError> {
    if response_action_id.is_none() {
        if request.response_action_id.is_some() {
            return Err(ApiError::BadRequest(
                "response_action_id must be anchored by the verified event".to_string(),
            ));
        }
        return Ok(None);
    }

    let Some(response_action_id) = response_action_id else {
        return Ok(None);
    };
    let action_uuid = Uuid::parse_str(response_action_id).map_err(|_| {
        ApiError::Internal("verified event carried a non-UUID response_action_id".to_string())
    })?;
    let row = sqlx::query::query(
        r#"SELECT id, action_type, status, target_kind, target_id
           FROM response_actions
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(action_uuid)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let action_type: String = row.try_get("action_type").map_err(ApiError::Database)?;
    let target_kind: String = row.try_get("target_kind").map_err(ApiError::Database)?;
    let target_id: String = row.try_get("target_id").map_err(ApiError::Database)?;

    Ok(Some(ResponseActionNode {
        id: response_action_id.to_string(),
        label: format!("{action_type} -> {target_kind}:{target_id}"),
        state: row.try_get("status").map_err(ApiError::Database)?,
        metadata: json!({
            "response_action_id": response_action_id,
            "action_type": action_type,
            "target_kind": target_kind,
            "target_id": target_id,
        }),
    }))
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
    let grant_ids = if request.revoke_descendants.unwrap_or(true) {
        let descendant_ids = fetch_descendant_grant_ids(db, tenant_id, &[grant_id]).await?;
        if descendant_ids.is_empty() {
            return Err(ApiError::NotFound);
        }
        descendant_ids
    } else {
        get_grant(db, tenant_id, grant_id).await?;
        let mut only_self = BTreeSet::new();
        only_self.insert(grant_id);
        only_self
    };
    let revoked_ids = grant_ids.iter().copied().collect::<Vec<_>>();

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let now = Utc::now();
    revoke_grant_ids(
        &mut tx,
        tenant_id,
        &revoked_ids,
        now,
        &revoked_by,
        &request.reason,
    )
    .await?;

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

pub async fn revoke_principal_grants(
    db: &PgPool,
    tenant_id: Uuid,
    request: RevokePrincipalGrantsRequest,
) -> Result<Vec<Uuid>, ApiError> {
    let mut principal_aliases = BTreeSet::new();
    principal_aliases.insert(request.principal_id.to_string());
    principal_aliases.insert(request.principal_stable_ref.clone());
    let seed_grant_ids = fetch_principal_seed_grant_ids(db, tenant_id, &principal_aliases).await?;
    let revoked_ids = if seed_grant_ids.is_empty() {
        Vec::new()
    } else {
        fetch_descendant_grant_ids(
            db,
            tenant_id,
            &seed_grant_ids.iter().copied().collect::<Vec<_>>(),
        )
        .await?
        .into_iter()
        .collect::<Vec<_>>()
    };

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let now = Utc::now();
    if !revoked_ids.is_empty() {
        revoke_grant_ids(
            &mut tx,
            tenant_id,
            &revoked_ids,
            now,
            request.revoked_by.as_deref().unwrap_or("control-api"),
            &request.reason,
        )
        .await?;
    }
    sqlx::query::query(
        r#"UPDATE grants
           SET status = 'revoked',
               updated_at = now()
           WHERE tenant_id = $1
             AND status = 'active'
             AND (issuer_principal_id = $2 OR subject_principal_id = $2)"#,
    )
    .bind(tenant_id)
    .bind(request.principal_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

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
        for grant_id in &revoked_ids {
            let grant_node_id = DelegationGraphNodeKind::Grant.node_id(&grant_id.to_string());
            upsert_edge(
                &mut tx,
                tenant_id,
                &response_node_id,
                &grant_node_id,
                DelegationGraphEdgeKind::RevokedBy.as_str(),
                json!({
                    "reason": &request.reason,
                    "revoked_by": request.revoked_by.as_deref().unwrap_or("control-api"),
                    "principal_id": request.principal_id.to_string(),
                    "principal_stable_ref": &request.principal_stable_ref,
                }),
            )
            .await?;
        }
    }

    tx.commit().await.map_err(ApiError::Database)?;
    Ok(revoked_ids)
}

async fn revoke_grant_ids(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    grant_ids: &[Uuid],
    revoked_at: DateTime<Utc>,
    revoked_by: &str,
    reason: &str,
) -> Result<(), ApiError> {
    for current_grant_id in grant_ids {
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
        .bind(revoked_at)
        .bind(revoked_by)
        .bind(reason)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;

        let current_grant = FleetGrant::from_row(row).map_err(ApiError::Database)?;
        let node_id = DelegationGraphNodeKind::Grant.node_id(&current_grant.id.to_string());
        upsert_node(
            tx,
            tenant_id,
            &node_id,
            DelegationGraphNodeKind::Grant.as_str(),
            &grant_label(&current_grant),
            Some("revoked"),
            json!({
                "grant_id": current_grant.id.to_string(),
                "revoked_by": revoked_by,
                "revoke_reason": reason,
            }),
        )
        .await?;
    }

    Ok(())
}

pub async fn grant_lineage_snapshot(
    db: &PgPool,
    tenant_id: Uuid,
    grant_id: Uuid,
) -> Result<DelegationGraphSnapshot, ApiError> {
    let grant_ids = fetch_related_grant_ids(db, tenant_id, &[grant_id]).await?;
    if grant_ids.is_empty() {
        return Err(ApiError::NotFound);
    }
    let root_node_id = Some(DelegationGraphNodeKind::Grant.node_id(&grant_id.to_string()));
    let data =
        load_graph_data_for_grant_ids(db, tenant_id, &grant_ids, true, root_node_id.as_deref())
            .await?;
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
    let starting_grants =
        fetch_principal_seed_grant_ids(db, tenant_id, &principal_aliases.aliases).await?;
    let expanded = fetch_related_grant_ids(
        db,
        tenant_id,
        &starting_grants.iter().copied().collect::<Vec<_>>(),
    )
    .await?;

    let root_node_id =
        Some(DelegationGraphNodeKind::Principal.node_id(&principal_aliases.canonical_id));
    let data = load_graph_data_for_grant_ids(
        db,
        tenant_id,
        &expanded,
        include_context,
        root_node_id.as_deref(),
    )
    .await?;
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
    let mut aliases = BTreeSet::new();
    aliases.insert(principal_identifier.to_string());

    let canonical_id = if let Some(principal) =
        principal_resolution::resolve_principal_identifier_optional(
            db,
            tenant_id,
            principal_identifier,
        )
        .await?
    {
        aliases.insert(principal.id.to_string());
        aliases.insert(principal.stable_ref.clone());
        principal.id.to_string()
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
    if from == to {
        let nodes = load_nodes_by_ids(db, tenant_id, &[from.to_string()]).await?;
        return Ok(DelegationGraphSnapshot {
            root_node_id: Some(from.to_string()),
            nodes: nodes.into_values().collect(),
            edges: Vec::new(),
            generated_at: Utc::now(),
        });
    }

    let row = sqlx::query::query(
        r#"WITH RECURSIVE walk AS (
               SELECT e.to_node_id,
                      ARRAY[$2::text, e.to_node_id]::text[] AS path_nodes,
                      ARRAY[e.id]::uuid[] AS path_edges
               FROM delegation_graph_edges e
               WHERE e.tenant_id = $1
                 AND e.from_node_id = $2
               UNION ALL
               SELECT e.to_node_id,
                      walk.path_nodes || e.to_node_id,
                      walk.path_edges || e.id
               FROM delegation_graph_edges e
               JOIN walk ON e.from_node_id = walk.to_node_id
               WHERE e.tenant_id = $1
                 AND NOT e.to_node_id = ANY(walk.path_nodes)
                 AND cardinality(walk.path_edges) < 64
           )
           SELECT path_nodes, path_edges
           FROM walk
           WHERE to_node_id = $3
           ORDER BY cardinality(path_edges)
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(from)
    .bind(to)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?;

    let Some(row) = row else {
        return Ok(empty_snapshot(Some(from.to_string())));
    };
    let node_ids: Vec<String> = row.try_get("path_nodes").map_err(ApiError::Database)?;
    let edge_ids: Vec<Uuid> = row.try_get("path_edges").map_err(ApiError::Database)?;

    let nodes = load_nodes_by_ids(db, tenant_id, &node_ids)
        .await?
        .into_values()
        .collect::<Vec<_>>();
    let mut edges = load_edges_by_ids(db, tenant_id, &edge_ids).await?;
    let mut nodes = nodes;
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(DelegationGraphSnapshot {
        root_node_id: Some(from.to_string()),
        nodes,
        edges,
        generated_at: Utc::now(),
    })
}

async fn fetch_related_grant_ids(
    db: &PgPool,
    tenant_id: Uuid,
    seed_grant_ids: &[Uuid],
) -> Result<BTreeSet<Uuid>, ApiError> {
    if seed_grant_ids.is_empty() {
        return Ok(BTreeSet::new());
    }

    let rows = sqlx::query::query(
        r#"WITH RECURSIVE seed AS (
               SELECT id, parent_grant_id
               FROM fleet_grants
               WHERE tenant_id = $1
                 AND id = ANY($2::uuid[])
           ),
           ancestors AS (
               SELECT id, parent_grant_id FROM seed
               UNION
               SELECT parent.id, parent.parent_grant_id
               FROM fleet_grants parent
               JOIN ancestors child ON child.parent_grant_id = parent.id
               WHERE parent.tenant_id = $1
           ),
           descendants AS (
               SELECT id, parent_grant_id FROM seed
               UNION
               SELECT child.id, child.parent_grant_id
               FROM fleet_grants child
               JOIN descendants parent_tree ON child.parent_grant_id = parent_tree.id
               WHERE child.tenant_id = $1
           ),
           selected AS (
               SELECT id FROM ancestors
               UNION
               SELECT id FROM descendants
           )
           SELECT id FROM selected"#,
    )
    .bind(tenant_id)
    .bind(seed_grant_ids)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(|row| row.try_get("id"))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(ApiError::Database)
}

async fn fetch_descendant_grant_ids(
    db: &PgPool,
    tenant_id: Uuid,
    seed_grant_ids: &[Uuid],
) -> Result<BTreeSet<Uuid>, ApiError> {
    if seed_grant_ids.is_empty() {
        return Ok(BTreeSet::new());
    }

    let rows = sqlx::query::query(
        r#"WITH RECURSIVE descendants AS (
               SELECT id
               FROM fleet_grants
               WHERE tenant_id = $1
                 AND id = ANY($2::uuid[])
               UNION
               SELECT child.id
               FROM fleet_grants child
               JOIN descendants parent_tree ON child.parent_grant_id = parent_tree.id
               WHERE child.tenant_id = $1
           )
           SELECT id FROM descendants"#,
    )
    .bind(tenant_id)
    .bind(seed_grant_ids)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(|row| row.try_get("id"))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(ApiError::Database)
}

async fn fetch_principal_seed_grant_ids(
    db: &PgPool,
    tenant_id: Uuid,
    principal_aliases: &BTreeSet<String>,
) -> Result<BTreeSet<Uuid>, ApiError> {
    if principal_aliases.is_empty() {
        return Ok(BTreeSet::new());
    }

    let aliases = principal_aliases.iter().cloned().collect::<Vec<_>>();
    let rows = sqlx::query::query(
        r#"SELECT id
           FROM fleet_grants
           WHERE tenant_id = $1
             AND status = 'active'
             AND (
                 issuer_principal_id = ANY($2::text[])
                 OR subject_principal_id = ANY($2::text[])
             )"#,
    )
    .bind(tenant_id)
    .bind(&aliases)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(|row| row.try_get("id"))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(ApiError::Database)
}

async fn load_graph_data_for_grant_ids(
    db: &PgPool,
    tenant_id: Uuid,
    grant_ids: &BTreeSet<Uuid>,
    include_context: bool,
    root_node_id: Option<&str>,
) -> Result<TenantGraphData, ApiError> {
    if grant_ids.is_empty() {
        return Ok(TenantGraphData {
            grants: BTreeMap::new(),
            nodes: load_nodes_by_ids(
                db,
                tenant_id,
                &root_node_id
                    .into_iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .await?,
            edges: Vec::new(),
        });
    }

    let grant_id_list = grant_ids.iter().copied().collect::<Vec<_>>();
    let grant_rows = sqlx::query::query(
        "SELECT * FROM fleet_grants WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
    )
    .bind(tenant_id)
    .bind(&grant_id_list)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;
    let grants = grant_rows
        .into_iter()
        .map(FleetGrant::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;
    let grants_by_id = grants
        .into_iter()
        .map(|grant| (grant.id, grant))
        .collect::<BTreeMap<_, _>>();

    let grant_node_ids = grant_id_list
        .iter()
        .map(|grant_id| DelegationGraphNodeKind::Grant.node_id(&grant_id.to_string()))
        .collect::<Vec<_>>();
    let edge_rows = if include_context {
        sqlx::query::query(
            r#"SELECT id, from_node_id, to_node_id, kind, metadata
               FROM delegation_graph_edges
               WHERE tenant_id = $1
                 AND (from_node_id = ANY($2::text[]) OR to_node_id = ANY($2::text[]))"#,
        )
        .bind(tenant_id)
        .bind(&grant_node_ids)
        .fetch_all(db)
        .await
    } else {
        sqlx::query::query(
            r#"SELECT id, from_node_id, to_node_id, kind, metadata
               FROM delegation_graph_edges
               WHERE tenant_id = $1
                 AND from_node_id = ANY($2::text[])
                 AND to_node_id = ANY($2::text[])"#,
        )
        .bind(tenant_id)
        .bind(&grant_node_ids)
        .fetch_all(db)
        .await
    }
    .map_err(ApiError::Database)?;
    let edges = edge_rows
        .into_iter()
        .map(DelegationGraphEdge::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;
    let mut edges_by_id = edges
        .into_iter()
        .map(|edge| (edge.id, edge))
        .collect::<BTreeMap<_, _>>();

    if include_context {
        let event_node_ids = edges_by_id
            .values()
            .flat_map(|edge| [&edge.from, &edge.to])
            .filter(|node_id| node_id.starts_with("event:"))
            .cloned()
            .collect::<BTreeSet<_>>();
        if !event_node_ids.is_empty() {
            let extra_edge_rows = sqlx::query::query(
                r#"SELECT id, from_node_id, to_node_id, kind, metadata
                   FROM delegation_graph_edges
                   WHERE tenant_id = $1
                     AND (from_node_id = ANY($2::text[]) OR to_node_id = ANY($2::text[]))"#,
            )
            .bind(tenant_id)
            .bind(event_node_ids.into_iter().collect::<Vec<_>>())
            .fetch_all(db)
            .await
            .map_err(ApiError::Database)?;
            for edge in extra_edge_rows
                .into_iter()
                .map(DelegationGraphEdge::from_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::Database)?
            {
                edges_by_id.insert(edge.id, edge);
            }
        }
    }
    let edges = edges_by_id.into_values().collect::<Vec<_>>();

    let mut node_ids = grant_node_ids.into_iter().collect::<BTreeSet<_>>();
    if let Some(root_node_id) = root_node_id {
        node_ids.insert(root_node_id.to_string());
    }
    for edge in &edges {
        node_ids.insert(edge.from.clone());
        node_ids.insert(edge.to.clone());
    }

    Ok(TenantGraphData {
        grants: grants_by_id,
        nodes: load_nodes_by_ids(db, tenant_id, &node_ids.into_iter().collect::<Vec<_>>()).await?,
        edges,
    })
}

async fn load_nodes_by_ids(
    db: &PgPool,
    tenant_id: Uuid,
    node_ids: &[String],
) -> Result<BTreeMap<String, DelegationGraphNode>, ApiError> {
    if node_ids.is_empty() {
        return Ok(BTreeMap::new());
    }

    let node_rows = sqlx::query::query(
        r#"SELECT id, kind, label, state, metadata
           FROM delegation_graph_nodes
           WHERE tenant_id = $1
             AND id = ANY($2::text[])"#,
    )
    .bind(tenant_id)
    .bind(node_ids)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    node_rows
        .into_iter()
        .map(DelegationGraphNode::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(|nodes| {
            nodes
                .into_iter()
                .map(|node| (node.id.clone(), node))
                .collect::<BTreeMap<_, _>>()
        })
        .map_err(ApiError::Database)
}

async fn load_edges_by_ids(
    db: &PgPool,
    tenant_id: Uuid,
    edge_ids: &[Uuid],
) -> Result<Vec<DelegationGraphEdge>, ApiError> {
    if edge_ids.is_empty() {
        return Ok(Vec::new());
    }

    let edge_rows = sqlx::query::query(
        r#"SELECT id, from_node_id, to_node_id, kind, metadata
           FROM delegation_graph_edges
           WHERE tenant_id = $1
             AND id = ANY($2::uuid[])"#,
    )
    .bind(tenant_id)
    .bind(edge_ids)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    edge_rows
        .into_iter()
        .map(DelegationGraphEdge::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
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

    let mut included_edge_ids = BTreeSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for edge in &data.edges {
            if included_edge_ids.contains(&edge.id) {
                continue;
            }

            let touches_included =
                included_node_ids.contains(&edge.from) || included_node_ids.contains(&edge.to);
            let both_included =
                included_node_ids.contains(&edge.from) && included_node_ids.contains(&edge.to);
            if both_included || (include_context && touches_included) {
                let inserted_edge = included_edge_ids.insert(edge.id);
                let inserted_from = included_node_ids.insert(edge.from.clone());
                let inserted_to = included_node_ids.insert(edge.to.clone());
                changed |= inserted_edge || inserted_from || inserted_to;
            }
        }
    }

    if let Some(root) = root_node_id.as_deref() {
        included_node_ids.insert(root.to_string());
    }

    let mut nodes = included_node_ids
        .into_iter()
        .filter_map(|node_id| data.nodes.get(&node_id).cloned())
        .collect::<Vec<_>>();
    let mut included_edges = data
        .edges
        .iter()
        .filter(|edge| included_edge_ids.contains(&edge.id))
        .cloned()
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

#[cfg(test)]
fn lineage_grant_ids(grants: &BTreeMap<Uuid, FleetGrant>, grant_id: Uuid) -> BTreeSet<Uuid> {
    let mut visited = BTreeSet::new();
    let mut pending = vec![grant_id];

    while let Some(current_id) = pending.pop() {
        if !visited.insert(current_id) {
            continue;
        }
        if let Some(parent_id) = grants
            .get(&current_id)
            .and_then(|grant| grant.parent_grant_id)
        {
            pending.push(parent_id);
        }
        pending.extend(
            grants
                .values()
                .filter(|grant| grant.parent_grant_id == Some(current_id))
                .map(|grant| grant.id),
        );
    }

    visited
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
    public_key: &hush_core::PublicKey,
) -> Result<(), ApiError> {
    let revocations = InMemoryRevocationStore::default();
    token
        .verify_and_validate(
            public_key,
            Utc::now().timestamp(),
            &revocations,
            DELEGATION_AUDIENCE,
            None,
        )
        .map_err(|err| ApiError::BadRequest(format!("invalid delegation token: {err}")))
}

async fn resolve_trusted_issuer_public_key(
    db: &PgPool,
    tenant_id: Uuid,
    issuer_identifier: &str,
    issuer_public_key: Option<&str>,
) -> Result<hush_core::PublicKey, ApiError> {
    let requested_key = issuer_public_key
        .map(hush_core::PublicKey::from_hex)
        .transpose()
        .map_err(|_| ApiError::BadRequest("issuer_public_key must be valid hex".to_string()))?;
    let registered_key =
        load_registered_issuer_public_key(db, tenant_id, issuer_identifier).await?;

    match (registered_key, requested_key) {
        (Some(registered_key), Some(requested_key)) => {
            if registered_key.to_hex() != requested_key.to_hex() {
                return Err(ApiError::BadRequest(
                    "issuer_public_key does not match the registered issuer key".to_string(),
                ));
            }
            Ok(registered_key)
        }
        (Some(registered_key), None) => Ok(registered_key),
        (None, Some(requested_key)) => Ok(requested_key),
        (None, None) => Err(ApiError::BadRequest(
            "issuer_public_key is required for issuers that are not enrolled in the directory"
                .to_string(),
        )),
    }
}

async fn load_registered_issuer_public_key(
    db: &PgPool,
    tenant_id: Uuid,
    issuer_identifier: &str,
) -> Result<Option<hush_core::PublicKey>, ApiError> {
    if let Some(principal) = principal_resolution::resolve_principal_identifier_optional(
        db,
        tenant_id,
        issuer_identifier,
    )
    .await?
    {
        principal_resolution::ensure_delegation_allowed(&principal, "issuer")?;
        let encoded = principal.public_key.ok_or_else(|| {
            ApiError::BadRequest(format!(
                "registered principal '{}' is missing a public key",
                principal.stable_ref
            ))
        })?;
        let public_key = hush_core::PublicKey::from_hex(&encoded).map_err(|err| {
            ApiError::Internal(format!(
                "registered issuer key for '{issuer_identifier}' is invalid: {err}"
            ))
        })?;
        return Ok(Some(public_key));
    }

    let row = sqlx::query::query(
        r#"SELECT public_key
           FROM agents
           WHERE tenant_id = $1
             AND public_key IS NOT NULL
             AND (agent_id = $2 OR id::text = $2)
           ORDER BY created_at DESC, id DESC
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(issuer_identifier)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let encoded = row
        .try_get::<String, _>("public_key")
        .map_err(ApiError::Database)?;
    let public_key = hush_core::PublicKey::from_hex(&encoded).map_err(|err| {
        ApiError::Internal(format!(
            "registered issuer key for '{issuer_identifier}' is invalid: {err}"
        ))
    })?;
    Ok(Some(public_key))
}

async fn reject_blocked_principal_authority(
    db: &PgPool,
    tenant_id: Uuid,
    principal_identifier: &str,
    purpose: &str,
) -> Result<(), ApiError> {
    let Some(principal) = principal_resolution::resolve_principal_identifier_optional(
        db,
        tenant_id,
        principal_identifier,
    )
    .await?
    else {
        return Ok(());
    };

    principal_resolution::ensure_delegation_allowed(&principal, purpose)
}

async fn validate_child_grant_against_parent(
    db: &PgPool,
    tenant_id: Uuid,
    child_claims: &DelegationClaims,
    parent_grant: &FleetGrant,
) -> Result<(), ApiError> {
    if parent_grant.status == "revoked" {
        return Err(ApiError::BadRequest(format!(
            "parent grant {} is revoked",
            parent_grant.token_jti
        )));
    }
    reject_blocked_principal_authority(db, tenant_id, &parent_grant.issuer_principal_id, "issuer")
        .await?;
    reject_blocked_principal_authority(
        db,
        tenant_id,
        &parent_grant.subject_principal_id,
        "subject",
    )
    .await?;

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
