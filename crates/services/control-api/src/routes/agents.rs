use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use std::collections::HashSet;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::crypto::hash_enrollment_token;
use crate::error::{is_unique_violation, ApiError};
use crate::models::agent::{
    Agent, EnrollmentRequest, EnrollmentResponse, HeartbeatRequest, RegisterAgentRequest,
    RegisterAgentResponse,
};
use crate::services::policy_distribution;
use crate::state::AppState;
use crate::validation;

const HEARTBEAT_UPDATE_SQL: &str = r#"UPDATE agents
           SET last_heartbeat_at = now(),
               status = 'active',
               metadata = COALESCE($3, metadata)
           WHERE tenant_id = $1
             AND agent_id = $2
             AND status IN ('active', 'stale', 'dead')
           RETURNING principal_id"#;

const ENROLL_TOKEN_LOCK_SQL: &str = r#"SELECT et.id AS enrollment_token_id,
                  et.tenant_id,
                  t.slug,
                  t.agent_limit
           FROM tenant_enrollment_tokens AS et
           JOIN tenants AS t
             ON t.id = et.tenant_id
           WHERE et.token_hash = $1
             AND et.consumed_at IS NULL
             AND et.expires_at > now()
           FOR UPDATE OF t, et"#;

const ENROLL_TOKEN_CONSUME_SQL: &str = r#"UPDATE tenant_enrollment_tokens
           SET consumed_at = now()
           WHERE id = $1
             AND consumed_at IS NULL"#;

/// Authenticated agent routes (behind require_auth middleware).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/agents", post(register_agent))
        .route("/agents", get(list_agents))
        .route("/agents/{id}", get(get_agent))
        .route("/agents/{id}", delete(delete_agent))
        .route(
            "/agents/{id}/effective-policy",
            get(get_agent_effective_policy),
        )
        .route(
            "/agents/{id}/runtimes",
            get(list_runtimes).post(register_runtime),
        )
        .route("/agents/heartbeat", post(heartbeat))
}

/// Public enrollment route — uses enrollment_token for auth, not JWT/API key.
pub fn enrollment_router() -> Router<AppState> {
    Router::new().route("/agents/enroll", post(enroll_agent))
}

async fn register_agent(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, ApiError> {
    ensure_write_access(&auth)?;

    // Input length validation
    validation::validate_agent_id(&req.agent_id)?;
    validation::validate_name(&req.name)?;
    validation::validate_public_key_length(&req.public_key)?;
    validation::validate_trust_level(req.trust_level.as_deref())?;
    validation::validate_metadata(req.metadata.as_ref())?;

    // Validate Ed25519 public key using hush-core
    hush_core::PublicKey::from_hex(&req.public_key).map_err(|_| ApiError::InvalidPublicKey)?;

    let role = req.role.as_deref().unwrap_or("coder");
    let trust_level = req.trust_level.as_deref().unwrap_or("medium");
    let metadata = req.metadata.clone().unwrap_or(serde_json::json!({}));
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;

    // Lock the tenant row so concurrent registrations for the same tenant
    // serialize around the agent-limit check.
    let tenant_row = sqlx::query::query("SELECT agent_limit FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(auth.tenant_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;
    let tenant_agent_limit: i32 = tenant_row
        .try_get("agent_limit")
        .map_err(ApiError::Database)?;

    let count_row = sqlx::query::query(
        "SELECT COUNT(*)::bigint as cnt FROM agents WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(auth.tenant_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;
    let count: i64 = count_row.try_get("cnt").map_err(ApiError::Database)?;

    if count >= i64::from(tenant_agent_limit) {
        return Err(ApiError::AgentLimitReached);
    }
    let principal_id = upsert_endpoint_principal(
        &mut tx,
        EndpointPrincipalUpsert {
            tenant_id: auth.tenant_id,
            stable_ref: &req.agent_id,
            display_name: &req.name,
            public_key: &req.public_key,
            trust_level,
            lifecycle_state: "active",
            liveness_state: Some("active"),
            metadata: &metadata,
        },
    )
    .await?;

    let row = sqlx::query::query(
        r#"INSERT INTO agents (
               tenant_id,
               principal_id,
               agent_id,
               name,
               public_key,
               role,
               trust_level,
               metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(principal_id)
    .bind(&req.agent_id)
    .bind(&req.name)
    .bind(&req.public_key)
    .bind(role)
    .bind(trust_level)
    .bind(&metadata)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            ApiError::Conflict(format!("agent '{}' already exists", req.agent_id))
        } else {
            ApiError::Database(err)
        }
    })?;

    let agent = Agent::from_row(row).map_err(ApiError::Database)?;
    link_endpoint_hierarchy_node_if_unambiguous(&mut tx, auth.tenant_id, &req.agent_id, &req.name)
        .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    // Generate NATS credentials for this agent
    let nats_creds = match state
        .provisioner
        .create_agent_credentials(auth.tenant_id, &auth.slug, &req.agent_id)
        .await
    {
        Ok(creds) => creds,
        Err(err) => {
            rollback_failed_agent_creation(&state.db, agent.id, auth.tenant_id, &req.agent_id)
                .await
                .map_err(ApiError::Database)?;
            return Err(ApiError::Nats(err.to_string()));
        }
    };

    // Record usage event
    let _ = state
        .metering
        .record(auth.tenant_id, "agent_registered", 1)
        .await;

    Ok(Json(RegisterAgentResponse {
        id: agent.id,
        agent_id: agent.agent_id,
        nats_credentials: nats_creds,
    }))
}

/// Query parameters for listing agents.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListAgentsQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

async fn list_agents(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ListAgentsQuery>,
) -> Result<Json<Vec<Agent>>, ApiError> {
    let offset = query.offset.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 500);

    let rows = sqlx::query::query(
        "SELECT * FROM agents WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let agents: Vec<Agent> = rows
        .into_iter()
        .map(Agent::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    Ok(Json(agents))
}

async fn get_agent(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<Agent>, ApiError> {
    let row = sqlx::query::query("SELECT * FROM agents WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;

    let agent = Agent::from_row(row).map_err(ApiError::Database)?;
    Ok(Json(agent))
}

async fn delete_agent(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_write_access(&auth)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let row = sqlx::query::query(
        r#"SELECT principal_id, agent_id, name
           FROM agents
           WHERE id = $1
             AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let principal_id = row
        .try_get::<Option<Uuid>, _>("principal_id")
        .map_err(ApiError::Database)?;
    let agent_id: String = row.try_get("agent_id").map_err(ApiError::Database)?;
    let agent_name: String = row.try_get("name").map_err(ApiError::Database)?;

    if let Some(principal_id) = principal_id {
        // Clean up runtime principals and their memberships that are linked
        // to this endpoint.  Without this, deleting an endpoint would leave
        // runtime principals and their `principal_memberships` rows
        // permanently orphaned.

        // 1. Collect runtime principal IDs linked via memberships to this
        //    endpoint (scoped by tenant_id for tenant isolation).
        let runtime_rows = sqlx::query::query(
            r#"SELECT pm.principal_id
               FROM principal_memberships AS pm
               JOIN principals AS p
                 ON p.id = pm.principal_id
                AND p.tenant_id = pm.tenant_id
               WHERE pm.tenant_id = $1
                 AND pm.target_kind = 'endpoint'
                 AND pm.target_id = $2
                 AND p.principal_type = 'runtime_agent'"#,
        )
        .bind(auth.tenant_id)
        .bind(principal_id)
        .fetch_all(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

        let runtime_principal_ids: Vec<Uuid> = runtime_rows
            .iter()
            .map(|row| row.try_get("principal_id"))
            .collect::<Result<_, _>>()
            .map_err(ApiError::Database)?;

        if !runtime_principal_ids.is_empty() {
            // 2. Delete principal_memberships rows for the runtime principals.
            sqlx::query::query(
                r#"DELETE FROM principal_memberships
                   WHERE tenant_id = $1
                     AND principal_id = ANY($2)"#,
            )
            .bind(auth.tenant_id)
            .bind(&runtime_principal_ids)
            .execute(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;

            // 3. Delete the runtime principal rows themselves.
            sqlx::query::query(
                r#"DELETE FROM principals
                   WHERE tenant_id = $1
                     AND id = ANY($2)
                     AND principal_type = 'runtime_agent'"#,
            )
            .bind(auth.tenant_id)
            .bind(&runtime_principal_ids)
            .execute(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;

            tracing::info!(
                tenant_id = %auth.tenant_id,
                endpoint_principal_id = %principal_id,
                runtime_count = runtime_principal_ids.len(),
                "Cleaned up orphaned runtime principals during endpoint deletion"
            );
        }

        if let Some(parent_node_id) = resolve_endpoint_hierarchy_node_id(
            &mut tx,
            auth.tenant_id,
            &agent_id,
            Some(&agent_name),
        )
        .await?
        {
            sqlx::query::query(
                r#"DELETE FROM hierarchy_nodes
                   WHERE tenant_id = $1
                     AND node_type = 'runtime'
                     AND parent_id = $2"#,
            )
            .bind(auth.tenant_id)
            .bind(parent_node_id)
            .execute(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;
        }
    }

    // Delete the agent row.
    sqlx::query::query("DELETE FROM agents WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

    unlink_endpoint_hierarchy_nodes(&mut tx, auth.tenant_id, &agent_id)
        .await
        .map_err(ApiError::Database)?;

    // Clean up the endpoint principal if no other references remain.
    if let Some(principal_id) = principal_id {
        delete_principal_if_unreferenced(&mut tx, principal_id, auth.tenant_id).await?;
    }

    tx.commit().await.map_err(ApiError::Database)?;

    Ok(Json(json!({ "deleted": true })))
}

async fn get_agent_effective_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<EffectivePolicyResponse>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT a.id,
                  a.tenant_id,
                  a.agent_id,
                  a.principal_id,
                  p.lifecycle_state,
                  p.liveness_state
           FROM agents AS a
           LEFT JOIN principals AS p
             ON p.id = a.principal_id
           WHERE a.id = $1
             AND a.tenant_id = $2"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let principal_id: Option<Uuid> = row.try_get("principal_id").map_err(ApiError::Database)?;
    let principal_id = principal_id.ok_or_else(|| {
        ApiError::BadRequest("agent is not linked to a directory principal".to_string())
    })?;

    let memberships = sqlx::query::query(
        r#"SELECT target_kind, target_id
           FROM principal_memberships
           WHERE tenant_id = $1
             AND principal_id = $2"#,
    )
    .bind(auth.tenant_id)
    .bind(principal_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let mut swarm_ids = HashSet::new();
    let mut project_ids = HashSet::new();
    let mut capability_group_ids = HashSet::new();
    for membership in memberships {
        let target_kind: String = membership
            .try_get("target_kind")
            .map_err(ApiError::Database)?;
        let target_id: Uuid = membership
            .try_get("target_id")
            .map_err(ApiError::Database)?;
        match target_kind.as_str() {
            "swarm" => {
                swarm_ids.insert(target_id);
            }
            "project" => {
                project_ids.insert(target_id);
            }
            "capability_group" => {
                capability_group_ids.insert(target_id);
            }
            _ => {}
        }
    }

    let attachment_rows = sqlx::query::query(
        r#"SELECT id,
                  target_kind,
                  target_id,
                  priority,
                  policy_ref,
                  policy_yaml,
                  checksum_sha256,
                  created_at
           FROM policy_attachments
           WHERE tenant_id = $1
           ORDER BY CASE target_kind
                        WHEN 'tenant' THEN 1
                        WHEN 'swarm' THEN 2
                        WHEN 'project' THEN 3
                        WHEN 'capability_group' THEN 4
                        WHEN 'principal' THEN 5
                        ELSE 6
                    END ASC,
                    priority ASC,
                    created_at ASC,
                    id ASC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let active_policy =
        policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id)
            .await
            .map_err(ApiError::Database)?;

    let mut compiled = match active_policy.as_ref() {
        Some(policy) => parse_yaml_value(&policy.policy_yaml).map_err(|err| {
            ApiError::Internal(format!("active tenant policy is invalid YAML: {err}"))
        })?,
        None => serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
    };
    let mut source_attachments = Vec::new();
    let mut applied_attachment_count = 0_i64;

    for row in attachment_rows {
        let attachment = PolicyAttachmentRow::from_row(row).map_err(ApiError::Database)?;
        if !attachment.matches(
            auth.tenant_id,
            principal_id,
            &swarm_ids,
            &project_ids,
            &capability_group_ids,
        ) {
            continue;
        }

        if let Some(policy_yaml) = attachment.resolved_policy_yaml()? {
            let overlay = parse_yaml_value(policy_yaml).map_err(|err| {
                ApiError::Internal(format!(
                    "policy attachment {} contains invalid YAML: {err}",
                    attachment.id
                ))
            })?;
            merge_yaml_value(&mut compiled, overlay);
        }

        source_attachments.push(ResolvedPolicyAttachment {
            attachment_id: attachment.id,
            target_kind: attachment.target_kind.clone(),
            target_id: attachment.target_id.unwrap_or(auth.tenant_id),
            priority: attachment.priority,
            policy_ref: attachment.policy_ref.clone(),
            checksum_sha256: attachment.checksum_sha256.clone(),
        });
        applied_attachment_count += 1;
    }

    let lifecycle_state: String = row.try_get("lifecycle_state").map_err(ApiError::Database)?;
    let liveness_state: Option<String> =
        row.try_get("liveness_state").map_err(ApiError::Database)?;
    let applied_overlays = lifecycle_overlay_names(&lifecycle_state);
    let compiled_policy_yaml = serialize_compiled_policy(&compiled).map_err(|err| {
        ApiError::Internal(format!("failed to serialize effective policy YAML: {err}"))
    })?;
    let compiled_policy_sha256 = checksum_sha256_hex(&compiled_policy_yaml);
    let resolution_version = active_policy
        .as_ref()
        .map(|policy| policy.version)
        .unwrap_or(0)
        + applied_attachment_count;

    Ok(Json(EffectivePolicyResponse {
        tenant_id: auth.tenant_id,
        principal_id,
        agent_id: Some(row.try_get("agent_id").map_err(ApiError::Database)?),
        lifecycle_state,
        liveness_state,
        compiled_policy_yaml,
        compiled_policy_sha256,
        resolution_version,
        resolved_at: Utc::now(),
        source_attachments,
        applied_overlays,
    }))
}

async fn heartbeat(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Input length validation
    validation::validate_agent_id(&req.agent_id)?;
    validation::validate_metadata(req.metadata.as_ref())?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let row = sqlx::query::query(HEARTBEAT_UPDATE_SQL)
        .bind(auth.tenant_id)
        .bind(&req.agent_id)
        .bind(req.metadata.as_ref())
        .fetch_optional(tx.as_mut())
        .await
        .map_err(ApiError::Database)?;

    let Some(row) = row else {
        return Err(ApiError::NotFound);
    };

    let principal_id = row
        .try_get::<Option<Uuid>, _>("principal_id")
        .map_err(ApiError::Database)?;
    set_principal_liveness_state(&mut tx, principal_id, auth.tenant_id, "active").await?;
    tx.commit().await.map_err(ApiError::Database)?;

    // Reconciliation path: if a tenant-level active policy exists, ensure this
    // agent's KV bucket converges even if it missed a historical deploy.
    match policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id).await {
        Ok(Some(active_policy)) => {
            if let Err(err) = policy_distribution::reconcile_policy_for_agent(
                &state.nats,
                &active_policy,
                &req.agent_id,
            )
            .await
            {
                tracing::warn!(
                    error = %err,
                    tenant = %auth.slug,
                    agent_id = %req.agent_id,
                    "Heartbeat policy reconciliation failed"
                );
            }
        }
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(
                error = %err,
                tenant = %auth.slug,
                agent_id = %req.agent_id,
                "Failed to load active policy during heartbeat reconciliation"
            );
        }
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// Enroll an agent using a one-time enrollment token.
///
/// This endpoint is NOT behind `require_auth` — the enrollment_token itself
/// authenticates the request (solving the bootstrap chicken-and-egg problem
/// where the agent has no JWT or API key yet).
async fn enroll_agent(
    State(state): State<AppState>,
    Json(req): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, ApiError> {
    // Input length validation
    validation::validate_public_key_length(&req.public_key)?;
    validation::validate_hostname(&req.hostname)?;
    validation::validate_version(&req.version)?;

    // Validate the Ed25519 public key.
    hush_core::PublicKey::from_hex(&req.public_key).map_err(|_| ApiError::InvalidPublicKey)?;
    let approval_response_trusted_issuer = state
        .signing_keypair
        .as_ref()
        .map(|keypair| spine::issuer_from_keypair(keypair.as_ref()))
        .ok_or_else(|| {
            ApiError::Internal("approval response signing keypair is not configured".to_string())
        })?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let enrollment_token_hash = hash_enrollment_token(&req.enrollment_token);

    // Lock the tenant row for this token to make consumption atomic and race-free.
    let tenant_row = sqlx::query::query(ENROLL_TOKEN_LOCK_SQL)
        .bind(enrollment_token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ApiError::Database)?
        .ok_or_else(|| ApiError::BadRequest("invalid or expired enrollment token".to_string()))?;

    let enrollment_token_id: Uuid = tenant_row
        .try_get("enrollment_token_id")
        .map_err(ApiError::Database)?;
    let tenant_id: Uuid = tenant_row
        .try_get("tenant_id")
        .map_err(ApiError::Database)?;
    let slug: String = tenant_row.try_get("slug").map_err(ApiError::Database)?;
    let agent_limit: i32 = tenant_row
        .try_get("agent_limit")
        .map_err(ApiError::Database)?;

    // Check agent limit.
    let count_row = sqlx::query::query(
        "SELECT COUNT(*)::bigint as cnt FROM agents WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(tenant_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;
    let count: i64 = count_row.try_get("cnt").map_err(ApiError::Database)?;

    if count >= i64::from(agent_limit) {
        return Err(ApiError::AgentLimitReached);
    }

    // Generate a stable agent_id from the enrollment.
    let agent_uuid = Uuid::new_v4();
    let agent_id = format!("agent-{}", agent_uuid);

    let metadata = serde_json::json!({
        "hostname": req.hostname,
        "version": req.version,
        "enrolled_at": chrono::Utc::now().to_rfc3339(),
    });
    let principal_id = upsert_endpoint_principal(
        &mut tx,
        EndpointPrincipalUpsert {
            tenant_id,
            stable_ref: &agent_id,
            display_name: &req.hostname,
            public_key: &req.public_key,
            trust_level: "medium",
            lifecycle_state: "active",
            liveness_state: Some("active"),
            metadata: &metadata,
        },
    )
    .await?;

    let row = sqlx::query::query(
        r#"INSERT INTO agents (
               tenant_id,
               principal_id,
               agent_id,
               name,
               public_key,
               role,
               trust_level,
               metadata
           )
           VALUES ($1, $2, $3, $4, $5, 'coder', 'medium', $6)
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(&agent_id)
    .bind(&req.hostname)
    .bind(&req.public_key)
    .bind(&metadata)
    .fetch_one(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    let agent = Agent::from_row(row).map_err(ApiError::Database)?;
    link_endpoint_hierarchy_node_if_unambiguous(&mut tx, tenant_id, &agent_id, &req.hostname)
        .await?;

    // Invalidate the enrollment token so it cannot be reused.
    let token_consumed = sqlx::query::query(ENROLL_TOKEN_CONSUME_SQL)
        .bind(enrollment_token_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::Database)?;
    if token_consumed.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "failed to consume enrollment token atomically".to_string(),
        ));
    }

    tx.commit().await.map_err(ApiError::Database)?;

    // Provision NATS credentials after the enrollment transaction commits.
    // If provisioning fails, compensate by removing the new agent row and
    // re-opening the one-time token so enrollment can be retried.
    let nats_creds = match state
        .provisioner
        .create_agent_credentials(tenant_id, &slug, &agent_id)
        .await
    {
        Ok(creds) => creds,
        Err(err) => {
            if let Err(cleanup_err) = rollback_failed_enrollment(
                &state.db,
                agent.id,
                enrollment_token_id,
                tenant_id,
                &agent_id,
            )
            .await
            {
                tracing::error!(
                    error = %cleanup_err,
                    tenant = %slug,
                    agent_id = %agent_id,
                    "Failed to rollback enrollment after NATS credential provisioning error"
                );
                return Err(ApiError::Internal(
                    "failed to provision credentials and failed to rollback enrollment".to_string(),
                ));
            }

            return Err(ApiError::Nats(err.to_string()));
        }
    };

    // Backfill policy KV for newly enrolled agents if a tenant-level active
    // policy already exists.
    match policy_distribution::fetch_active_policy_by_tenant_id(&state.db, tenant_id).await {
        Ok(Some(active_policy)) => {
            if let Err(err) = policy_distribution::reconcile_policy_for_agent(
                &state.nats,
                &active_policy,
                &agent_id,
            )
            .await
            {
                tracing::warn!(
                    error = %err,
                    tenant = %slug,
                    agent_id = %agent_id,
                    "Enrollment policy backfill failed"
                );
            }
        }
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(
                error = %err,
                tenant = %slug,
                agent_id = %agent_id,
                "Failed to load active policy during enrollment backfill"
            );
        }
    }

    // Record usage event.
    let _ = state.metering.record(tenant_id, "agent_enrolled", 1).await;
    Ok(Json(EnrollmentResponse {
        agent_uuid: agent.id.to_string(),
        tenant_id: tenant_id.to_string(),
        nats_url: nats_creds.nats_url,
        nats_account: nats_creds.account,
        nats_subject_prefix: nats_creds.subject_prefix,
        nats_token: nats_creds.token,
        approval_response_trusted_issuer: Some(approval_response_trusted_issuer),
        agent_id,
    }))
}

// ---------------------------------------------------------------------------
// Runtime registration — endpoint/runtime two-level hierarchy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRuntimeRequest {
    /// A human-readable name for the runtime (e.g. "claude-code-main").
    name: String,
    /// Ed25519 public key (hex-encoded) for the runtime identity.
    public_key: String,
    /// Trust level override; defaults to the endpoint's trust level.
    trust_level: Option<String>,
    /// Arbitrary metadata to attach to the runtime principal.
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RegisterRuntimeResponse {
    runtime_principal_id: Uuid,
    endpoint_principal_id: Uuid,
    hierarchy_node_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct RuntimeEntry {
    principal_id: Uuid,
    stable_ref: String,
    display_name: String,
    trust_level: String,
    lifecycle_state: String,
    liveness_state: Option<String>,
    metadata: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
}

fn build_runtime_stable_ref(endpoint_agent_id: &str, runtime_name: &str) -> String {
    format!(
        "runtime:endpoint:{}:name:{}",
        hex::encode(endpoint_agent_id.as_bytes()),
        hex::encode(runtime_name.as_bytes()),
    )
}

/// POST /api/v1/agents/{id}/runtimes — register a runtime under an endpoint.
async fn register_runtime(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(agent_uuid): Path<Uuid>,
    Json(req): Json<RegisterRuntimeRequest>,
) -> Result<Json<RegisterRuntimeResponse>, ApiError> {
    ensure_write_access(&auth)?;

    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_string()));
    }

    // Input length validation
    validation::validate_runtime_name(&req.name)?;
    validation::validate_public_key_length(&req.public_key)?;
    validation::validate_trust_level(req.trust_level.as_deref())?;
    validation::validate_metadata(req.metadata.as_ref())?;

    // Validate the Ed25519 public key.
    hush_core::PublicKey::from_hex(&req.public_key).map_err(|_| ApiError::InvalidPublicKey)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;

    // 1. Verify the endpoint agent exists and belongs to the tenant inside the
    //    registration transaction so endpoint deletion cannot race this flow
    //    after a stale pre-check.
    let endpoint_row = sqlx::query::query(
        r#"SELECT agent_id, name, principal_id, trust_level
           FROM agents
           WHERE id = $1
             AND tenant_id = $2
           FOR UPDATE"#,
    )
    .bind(agent_uuid)
    .bind(auth.tenant_id)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let endpoint_agent_id: String = endpoint_row
        .try_get("agent_id")
        .map_err(ApiError::Database)?;
    let endpoint_name: String = endpoint_row.try_get("name").map_err(ApiError::Database)?;
    let endpoint_principal_id: Option<Uuid> = endpoint_row
        .try_get("principal_id")
        .map_err(ApiError::Database)?;
    let endpoint_principal_id = endpoint_principal_id.ok_or_else(|| {
        ApiError::BadRequest("endpoint agent is not linked to a directory principal".to_string())
    })?;
    let endpoint_trust_level: String = endpoint_row
        .try_get("trust_level")
        .map_err(ApiError::Database)?;

    let inherited_trust_level = validation::sanitize_trust_level(&endpoint_trust_level);
    let trust_level = req.trust_level.as_deref().unwrap_or(inherited_trust_level);
    let metadata = req.metadata.unwrap_or(serde_json::json!({}));

    // Encode the endpoint/runtime pair so different inputs cannot collide on
    // the same stable_ref via crafted delimiter injection.
    let runtime_stable_ref = build_runtime_stable_ref(&endpoint_agent_id, &req.name);

    // 2. Upsert the runtime_agent principal.
    let runtime_principal_id = upsert_runtime_principal(
        &mut tx,
        RuntimePrincipalUpsert {
            tenant_id: auth.tenant_id,
            stable_ref: &runtime_stable_ref,
            display_name: &req.name,
            public_key: &req.public_key,
            trust_level,
            lifecycle_state: "active",
            liveness_state: Some("active"),
            metadata: &metadata,
        },
    )
    .await?;

    // 3. Create a principal_membership linking runtime to endpoint.
    sqlx::query::query(
        r#"INSERT INTO principal_memberships (
               tenant_id, principal_id, target_kind, target_id
           )
           VALUES ($1, $2, 'endpoint', $3)
           ON CONFLICT (tenant_id, principal_id, target_kind, target_id)
           DO NOTHING"#,
    )
    .bind(auth.tenant_id)
    .bind(runtime_principal_id)
    .bind(endpoint_principal_id)
    .execute(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    // 4. Optionally create a hierarchy_node of type "runtime" under the
    //    endpoint's hierarchy node (if one exists).
    let hierarchy_node_id = create_runtime_hierarchy_node(
        &mut tx,
        auth.tenant_id,
        &endpoint_agent_id,
        &endpoint_name,
        &req.name,
    )
    .await?;

    tx.commit().await.map_err(ApiError::Database)?;

    tracing::info!(
        tenant = %auth.slug,
        endpoint_agent_id = %endpoint_agent_id,
        runtime_principal_id = %runtime_principal_id,
        runtime_name = %req.name,
        "Runtime registered under endpoint"
    );

    Ok(Json(RegisterRuntimeResponse {
        runtime_principal_id,
        endpoint_principal_id,
        hierarchy_node_id,
    }))
}

/// Query parameters for listing runtimes under an endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListRuntimesQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

/// GET /api/v1/agents/{id}/runtimes — list runtimes registered under an endpoint.
async fn list_runtimes(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(agent_uuid): Path<Uuid>,
    Query(query): Query<ListRuntimesQuery>,
) -> Result<Json<Vec<RuntimeEntry>>, ApiError> {
    let offset = query.offset.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    // Verify the endpoint agent exists and get its principal_id.
    let endpoint_row =
        sqlx::query::query("SELECT principal_id FROM agents WHERE id = $1 AND tenant_id = $2")
            .bind(agent_uuid)
            .bind(auth.tenant_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::Database)?
            .ok_or(ApiError::NotFound)?;

    let endpoint_principal_id: Option<Uuid> = endpoint_row
        .try_get("principal_id")
        .map_err(ApiError::Database)?;
    let endpoint_principal_id = endpoint_principal_id.ok_or_else(|| {
        ApiError::BadRequest("endpoint agent is not linked to a directory principal".to_string())
    })?;

    // Query principal_memberships for runtimes linked to this endpoint, then
    // join against principals to get full details.
    let rows = sqlx::query::query(
        r#"SELECT p.id AS principal_id,
                  p.stable_ref,
                  p.display_name,
                  p.trust_level,
                  p.lifecycle_state,
                  p.liveness_state,
                  p.metadata,
                  p.created_at
           FROM principal_memberships AS pm
           JOIN principals AS p
             ON p.id = pm.principal_id
            AND p.tenant_id = pm.tenant_id
           WHERE pm.tenant_id = $1
             AND pm.target_kind = 'endpoint'
             AND pm.target_id = $2
             AND p.principal_type = 'runtime_agent'
           ORDER BY p.created_at ASC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(auth.tenant_id)
    .bind(endpoint_principal_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let runtimes: Vec<RuntimeEntry> = rows
        .into_iter()
        .map(|row| {
            Ok(RuntimeEntry {
                principal_id: row.try_get("principal_id")?,
                stable_ref: row.try_get("stable_ref")?,
                display_name: row.try_get("display_name")?,
                trust_level: row.try_get("trust_level")?,
                lifecycle_state: row.try_get("lifecycle_state")?,
                liveness_state: row.try_get("liveness_state")?,
                metadata: row.try_get("metadata")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect::<Result<_, sqlx::error::Error>>()
        .map_err(ApiError::Database)?;

    Ok(Json(runtimes))
}

async fn upsert_runtime_principal(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    principal: RuntimePrincipalUpsert<'_>,
) -> Result<Uuid, ApiError> {
    let row = sqlx::query::query(
        r#"INSERT INTO principals (
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           )
           VALUES ($1, 'runtime_agent', $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (tenant_id, principal_type, stable_ref) DO UPDATE
           SET display_name = EXCLUDED.display_name,
               trust_level = EXCLUDED.trust_level,
               lifecycle_state = EXCLUDED.lifecycle_state,
               liveness_state = EXCLUDED.liveness_state,
               public_key = EXCLUDED.public_key,
               metadata = EXCLUDED.metadata,
               updated_at = now()
           RETURNING id"#,
    )
    .bind(principal.tenant_id)
    .bind(principal.stable_ref)
    .bind(principal.display_name)
    .bind(principal.trust_level)
    .bind(principal.lifecycle_state)
    .bind(principal.liveness_state)
    .bind(principal.public_key)
    .bind(principal.metadata)
    .fetch_one(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    row.try_get("id").map_err(ApiError::Database)
}

struct RuntimePrincipalUpsert<'a> {
    tenant_id: Uuid,
    stable_ref: &'a str,
    display_name: &'a str,
    public_key: &'a str,
    trust_level: &'a str,
    lifecycle_state: &'a str,
    liveness_state: Option<&'a str>,
    metadata: &'a serde_json::Value,
}

/// If the endpoint has a hierarchy node, create a "runtime" child node under it.
/// Returns `Some(node_id)` if a node was created, `None` if no parent node exists.
async fn create_runtime_hierarchy_node(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    endpoint_agent_id: &str,
    endpoint_name: &str,
    runtime_name: &str,
) -> Result<Option<Uuid>, ApiError> {
    let Some(parent_node_id) =
        resolve_endpoint_hierarchy_node_id(tx, tenant_id, endpoint_agent_id, Some(endpoint_name))
            .await?
    else {
        return Ok(None);
    };

    // Use runtime_name as external_id to leverage the partial unique index
    // (tenant_id, parent_id, external_id) WHERE node_type = 'runtime'.
    // This makes the insert truly idempotent — a duplicate registration
    // hits the conflict and returns the existing node's id.
    let row = sqlx::query::query(
        r#"INSERT INTO hierarchy_nodes (
               tenant_id, name, node_type, parent_id, metadata, external_id
           )
           VALUES ($1, $2, 'runtime', $3, '{}', $4)
           ON CONFLICT (tenant_id, parent_id, external_id)
               WHERE node_type = 'runtime'
           DO UPDATE SET name = EXCLUDED.name
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(runtime_name)
    .bind(parent_node_id)
    .bind(runtime_name)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    row.map(|r| r.try_get("id"))
        .transpose()
        .map_err(ApiError::Database)
}

/// Link an endpoint hierarchy node to its stable endpoint agent id when that
/// mapping can be established unambiguously.
async fn link_endpoint_hierarchy_node_if_unambiguous(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    endpoint_agent_id: &str,
    endpoint_name: &str,
) -> Result<(), ApiError> {
    let _ =
        resolve_endpoint_hierarchy_node_id(tx, tenant_id, endpoint_agent_id, Some(endpoint_name))
            .await?;
    Ok(())
}

/// Resolve the hierarchy node that represents an endpoint.
///
/// The stable link uses `hierarchy_nodes.external_id = agents.agent_id`. If no
/// explicit link exists yet, we only backfill it when there is exactly one
/// unlinked endpoint node matching the endpoint's display name; otherwise we
/// leave the hierarchy untouched rather than guessing and corrupting another
/// endpoint's subtree.
async fn resolve_endpoint_hierarchy_node_id(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    endpoint_agent_id: &str,
    endpoint_name: Option<&str>,
) -> Result<Option<Uuid>, ApiError> {
    let linked_rows = sqlx::query::query(
        r#"SELECT id
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND node_type IN ('endpoint', 'agent')
             AND external_id = $2
           ORDER BY created_at ASC
           LIMIT 2"#,
    )
    .bind(tenant_id)
    .bind(endpoint_agent_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    match linked_rows.as_slice() {
        [row] => {
            let node_id: Uuid = row.try_get("id").map_err(ApiError::Database)?;
            return Ok(Some(node_id));
        }
        [] => {}
        _ => {
            tracing::warn!(
                tenant_id = %tenant_id,
                endpoint_agent_id,
                "multiple endpoint hierarchy nodes share the same external_id; skipping hierarchy linkage"
            );
            return Ok(None);
        }
    }

    let Some(endpoint_name) = endpoint_name else {
        return Ok(None);
    };

    let candidate_rows = sqlx::query::query(
        r#"SELECT id
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND node_type IN ('endpoint', 'agent')
             AND external_id IS NULL
             AND name = $2
           ORDER BY created_at ASC
           LIMIT 2
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .bind(endpoint_name)
    .fetch_all(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    match candidate_rows.as_slice() {
        [row] => {
            let node_id: Uuid = row.try_get("id").map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE hierarchy_nodes
                   SET external_id = $3,
                       updated_at = now()
                   WHERE tenant_id = $1
                     AND id = $2
                     AND external_id IS NULL"#,
            )
            .bind(tenant_id)
            .bind(node_id)
            .bind(endpoint_agent_id)
            .execute(tx.as_mut())
            .await
            .map_err(ApiError::Database)?;
            Ok(Some(node_id))
        }
        [] => Ok(None),
        _ => {
            tracing::warn!(
                tenant_id = %tenant_id,
                endpoint_agent_id,
                endpoint_name,
                "multiple unlinked endpoint hierarchy nodes matched by name; refusing ambiguous linkage"
            );
            Ok(None)
        }
    }
}

async fn rollback_failed_enrollment(
    db: &crate::db::PgPool,
    agent_uuid: Uuid,
    enrollment_token_id: Uuid,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<(), sqlx::error::Error> {
    let mut tx = db.begin().await?;

    let principal_row =
        sqlx::query::query("SELECT principal_id FROM agents WHERE id = $1 AND tenant_id = $2")
            .bind(agent_uuid)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
    let principal_id = principal_row
        .as_ref()
        .and_then(|row| row.try_get::<Option<Uuid>, _>("principal_id").ok())
        .flatten();

    sqlx::query::query("DELETE FROM agents WHERE id = $1 AND tenant_id = $2")
        .bind(agent_uuid)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    if let Some(principal_id) = principal_id {
        delete_principal_if_unreferenced(&mut tx, principal_id, tenant_id).await?;
    }

    unlink_endpoint_hierarchy_nodes(&mut tx, tenant_id, agent_id).await?;

    sqlx::query::query(
        r#"UPDATE tenant_enrollment_tokens
           SET consumed_at = NULL
           WHERE id = $1"#,
    )
    .bind(enrollment_token_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

async fn rollback_failed_agent_creation(
    db: &crate::db::PgPool,
    agent_uuid: Uuid,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<(), sqlx::error::Error> {
    let mut tx = db.begin().await?;

    let principal_row =
        sqlx::query::query("SELECT principal_id FROM agents WHERE id = $1 AND tenant_id = $2")
            .bind(agent_uuid)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
    let principal_id = principal_row
        .as_ref()
        .and_then(|row| row.try_get::<Option<Uuid>, _>("principal_id").ok())
        .flatten();

    sqlx::query::query("DELETE FROM agents WHERE id = $1 AND tenant_id = $2")
        .bind(agent_uuid)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    if let Some(principal_id) = principal_id {
        delete_principal_if_unreferenced(&mut tx, principal_id, tenant_id).await?;
    }

    unlink_endpoint_hierarchy_nodes(&mut tx, tenant_id, agent_id).await?;

    tx.commit().await?;
    Ok(())
}

async fn unlink_endpoint_hierarchy_nodes(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<(), sqlx::error::Error> {
    sqlx::query::query(
        r#"UPDATE hierarchy_nodes
           SET external_id = NULL,
               updated_at = now()
           WHERE tenant_id = $1
             AND node_type IN ('endpoint', 'agent')
             AND external_id = $2"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

async fn upsert_endpoint_principal(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    principal: EndpointPrincipalUpsert<'_>,
) -> Result<Uuid, ApiError> {
    let row = sqlx::query::query(
        r#"INSERT INTO principals (
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           )
           VALUES ($1, 'endpoint_agent', $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (tenant_id, principal_type, stable_ref) DO UPDATE
           SET display_name = EXCLUDED.display_name,
               trust_level = EXCLUDED.trust_level,
               lifecycle_state = EXCLUDED.lifecycle_state,
               liveness_state = EXCLUDED.liveness_state,
               public_key = EXCLUDED.public_key,
               metadata = EXCLUDED.metadata,
               updated_at = now()
           RETURNING id"#,
    )
    .bind(principal.tenant_id)
    .bind(principal.stable_ref)
    .bind(principal.display_name)
    .bind(principal.trust_level)
    .bind(principal.lifecycle_state)
    .bind(principal.liveness_state)
    .bind(principal.public_key)
    .bind(principal.metadata)
    .fetch_one(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    row.try_get("id").map_err(ApiError::Database)
}

async fn set_principal_liveness_state(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    principal_id: Option<Uuid>,
    tenant_id: Uuid,
    liveness_state: &str,
) -> Result<(), ApiError> {
    let Some(principal_id) = principal_id else {
        return Ok(());
    };

    sqlx::query::query(
        r#"UPDATE principals
           SET liveness_state = $2,
               updated_at = now()
           WHERE id = $1
             AND tenant_id = $3"#,
    )
    .bind(principal_id)
    .bind(liveness_state)
    .bind(tenant_id)
    .execute(tx.as_mut())
    .await
    .map_err(ApiError::Database)?;

    Ok(())
}

async fn delete_principal_if_unreferenced(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    principal_id: Uuid,
    tenant_id: Uuid,
) -> Result<(), sqlx::error::Error> {
    sqlx::query::query(
        r#"DELETE FROM principals AS p
           WHERE p.id = $1
             AND p.tenant_id = $2
             AND NOT EXISTS (
                 SELECT 1
                 FROM agents AS a
                 WHERE a.principal_id = p.id
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM approvals AS ap
                 WHERE ap.principal_id = p.id
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM principal_memberships AS pm
                 WHERE pm.principal_id = p.id
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM grants AS g
                 WHERE g.issuer_principal_id = p.id
                    OR g.subject_principal_id = p.id
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM delegation_edges AS de
                 WHERE de.parent_principal_id = p.id
                    OR de.child_principal_id = p.id
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM policy_attachments AS pa
                 WHERE pa.target_kind = 'principal'
                   AND pa.target_id = p.id
             )"#,
    )
    .bind(principal_id)
    .bind(tenant_id)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

struct EndpointPrincipalUpsert<'a> {
    tenant_id: Uuid,
    stable_ref: &'a str,
    display_name: &'a str,
    public_key: &'a str,
    trust_level: &'a str,
    lifecycle_state: &'a str,
    liveness_state: Option<&'a str>,
    metadata: &'a serde_json::Value,
}

fn checksum_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_yaml_value(input: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    serde_yaml::from_str::<serde_yaml::Value>(input)
}

fn serialize_compiled_policy(value: &serde_yaml::Value) -> Result<String, serde_yaml::Error> {
    match value {
        serde_yaml::Value::Mapping(map) if map.is_empty() => Ok(String::new()),
        serde_yaml::Value::Null => Ok(String::new()),
        _ => serde_yaml::to_string(value),
    }
}

fn merge_yaml_value(base: &mut serde_yaml::Value, overlay: serde_yaml::Value) {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(base_map), serde_yaml::Value::Mapping(overlay_map)) => {
            for (key, value) in overlay_map {
                if value.is_null() {
                    base_map.remove(&key);
                    continue;
                }

                if let Some(existing) = base_map.get_mut(&key) {
                    merge_yaml_value(existing, value);
                } else {
                    base_map.insert(key, value);
                }
            }
        }
        (base_slot, replacement) => {
            *base_slot = replacement;
        }
    }
}

fn lifecycle_overlay_names(lifecycle_state: &str) -> Vec<String> {
    match lifecycle_state {
        "restricted" => vec!["restricted".to_string()],
        "observe_only" => vec!["observe_only".to_string()],
        "quarantined" => vec!["quarantined".to_string()],
        "revoked" => vec!["revoked".to_string()],
        _ => Vec::new(),
    }
}

#[derive(Debug, Serialize)]
struct EffectivePolicyResponse {
    tenant_id: Uuid,
    principal_id: Uuid,
    agent_id: Option<String>,
    lifecycle_state: String,
    liveness_state: Option<String>,
    compiled_policy_yaml: String,
    compiled_policy_sha256: String,
    resolution_version: i64,
    resolved_at: chrono::DateTime<chrono::Utc>,
    source_attachments: Vec<ResolvedPolicyAttachment>,
    applied_overlays: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResolvedPolicyAttachment {
    attachment_id: Uuid,
    target_kind: String,
    target_id: Uuid,
    priority: i32,
    policy_ref: Option<String>,
    checksum_sha256: Option<String>,
}

struct PolicyAttachmentRow {
    id: Uuid,
    target_kind: String,
    target_id: Option<Uuid>,
    priority: i32,
    policy_ref: Option<String>,
    policy_yaml: Option<String>,
    checksum_sha256: Option<String>,
}

impl PolicyAttachmentRow {
    fn from_row(row: sqlx_postgres::PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            target_kind: row.try_get("target_kind")?,
            target_id: row.try_get("target_id")?,
            priority: row.try_get("priority")?,
            policy_ref: row.try_get("policy_ref")?,
            policy_yaml: row.try_get("policy_yaml")?,
            checksum_sha256: row.try_get("checksum_sha256")?,
        })
    }

    fn matches(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        swarm_ids: &HashSet<Uuid>,
        project_ids: &HashSet<Uuid>,
        capability_group_ids: &HashSet<Uuid>,
    ) -> bool {
        match self.target_kind.as_str() {
            "tenant" => self.target_id.is_none(),
            "swarm" => self.target_id.is_some_and(|id| swarm_ids.contains(&id)),
            "project" => self.target_id.is_some_and(|id| project_ids.contains(&id)),
            "capability_group" => self
                .target_id
                .is_some_and(|id| capability_group_ids.contains(&id)),
            "principal" => self.target_id == Some(principal_id),
            _ => self.target_id == Some(tenant_id) && self.target_kind == "tenant",
        }
    }

    fn resolved_policy_yaml(&self) -> Result<Option<&str>, ApiError> {
        match (self.policy_yaml.as_deref(), self.policy_ref.as_deref()) {
            (Some(policy_yaml), _) => Ok(Some(policy_yaml)),
            (None, Some(policy_ref)) => Err(ApiError::Conflict(format!(
                "policy attachment {} references unresolved policy_ref `{policy_ref}`",
                self.id
            ))),
            (None, None) => Ok(None),
        }
    }
}

/// Allow-list check: member, admin, and owner may write.
fn ensure_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "member" | "admin" | "owner") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_agent_id_prefix() {
        let id = Uuid::new_v4();
        assert!(format!("agent-{}", id).starts_with("agent-"));
    }

    #[test]
    fn heartbeat_recovers_stale_and_dead_statuses() {
        assert!(HEARTBEAT_UPDATE_SQL.contains("status IN ('active', 'stale', 'dead')"));
        assert!(HEARTBEAT_UPDATE_SQL.contains("status = 'active'"));
    }

    #[test]
    fn enrollment_queries_are_atomic() {
        assert!(ENROLL_TOKEN_LOCK_SQL.contains("FOR UPDATE"));
        assert!(ENROLL_TOKEN_LOCK_SQL.contains("OF t, et"));
        assert!(ENROLL_TOKEN_LOCK_SQL.contains("expires_at > now()"));
        assert!(ENROLL_TOKEN_CONSUME_SQL.contains("WHERE id = $1"));
    }

    #[test]
    fn enrollment_token_hash_is_sha256_hex() {
        let hash = hash_enrollment_token("cset_example");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn merge_yaml_replaces_arrays_and_removes_null_fields() {
        let mut base =
            parse_yaml_value("rules:\n  - name: base\nsettings:\n  mode: standard\n  keep: true\n")
                .expect("base yaml");
        let overlay = parse_yaml_value(
            "rules:\n  - name: override\nsettings:\n  mode: restricted\n  keep: null\n",
        )
        .expect("overlay yaml");

        merge_yaml_value(&mut base, overlay);
        let rendered = serialize_compiled_policy(&base).expect("serialize merged yaml");
        let merged: serde_yaml::Value = serde_yaml::from_str(&rendered).expect("parse merged yaml");
        assert_eq!(merged["rules"][0]["name"], "override");
        assert_eq!(merged["settings"]["mode"], "restricted");
        assert!(merged["settings"].get("keep").is_none());
    }

    #[test]
    fn lifecycle_overlay_names_follow_directory_contract() {
        assert!(lifecycle_overlay_names("active").is_empty());
        assert_eq!(
            lifecycle_overlay_names("observe_only"),
            vec!["observe_only"]
        );
        assert_eq!(lifecycle_overlay_names("quarantined"), vec!["quarantined"]);
        assert_eq!(lifecycle_overlay_names("revoked"), vec!["revoked"]);
    }

    #[test]
    fn policy_attachment_rejects_unknown_target_kind() {
        let attachment = PolicyAttachmentRow {
            id: Uuid::new_v4(),
            target_kind: "unknown".to_string(),
            target_id: Some(Uuid::new_v4()),
            priority: 10,
            policy_ref: None,
            policy_yaml: Some("policy:\n  mode: noop\n".to_string()),
            checksum_sha256: None,
        };

        assert!(!attachment.matches(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        ));
    }

    #[test]
    fn policy_attachment_ref_without_inline_yaml_fails_closed() {
        let attachment = PolicyAttachmentRow {
            id: Uuid::new_v4(),
            target_kind: "tenant".to_string(),
            target_id: None,
            priority: 10,
            policy_ref: Some("catalog/default".to_string()),
            policy_yaml: None,
            checksum_sha256: None,
        };

        let error = attachment
            .resolved_policy_yaml()
            .expect_err("ref-only attachment should fail closed");
        assert!(matches!(error, ApiError::Conflict(_)));
        assert!(error.to_string().contains("catalog/default"));
    }

    #[test]
    fn policy_attachment_prefers_inline_yaml_when_present() {
        let attachment = PolicyAttachmentRow {
            id: Uuid::new_v4(),
            target_kind: "tenant".to_string(),
            target_id: None,
            priority: 10,
            policy_ref: Some("catalog/default".to_string()),
            policy_yaml: Some("policy:\n  mode: inline\n".to_string()),
            checksum_sha256: None,
        };

        assert_eq!(
            attachment
                .resolved_policy_yaml()
                .expect("inline yaml should resolve"),
            Some("policy:\n  mode: inline\n")
        );
    }
}
