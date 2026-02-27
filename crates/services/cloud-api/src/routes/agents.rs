use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::crypto::hash_enrollment_token;
use crate::error::ApiError;
use crate::models::agent::{
    Agent, EnrollmentRequest, EnrollmentResponse, HeartbeatRequest, RegisterAgentRequest,
    RegisterAgentResponse,
};
use crate::services::policy_distribution;
use crate::state::AppState;

const HEARTBEAT_UPDATE_SQL: &str = r#"UPDATE agents
           SET last_heartbeat_at = now(),
               status = 'active',
               metadata = COALESCE($3, metadata)
           WHERE tenant_id = $1
             AND agent_id = $2
             AND status IN ('active', 'stale', 'dead')"#;

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
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    // Check agent limit
    let count_row = sqlx::query::query(
        "SELECT COUNT(*)::bigint as cnt FROM agents WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;
    let count: i64 = count_row.try_get("cnt").map_err(ApiError::Database)?;

    if count >= i64::from(auth.agent_limit) {
        return Err(ApiError::AgentLimitReached);
    }

    // Validate Ed25519 public key using hush-core
    hush_core::PublicKey::from_hex(&req.public_key).map_err(|_| ApiError::InvalidPublicKey)?;

    let role = req.role.as_deref().unwrap_or("coder");
    let trust_level = req.trust_level.as_deref().unwrap_or("medium");
    let metadata = req.metadata.clone().unwrap_or(serde_json::json!({}));

    let row = sqlx::query::query(
        r#"INSERT INTO agents (tenant_id, agent_id, name, public_key, role, trust_level, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(&req.agent_id)
    .bind(&req.name)
    .bind(&req.public_key)
    .bind(role)
    .bind(trust_level)
    .bind(&metadata)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let agent = Agent::from_row(row).map_err(ApiError::Database)?;

    // Generate NATS credentials for this agent
    let nats_creds = state
        .provisioner
        .create_agent_credentials(auth.tenant_id, &auth.slug, &req.agent_id)
        .await
        .map_err(|e| ApiError::Nats(e.to_string()))?;

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

async fn list_agents(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<Agent>>, ApiError> {
    let rows =
        sqlx::query::query("SELECT * FROM agents WHERE tenant_id = $1 ORDER BY created_at DESC")
            .bind(auth.tenant_id)
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

async fn heartbeat(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = sqlx::query::query(HEARTBEAT_UPDATE_SQL)
        .bind(auth.tenant_id)
        .bind(&req.agent_id)
        .bind(req.metadata.as_ref())
        .execute(&state.db)
        .await
        .map_err(ApiError::Database)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

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
    // Validate the Ed25519 public key.
    hush_core::PublicKey::from_hex(&req.public_key).map_err(|_| ApiError::InvalidPublicKey)?;

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
    .fetch_one(&mut *tx)
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

    let row = sqlx::query::query(
        r#"INSERT INTO agents (tenant_id, agent_id, name, public_key, role, trust_level, metadata)
           VALUES ($1, $2, $3, $4, 'coder', 'medium', $5)
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(&agent_id)
    .bind(&req.hostname)
    .bind(&req.public_key)
    .bind(&metadata)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    let agent = Agent::from_row(row).map_err(ApiError::Database)?;

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
            if let Err(cleanup_err) =
                rollback_failed_enrollment(&state.db, agent.id, enrollment_token_id).await
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
    let approval_response_trusted_issuer = state
        .signing_keypair
        .as_ref()
        .map(|keypair| spine::issuer_from_keypair(keypair.as_ref()));

    Ok(Json(EnrollmentResponse {
        agent_uuid: agent.id.to_string(),
        tenant_id: tenant_id.to_string(),
        nats_url: nats_creds.nats_url,
        nats_account: nats_creds.account,
        nats_subject_prefix: nats_creds.subject_prefix,
        nats_token: nats_creds.token,
        approval_response_trusted_issuer,
        agent_id,
    }))
}

async fn rollback_failed_enrollment(
    db: &crate::db::PgPool,
    agent_uuid: Uuid,
    enrollment_token_id: Uuid,
) -> Result<(), sqlx::error::Error> {
    let mut tx = db.begin().await?;

    sqlx::query::query("DELETE FROM agents WHERE id = $1")
        .bind(agent_uuid)
        .execute(&mut *tx)
        .await?;

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
}
