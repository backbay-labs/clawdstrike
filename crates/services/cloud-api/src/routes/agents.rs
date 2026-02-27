use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::agent::{
    Agent, EnrollmentRequest, EnrollmentResponse, HeartbeatRequest, RegisterAgentRequest,
    RegisterAgentResponse,
};
use crate::state::AppState;

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
    let result = sqlx::query::query(
        r#"UPDATE agents SET last_heartbeat_at = now(), metadata = COALESCE($3, metadata)
           WHERE tenant_id = $1 AND agent_id = $2 AND status = 'active'"#,
    )
    .bind(auth.tenant_id)
    .bind(&req.agent_id)
    .bind(req.metadata.as_ref())
    .execute(&state.db)
    .await
    .map_err(ApiError::Database)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
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
    // Look up the tenant by enrollment_token (this IS the auth for enrollment).
    let tenant_row =
        sqlx::query::query("SELECT id, slug, agent_limit FROM tenants WHERE enrollment_token = $1")
            .bind(&req.enrollment_token)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::Database)?
            .ok_or_else(|| ApiError::BadRequest("invalid enrollment token".to_string()))?;

    let tenant_id: Uuid = tenant_row.try_get("id").map_err(ApiError::Database)?;
    let slug: String = tenant_row.try_get("slug").map_err(ApiError::Database)?;
    let agent_limit: i32 = tenant_row
        .try_get("agent_limit")
        .map_err(ApiError::Database)?;

    // Validate the Ed25519 public key.
    hush_core::PublicKey::from_hex(&req.public_key).map_err(|_| ApiError::InvalidPublicKey)?;

    // Check agent limit.
    let count_row = sqlx::query::query(
        "SELECT COUNT(*)::bigint as cnt FROM agents WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
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
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let agent = Agent::from_row(row).map_err(ApiError::Database)?;

    // Provision NATS credentials.
    let nats_creds = state
        .provisioner
        .create_agent_credentials(tenant_id, &slug, &agent_id)
        .await
        .map_err(|e| ApiError::Nats(e.to_string()))?;

    // Invalidate the enrollment token so it cannot be reused.
    sqlx::query::query("UPDATE tenants SET enrollment_token = NULL WHERE id = $1")
        .bind(tenant_id)
        .execute(&state.db)
        .await
        .map_err(ApiError::Database)?;

    // Record usage event.
    let _ = state.metering.record(tenant_id, "agent_enrolled", 1).await;

    Ok(Json(EnrollmentResponse {
        agent_uuid: agent.id.to_string(),
        tenant_id: tenant_id.to_string(),
        nats_url: nats_creds.nats_url,
        nats_account: nats_creds.account,
        nats_subject_prefix: nats_creds.subject_prefix,
        nats_token: nats_creds.token,
        agent_id,
    }))
}
