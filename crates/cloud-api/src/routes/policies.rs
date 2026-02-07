use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies/deploy", post(deploy_policy))
        .route("/policies/active", get(get_active_policy))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployPolicyRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeployPolicyResponse {
    pub deployment_id: Uuid,
    pub tenant_slug: String,
    pub nats_subject: String,
    pub agent_count: i64,
}

async fn deploy_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<DeployPolicyRequest>,
) -> Result<Json<DeployPolicyResponse>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    // Validate the policy YAML by attempting to parse it
    serde_yaml::from_str::<serde_json::Value>(&req.policy_yaml)
        .map_err(|e| ApiError::BadRequest(format!("invalid policy YAML: {e}")))?;

    // Count active agents that will receive this policy
    let count_row = sqlx::query::query(
        "SELECT COUNT(*)::bigint as cnt FROM agents WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;
    let agent_count: i64 = count_row.try_get("cnt").map_err(ApiError::Database)?;

    // Publish policy update to tenant's NATS subject
    let subject = format!("tenant-{}.clawdstrike.policy.update", auth.slug);
    state
        .nats
        .publish(subject.clone(), req.policy_yaml.into())
        .await
        .map_err(|e| ApiError::Nats(e.to_string()))?;

    let deployment_id = Uuid::new_v4();

    tracing::info!(
        deployment_id = %deployment_id,
        tenant = %auth.slug,
        agents = agent_count,
        "Policy deployed to tenant fleet"
    );

    Ok(Json(DeployPolicyResponse {
        deployment_id,
        tenant_slug: auth.slug,
        nats_subject: subject,
        agent_count,
    }))
}

async fn get_active_policy(
    State(_state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "tenant": auth.slug,
        "status": "no active policy",
    })))
}
