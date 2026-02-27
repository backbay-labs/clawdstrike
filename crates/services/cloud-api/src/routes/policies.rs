use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::services::policy_distribution;
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
    pub kv_write_failures: i64,
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

    // Persist tenant-level active policy so enroll/recovery paths can converge later.
    let active_policy = policy_distribution::upsert_active_policy(
        &state.db,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
    )
    .await
    .map_err(ApiError::Database)?;

    // Enumerate all non-revoked agents (active + inactive lifecycle states).
    // This avoids only targeting currently-active agents during deploy.
    let agent_rows = sqlx::query::query(
        r#"SELECT agent_id
           FROM agents
           WHERE tenant_id = $1
             AND status IN ('active', 'inactive', 'stale', 'dead')
           ORDER BY created_at ASC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let agent_ids: Vec<String> = agent_rows
        .into_iter()
        .map(|row| row.try_get("agent_id"))
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;
    let agent_count = agent_ids.len() as i64;

    // Write policy into each agent-scoped KV bucket used by PolicySync.
    let mut kv_write_failures = 0_i64;
    for agent_id in &agent_ids {
        if let Err(err) = policy_distribution::put_policy_for_agent(
            &state.nats,
            &auth.slug,
            agent_id,
            &req.policy_yaml,
        )
        .await
        {
            kv_write_failures += 1;
            tracing::warn!(
                error = %err,
                tenant = %auth.slug,
                agent_id = %agent_id,
                "Failed to push deployed policy to agent KV bucket"
            );
        }
    }

    // Best-effort compatibility broadcast for legacy subscribers.
    let subject = policy_distribution::policy_update_subject(&auth.slug);
    if let Err(err) = state
        .nats
        .publish(subject.clone(), req.policy_yaml.clone().into_bytes().into())
        .await
    {
        tracing::warn!(
            error = %err,
            subject = %subject,
            "Legacy policy update publish failed (KV writes succeeded)"
        );
    }

    let deployment_id = Uuid::new_v4();

    tracing::info!(
        deployment_id = %deployment_id,
        tenant = %auth.slug,
        policy_version = active_policy.version,
        agents = agent_count,
        kv_write_failures,
        "Policy deployed to tenant fleet"
    );

    Ok(Json(DeployPolicyResponse {
        deployment_id,
        tenant_slug: auth.slug,
        nats_subject: subject,
        agent_count,
        kv_write_failures,
    }))
}

async fn get_active_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let active = policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id)
        .await
        .map_err(ApiError::Database)?;

    if let Some(policy) = active {
        return Ok(Json(serde_json::json!({
            "tenant": auth.slug,
            "status": "active",
            "version": policy.version,
            "checksum_sha256": policy.checksum_sha256,
            "description": policy.description,
            "updated_at": policy.updated_at,
            "policy_yaml": policy.policy_yaml,
        })));
    }

    Ok(Json(serde_json::json!({
        "tenant": auth.slug,
        "status": "no active policy",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_subject_uses_tenant_prefix_contract() {
        assert_eq!(
            policy_distribution::policy_update_subject("acme"),
            "tenant-acme.clawdstrike.policy.update"
        );
    }

    #[test]
    fn policy_sync_bucket_matches_agent_contract() {
        assert_eq!(
            policy_distribution::policy_sync_bucket("tenant-acme.clawdstrike", "agent-123"),
            "tenant-acme-clawdstrike-policy-sync-agent-123"
        );
    }

    #[test]
    fn policy_sync_key_is_stable() {
        assert_eq!(policy_distribution::POLICY_SYNC_KEY, "policy.yaml");
    }
}
