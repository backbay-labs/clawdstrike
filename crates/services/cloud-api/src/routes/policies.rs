use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::services::tenant_provisioner::tenant_subject_prefix;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies/deploy", post(deploy_policy))
        .route("/policies/active", get(get_active_policy))
}

fn policy_update_subject(tenant_slug: &str) -> String {
    format!("{}.policy.update", tenant_subject_prefix(tenant_slug))
}

fn policy_sync_bucket(subject_prefix: &str, agent_id: &str) -> String {
    format!(
        "{}-policy-sync-{}",
        sanitize_bucket_component(subject_prefix),
        sanitize_bucket_component(agent_id)
    )
}

fn sanitize_bucket_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn policy_sync_key() -> &'static str {
    "policy.yaml"
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

    // Enumerate active agents that should receive this deployment.
    let agent_rows = sqlx::query::query(
        "SELECT agent_id FROM agents WHERE tenant_id = $1 AND status = 'active' ORDER BY created_at ASC",
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
    let js = async_nats::jetstream::new(state.nats.clone());
    let subject_prefix = tenant_subject_prefix(&auth.slug);
    let policy_bytes = req.policy_yaml.into_bytes();
    for agent_id in &agent_ids {
        let bucket = policy_sync_bucket(&subject_prefix, agent_id);
        let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
            .await
            .map_err(|e| ApiError::Nats(e.to_string()))?;
        store
            .put(policy_sync_key().to_string(), policy_bytes.clone().into())
            .await
            .map_err(|e| ApiError::Nats(e.to_string()))?;
    }

    // Best-effort compatibility broadcast for legacy subscribers.
    let subject = policy_update_subject(&auth.slug);
    if let Err(err) = state
        .nats
        .publish(subject.clone(), policy_bytes.into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_subject_uses_tenant_prefix_contract() {
        assert_eq!(
            policy_update_subject("acme"),
            "tenant-acme.clawdstrike.policy.update"
        );
    }

    #[test]
    fn policy_sync_bucket_matches_agent_contract() {
        assert_eq!(
            policy_sync_bucket("tenant-acme.clawdstrike", "agent-123"),
            "tenant-acme-clawdstrike-policy-sync-agent-123"
        );
    }

    #[test]
    fn policy_sync_key_is_stable() {
        assert_eq!(policy_sync_key(), "policy.yaml");
    }
}
