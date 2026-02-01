//! Policy management endpoints

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use hushclaw::Policy;

use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub policy_hash: String,
    pub yaml: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    /// YAML policy content
    pub yaml: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePolicyResponse {
    pub success: bool,
    pub message: String,
}

/// GET /api/v1/policy
pub async fn get_policy(
    State(state): State<AppState>,
) -> Result<Json<PolicyResponse>, (StatusCode, String)> {
    let engine = state.engine.read().await;

    // We need to access the policy - let's get the hash first
    let policy_hash = engine
        .policy_hash()
        .map(|h| h.to_hex())
        .unwrap_or_else(|_| "unknown".to_string());

    // Get the ruleset name from config
    let ruleset = hushclaw::RuleSet::by_name(&state.config.ruleset)
        .unwrap_or_else(hushclaw::RuleSet::default_ruleset);

    let yaml = ruleset
        .policy
        .to_yaml()
        .unwrap_or_else(|_| "# Unable to serialize policy".to_string());

    Ok(Json(PolicyResponse {
        name: ruleset.name,
        version: ruleset.policy.version,
        description: ruleset.description,
        policy_hash,
        yaml,
    }))
}

/// PUT /api/v1/policy
pub async fn update_policy(
    State(state): State<AppState>,
    Json(request): Json<UpdatePolicyRequest>,
) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    // Parse the new policy
    let policy = Policy::from_yaml(&request.yaml)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid policy YAML: {}", e)))?;

    // Update the engine
    let mut engine = state.engine.write().await;
    *engine = hushclaw::HushEngine::with_policy(policy).with_generated_keypair();

    tracing::info!("Policy updated via API");

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy updated successfully".to_string(),
    }))
}

/// POST /api/v1/policy/reload
pub async fn reload_policy(
    State(state): State<AppState>,
) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    state
        .reload_policy()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy reloaded from file".to_string(),
    }))
}
