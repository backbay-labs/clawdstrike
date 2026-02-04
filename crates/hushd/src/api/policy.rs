//! Policy management endpoints

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::{HushEngine, Policy};
use hush_core::Keypair;

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

    let policy = engine.policy();
    let policy_hash = engine
        .policy_hash()
        .map(|h| h.to_hex())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let yaml = engine
        .policy_yaml()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let name = if policy.name.is_empty() {
        state.config.ruleset.clone()
    } else {
        policy.name.clone()
    };

    let description = policy.description.clone();

    Ok(Json(PolicyResponse {
        name,
        version: policy.version.clone(),
        description,
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
    let policy = Policy::from_yaml_with_extends(&request.yaml, state.config.policy_path.as_deref())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid policy YAML: {}", e),
            )
        })?;

    // Update the engine
    let mut engine = state.engine.write().await;
    let keypair = if let Some(ref key_path) = state.config.signing_key {
        let key_hex = std::fs::read_to_string(key_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .trim()
            .to_string();
        Some(
            Keypair::from_hex(&key_hex)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        )
    } else {
        engine.keypair().cloned()
    };

    let mut new_engine = HushEngine::with_policy(policy);
    new_engine = match keypair {
        Some(keypair) => new_engine.with_keypair(keypair),
        None => new_engine.with_generated_keypair(),
    };
    *engine = new_engine;

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
