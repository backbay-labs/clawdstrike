//! Policy management endpoints

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::{HushEngine, Policy};
use hush_core::Keypair;

use crate::audit::AuditEvent;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
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

fn actor_string(actor: Option<&AuthenticatedActor>) -> String {
    match actor {
        Some(AuthenticatedActor::ApiKey(key)) => format!("api_key:{}", key.id),
        Some(AuthenticatedActor::User(principal)) => {
            format!("user:{}:{}", principal.issuer, principal.id)
        }
        None => "system".to_string(),
    }
}

/// GET /api/v1/policy
pub async fn get_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<PolicyResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Policy,
        Action::Read,
    )?;

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
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<UpdatePolicyRequest>,
) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Policy,
        Action::Update,
    )?;

    let (before_yaml, before_hash) = {
        let engine = state.engine.read().await;
        let yaml = engine
            .policy_yaml()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let hash = engine
            .policy_hash()
            .map(|h| h.to_hex())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        (yaml, hash)
    };

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
    state.policy_engine_cache.clear();

    tracing::info!("Policy updated via API");

    let after_hash = hush_core::sha256(request.yaml.as_bytes()).to_hex();
    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "policy_updated".to_string();
    audit.action_type = "policy".to_string();
    audit.target = Some("default_policy".to_string());
    audit.message = Some("Default policy updated".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_string(actor.as_ref().map(|e| &e.0)),
        "before": { "policy_hash": before_hash, "yaml": before_yaml },
        "after": { "policy_hash": after_hash, "yaml": request.yaml },
    }));
    if let Err(err) = state.ledger.record(&audit) {
        tracing::warn!(error = %err, "Failed to record audit event");
    }

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy updated successfully".to_string(),
    }))
}

/// POST /api/v1/policy/reload
pub async fn reload_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Policy,
        Action::Update,
    )?;

    let before_hash = {
        let engine = state.engine.read().await;
        engine
            .policy_hash()
            .map(|h| h.to_hex())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    state
        .reload_policy()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let after_hash = {
        let engine = state.engine.read().await;
        engine
            .policy_hash()
            .map(|h| h.to_hex())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    let mut audit = AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "policy_reloaded".to_string();
    audit.action_type = "policy".to_string();
    audit.target = Some("default_policy".to_string());
    audit.message = Some("Default policy reloaded".to_string());
    audit.metadata = Some(serde_json::json!({
        "actor": actor_string(actor.as_ref().map(|e| &e.0)),
        "before_policy_hash": before_hash,
        "after_policy_hash": after_hash,
    }));
    if let Err(err) = state.ledger.record(&audit) {
        tracing::warn!(error = %err, "Failed to record audit event");
    }

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy reloaded from file".to_string(),
    }))
}
