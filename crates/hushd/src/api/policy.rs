//! Policy management endpoints

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::{HushEngine, Policy, PolicyBundle, SignedPolicyBundle};
use hush_core::canonical::canonicalize;
use hush_core::{sha256, Keypair};

use crate::audit::AuditEvent;
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

/// GET /api/v1/policy/bundle
pub async fn get_policy_bundle(
    State(state): State<AppState>,
) -> Result<Json<SignedPolicyBundle>, (StatusCode, String)> {
    let engine = state.engine.read().await;
    let policy = engine.policy().clone();

    let mut sources = Vec::new();
    if let Some(path) = state.config.policy_path.as_ref() {
        sources.push(format!("file:{}", path.display()));
    } else {
        sources.push(format!("ruleset:{}", state.config.ruleset.clone()));
    }

    let mut bundle = PolicyBundle::new_with_sources(policy, sources)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    bundle.metadata = Some(serde_json::json!({
        "daemon": {
            "session_id": state.session_id.clone(),
            "started_at": state.started_at.to_rfc3339(),
        }
    }));

    let keypair = engine.keypair().cloned().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Daemon signing key is not configured".to_string(),
        )
    })?;

    let signed = SignedPolicyBundle::sign_with_public_key(bundle, &keypair)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(signed))
}

/// PUT /api/v1/policy/bundle
pub async fn update_policy_bundle(
    State(state): State<AppState>,
    Json(signed): Json<SignedPolicyBundle>,
) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    // Verify signature before accepting the policy.
    let trusted = &state.policy_bundle_trusted_keys;
    let verified = if trusted.is_empty() {
        signed.verify_embedded().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Policy bundle verification failed: {}", e),
            )
        })?
    } else {
        let mut ok = false;
        for pk in trusted.iter() {
            if signed.verify(pk).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Policy bundle verification failed: {}", e),
                )
            })? {
                ok = true;
                break;
            }
        }
        ok
    };

    if !verified {
        return Err((
            StatusCode::FORBIDDEN,
            "Invalid policy bundle signature".to_string(),
        ));
    }

    // Validate policy.
    signed
        .bundle
        .policy
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid policy: {}", e)))?;

    // Ensure policy_hash is correctly derived from the policy itself.
    //
    // The bundle is signed, but we still treat policy_hash as a derived field (it must not be
    // allowed to lie).
    let computed_policy_hash = {
        let value = serde_json::to_value(&signed.bundle.policy)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid policy: {}", e)))?;
        let canonical = canonicalize(&value)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid policy: {}", e)))?;
        sha256(canonical.as_bytes())
    };
    if computed_policy_hash != signed.bundle.policy_hash {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "Policy bundle policy_hash mismatch (expected {}, got {})",
                computed_policy_hash.to_hex_prefixed(),
                signed.bundle.policy_hash.to_hex_prefixed(),
            ),
        ));
    }

    // Update the engine (preserve signing keypair so receipts remain verifiable).
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

    let mut new_engine = HushEngine::with_policy(signed.bundle.policy.clone());
    new_engine = match keypair {
        Some(keypair) => new_engine.with_keypair(keypair),
        None => new_engine.with_generated_keypair(),
    };
    *engine = new_engine;

    tracing::info!(
        bundle_id = %signed.bundle.bundle_id,
        policy_hash = %signed.bundle.policy_hash.to_hex_prefixed(),
        "Policy updated via signed bundle"
    );

    state.record_audit_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: "policy_bundle_update".to_string(),
        action_type: "policy".to_string(),
        target: None,
        decision: "allowed".to_string(),
        guard: None,
        severity: None,
        message: Some("Policy updated via signed bundle".to_string()),
        session_id: Some(state.session_id.clone()),
        agent_id: None,
        metadata: Some(serde_json::json!({
            "bundle_id": signed.bundle.bundle_id,
            "policy_hash": signed.bundle.policy_hash.to_hex_prefixed(),
            "sources": signed.bundle.sources,
        })),
    });

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy updated successfully".to_string(),
    }))
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
