//! Policy management endpoints

use axum::{extract::State, http::StatusCode, Json};

use crate::api::v1::V1Error;
use serde::{Deserialize, Serialize};

use clawdstrike::error::{Error as PolicyError, PolicyValidationError};
use clawdstrike::{HushEngine, Policy, PolicyBundle, SignedPolicyBundle};
use hush_core::canonical::canonicalize;
use hush_core::{sha256, Keypair};

use crate::audit::AuditEvent;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::remote_extends::{RemoteExtendsResolverConfig, RemotePolicyResolver};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub policy_hash: String,
    pub yaml: String,
    pub source: PolicySource,
    pub schema: PolicySchemaInfo,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySource {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_exists: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySchemaInfo {
    pub current: String,
    pub supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ValidatePolicyRequest {
    pub yaml: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub path: String,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatePolicyResponse {
    pub valid: bool,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_version: Option<String>,
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

fn policy_source_from_state(state: &AppState) -> PolicySource {
    if let Some(path) = state.config.policy_path.as_ref() {
        return PolicySource {
            kind: "file".to_string(),
            path: Some(path.display().to_string()),
            path_exists: Some(path.exists()),
        };
    }

    PolicySource {
        kind: format!("ruleset:{}", state.config.ruleset),
        path: None,
        path_exists: None,
    }
}

fn policy_schema_info() -> PolicySchemaInfo {
    PolicySchemaInfo {
        current: clawdstrike::policy::POLICY_SCHEMA_VERSION.to_string(),
        supported: clawdstrike::policy::POLICY_SUPPORTED_SCHEMA_VERSIONS
            .iter()
            .map(|v| v.to_string())
            .collect(),
    }
}

fn validation_issues_from_policy_error(err: &PolicyError) -> Vec<ValidationIssue> {
    match err {
        PolicyError::PolicyValidation(PolicyValidationError { errors }) => errors
            .iter()
            .map(|e| ValidationIssue {
                path: e.path.clone(),
                code: "validation_error".to_string(),
                message: e.message.clone(),
            })
            .collect(),
        PolicyError::UnsupportedPolicyVersion { found, supported } => vec![ValidationIssue {
            path: "version".to_string(),
            code: "policy_schema_unsupported".to_string(),
            message: format!("unsupported policy version: {found} (supported: {supported})"),
        }],
        PolicyError::InvalidPolicyVersion { version } => vec![ValidationIssue {
            path: "version".to_string(),
            code: "policy_schema_invalid".to_string(),
            message: format!("invalid policy version: {version}"),
        }],
        PolicyError::YamlError(err) => vec![ValidationIssue {
            path: "yaml".to_string(),
            code: "policy_yaml_invalid".to_string(),
            message: err.to_string(),
        }],
        PolicyError::ConfigError(message) => {
            let code = if message.contains("file not found") || message.contains("No such file") {
                "policy_path_missing"
            } else {
                "policy_config_invalid"
            };
            vec![ValidationIssue {
                path: "policy".to_string(),
                code: code.to_string(),
                message: message.clone(),
            }]
        }
        other => vec![ValidationIssue {
            path: "policy".to_string(),
            code: "policy_validation_failed".to_string(),
            message: other.to_string(),
        }],
    }
}

/// GET /api/v1/policy/bundle
pub async fn get_policy_bundle(
    State(state): State<AppState>,
) -> Result<Json<SignedPolicyBundle>, V1Error> {
    let engine = state.engine.read().await;
    let policy = engine.policy().clone();

    let mut sources = Vec::new();
    if let Some(path) = state.config.policy_path.as_ref() {
        sources.push(format!("file:{}", path.display()));
    } else {
        sources.push(format!("ruleset:{}", state.config.ruleset.clone()));
    }

    let mut bundle = PolicyBundle::new_with_sources(policy, sources)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    bundle.metadata = Some(serde_json::json!({
        "daemon": {
            "session_id": state.session_id.clone(),
            "started_at": state.started_at.to_rfc3339(),
        }
    }));

    let keypair = engine.keypair().cloned().ok_or_else(|| {
        V1Error::internal(
            "SIGNING_KEY_NOT_CONFIGURED",
            "Daemon signing key is not configured",
        )
    })?;

    let signed = SignedPolicyBundle::sign_with_public_key(bundle, &keypair)
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;

    Ok(Json(signed))
}

/// PUT /api/v1/policy/bundle
pub async fn update_policy_bundle(
    State(state): State<AppState>,
    Json(signed): Json<SignedPolicyBundle>,
) -> Result<Json<UpdatePolicyResponse>, V1Error> {
    // Verify signature before accepting the policy.
    let trusted = &state.policy_bundle_trusted_keys;
    let verified = if trusted.is_empty() {
        signed.verify_embedded().map_err(|e| {
            V1Error::bad_request(
                "BUNDLE_VERIFICATION_FAILED",
                format!("Policy bundle verification failed: {}", e),
            )
        })?
    } else {
        let mut ok = false;
        for pk in trusted.iter() {
            if signed.verify(pk).map_err(|e| {
                V1Error::bad_request(
                    "BUNDLE_VERIFICATION_FAILED",
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
        return Err(V1Error::forbidden(
            "INVALID_BUNDLE_SIGNATURE",
            "Invalid policy bundle signature",
        ));
    }

    // Validate policy.
    signed
        .bundle
        .policy
        .validate()
        .map_err(|e| V1Error::bad_request("INVALID_POLICY", format!("Invalid policy: {}", e)))?;

    // Ensure policy_hash is correctly derived from the policy itself.
    //
    // The bundle is signed, but we still treat policy_hash as a derived field (it must not be
    // allowed to lie).
    let computed_policy_hash = {
        let value = serde_json::to_value(&signed.bundle.policy).map_err(|e| {
            V1Error::bad_request("INVALID_POLICY", format!("Invalid policy: {}", e))
        })?;
        let canonical = canonicalize(&value).map_err(|e| {
            V1Error::bad_request("INVALID_POLICY", format!("Invalid policy: {}", e))
        })?;
        sha256(canonical.as_bytes())
    };
    if computed_policy_hash != signed.bundle.policy_hash {
        return Err(V1Error::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "POLICY_HASH_MISMATCH",
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
            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
            .trim()
            .to_string();
        Some(
            Keypair::from_hex(&key_hex)
                .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?,
        )
    } else {
        engine.keypair().cloned()
    };

    // Fail closed if custom guards are requested but unavailable.
    let mut new_engine = HushEngine::builder(signed.bundle.policy.clone())
        .build()
        .map_err(|e| V1Error::bad_request("INVALID_POLICY", e.to_string()))?;
    new_engine = match keypair {
        Some(keypair) => new_engine.with_keypair(keypair),
        None => new_engine.with_generated_keypair(),
    };
    let active_policy_hash = new_engine
        .policy_hash()
        .map(|h| h.to_hex())
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    *engine = new_engine;
    state.policy_engine_cache.clear();
    drop(engine);

    tracing::info!(
        bundle_id = %signed.bundle.bundle_id,
        policy_hash = %active_policy_hash,
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
            "policy_hash": active_policy_hash.clone(),
            "bundle_policy_hash": signed.bundle.policy_hash.to_hex(),
            "sources": signed.bundle.sources,
        })),
    });

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy updated successfully".to_string(),
        policy_hash: Some(active_policy_hash),
    }))
}

/// GET /api/v1/policy
pub async fn get_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<PolicyResponse>, V1Error> {
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
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    let yaml = engine
        .policy_yaml()
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;

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
        source: policy_source_from_state(&state),
        schema: policy_schema_info(),
    }))
}

/// POST /api/v1/policy/validate
pub async fn validate_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<ValidatePolicyRequest>,
) -> Result<Json<ValidatePolicyResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Policy,
        Action::Update,
    )?;

    let resolver = RemotePolicyResolver::new(RemoteExtendsResolverConfig::from_config(
        &state.config.remote_extends,
    ))
    .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    let base_path = state.config.policy_path.as_deref();

    match Policy::from_yaml_with_extends_resolver(&request.yaml, base_path, &resolver) {
        Ok(policy) => {
            let normalized_version = policy.version.clone();
            if let Err(err) = HushEngine::builder(policy).build() {
                return Ok(Json(ValidatePolicyResponse {
                    valid: false,
                    errors: vec![ValidationIssue {
                        path: "policy".to_string(),
                        code: "policy_engine_invalid".to_string(),
                        message: err.to_string(),
                    }],
                    warnings: Vec::new(),
                    normalized_version: Some(normalized_version),
                }));
            }

            Ok(Json(ValidatePolicyResponse {
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
                normalized_version: Some(normalized_version),
            }))
        }
        Err(err) => Ok(Json(ValidatePolicyResponse {
            valid: false,
            errors: validation_issues_from_policy_error(&err),
            warnings: Vec::new(),
            normalized_version: None,
        })),
    }
}

/// PUT /api/v1/policy
pub async fn update_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<UpdatePolicyRequest>,
) -> Result<Json<UpdatePolicyResponse>, V1Error> {
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
            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
        let hash = engine
            .policy_hash()
            .map(|h| h.to_hex())
            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
        (yaml, hash)
    };

    // Parse the new policy
    let resolver = RemotePolicyResolver::new(RemoteExtendsResolverConfig::from_config(
        &state.config.remote_extends,
    ))
    .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;

    let base_path = state.config.policy_path.as_deref();
    let policy = Policy::from_yaml_with_extends_resolver(&request.yaml, base_path, &resolver)
        .map_err(|e| {
            V1Error::bad_request("INVALID_POLICY_YAML", format!("Invalid policy YAML: {}", e))
        })?;

    // Update the engine
    let mut engine = state.engine.write().await;
    let keypair = if let Some(ref key_path) = state.config.signing_key {
        let key_hex = std::fs::read_to_string(key_path)
            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
            .trim()
            .to_string();
        Some(
            Keypair::from_hex(&key_hex)
                .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?,
        )
    } else {
        engine.keypair().cloned()
    };

    // Fail closed if custom guards are requested but unavailable.
    let mut new_engine = HushEngine::builder(policy)
        .build()
        .map_err(|e| V1Error::bad_request("INVALID_POLICY", e.to_string()))?;
    new_engine = match keypair {
        Some(keypair) => new_engine.with_keypair(keypair),
        None => new_engine.with_generated_keypair(),
    };
    let after_hash = new_engine
        .policy_hash()
        .map(|h| h.to_hex())
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;
    *engine = new_engine;
    state.policy_engine_cache.clear();

    tracing::info!("Policy updated via API");
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
    state.record_audit_event(audit);

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy updated successfully".to_string(),
        policy_hash: Some(after_hash),
    }))
}

/// POST /api/v1/policy/reload
pub async fn reload_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<UpdatePolicyResponse>, V1Error> {
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
            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
    };

    state
        .reload_policy()
        .await
        .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?;

    let after_hash = {
        let engine = state.engine.read().await;
        engine
            .policy_hash()
            .map(|h| h.to_hex())
            .map_err(|e| V1Error::internal("INTERNAL_ERROR", e.to_string()))?
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
    state.record_audit_event(audit);

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy reloaded from file".to_string(),
        policy_hash: Some(after_hash),
    }))
}
