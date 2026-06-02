//! Authorization guards, break-glass enforcement, and impact-field validators.

use super::*;

pub(crate) fn ensure_policy_author(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub(crate) fn ensure_policy_deployer(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "admin" || auth.role == "owner" {
        return Ok(());
    }
    Err(ApiError::Forbidden)
}

pub(crate) fn require_direct_policy_deploy_break_glass(
    req: &DeployPolicyRequest,
) -> Result<&str, ApiError> {
    if !req.break_glass {
        return Err(ApiError::Conflict(
            "direct policy deployment bypasses proposal simulation receipts; use /api/v1/policies/proposals or set break_glass=true with break_glass_reason for emergency recovery"
                .to_string(),
        ));
    }
    req.break_glass_reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "break_glass_reason is required for direct policy deployment".to_string(),
            )
        })
}

pub(crate) fn append_policy_proposal_approval_note(
    existing: &serde_json::Value,
    actor_id: &str,
    note: Option<&str>,
) -> serde_json::Value {
    let mut notes = existing.as_object().cloned().unwrap_or_default();
    notes.insert(
        actor_id.to_string(),
        serde_json::json!({
            "note": note,
            "recordedAt": Utc::now().to_rfc3339(),
        }),
    );
    serde_json::Value::Object(notes)
}

pub(crate) fn require_non_empty_policy_impact_field(
    field: &str,
    value: String,
) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn validate_non_negative_policy_impact_count(
    field: &str,
    value: i64,
) -> Result<(), ApiError> {
    if value < 0 {
        return Err(ApiError::BadRequest(format!(
            "{field} must be greater than or equal to 0"
        )));
    }
    Ok(())
}

pub(crate) fn normalize_policy_impact_sha256(field: &str, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let digest = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be a SHA-256 hex digest"
        )));
    }
    Ok(digest.to_ascii_lowercase())
}

pub(crate) fn policy_preview_error(err: String) -> ApiError {
    if err.contains("invalid policy YAML") || err.contains("policy YAML root must be a mapping") {
        return ApiError::BadRequest(err);
    }
    if err.contains("unresolved policy_ref") {
        return ApiError::Conflict(err);
    }
    ApiError::Internal(err)
}
