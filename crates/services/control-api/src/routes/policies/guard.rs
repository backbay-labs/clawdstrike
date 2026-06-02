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

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_deploy_request(break_glass: bool, reason: Option<&str>) -> DeployPolicyRequest {
        DeployPolicyRequest {
            policy_yaml: "version: \"1.0.0\"\nrules: []\n".to_string(),
            description: None,
            break_glass,
            break_glass_reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn direct_policy_deploy_requires_break_glass_flag() {
        let req = direct_deploy_request(false, Some("emergency recovery"));

        match require_direct_policy_deploy_break_glass(&req) {
            Err(ApiError::Conflict(message)) => {
                assert!(message.contains("proposal simulation receipts"));
            }
            Ok(_) => panic!("direct deploy without break_glass unexpectedly succeeded"),
            Err(err) => panic!("unexpected direct deploy error: {err}"),
        }
    }

    #[test]
    fn direct_policy_deploy_requires_break_glass_reason() {
        let req = direct_deploy_request(true, Some("   "));

        match require_direct_policy_deploy_break_glass(&req) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("break_glass_reason"));
            }
            Ok(_) => panic!("direct deploy without reason unexpectedly succeeded"),
            Err(err) => panic!("unexpected direct deploy error: {err}"),
        }
    }

    #[test]
    fn direct_policy_deploy_accepts_explicit_break_glass_reason() {
        let req = direct_deploy_request(true, Some("  emergency recovery  "));

        match require_direct_policy_deploy_break_glass(&req) {
            Ok(reason) => assert_eq!(reason, "emergency recovery"),
            Err(err) => panic!("direct deploy break-glass rejected valid reason: {err}"),
        }
    }
}
