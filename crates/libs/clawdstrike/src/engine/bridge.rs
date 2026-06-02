//! Cross-Origin Bridge Helpers (Phase 1b)

use crate::origin::OriginContext;

/// Result of checking a bridge policy for a cross-origin transition.
pub(super) enum BridgeCheckResult {
    /// The transition is allowed.
    Allow,
    /// The transition requires approval (denied with Warning severity).
    RequireApproval,
    /// The transition is denied with the given reason.
    Deny(String),
}

/// Check the bridge policy on the **session's** enclave (source) to determine
/// whether bridging to the given target origin is allowed.
pub(super) fn check_bridge_policy(
    source_enclave: &crate::enclave::ResolvedEnclave,
    target_origin: &OriginContext,
) -> BridgeCheckResult {
    let Some(ref bridge) = source_enclave.bridge_policy else {
        return BridgeCheckResult::Deny("no bridge policy configured".to_string());
    };

    if !bridge.allow_cross_origin {
        return BridgeCheckResult::Deny("cross-origin transitions disabled".to_string());
    }

    // Check if target matches any allowed target.
    // An empty allowed_targets list means "all targets are allowed".
    let target_matches = bridge.allowed_targets.is_empty()
        || bridge.allowed_targets.iter().any(|t| {
            // Use to_string() comparison to match EnclaveResolver behavior
            // and avoid Custom("slack") != Slack inconsistency.
            let provider_ok = t
                .provider
                .as_ref()
                .is_none_or(|p| p.to_string() == target_origin.provider.to_string());
            let space_type_ok = t.space_type.as_ref().is_none_or(|st| {
                target_origin
                    .space_type
                    .as_ref()
                    .is_some_and(|tst| tst.to_string() == st.to_string())
            });
            let tags_ok =
                t.tags.is_empty() || t.tags.iter().all(|tag| target_origin.tags.contains(tag));
            let visibility_ok = t.visibility.as_ref().is_none_or(|v| {
                target_origin
                    .visibility
                    .as_ref()
                    .is_some_and(|tv| tv.to_string() == v.to_string())
            });
            provider_ok && space_type_ok && tags_ok && visibility_ok
        });

    if !target_matches {
        return BridgeCheckResult::Deny(
            "target origin does not match any allowed bridge target".to_string(),
        );
    }

    if bridge.require_approval {
        return BridgeCheckResult::RequireApproval;
    }

    BridgeCheckResult::Allow
}

/// Format an origin context briefly for error messages.
pub(super) fn format_origin_brief(origin: &OriginContext) -> String {
    let mut parts = vec![format!("provider={}", origin.provider)];
    if let Some(ref id) = origin.space_id {
        parts.push(format!("space_id={}", id));
    }
    parts.join(",")
}
