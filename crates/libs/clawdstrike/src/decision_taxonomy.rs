//! Shared decision taxonomy helpers for policy-eval surfaces.

use crate::{GuardResult, Severity};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalDecisionSummary {
    pub denied: bool,
    pub warn: bool,
    pub reason_code: String,
    pub severity: Option<String>,
}

pub fn canonical_severity_for_decision(result: &GuardResult) -> Option<String> {
    if result.allowed && result.severity == Severity::Info {
        return None;
    }

    Some(
        match result.severity {
            Severity::Info => "low",
            Severity::Warning => "medium",
            Severity::Error => "high",
            Severity::Critical => "critical",
        }
        .to_string(),
    )
}

pub fn normalize_reason_code(reason: &str) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(trimmed.len() + 4);
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_uppercase());
        } else {
            normalized.push('_');
        }
    }
    let normalized = normalized.trim_matches('_').to_string();
    if normalized.is_empty() {
        return None;
    }

    if normalized.starts_with("ADC_")
        || normalized.starts_with("HSH_")
        || normalized.starts_with("OCLAW_")
        || normalized.starts_with("PRV_")
    {
        return Some(normalized);
    }

    Some(format!("HSH_{normalized}"))
}

pub fn canonical_reason_code_for_decision(
    overall: &GuardResult,
    reason_override: Option<&str>,
) -> String {
    // Outcome taxonomy stays authoritative for deny/warn so mapper hints
    // cannot mask policy outcomes in downstream analytics.
    if !overall.allowed {
        return "ADC_POLICY_DENY".to_string();
    }

    if overall.severity == Severity::Warning {
        return "ADC_POLICY_WARN".to_string();
    }

    if let Some(code) = reason_override.and_then(normalize_reason_code) {
        return code;
    }

    "ADC_POLICY_ALLOW".to_string()
}

pub fn summarize_decision(
    overall: &GuardResult,
    reason_override: Option<&str>,
) -> CanonicalDecisionSummary {
    CanonicalDecisionSummary {
        denied: !overall.allowed,
        warn: overall.allowed && overall.severity == Severity::Warning,
        reason_code: canonical_reason_code_for_decision(overall, reason_override),
        severity: canonical_severity_for_decision(overall),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_reason_code_prefixes_hsh_for_free_form_values() {
        assert_eq!(
            normalize_reason_code("engine error"),
            Some("HSH_ENGINE_ERROR".to_string())
        );
    }

    #[test]
    fn normalize_reason_code_preserves_known_prefixes() {
        assert_eq!(
            normalize_reason_code("adc_policy_warn"),
            Some("ADC_POLICY_WARN".to_string())
        );
        assert_eq!(
            normalize_reason_code("hsh_nonce_stale"),
            Some("HSH_NONCE_STALE".to_string())
        );
    }

    #[test]
    fn canonical_reason_code_preserves_deny_taxonomy_over_override() {
        let overall = GuardResult::block(
            "forbidden_path",
            Severity::Critical,
            "Access to forbidden path: /etc/sudoers",
        );
        assert_eq!(
            canonical_reason_code_for_decision(&overall, Some("missing_content_bytes")),
            "ADC_POLICY_DENY"
        );
    }

    #[test]
    fn canonical_reason_code_preserves_warn_taxonomy_over_override() {
        let overall = GuardResult::warn("secret_leak", "Potential secret detected");
        assert_eq!(
            canonical_reason_code_for_decision(&overall, Some("missing_content_bytes")),
            "ADC_POLICY_WARN"
        );
    }

    #[test]
    fn canonical_reason_code_uses_override_for_allow_outcome() {
        let overall = GuardResult::allow("forbidden_path");
        assert_eq!(
            canonical_reason_code_for_decision(&overall, Some("missing_content_bytes")),
            "HSH_MISSING_CONTENT_BYTES"
        );
    }
}
