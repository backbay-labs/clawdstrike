//! Shared helpers for decision metadata parsing across converters.

use clawdstrike_ocsf::decision as ocsf_decision;

/// Extract the `allowed` flag from a decision object.
pub(crate) fn decision_allowed(
    decision_obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<bool> {
    ocsf_decision::decision_object_allowed(decision_obj)
}

/// Determine whether a structured decision object should be treated as a warning.
pub(crate) fn decision_object_is_warn(
    decision_obj: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    ocsf_decision::decision_object_is_warn(decision_obj)
}

/// Extract a severity string from either a plain string or a nested object.
pub(crate) fn severity_from_value(value: &serde_json::Value) -> Option<String> {
    ocsf_decision::severity_from_value(value)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decision_field_warn_string_is_treated_as_warn() {
        let decision_obj = serde_json::Map::from_iter([("decision".to_string(), json!("warn"))]);

        assert!(decision_object_is_warn(&decision_obj));
    }

    #[test]
    fn decision_allowed_aliases_are_supported() {
        let passed = serde_json::Map::from_iter([("passed".to_string(), json!(false))]);
        assert_eq!(decision_allowed(&passed), Some(false));

        let denied = serde_json::Map::from_iter([("denied".to_string(), json!(true))]);
        assert_eq!(decision_allowed(&denied), Some(false));

        let blocked = serde_json::Map::from_iter([("blocked".to_string(), json!(false))]);
        assert_eq!(decision_allowed(&blocked), Some(true));
    }
}
