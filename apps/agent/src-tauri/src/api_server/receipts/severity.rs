//! Severity label coercion from policy YAML strings to the
//! `DetectionSeverity` enum used by detection findings.

use super::super::*;

pub(crate) fn detection_severity_from_policy_label(
    value: Option<&str>,
) -> Option<DetectionSeverity> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "info" => Some(DetectionSeverity::Info),
        "low" => Some(DetectionSeverity::Low),
        "medium" => Some(DetectionSeverity::Medium),
        "high" => Some(DetectionSeverity::High),
        "critical" => Some(DetectionSeverity::Critical),
        _ => None,
    }
}
