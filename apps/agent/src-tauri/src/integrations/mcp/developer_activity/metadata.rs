//! Metadata helpers and activity identifiers for developer-activity records.

use crate::policy::PolicyCheckInput;
use hush_core::sha256;

pub(super) fn mcp_shell_activity_metadata(
    base_metadata: &serde_json::Value,
    input: &PolicyCheckInput,
    classifier: &str,
) -> serde_json::Value {
    let mut metadata = base_metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("mcp_policy_check".to_string()),
    );
    metadata.insert(
        "shellClassifier".to_string(),
        serde_json::Value::String(classifier.to_string()),
    );
    if let Some(content) = input
        .content
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        metadata.insert(
            "policyContent".to_string(),
            serde_json::Value::String(content.to_string()),
        );
    }
    serde_json::Value::Object(metadata)
}

pub(super) fn local_mcp_activity_id(
    prefix: &str,
    session_id: Option<&str>,
    agent_id: &str,
    target: &str,
) -> String {
    let material = format!(
        "{prefix}\0{}\0{agent_id}\0{target}",
        session_id.unwrap_or_default()
    );
    let digest = sha256(material.as_bytes()).to_hex_prefixed();
    let fragment = digest
        .trim_start_matches("0x")
        .chars()
        .take(32)
        .collect::<String>();
    format!("{prefix}-{fragment}")
}
