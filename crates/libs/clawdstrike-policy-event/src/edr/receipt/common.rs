use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Context, Result};
use hush_core::{sha256, Hash};

use super::super::stable_id;
use super::{EndpointEvidenceRedactionClass, EndpointGraphReference, EndpointReceiptEvidence};

pub(crate) fn require_field_eq(actual: &str, expected: &str, field_name: &str) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    Err(anyhow!(
        "{field_name} must be {expected}, got {}",
        if actual.is_empty() {
            "<missing>"
        } else {
            actual
        }
    ))
}

pub(crate) fn require_nonempty(value: &str, field_name: &str) -> Result<()> {
    if !value.trim().is_empty() {
        return Ok(());
    }
    Err(anyhow!("{field_name} is required"))
}

pub(crate) fn require_optional_nonempty(value: Option<&str>, field_name: &str) -> Result<()> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(_) => Ok(()),
        None => Err(anyhow!("{field_name} is required")),
    }
}

pub(crate) fn require_nonzero(value: u64, field_name: &str) -> Result<()> {
    if value > 0 {
        return Ok(());
    }
    Err(anyhow!("{field_name} is required"))
}

pub(crate) fn require_confidence(value: Option<f32>, field_name: &str) -> Result<()> {
    match value {
        Some(value) if value.is_finite() && (0.0..=1.0).contains(&value) => Ok(()),
        Some(_) => Err(anyhow!("{field_name} must be between 0.0 and 1.0")),
        None => Err(anyhow!("{field_name} is required")),
    }
}

pub(crate) fn require_receipt_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    if evidence.is_empty() {
        return Err(anyhow!("endpoint receipt evidence is required"));
    }
    let mut evidence_keys = BTreeSet::new();
    for item in evidence {
        require_nonempty(item.key.as_str(), "endpoint receipt evidence key")?;
        let evidence_key = item.key.trim();
        if !evidence_keys.insert(evidence_key) {
            return Err(anyhow!(
                "duplicate evidence key {evidence_key} in endpoint receipt"
            ));
        }
        require_nonempty(
            item.value_hash.as_str(),
            "endpoint receipt evidence value hash",
        )?;
        Hash::from_hex(item.value_hash.as_str())
            .with_context(|| "endpoint receipt evidence value hash must be a 32-byte hex hash")?;
        if let Some(raw_value) = item.raw_value.as_deref() {
            if item.redaction_class != EndpointEvidenceRedactionClass::RawArtifactPermitted {
                return Err(anyhow!(
                    "endpoint receipt raw evidence requires raw artifact permitted redaction"
                ));
            }
            require_nonempty(raw_value, "endpoint receipt evidence raw value")?;
            let raw_value_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
            if item.value_hash != raw_value_hash {
                return Err(anyhow!(
                    "endpoint receipt raw evidence hash does not match raw evidence value"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn require_evidence_value_hash(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    expected_value: impl AsRef<str>,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    let expected_hash = sha256(expected_value.as_ref().as_bytes()).to_hex_prefixed();
    if item.value_hash != expected_hash {
        return Err(anyhow!("{field_name} hash must match signed receipt field"));
    }
    Ok(())
}

pub(crate) fn require_subgraph_reference(
    graph: &EndpointGraphReference,
    label: &str,
) -> Result<()> {
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph root reference is required"))?;
    if !graph.node_ids.iter().any(|node_id| node_id == root_node_id) {
        return Err(anyhow!(
            "{label} graph root reference must be included in graph node ids"
        ));
    }

    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph slice reference is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph content hash is required"))?;
    let expected_graph_slice_id = stable_id("graph_slice", [root_node_id, graph_content_hash]);
    if graph_slice_id != expected_graph_slice_id {
        return Err(anyhow!(
            "{label} graph slice reference must match root and graph content hash"
        ));
    }
    Ok(())
}

pub(crate) fn require_nonempty_hashed_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)
}

pub(crate) fn evidence_value_hash<'a>(
    evidence: &'a [EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<&'a str> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    Ok(item.value_hash.as_str())
}

pub(crate) fn require_boolean_hashed_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    let true_hash = sha256(b"true").to_hex_prefixed();
    let false_hash = sha256(b"false").to_hex_prefixed();
    if !hex_strings_match(true_hash.as_str(), item.value_hash.as_str())
        && !hex_strings_match(false_hash.as_str(), item.value_hash.as_str())
    {
        return Err(anyhow!("{field_name} must be boolean"));
    }
    Ok(())
}

pub(crate) fn require_evidence_hash_not_empty(
    item: &EndpointReceiptEvidence,
    field_name: &str,
) -> Result<()> {
    let empty_value_hash = sha256(b"").to_hex_prefixed();
    if hex_strings_match(empty_value_hash.as_str(), item.value_hash.as_str()) {
        return Err(anyhow!("{field_name} must not be empty"));
    }
    Ok(())
}

pub(crate) fn hex_strings_match(expected: &str, actual: &str) -> bool {
    trim_hex_prefix(expected).eq_ignore_ascii_case(trim_hex_prefix(actual))
}

pub(crate) fn trim_hex_prefix(value: &str) -> &str {
    value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or_else(|| value.trim())
}

pub(crate) fn camel_debug_to_snake(value: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

pub(crate) fn reconstruct_path(
    from: &str,
    to: &str,
    previous: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut path = vec![to.to_string()];
    let mut cursor = to;
    while let Some(prev) = previous.get(cursor) {
        path.push(prev.clone());
        if prev == from {
            break;
        }
        cursor = prev;
    }
    path.reverse();
    path
}
