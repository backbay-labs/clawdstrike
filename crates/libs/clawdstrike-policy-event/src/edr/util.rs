//! Shared ID, hash, and path utilities for the EDR module.
//!
//! `stable_id` is the one true shared seam: many sibling submodules derive
//! deterministic identifiers through it. These helpers are deliberately pure
//! and free of transport concerns.

#![allow(dead_code)]

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use hush_core::sha256;
use serde::Serialize;

use super::receipt::response_execution_effect_binding_digest_from_effects;
use super::EndpointResponseExecutionEffect;

pub(crate) const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
pub(crate) const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub(crate) fn normalize_path_string(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let is_absolute = replaced.starts_with('/');
    let normalized = replaced
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");

    if is_absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

pub(crate) fn normalize_hostname(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub(crate) fn hostname_from_url_like(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
        .rsplit('@')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    if authority.is_empty() {
        return None;
    }
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[..=end]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let normalized = normalize_hostname(host);
    (!normalized.is_empty()).then_some(normalized)
}

pub(crate) fn stable_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hash = FNV_OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{prefix}:{hash:016x}")
}

pub(crate) fn evidence_hash_for_value(value: impl AsRef<str>) -> String {
    sha256(value.as_ref().as_bytes()).to_hex_prefixed()
}

pub(crate) fn insert_json<T: Serialize>(
    map: &mut BTreeMap<String, serde_json::Value>,
    key: &str,
    value: T,
) {
    if let Ok(value) = serde_json::to_value(value) {
        if !value.is_null() {
            map.insert(key.to_string(), value);
        }
    }
}

pub(crate) fn telemetry_privacy_report_id_from_values(
    privacy_mode: &str,
    raw_artifact_upload_permitted: bool,
    raw_artifact_approval_id: Option<&str>,
    raw_artifact_approval_reason_hash: Option<&str>,
    projection_content_hash: &str,
    count_values: [&str; 7],
) -> String {
    let privacy_mode_hash = sha256(privacy_mode.as_bytes()).to_hex_prefixed();
    let raw_permitted = raw_artifact_upload_permitted.to_string();
    let raw_permitted_hash = sha256(raw_permitted.as_bytes()).to_hex_prefixed();
    let observation_count_hash = sha256(count_values[0].as_bytes()).to_hex_prefixed();
    let field_count_hash = sha256(count_values[1].as_bytes()).to_hex_prefixed();
    let hash_only_count_hash = sha256(count_values[2].as_bytes()).to_hex_prefixed();
    let metadata_only_count_hash = sha256(count_values[3].as_bytes()).to_hex_prefixed();
    let redacted_count_hash = sha256(count_values[4].as_bytes()).to_hex_prefixed();
    let raw_suppressed_count_hash = sha256(count_values[5].as_bytes()).to_hex_prefixed();
    let local_only_count_hash = sha256(count_values[6].as_bytes()).to_hex_prefixed();
    let projection_content_hash_hash = sha256(projection_content_hash.as_bytes()).to_hex_prefixed();
    let mut evidence_hashes = vec![
        privacy_mode_hash.as_str(),
        raw_permitted_hash.as_str(),
        projection_content_hash_hash.as_str(),
        observation_count_hash.as_str(),
        field_count_hash.as_str(),
        hash_only_count_hash.as_str(),
        metadata_only_count_hash.as_str(),
        redacted_count_hash.as_str(),
        raw_suppressed_count_hash.as_str(),
        local_only_count_hash.as_str(),
    ];
    let raw_artifact_approval_id_hash =
        raw_artifact_approval_id.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let raw_artifact_approval_reason_hash_hash =
        raw_artifact_approval_reason_hash.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let empty_hash = sha256(b"").to_hex_prefixed();
    if raw_artifact_upload_permitted {
        evidence_hashes.push(
            raw_artifact_approval_id_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
        evidence_hashes.push(
            raw_artifact_approval_reason_hash_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
    }
    telemetry_privacy_report_id_from_evidence_hashes(evidence_hashes)
}

pub(crate) fn telemetry_privacy_report_id_from_evidence_hashes<'a>(
    evidence_hashes: impl IntoIterator<Item = &'a str>,
) -> String {
    stable_id("telemetry_privacy_report", evidence_hashes)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseExecutionEffectBindingEntry {
    key: String,
    value_hash: String,
}

pub(crate) fn response_execution_id_from_effects(
    response_action_id: &str,
    evidence_bundle_id: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<String> {
    let effect_binding_digest = response_execution_effect_binding_digest_from_effects(effects)?
        .ok_or_else(|| anyhow!("response execution effect binding requires at least one effect"))?;
    Ok(response_execution_id_from_effect_digest(
        response_action_id,
        evidence_bundle_id,
        effect_binding_digest.as_str(),
    ))
}

pub(crate) fn response_execution_id_from_effect_digest(
    response_action_id: &str,
    evidence_bundle_id: &str,
    effect_binding_digest: &str,
) -> String {
    stable_id(
        "response_execution",
        [
            response_action_id,
            evidence_bundle_id,
            effect_binding_digest,
        ],
    )
}

pub(crate) fn response_execution_transition_id_from_reason_hash(
    prefix: &str,
    response_action_id: &str,
    evidence_bundle_id: &str,
    rollback_ref: &str,
    reason_hash: &str,
) -> String {
    stable_id(
        prefix,
        [
            response_action_id,
            evidence_bundle_id,
            rollback_ref,
            reason_hash,
        ],
    )
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
