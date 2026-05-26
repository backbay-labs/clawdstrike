use super::*;

pub(crate) fn select_staged_detection_for_policy_delta(
    records: Vec<EdrStagedDetectionRecord>,
    staged_detection_id: Option<&str>,
    rule_id: Option<&str>,
    stage: Option<&str>,
) -> Result<EdrStagedDetectionRecord, (StatusCode, String)> {
    if staged_detection_id.is_none() && rule_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "stagedDetectionId or ruleId must be provided".to_string(),
        ));
    }
    records
        .into_iter()
        .rev()
        .find(|record| {
            staged_detection_id.map_or(true, |expected| record.staged_detection_id == expected)
                && rule_id.map_or(true, |expected| record.candidate.rule_id == expected)
                && stage.map_or(true, |expected| record.stage == expected)
        })
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "matching staged detection not found".to_string(),
            )
        })
}

pub(crate) fn staged_detection_stage_entry(
    record: &EdrStagedDetectionRecord,
) -> Result<&EdrDetectionCandidateStage, (StatusCode, String)> {
    record
        .stage_plan
        .iter()
        .find(|candidate| candidate.stage == record.stage)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "staged detection {} has unknown stage {}",
                    record.staged_detection_id, record.stage
                ),
            )
        })
}

// build_edr_policy_delta_artifact, build_edr_policy_delta_patch,
// policy_delta_stage_is_enforcing, policy_delta_enforcement_action_supported,
// validate_policy_delta_stage_action, conventional_policy_guard_patch, merge_json_values
// moved to crate::edr::policy_events

pub(crate) fn policy_delta_artifact_hash(artifact: &EdrPolicyDeltaArtifact) -> Result<String> {
    let value = serde_json::to_value(artifact)
        .with_context(|| format!("serialize policy delta {}", artifact.policy_delta_id))?;
    let canonical = canonicalize_json(&value)
        .with_context(|| format!("canonicalize policy delta {}", artifact.policy_delta_id))?;
    Ok(sha256(canonical.as_bytes()).to_hex_prefixed())
}

pub(crate) async fn verify_policy_delta_record_before_apply(
    state: &AgentApiState,
    record: &EdrPolicyDeltaRecord,
) -> Result<(), (StatusCode, String)> {
    if record.policy_delta_id != record.artifact.policy_delta_id {
        return Err((
            StatusCode::CONFLICT,
            "policy delta record id does not match artifact id".to_string(),
        ));
    }
    if record.rule_id != record.artifact.candidate.rule_id {
        return Err((
            StatusCode::CONFLICT,
            "policy delta record rule does not match artifact rule".to_string(),
        ));
    }
    if record.stage != record.artifact.rollout.stage
        || record.action != record.artifact.rollout.action
    {
        return Err((
            StatusCode::CONFLICT,
            "policy delta record rollout does not match artifact rollout".to_string(),
        ));
    }
    let computed_artifact_hash =
        policy_delta_artifact_hash(&record.artifact).map_err(internal_error)?;
    if computed_artifact_hash != record.artifact_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "policy delta artifact hash mismatch: expected {}, computed {}",
                record.artifact_hash, computed_artifact_hash
            ),
        ));
    }
    validate_policy_delta_artifact_materializes_required_guard(&record.artifact)?;

    let signer_public_key = {
        let ledger = state.edr_receipt_ledger.lock().await;
        ledger.signer_public_key.clone()
    };
    verify_endpoint_receipt_signature(
        &record.receipt,
        "policy delta generated receipt",
        signer_public_key.as_str(),
    )
    .map_err(|reason| {
        (
            StatusCode::CONFLICT,
            format!("policy delta generated receipt failed verification: {reason}"),
        )
    })?;

    if receipt_family(&record.receipt) != Some("policy_delta") {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt has wrong family".to_string(),
        ));
    }
    if !receipt_evidence_hash_matches(&record.receipt, "policyDeltaId", &record.policy_delta_id) {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt does not bind policy delta id".to_string(),
        ));
    }
    if !receipt_evidence_hash_matches(&record.receipt, "artifactHash", &record.artifact_hash) {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt does not bind artifact hash".to_string(),
        ));
    }
    if !receipt_evidence_hash_matches(
        &record.receipt,
        "stagedDetectionId",
        &record.artifact.staged_detection_id,
    ) {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt does not bind staged detection id".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn policy_delta_source_context_evidence_value<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| "null".to_string())
}

pub(crate) fn apply_policy_delta_patch_to_policy(
    current_bytes: &[u8],
    patch: &Value,
) -> Result<Vec<u8>> {
    let current_yaml: serde_yaml::Value =
        serde_yaml::from_slice(current_bytes).context("parse current policy yaml")?;
    let mut current_json =
        serde_json::to_value(current_yaml).context("convert current policy yaml to json value")?;
    merge_policy_patch_values(&mut current_json, patch.clone());
    let merged_yaml: serde_yaml::Value =
        serde_json::from_value(current_json).context("convert merged policy to yaml value")?;
    let mut rendered =
        serde_yaml::to_string(&merged_yaml).context("serialize merged policy yaml")?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered.into_bytes())
}

fn merge_policy_patch_values(target: &mut Value, source: Value) {
    match (target, source) {
        (Value::Object(target_obj), Value::Object(source_obj)) => {
            for (key, value) in source_obj {
                if let Some(existing) = target_obj.get_mut(&key) {
                    merge_policy_patch_values(existing, value);
                } else {
                    target_obj.insert(key, value);
                }
            }
        }
        (Value::Array(target_items), Value::Array(source_items)) => {
            for value in source_items {
                if !target_items.iter().any(|existing| existing == &value) {
                    target_items.push(value);
                }
            }
        }
        (target_value, source_value) => {
            *target_value = source_value;
        }
    }
}

pub(crate) fn policy_delta_backup_path(
    policy_path: &FsPath,
    policy_delta_id: &str,
    applied_at: chrono::DateTime<chrono::Utc>,
) -> PathBuf {
    let parent = policy_path.parent().unwrap_or_else(|| FsPath::new("."));
    let file_name = policy_path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "policy.yaml".to_string());
    let id_fragment = policy_delta_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(40)
        .collect::<String>();
    let timestamp = applied_at.format("%Y%m%dT%H%M%SZ");
    parent.join(format!(
        "{file_name}.policy-delta-{id_fragment}-{timestamp}.bak"
    ))
}
