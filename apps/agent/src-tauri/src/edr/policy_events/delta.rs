//! Pure helpers for EDR policy delta artifact construction and patch generation.

use crate::edr::dto::{
    EdrDetectionCandidateStage, EdrPolicyDeltaArtifact, EdrPolicyDeltaRollout,
    EdrPolicyDeltaTargetPolicy, EdrStagedDetectionRecord,
};
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{CausalNodeKind, EndpointDecisionAction};
use serde_json::Value;

pub(crate) fn build_edr_policy_delta_artifact(
    staged: &EdrStagedDetectionRecord,
    stage_entry: &EdrDetectionCandidateStage,
    policy_delta_id: String,
    generated_at: chrono::DateTime<chrono::Utc>,
    generated_by: &str,
    note: Option<String>,
) -> Result<EdrPolicyDeltaArtifact, (StatusCode, String)> {
    validate_policy_delta_stage_action(staged.stage.as_str(), &stage_entry.action)?;
    let target_policy_epoch = staged.policy.policy_epoch.saturating_add(1).max(1);
    let target_policy = EdrPolicyDeltaTargetPolicy {
        base_policy_version: staged.policy.policy_version.clone(),
        base_policy_hash: staged.policy.policy_hash.clone(),
        base_policy_epoch: staged.policy.policy_epoch,
        target_policy_epoch,
    };
    let rollout = EdrPolicyDeltaRollout {
        stage: staged.stage.clone(),
        action: stage_entry.action.clone(),
        recommended_stage: staged.recommended_stage.clone(),
        promotion_gate: stage_entry.promotion_gate.clone(),
        cross_window_impact_hash: staged.cross_window_impact_hash.clone(),
        cross_window_recommendation_hash: staged.cross_window_recommendation_hash.clone(),
        developer_breakage_score: staged.simulation.developer_breakage_score,
        impact_level: staged.simulation.impact_level.as_str().to_string(),
        would_block: staged.simulation.would_block,
    };
    let source_simulation_receipt_id = staged.simulation_receipt.receipt.receipt_id.clone();
    let policy_patch =
        build_edr_policy_delta_patch(staged, stage_entry, &target_policy, generated_at)?;

    Ok(EdrPolicyDeltaArtifact {
        schema_version: crate::api_server::EDR_POLICY_DELTA_SCHEMA_VERSION.to_string(),
        policy_delta_id,
        generated_at,
        generated_by: generated_by.to_string(),
        note,
        staged_detection_id: staged.staged_detection_id.clone(),
        source_simulation_id: staged.simulation.simulation_id.clone(),
        source_simulation_receipt_id,
        source_affected_identities: staged.simulation.affected_identities.clone(),
        source_affected_tools: staged.simulation.affected_tools.clone(),
        candidate: staged.candidate.clone(),
        target_policy,
        rollout,
        policy_patch,
    })
}

pub(crate) fn build_edr_policy_delta_patch(
    staged: &EdrStagedDetectionRecord,
    stage_entry: &EdrDetectionCandidateStage,
    target_policy: &EdrPolicyDeltaTargetPolicy,
    generated_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, (StatusCode, String)> {
    let mut overlay = serde_json::json!({
        "version": staged.policy.policy_version,
        "policy_epoch": target_policy.target_policy_epoch,
        "merge_strategy": "deep_merge",
        "endpoint_decision_engine": {
            "generated_rules": [{
                "id": staged.candidate.rule_id,
                "stage": staged.stage,
                "action": stage_entry.action.as_str(),
                "description": staged.candidate.description,
                "generated_at": generated_at.to_rfc3339(),
                "staged_detection_id": staged.staged_detection_id,
                "simulation_id": staged.simulation.simulation_id,
                "graph_slice_id": staged.candidate.graph_slice_id,
                "root": {
                    "node_id": staged.candidate.root_node_id,
                    "kind": crate::api_server::causal_node_kind_name(&staged.candidate.root_kind),
                    "label": staged.candidate.root_label,
                },
                "impact": {
                    "developer_breakage_score": staged.simulation.developer_breakage_score,
                    "impact_level": staged.simulation.impact_level.as_str(),
                    "affected_node_count": staged.simulation.affected_node_count,
                    "affected_process_count": staged.simulation.affected_process_count,
                    "affected_file_count": staged.simulation.affected_file_count,
                    "affected_network_count": staged.simulation.affected_network_count,
                    "affected_credential_count": staged.simulation.affected_credential_count,
                    "affected_tool_count": staged.simulation.affected_tool_count,
                    "affected_identity_context": staged.simulation.affected_identities,
                    "affected_tool_context": staged.simulation.affected_tools,
                }
            }]
        }
    });

    if policy_delta_stage_is_enforcing(&staged.stage, &stage_entry.action) {
        let guard_patch =
            conventional_policy_guard_patch(staged, &stage_entry.action).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "{} cannot be promoted to {} for {} roots because this policy delta would not materialize a concrete local guard",
                        stage_entry.action.as_str(),
                        staged.stage,
                        crate::api_server::causal_node_kind_name(&staged.candidate.root_kind)
                    ),
                )
            })?;
        merge_json_values(&mut overlay, guard_patch);
    }
    if let Some(rule) = overlay
        .get_mut("endpoint_decision_engine")
        .and_then(|engine| engine.get_mut("generated_rules"))
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|rules| rules.first_mut())
    {
        if let Some(hash) = staged.cross_window_impact_hash.as_deref() {
            rule["cross_window_impact_hash"] = serde_json::Value::String(hash.to_string());
        }
        if let Some(hash) = staged.cross_window_recommendation_hash.as_deref() {
            rule["cross_window_recommendation_hash"] = serde_json::Value::String(hash.to_string());
        }
    }

    Ok(overlay)
}

pub(crate) fn policy_delta_stage_is_enforcing(
    stage: &str,
    action: &EndpointDecisionAction,
) -> bool {
    matches!(stage, "limited_block" | "full_block")
        && policy_delta_enforcement_action_supported(action)
}

pub(crate) fn policy_delta_enforcement_action_supported(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

pub(crate) fn policy_delta_stage_materializes_guard(
    root_kind: &CausalNodeKind,
    action: &EndpointDecisionAction,
) -> bool {
    matches!(
        (root_kind, action),
        (
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress | EndpointDecisionAction::Block
        ) | (
            CausalNodeKind::File | CausalNodeKind::Credential,
            EndpointDecisionAction::QuarantineFile | EndpointDecisionAction::Block
        )
    )
}

pub(crate) fn validate_policy_delta_artifact_materializes_required_guard(
    artifact: &EdrPolicyDeltaArtifact,
) -> Result<(), (StatusCode, String)> {
    if !policy_delta_stage_is_enforcing(&artifact.rollout.stage, &artifact.rollout.action) {
        return Ok(());
    }

    let root_label = artifact.candidate.root_label.trim();
    if root_label.is_empty() {
        return Err((
            StatusCode::CONFLICT,
            "enforcing policy delta artifact has an empty root label and cannot materialize a concrete local guard"
                .to_string(),
        ));
    }

    let guard_path = match (&artifact.candidate.root_kind, &artifact.rollout.action) {
        (
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress | EndpointDecisionAction::Block,
        ) => "/guards/egress_allowlist/block",
        (
            CausalNodeKind::File | CausalNodeKind::Credential,
            EndpointDecisionAction::QuarantineFile | EndpointDecisionAction::Block,
        ) => "/guards/forbidden_path/patterns",
        _ => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "enforcing policy delta artifact for {} on {} roots does not materialize a concrete local guard",
                    artifact.rollout.action.as_str(),
                    crate::api_server::causal_node_kind_name(&artifact.candidate.root_kind)
                ),
            ));
        }
    };

    let Some(guard_values) = artifact
        .policy_patch
        .pointer(guard_path)
        .and_then(serde_json::Value::as_array)
    else {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "enforcing policy delta artifact is missing required guard patch at {guard_path}"
            ),
        ));
    };

    if guard_values
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|value| value.trim() == root_label)
    {
        return Ok(());
    }

    Err((
        StatusCode::CONFLICT,
        format!(
            "enforcing policy delta artifact guard patch at {guard_path} does not bind root label {root_label}"
        ),
    ))
}

pub(crate) fn validate_policy_delta_stage_action(
    stage: &str,
    action: &EndpointDecisionAction,
) -> Result<(), (StatusCode, String)> {
    if matches!(stage, "limited_block" | "full_block")
        && !policy_delta_enforcement_action_supported(action)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{} can be simulated or dry-run only; policy deltas cannot promote it to {stage} because enforcement stages require rollback-capable policy actions",
                action.as_str()
            ),
        ));
    }
    Ok(())
}

pub(crate) fn conventional_policy_guard_patch(
    staged: &EdrStagedDetectionRecord,
    action: &EndpointDecisionAction,
) -> Option<Value> {
    match (&staged.candidate.root_kind, action) {
        (
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress | EndpointDecisionAction::Block,
        ) => {
            let target = staged.candidate.root_label.trim();
            if target.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "guards": {
                    "egress_allowlist": {
                        "block": [target]
                    }
                }
            }))
        }
        (
            CausalNodeKind::File | CausalNodeKind::Credential,
            EndpointDecisionAction::QuarantineFile | EndpointDecisionAction::Block,
        ) => {
            let pattern = staged.candidate.root_label.trim();
            if pattern.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "guards": {
                    "forbidden_path": {
                        "patterns": [pattern]
                    }
                }
            }))
        }
        _ => None,
    }
}

pub(crate) fn merge_json_values(target: &mut Value, source: Value) {
    let Value::Object(source_obj) = source else {
        *target = source;
        return;
    };
    let Value::Object(target_obj) = target else {
        *target = Value::Object(source_obj);
        return;
    };

    for (key, value) in source_obj {
        if let Some(existing) = target_obj.get_mut(&key) {
            if existing.is_object() && value.is_object() {
                merge_json_values(existing, value);
            } else {
                *existing = value;
            }
        } else {
            target_obj.insert(key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::edr::dto::{EdrDetectionCandidate, EdrPolicyDeltaTargetPolicy};

    fn policy_delta_artifact(
        root_kind: CausalNodeKind,
        action: EndpointDecisionAction,
        policy_patch: Value,
    ) -> EdrPolicyDeltaArtifact {
        EdrPolicyDeltaArtifact {
            schema_version: "edr.policyDelta.v1".to_string(),
            policy_delta_id: "policy-delta-test".to_string(),
            generated_at: chrono::Utc::now(),
            generated_by: "test".to_string(),
            note: None,
            staged_detection_id: "staged-test".to_string(),
            source_simulation_id: "simulation-test".to_string(),
            source_simulation_receipt_id: None,
            source_affected_identities: Vec::new(),
            source_affected_tools: Vec::new(),
            candidate: EdrDetectionCandidate {
                rule_id: "rule-test".to_string(),
                action: action.clone(),
                description: "test candidate".to_string(),
                root_node_id: "node-test".to_string(),
                root_label: "delta.example.invalid:443".to_string(),
                root_kind,
                graph_slice_id: "slice-test".to_string(),
            },
            target_policy: EdrPolicyDeltaTargetPolicy {
                base_policy_version: "test-policy".to_string(),
                base_policy_hash:
                    "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                base_policy_epoch: 1,
                target_policy_epoch: 2,
            },
            rollout: EdrPolicyDeltaRollout {
                stage: "full_block".to_string(),
                action,
                recommended_stage: "full_block".to_string(),
                promotion_gate: "cross_window".to_string(),
                cross_window_impact_hash: None,
                cross_window_recommendation_hash: None,
                developer_breakage_score: 0,
                impact_level: "low".to_string(),
                would_block: true,
            },
            policy_patch,
        }
    }

    #[test]
    fn enforcing_policy_delta_apply_requires_concrete_guard_patch() {
        let missing_guard = policy_delta_artifact(
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress,
            serde_json::json!({
                "endpoint_decision_engine": {
                    "generated_rules": []
                }
            }),
        );
        let err = validate_policy_delta_artifact_materializes_required_guard(&missing_guard)
            .expect_err("missing guard patch should be rejected");
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(err.1.contains("/guards/egress_allowlist/block"));

        let with_guard = policy_delta_artifact(
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress,
            serde_json::json!({
                "guards": {
                    "egress_allowlist": {
                        "block": ["delta.example.invalid:443"]
                    }
                }
            }),
        );
        validate_policy_delta_artifact_materializes_required_guard(&with_guard)
            .expect("matching guard patch should be accepted");
    }
}
