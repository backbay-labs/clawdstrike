use super::super::*;

pub(crate) fn response_action_id_from_rollback_ref(
    action: &EndpointDecisionAction,
    rollback_ref: &str,
) -> Result<String> {
    let action_id = if action == &EndpointDecisionAction::CollectEvidence {
        rollback_ref
            .strip_prefix("rollback:noop:")
            .or_else(|| rollback_ref.strip_prefix("rollback:"))
    } else {
        rollback_ref.strip_prefix("rollback:")
    }
    .ok_or_else(|| {
        anyhow!("response rollback evidence hash must match signed response action fields")
    })?;
    require_nonempty(action_id, "response action id")?;
    Ok(action_id.to_string())
}

pub(crate) fn expected_response_rollback_ref(
    action: &EndpointDecisionAction,
    dry_run: bool,
    response_action_id: &str,
) -> String {
    if !dry_run && action == &EndpointDecisionAction::CollectEvidence {
        format!("rollback:noop:{response_action_id}")
    } else {
        format!("rollback:{response_action_id}")
    }
}

pub(crate) fn expected_live_response_rollback_ref(
    action: &EndpointDecisionAction,
    response_action_id: &str,
) -> String {
    expected_response_rollback_ref(action, false, response_action_id)
}

pub(crate) fn response_rollback_id_from_effects(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<String> {
    let execution_id_hash = sha256(execution_id.as_bytes()).to_hex_prefixed();
    let effect_binding_digest = response_rollback_effect_binding_digest_from_effects(effects)?
        .ok_or_else(|| anyhow!("response rollback effect binding requires at least one effect"))?;
    Ok(response_rollback_id_from_effect_digest(
        response_action_id,
        rollback_ref,
        execution_id_hash.as_str(),
        effect_binding_digest.as_str(),
    ))
}

pub(crate) fn response_rollback_id_from_signed_evidence(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    rollback_ref: &str,
) -> Result<String> {
    let Some(execution_id) = evidence.iter().find(|item| item.key == "executionId") else {
        return Err(anyhow!("rollback execution id evidence is required"));
    };
    require_evidence_hash_not_empty(execution_id, "rollback execution id evidence")?;
    let effect_binding_digest = response_rollback_effect_binding_digest_from_evidence(evidence)?
        .ok_or_else(|| anyhow!("rollback effect evidence is required"))?;
    Ok(response_rollback_id_from_effect_digest(
        response_action_id,
        rollback_ref,
        execution_id.value_hash.as_str(),
        effect_binding_digest.as_str(),
    ))
}

pub(crate) fn response_rollback_id_from_effect_digest(
    response_action_id: &str,
    rollback_ref: &str,
    execution_id_hash: &str,
    effect_binding_digest: &str,
) -> String {
    stable_id(
        "response_rollback",
        [
            response_action_id,
            rollback_ref,
            execution_id_hash,
            effect_binding_digest,
        ],
    )
}

pub(crate) fn response_rollback_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("rollbackEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn response_rollback_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("rollbackEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn require_response_rollback_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_rollback_id: Option<&str>,
    response_action_id: &str,
    rollback_ref: &str,
) -> Result<()> {
    require_nonempty_hashed_evidence(evidence, "executionId", "rollback execution id evidence")?;
    let rollback_id =
        response_rollback_id_from_signed_evidence(evidence, response_action_id, rollback_ref)?;
    if signed_rollback_id != Some(rollback_id.as_str()) {
        return Err(anyhow!(
            "rollback execution id evidence hash must match signed rollback proof"
        ));
    }
    Ok(())
}

pub(crate) fn require_response_rollback_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_rollback_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "rollbackEffect:",
        "rollbackEffectType:",
        expected_effect_type,
        "rollback effect type evidence",
    )
}

pub(crate) fn response_rollback_effect_type_for_action(
    action: &EndpointDecisionAction,
) -> Option<&'static str> {
    match action {
        EndpointDecisionAction::RestrictEgress => Some("restore_egress"),
        EndpointDecisionAction::QuarantineFile => Some("restore_quarantine_file"),
        EndpointDecisionAction::DisablePersistence => Some("restore_persistence_file"),
        EndpointDecisionAction::SuspendProcessTree => Some("resume_process_tree"),
        _ => None,
    }
}

pub(crate) fn require_response_rollback_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    if decision.title.as_deref() != Some("Endpoint response rollback executed") {
        return Err(anyhow!("rollback status title is invalid"));
    }
    if !decision.passed {
        return Err(anyhow!("rollback status passed flag is inconsistent"));
    }
    require_evidence_value_hash(
        evidence,
        "rollbackStatus",
        "succeeded",
        "rollback status evidence",
    )
}
