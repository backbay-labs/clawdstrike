use super::super::*;

pub(crate) fn require_response_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
) -> Result<()> {
    require_response_family_id_evidence(
        evidence,
        "executionId",
        decision.finding_id.as_deref(),
        "execution id evidence",
    )?;
    let Some(expected_execution_id) = response_execution_id_from_signed_fields(
        decision,
        graph_slice_id,
        graph_content_hash,
        evidence,
    )?
    else {
        return Ok(());
    };
    if decision.finding_id.as_deref() != Some(expected_execution_id.as_str()) {
        return Err(anyhow!(
            "execution id evidence hash must match signed response action fields"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "executionId",
        expected_execution_id.as_str(),
        "execution id evidence",
    )
}

pub(crate) fn require_response_execution_evidence_bundle_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
) -> Result<()> {
    let graph_content_hash = graph_content_hash
        .ok_or_else(|| anyhow!("execution evidence bundle graph content hash is required"))?;
    let evidence_bundle_id = response_execution_bundle_id_from_signed_fields(
        decision,
        graph_slice_id,
        graph_content_hash,
    )?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleId",
        evidence_bundle_id.as_str(),
        "execution evidence bundle id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleContentHash",
        graph_content_hash,
        "execution evidence bundle content hash evidence",
    )
}

pub(crate) fn response_execution_id_from_signed_fields(
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let status = response_execution_status_from_decision(decision)?;
    let graph_content_hash =
        graph_content_hash.ok_or_else(|| anyhow!("execution id graph content hash is required"))?;
    let evidence_bundle_id = response_execution_bundle_id_from_signed_fields(
        decision,
        graph_slice_id,
        graph_content_hash,
    )?;
    let rollback_ref = decision
        .rollback_ref
        .as_deref()
        .ok_or_else(|| anyhow!("response rollback ref is required"))?;
    let response_action_id = response_action_id_from_rollback_ref(&decision.action, rollback_ref)?;
    if let Some(prefix) = response_execution_transition_id_prefix(status) {
        let reason_hash = response_execution_reason_evidence_hash(evidence)?;
        return Ok(Some(response_execution_transition_id_from_reason_hash(
            prefix,
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            rollback_ref,
            reason_hash,
        )));
    }
    if let Some(effect_binding_digest) =
        response_execution_effect_binding_digest_from_evidence(evidence)?
    {
        if decision.action == EndpointDecisionAction::CollectEvidence {
            return Err(anyhow!(
                "collect evidence execution effect evidence is invalid"
            ));
        }
        return Ok(Some(response_execution_id_from_effect_digest(
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            effect_binding_digest.as_str(),
        )));
    }
    if decision.action != EndpointDecisionAction::CollectEvidence {
        return Err(anyhow!("execution effect evidence is required"));
    }
    Ok(Some(stable_id(
        "response_execution",
        [
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            graph_content_hash,
        ],
    )))
}

pub(crate) fn response_execution_transition_id_prefix(status: &str) -> Option<&'static str> {
    match status {
        "failed" => Some("response_execution_failed"),
        "partial" => Some("response_execution_partial"),
        "rollback_pending" => Some("response_execution_rollback_pending"),
        "rollback_failed" => Some("response_execution_rollback_failed"),
        "expired" => Some("response_execution_expired"),
        "cancelled" => Some("response_execution_cancelled"),
        "rolled_back" => Some("response_execution_rolled_back"),
        _ => None,
    }
}

pub(crate) fn response_execution_reason_evidence_hash(
    evidence: &[EndpointReceiptEvidence],
) -> Result<&str> {
    let Some(reason) = evidence.iter().find(|item| item.key == "reason") else {
        return Err(anyhow!("response transition reason evidence is required"));
    };
    require_evidence_hash_not_empty(reason, "response transition reason evidence")?;
    Ok(reason.value_hash.as_str())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResponseExecutionEffectBindingEntry {
    pub(crate) key: String,
    pub(crate) value_hash: String,
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

pub(crate) fn response_execution_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("executionEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn response_execution_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("executionEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn response_execution_effect_binding_digest(
    mut entries: Vec<ResponseExecutionEffectBindingEntry>,
) -> Result<Option<String>> {
    if entries.is_empty() {
        return Ok(None);
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let value =
        serde_json::to_value(entries).context("serialize response execution effect binding")?;
    let canonical =
        canonicalize_json(&value).context("canonicalize response execution effect binding")?;
    Ok(Some(sha256(canonical.as_bytes()).to_hex_prefixed()))
}

pub(crate) fn response_execution_bundle_id_from_signed_fields(
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: &str,
) -> Result<String> {
    let rollback_ref = decision
        .rollback_ref
        .as_deref()
        .ok_or_else(|| anyhow!("response rollback ref is required"))?;
    let response_action_id = response_action_id_from_rollback_ref(&decision.action, rollback_ref)?;
    let status = response_execution_status_from_decision(decision)?;
    if status == "failed" {
        return Ok(stable_id(
            "evidence_bundle",
            [
                response_action_id.as_str(),
                graph_slice_id,
                graph_content_hash,
                "failed",
            ],
        ));
    }
    Ok(stable_id(
        "evidence_bundle",
        [
            response_action_id.as_str(),
            graph_slice_id,
            graph_content_hash,
        ],
    ))
}

pub(crate) fn require_response_execution_dry_run_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    require_evidence_value_hash(evidence, "dryRun", "false", "execution dry-run evidence")
}

pub(crate) fn require_response_execution_actor_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let actor_hash = evidence_value_hash(evidence, "actorHash", "response actor evidence")?;
    let execution_actor_hash =
        evidence_value_hash(evidence, "executionActorHash", "execution actor evidence")?;
    if !hex_strings_match(actor_hash, execution_actor_hash) {
        return Err(anyhow!(
            "execution actor evidence hash must match response actor evidence"
        ));
    }
    Ok(())
}

pub(crate) fn require_response_execution_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_execution_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "executionEffect:",
        "executionEffectType:",
        expected_effect_type,
        "execution effect type evidence",
    )
}

pub(crate) fn response_execution_effect_type_for_action(
    action: &EndpointDecisionAction,
) -> Option<&'static str> {
    match action {
        EndpointDecisionAction::RestrictEgress => Some("restrict_egress"),
        EndpointDecisionAction::QuarantineFile => Some("quarantine_file"),
        EndpointDecisionAction::DisablePersistence => Some("disable_persistence"),
        EndpointDecisionAction::RevokeGrant => Some("revoke_grant"),
        EndpointDecisionAction::SuspendProcessTree => Some("suspend_process_tree"),
        EndpointDecisionAction::TerminateProcessTree => Some("terminate_process_tree"),
        EndpointDecisionAction::CollectEvidence => None,
        _ => None,
    }
}

pub(crate) fn require_response_execution_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_status = response_execution_status_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "executionStatus",
        expected_status,
        "execution status evidence",
    )
}

pub(crate) fn response_execution_status_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<&'static str> {
    let Some(title) = decision.title.as_deref() else {
        return Err(anyhow!("execution status title is required"));
    };
    let expected = match title {
        "Endpoint response action executed" => "succeeded",
        "Endpoint response action failed" => "failed",
        "Endpoint response action partially executed" => "partial",
        "Endpoint response rollback pending" => "rollback_pending",
        "Endpoint response rollback failed" => "rollback_failed",
        "Endpoint response action expired" => "expired",
        "Endpoint response action cancelled" => "cancelled",
        "Endpoint response action rolled back" => "rolled_back",
        _ => return Err(anyhow!("execution status title is invalid")),
    };
    let expected_passed = expected == "succeeded";
    if decision.passed != expected_passed {
        return Err(anyhow!("execution status passed flag is inconsistent"));
    }
    Ok(expected)
}
