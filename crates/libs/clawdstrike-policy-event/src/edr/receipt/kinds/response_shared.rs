use super::super::*;

pub(crate) fn require_response_receipt_evidence(
    evidence: &[EndpointReceiptEvidence],
    action: &EndpointDecisionAction,
    root_node_id: &str,
    graph_slice_id: &str,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    let response_action_id = response_action_id_from_rollback_ref(action, rollback_ref)?;
    require_response_action_id_matches_signed_response_fields(
        response_action_id.as_str(),
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        "execute",
    )?;
    require_evidence_value_hash(
        evidence,
        "responseActionId",
        response_action_id.as_str(),
        "response action id evidence",
    )?;
    let expected_rollback_ref = expected_live_response_rollback_ref(action, &response_action_id);
    if rollback_ref != expected_rollback_ref {
        return Err(anyhow!(
            "response rollback evidence hash must match signed response action fields"
        ));
    }
    require_response_receipt_evidence_fields(
        evidence,
        response_action_id.as_str(),
        root_node_id,
        graph_slice_id,
        None,
        ttl_seconds,
        rollback_ref,
    )
}

pub(crate) fn require_response_receipt_evidence_fields(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "responseActionId",
        response_action_id,
        "response action id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "response root node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "response graph slice evidence",
    )?;
    if let Some(graph_content_hash) = graph_content_hash {
        require_evidence_value_hash(
            evidence,
            "contentHash",
            graph_content_hash,
            "response graph content hash evidence",
        )?;
    }
    require_evidence_value_hash(
        evidence,
        "ttlSeconds",
        ttl_seconds.to_string(),
        "response ttl evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rollbackRef",
        rollback_ref,
        "response rollback evidence",
    )?;
    Ok(())
}

pub(crate) fn require_response_action_id_matches_signed_response_fields(
    response_action_id: &str,
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
    mode: &str,
) -> Result<()> {
    let stable_response_action_id = response_action_id_from_signed_response_fields_with_mode(
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        mode,
    );
    if response_action_id == stable_response_action_id {
        return Ok(());
    }
    let Some(issuance_id) = response_action_id
        .strip_prefix(stable_response_action_id.as_str())
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return Err(anyhow!(
            "response action id evidence hash must match signed response action fields"
        ));
    };
    Uuid::parse_str(issuance_id).map_err(|_| {
        anyhow!("response action id evidence hash must match signed response action fields")
    })?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn response_action_id_from_signed_response_fields(
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
) -> String {
    response_action_id_from_signed_response_fields_with_mode(
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        "execute",
    )
}

pub(crate) fn response_action_id_from_signed_response_fields_with_mode(
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
    mode: &str,
) -> String {
    let ttl = ttl_seconds.to_string();
    stable_id(
        "response_action",
        [
            root_node_id,
            graph_slice_id,
            action.as_str(),
            mode,
            ttl.as_str(),
        ],
    )
}

pub(crate) fn require_response_family_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    signed_id: Option<&str>,
    field_name: &str,
) -> Result<()> {
    let signed_id = signed_id.ok_or_else(|| anyhow!("{field_name} signed id is required"))?;
    require_evidence_value_hash(evidence, key, signed_id, field_name)
}

pub(crate) fn require_response_reason_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "reason") else {
        return Err(anyhow!("response reason evidence is required"));
    };
    let empty_reason_hash = sha256(b"").to_hex_prefixed();
    if item.value_hash == empty_reason_hash {
        return Err(anyhow!("response reason evidence must not be empty"));
    }
    Ok(())
}

pub(crate) fn response_effect_evidence_value(effect: &EndpointResponseExecutionEffect) -> String {
    serde_json::to_value(effect)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| effect.effect_id.clone())
}

pub(crate) fn require_response_effect_count_evidence(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    field_name: &str,
) -> Result<()> {
    let effect_count = evidence
        .iter()
        .filter(|item| item.key.starts_with(effect_key_prefix))
        .count();
    require_evidence_value_hash(
        evidence,
        "effectCount",
        effect_count.to_string(),
        field_name,
    )
}

pub(crate) fn require_response_effect_evidence_hashes(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    field_name: &str,
) -> Result<()> {
    for effect_evidence in evidence
        .iter()
        .filter(|item| item.key.starts_with(effect_key_prefix))
    {
        require_evidence_hash_not_empty(effect_evidence, field_name)?;
    }
    Ok(())
}

pub(crate) fn require_response_typed_effect_evidence(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    effect_type_key_prefix: &str,
    expected_effect_type: Option<&str>,
    field_name: &str,
) -> Result<()> {
    let effect_ids = evidence
        .iter()
        .filter_map(|item| item.key.strip_prefix(effect_key_prefix))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let effect_type_ids = evidence
        .iter()
        .filter_map(|item| item.key.strip_prefix(effect_type_key_prefix))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    if effect_ids != effect_type_ids {
        return Err(anyhow!("{field_name} must match response effect evidence"));
    }
    if effect_ids.is_empty() {
        return Ok(());
    }

    let expected_effect_type =
        expected_effect_type.ok_or_else(|| anyhow!("{field_name} is invalid for action"))?;
    for effect_id in effect_ids {
        let effect_type_key = format!("{effect_type_key_prefix}{effect_id}");
        require_evidence_value_hash(
            evidence,
            effect_type_key.as_str(),
            expected_effect_type,
            field_name,
        )?;
    }
    Ok(())
}

pub(crate) fn require_response_action(action: &EndpointDecisionAction) -> Result<()> {
    if matches!(
        action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::CollectEvidence
    ) {
        return Ok(());
    }

    Err(anyhow!(
        "response action must be a bounded local response action"
    ))
}

pub(crate) fn require_response_action_for_family(
    family: &EndpointDecisionReceiptFamily,
    decision: &EndpointDecisionRecord,
) -> Result<()> {
    require_response_action(&decision.action)?;
    if decision.action != EndpointDecisionAction::TerminateProcessTree {
        return Ok(());
    }

    if family == &EndpointDecisionReceiptFamily::ResponseRequest
        && response_request_dry_run_from_decision(decision)?
    {
        return Ok(());
    }

    Err(anyhow!(
        "terminate_process_tree response proofs are limited to dry-run response requests"
    ))
}

pub(crate) fn require_response_actor_context(actor: &EndpointDecisionActor) -> Result<()> {
    let has_actor_context = [
        actor.user_id.as_deref(),
        actor.session_id.as_deref(),
        actor.agent_id.as_deref(),
        actor.workload_id.as_deref(),
        actor.approval_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty());

    if has_actor_context {
        return Ok(());
    }
    Err(anyhow!("response actor context is required"))
}

pub(crate) fn require_response_actor_evidence(
    actor: &EndpointDecisionActor,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "actorHash",
        endpoint_decision_actor_content_hash(actor),
        "response actor evidence",
    )
}
