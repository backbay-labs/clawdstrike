use super::super::*;

pub(crate) fn response_acknowledgement_id_from_report_fields(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
    note: Option<&str>,
    effects: &[EndpointResponseExecutionEffect],
) -> String {
    response_acknowledgement_id_from_report_fields_with_control(
        execution_id,
        response_action_id,
        rollback_ref,
        acknowledged_by,
        note,
        effects,
        None,
    )
}

pub(crate) fn response_acknowledgement_id_from_report_fields_with_control(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
    note: Option<&str>,
    effects: &[EndpointResponseExecutionEffect],
    control_correlation: Option<&EndpointResponseControlCorrelation>,
) -> String {
    let execution_id_hash = sha256(execution_id.as_bytes()).to_hex_prefixed();
    let note_hash = note
        .map(|note| sha256(note.as_bytes()).to_hex_prefixed())
        .unwrap_or_else(response_acknowledgement_absent_note_marker);
    let effect_binding_digest =
        response_acknowledgement_effect_binding_digest_from_effects(effects)
            .ok()
            .flatten()
            .unwrap_or_else(response_acknowledgement_absent_effect_marker);
    let control_binding_digest = control_correlation.and_then(|control| {
        response_control_acknowledgement_binding_digest_from_control(control).ok()
    });
    response_acknowledgement_id_from_evidence_hashes(
        response_action_id,
        rollback_ref,
        execution_id_hash.as_str(),
        acknowledged_by,
        note_hash.as_str(),
        effect_binding_digest.as_str(),
        control_binding_digest.as_deref(),
    )
}

pub(crate) fn response_acknowledgement_id_from_signed_evidence(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
) -> Result<String> {
    let Some(execution_id) = evidence.iter().find(|item| item.key == "executionId") else {
        return Err(anyhow!("acknowledgement execution id evidence is required"));
    };
    require_evidence_hash_not_empty(execution_id, "acknowledgement execution id evidence")?;
    let note_hash = if let Some(note) = evidence.iter().find(|item| item.key == "note") {
        require_evidence_hash_not_empty(note, "acknowledgement note evidence")?;
        note.value_hash.clone()
    } else {
        response_acknowledgement_absent_note_marker()
    };
    let effect_binding_digest =
        response_acknowledgement_effect_binding_digest_from_evidence(evidence)?
            .unwrap_or_else(response_acknowledgement_absent_effect_marker);
    let control_binding_digest =
        response_control_acknowledgement_binding_digest_from_evidence(evidence)?;
    Ok(response_acknowledgement_id_from_evidence_hashes(
        response_action_id,
        rollback_ref,
        execution_id.value_hash.as_str(),
        acknowledged_by,
        note_hash.as_str(),
        effect_binding_digest.as_str(),
        control_binding_digest.as_deref(),
    ))
}

pub(crate) fn response_acknowledgement_id_from_evidence_hashes(
    response_action_id: &str,
    rollback_ref: &str,
    execution_id_hash: &str,
    acknowledged_by: &str,
    note_hash: &str,
    effect_binding_digest: &str,
    control_binding_digest: Option<&str>,
) -> String {
    let mut parts = vec![
        response_action_id,
        rollback_ref,
        execution_id_hash,
        acknowledged_by,
        note_hash,
        effect_binding_digest,
    ];
    if let Some(control_binding_digest) = control_binding_digest {
        parts.push(control_binding_digest);
    }
    stable_id("response_acknowledgement", parts)
}

pub(crate) fn response_acknowledgement_absent_note_marker() -> String {
    "note:absent".to_string()
}

pub(crate) fn response_acknowledgement_absent_effect_marker() -> String {
    "effect:absent".to_string()
}

pub(crate) fn response_acknowledgement_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("acknowledgementEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn response_acknowledgement_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("acknowledgementEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn response_control_acknowledgement_binding_digest_from_control(
    control: &EndpointResponseControlCorrelation,
) -> Result<String> {
    let mut entries = vec![
        ResponseExecutionEffectBindingEntry {
            key: "controlResponseActionId".to_string(),
            value_hash: sha256(control.response_action_id.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlTargetKind".to_string(),
            value_hash: sha256(control.target_kind.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlTargetId".to_string(),
            value_hash: sha256(control.target_id.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlAckTokenHash".to_string(),
            value_hash: control.ack_token_hash.clone(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlAckStatus".to_string(),
            value_hash: sha256(control.ack_status.as_bytes()).to_hex_prefixed(),
        },
    ];
    if let Some(delivery_id) = &control.delivery_id {
        entries.push(ResponseExecutionEffectBindingEntry {
            key: "controlDeliveryId".to_string(),
            value_hash: sha256(delivery_id.as_bytes()).to_hex_prefixed(),
        });
    }
    if let Some(resulting_state) = &control.resulting_state {
        entries.push(ResponseExecutionEffectBindingEntry {
            key: "controlResultingState".to_string(),
            value_hash: sha256(resulting_state.as_bytes()).to_hex_prefixed(),
        });
    }
    response_execution_effect_binding_digest(entries)?
        .ok_or_else(|| anyhow!("control acknowledgement binding evidence is required"))
}

pub(crate) fn response_control_acknowledgement_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    if !evidence.iter().any(|item| item.key.starts_with("control")) {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for (key, field_name) in [
        (
            "controlResponseActionId",
            "control acknowledgement response action id evidence",
        ),
        (
            "controlTargetKind",
            "control acknowledgement target kind evidence",
        ),
        (
            "controlTargetId",
            "control acknowledgement target id evidence",
        ),
        (
            "controlAckTokenHash",
            "control acknowledgement token hash evidence",
        ),
        (
            "controlAckStatus",
            "control acknowledgement status evidence",
        ),
    ] {
        let item = evidence
            .iter()
            .find(|item| item.key == key)
            .ok_or_else(|| anyhow!("{field_name} is required"))?;
        require_evidence_hash_not_empty(item, field_name)?;
        entries.push(ResponseExecutionEffectBindingEntry {
            key: key.to_string(),
            value_hash: item.value_hash.clone(),
        });
    }
    for (key, field_name) in [
        (
            "controlDeliveryId",
            "control acknowledgement delivery id evidence",
        ),
        (
            "controlResultingState",
            "control acknowledgement resulting state evidence",
        ),
    ] {
        if let Some(item) = evidence.iter().find(|item| item.key == key) {
            require_evidence_hash_not_empty(item, field_name)?;
            entries.push(ResponseExecutionEffectBindingEntry {
                key: key.to_string(),
                value_hash: item.value_hash.clone(),
            });
        }
    }
    Ok(Some(
        response_execution_effect_binding_digest(entries)?
            .ok_or_else(|| anyhow!("control acknowledgement binding evidence is required"))?,
    ))
}

pub(crate) fn require_response_acknowledgement_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_acknowledgement_id: Option<&str>,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
) -> Result<()> {
    require_nonempty_hashed_evidence(
        evidence,
        "executionId",
        "acknowledgement execution id evidence",
    )?;
    let acknowledgement_id = response_acknowledgement_id_from_signed_evidence(
        evidence,
        response_action_id,
        rollback_ref,
        acknowledged_by,
    )?;
    if signed_acknowledgement_id != Some(acknowledgement_id.as_str()) {
        return Err(anyhow!(
            "acknowledgement execution id evidence hash must match signed acknowledgement proof"
        ));
    }
    Ok(())
}

pub(crate) fn require_response_acknowledgement_note_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    if evidence.iter().any(|item| item.key == "note") {
        require_nonempty_hashed_evidence(evidence, "note", "acknowledgement note evidence")?;
    }
    Ok(())
}

pub(crate) fn require_response_acknowledgement_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_execution_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "acknowledgementEffect:",
        "acknowledgementEffectType:",
        expected_effect_type,
        "acknowledgement effect type evidence",
    )
}

pub(crate) fn require_response_acknowledgement_effect_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let status = response_acknowledgement_status_from_decision(decision)?;
    let effect_count = evidence
        .iter()
        .filter(|item| item.key.starts_with("acknowledgementEffect:"))
        .count();
    if matches!(decision.action, EndpointDecisionAction::CollectEvidence) && effect_count > 0 {
        return Err(anyhow!(
            "collect evidence acknowledgement effect evidence is invalid"
        ));
    }
    if status == "succeeded"
        && !matches!(decision.action, EndpointDecisionAction::CollectEvidence)
        && effect_count == 0
    {
        return Err(anyhow!("acknowledgement effect evidence is required"));
    }
    Ok(())
}

pub(crate) fn require_response_acknowledgement_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_status = response_acknowledgement_status_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "acknowledgedStatus",
        expected_status,
        "acknowledgement status evidence",
    )
}

pub(crate) fn response_acknowledgement_status_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<&str> {
    let Some(title) = decision.title.as_deref() else {
        return Err(anyhow!("acknowledgement status title is required"));
    };
    let Some(status) = title.strip_prefix("Endpoint response execution acknowledged: ") else {
        return Err(anyhow!("acknowledgement status title is invalid"));
    };
    match status {
        "succeeded" | "failed" | "partial" | "expired" | "cancelled" | "rolled_back" => {}
        _ => return Err(anyhow!("acknowledgement status title is invalid")),
    }
    if !decision.passed {
        return Err(anyhow!(
            "acknowledgement status passed flag is inconsistent"
        ));
    }
    Ok(status)
}

pub(crate) fn require_response_acknowledged_by_evidence(
    actor: &EndpointDecisionActor,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let acknowledged_by = actor
        .agent_id
        .as_deref()
        .ok_or_else(|| anyhow!("acknowledged-by actor identity is required"))?;
    require_nonempty(acknowledged_by, "acknowledged-by actor identity")?;
    require_evidence_value_hash(
        evidence,
        "acknowledgedBy",
        acknowledged_by,
        "acknowledged-by evidence",
    )
}

pub(crate) fn require_response_control_acknowledgement_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let has_control_evidence = evidence.iter().any(|item| item.key.starts_with("control"));
    if !has_control_evidence {
        return Ok(());
    }

    require_nonempty_hashed_evidence(
        evidence,
        "controlResponseActionId",
        "control acknowledgement response action id evidence",
    )?;
    require_control_target_kind_evidence(evidence)?;
    require_nonempty_hashed_evidence(
        evidence,
        "controlTargetId",
        "control acknowledgement target id evidence",
    )?;
    require_control_ack_token_hash_evidence(evidence)?;
    require_control_ack_status_evidence(evidence)?;

    for (key, field_name) in [
        (
            "controlDeliveryId",
            "control acknowledgement delivery id evidence",
        ),
        (
            "controlResultingState",
            "control acknowledgement resulting state evidence",
        ),
    ] {
        if evidence.iter().any(|item| item.key == key) {
            require_nonempty_hashed_evidence(evidence, key, field_name)?;
        }
    }

    Ok(())
}

pub(crate) fn require_control_ack_token_hash_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let Some(item) = evidence
        .iter()
        .find(|item| item.key == "controlAckTokenHash")
    else {
        return Err(anyhow!(
            "control acknowledgement token hash evidence is required"
        ));
    };
    if item.redaction_class != EndpointEvidenceRedactionClass::HashOnly || item.raw_value.is_some()
    {
        return Err(anyhow!(
            "control acknowledgement token hash evidence must be hash-only"
        ));
    }
    require_evidence_hash_not_empty(item, "control acknowledgement token hash evidence")
}

pub(crate) fn require_control_ack_status_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "controlAckStatus") else {
        return Err(anyhow!(
            "control acknowledgement status evidence is required"
        ));
    };
    require_evidence_hash_not_empty(item, "control acknowledgement status evidence")?;
    let allowed_statuses = [
        "acknowledged",
        "rejected",
        "failed",
        "expired",
        "rolled_back",
    ];
    if allowed_statuses.iter().any(|status| {
        let expected_hash = sha256(status.as_bytes()).to_hex_prefixed();
        hex_strings_match(expected_hash.as_str(), item.value_hash.as_str())
    }) {
        return Ok(());
    }
    Err(anyhow!(
        "control acknowledgement status evidence must be acknowledged, rejected, failed, expired, or rolled_back"
    ))
}

pub(crate) fn require_control_target_kind_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "controlTargetKind") else {
        return Err(anyhow!(
            "control acknowledgement target kind evidence is required"
        ));
    };
    require_evidence_hash_not_empty(item, "control acknowledgement target kind evidence")?;
    let allowed_target_kinds = [
        "endpoint",
        "runtime",
        "session",
        "principal",
        "grant",
        "swarm",
        "project",
    ];
    if allowed_target_kinds.iter().any(|target_kind| {
        let expected_hash = sha256(target_kind.as_bytes()).to_hex_prefixed();
        hex_strings_match(expected_hash.as_str(), item.value_hash.as_str())
    }) {
        return Ok(());
    }
    Err(anyhow!(
        "control acknowledgement target kind evidence must be endpoint, runtime, session, principal, grant, swarm, or project"
    ))
}
