use super::super::*;

pub(crate) fn require_policy_event_replay_evidence(
    evidence: &[EndpointReceiptEvidence],
    replay_id: Option<&str>,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let replay_id =
        replay_id.ok_or_else(|| anyhow!("policy event replay signed id is required"))?;
    require_policy_event_stream_graph_reference(graph, replay_id, "policy event replay")?;
    require_evidence_value_hash(
        evidence,
        "replayId",
        replay_id,
        "policy event replay id evidence",
    )?;
    require_policy_event_source_evidence(
        evidence,
        "eventSource",
        "policy event replay source evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "eventStreamHash",
        "policy event replay stream hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "resultHash",
        "policy event replay result hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "eventCount", "policy event replay count evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "allowedCount",
        "policy event replay allowed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "warnCount",
        "policy event replay warn count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "blockedCount",
        "policy event replay blocked count evidence",
    )?;
    require_boolean_hashed_evidence(
        evidence,
        "trackPosture",
        "policy event replay posture evidence",
    )?;
    let expected_replay_id = policy_event_replay_id_from_evidence(policy, evidence)?;
    if replay_id != expected_replay_id {
        return Err(anyhow!(
            "policy event replay id must match signed policy, stream, result, count, and posture evidence"
        ));
    }
    Ok(())
}

pub(crate) fn require_policy_event_impact_evidence(
    evidence: &[EndpointReceiptEvidence],
    impact_id: Option<&str>,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let impact_id =
        impact_id.ok_or_else(|| anyhow!("policy event impact signed id is required"))?;
    require_policy_event_stream_graph_reference(graph, impact_id, "policy event impact")?;
    require_evidence_value_hash(
        evidence,
        "impactId",
        impact_id,
        "policy event impact id evidence",
    )?;
    require_policy_event_source_evidence(
        evidence,
        "eventSource",
        "policy event impact source evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "eventStreamHash",
        "policy event impact stream hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "currentResultHash",
        "policy event impact current-result evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedResultHash",
        "policy event impact proposed-result evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "impactHash", "policy event impact hash evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedPolicyHash",
        "policy event impact proposed-policy hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedPolicyEpoch",
        "policy event impact proposed-policy epoch evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "eventCount", "policy event impact count evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "changedCount",
        "policy event impact changed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "allowToBlockCount",
        "policy event impact allow-to-block count evidence",
    )?;
    require_boolean_hashed_evidence(
        evidence,
        "trackPosture",
        "policy event impact posture evidence",
    )?;
    let expected_impact_id = policy_event_impact_id_from_evidence(policy, evidence)?;
    if impact_id != expected_impact_id {
        return Err(anyhow!(
            "policy event impact id must match signed policy, proposed policy, stream, result, impact, count, and posture evidence"
        ));
    }
    Ok(())
}

pub(crate) fn policy_event_replay_id_from_evidence(
    policy: &EndpointPolicySnapshot,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let policy_epoch = policy.policy_epoch.to_string();
    Ok(stable_id(
        "policy_event_replay",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            evidence_value_hash(
                evidence,
                "eventSource",
                "policy event replay source evidence",
            )?,
            evidence_value_hash(
                evidence,
                "eventStreamHash",
                "policy event replay stream hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "resultHash",
                "policy event replay result hash evidence",
            )?,
            evidence_value_hash(evidence, "eventCount", "policy event replay count evidence")?,
            evidence_value_hash(
                evidence,
                "allowedCount",
                "policy event replay allowed count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "warnCount",
                "policy event replay warn count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "blockedCount",
                "policy event replay blocked count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "trackPosture",
                "policy event replay posture evidence",
            )?,
        ],
    ))
}

pub(crate) fn policy_event_impact_id_from_evidence(
    policy: &EndpointPolicySnapshot,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let policy_epoch = policy.policy_epoch.to_string();
    Ok(stable_id(
        "policy_event_impact",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            evidence_value_hash(
                evidence,
                "proposedPolicyHash",
                "policy event impact proposed-policy hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "proposedPolicyEpoch",
                "policy event impact proposed-policy epoch evidence",
            )?,
            evidence_value_hash(
                evidence,
                "eventSource",
                "policy event impact source evidence",
            )?,
            evidence_value_hash(
                evidence,
                "eventStreamHash",
                "policy event impact stream hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "currentResultHash",
                "policy event impact current-result evidence",
            )?,
            evidence_value_hash(
                evidence,
                "proposedResultHash",
                "policy event impact proposed-result evidence",
            )?,
            evidence_value_hash(evidence, "impactHash", "policy event impact hash evidence")?,
            evidence_value_hash(evidence, "eventCount", "policy event impact count evidence")?,
            evidence_value_hash(
                evidence,
                "changedCount",
                "policy event impact changed count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "allowToBlockCount",
                "policy event impact allow-to-block count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "trackPosture",
                "policy event impact posture evidence",
            )?,
        ],
    ))
}

pub(crate) fn require_policy_event_stream_graph_reference(
    graph: &EndpointGraphReference,
    stream_id: &str,
    label: &str,
) -> Result<()> {
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph slice reference is required"))?;
    if graph_slice_id != stream_id {
        return Err(anyhow!(
            "{label} graph slice reference must match signed id"
        ));
    }
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} stream node reference is required"))?;
    if process_node_id != "policy_event_stream" {
        return Err(anyhow!(
            "{label} stream node reference must be policy_event_stream"
        ));
    }
    if !graph
        .node_ids
        .iter()
        .any(|node_id| node_id == "policy_event_stream")
    {
        return Err(anyhow!(
            "{label} stream node reference must be included in graph node ids"
        ));
    }
    Ok(())
}

pub(crate) fn require_policy_event_source_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    let submitted_hash = sha256(b"submitted").to_hex_prefixed();
    let flight_recorder_hash = sha256(b"endpoint_flight_recorder").to_hex_prefixed();
    if !hex_strings_match(submitted_hash.as_str(), item.value_hash.as_str())
        && !hex_strings_match(flight_recorder_hash.as_str(), item.value_hash.as_str())
    {
        return Err(anyhow!(
            "{field_name} must be submitted or endpoint_flight_recorder"
        ));
    }
    Ok(())
}
