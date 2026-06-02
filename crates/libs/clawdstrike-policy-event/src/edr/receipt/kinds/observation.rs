use super::super::*;

pub(crate) fn require_observation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation id is required"))?;
    let receipt_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation receipt id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation receipt rule id is required"))?;
    let event_kind = rule_id
        .strip_prefix("endpoint.observation.")
        .ok_or_else(|| anyhow!("observation receipt rule id must include event kind"))?;
    require_nonempty(event_kind, "observation receipt event kind")?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation graph slice id is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("observation graph content hash is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation process node id is required"))?;
    require_detection_graph_reference(
        graph,
        observation_id,
        graph_slice_id,
        graph_content_hash,
        process_node_id,
    )?;

    require_evidence_value_hash(
        evidence,
        "observationId",
        observation_id,
        "observation id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "eventKind",
        event_kind,
        "observation event kind evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "observationHash",
        "observation content hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "target", "observation target evidence")?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "observation graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        graph_content_hash,
        "observation graph content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "processNodeId",
        process_node_id,
        "observation process node evidence",
    )?;
    let provider_id_hash = evidence_value_hash(evidence, "providerId", "provider id evidence")?;
    let provider_kind_hash =
        evidence_value_hash(evidence, "providerKind", "provider kind evidence")?;
    let provider = sensor_state
        .providers
        .iter()
        .find(|provider| {
            let expected_provider_id_hash =
                sha256(provider.provider_id.as_bytes()).to_hex_prefixed();
            hex_strings_match(expected_provider_id_hash.as_str(), provider_id_hash)
        })
        .ok_or_else(|| anyhow!("observation receipt provider id is not present in sensor state"))?;
    let expected_provider_kind_hash =
        sha256(camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str()).as_bytes())
            .to_hex_prefixed();
    if !hex_strings_match(expected_provider_kind_hash.as_str(), provider_kind_hash) {
        return Err(anyhow!(
            "observation receipt provider kind evidence must match sensor state"
        ));
    }

    let expected_receipt_id = observation_receipt_id_from_evidence(
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
        evidence,
    )?;
    if receipt_id != expected_receipt_id {
        return Err(anyhow!(
            "observation receipt id must match signed endpoint, policy, observation, graph, provider, target, and content-hash evidence"
        ));
    }
    Ok(())
}

pub(crate) struct ObservationReceiptIdFields<'a> {
    pub(crate) endpoint_id: &'a str,
    pub(crate) policy_hash: &'a str,
    pub(crate) observation_id: &'a str,
    pub(crate) event_kind: &'a str,
    pub(crate) observation_hash: &'a str,
    pub(crate) target: &'a str,
    pub(crate) graph_slice_id: &'a str,
    pub(crate) graph_content_hash: &'a str,
    pub(crate) process_node_id: &'a str,
    pub(crate) provider_id: &'a str,
    pub(crate) provider_kind: &'a str,
}

pub(crate) fn observation_receipt_id_from_fields(fields: ObservationReceiptIdFields<'_>) -> String {
    let observation_id_hash = sha256(fields.observation_id.as_bytes()).to_hex_prefixed();
    let event_kind_hash = sha256(fields.event_kind.as_bytes()).to_hex_prefixed();
    let observation_hash_hash = sha256(fields.observation_hash.as_bytes()).to_hex_prefixed();
    let target_hash = sha256(fields.target.as_bytes()).to_hex_prefixed();
    let graph_slice_id_hash = sha256(fields.graph_slice_id.as_bytes()).to_hex_prefixed();
    let graph_content_hash_hash = sha256(fields.graph_content_hash.as_bytes()).to_hex_prefixed();
    let process_node_id_hash = sha256(fields.process_node_id.as_bytes()).to_hex_prefixed();
    let provider_id_hash = sha256(fields.provider_id.as_bytes()).to_hex_prefixed();
    let provider_kind_hash = sha256(fields.provider_kind.as_bytes()).to_hex_prefixed();
    observation_receipt_id_from_evidence_hashes(
        fields.endpoint_id,
        fields.policy_hash,
        ObservationReceiptIdEvidenceHashes {
            observation_id_hash: observation_id_hash.as_str(),
            event_kind_hash: event_kind_hash.as_str(),
            observation_hash_hash: observation_hash_hash.as_str(),
            target_hash: target_hash.as_str(),
            graph_slice_id_hash: graph_slice_id_hash.as_str(),
            graph_content_hash_hash: graph_content_hash_hash.as_str(),
            process_node_id_hash: process_node_id_hash.as_str(),
            provider_id_hash: provider_id_hash.as_str(),
            provider_kind_hash: provider_kind_hash.as_str(),
        },
    )
}

pub(crate) fn observation_receipt_id_from_evidence(
    endpoint_id: &str,
    policy_hash: &str,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    Ok(observation_receipt_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        ObservationReceiptIdEvidenceHashes {
            observation_id_hash: evidence_value_hash(
                evidence,
                "observationId",
                "observation id evidence",
            )?,
            event_kind_hash: evidence_value_hash(
                evidence,
                "eventKind",
                "observation event kind evidence",
            )?,
            observation_hash_hash: evidence_value_hash(
                evidence,
                "observationHash",
                "observation content hash evidence",
            )?,
            target_hash: evidence_value_hash(evidence, "target", "observation target evidence")?,
            graph_slice_id_hash: evidence_value_hash(
                evidence,
                "graphSliceId",
                "observation graph slice evidence",
            )?,
            graph_content_hash_hash: evidence_value_hash(
                evidence,
                "contentHash",
                "observation graph content hash evidence",
            )?,
            process_node_id_hash: evidence_value_hash(
                evidence,
                "processNodeId",
                "observation process node evidence",
            )?,
            provider_id_hash: evidence_value_hash(evidence, "providerId", "provider id evidence")?,
            provider_kind_hash: evidence_value_hash(
                evidence,
                "providerKind",
                "provider kind evidence",
            )?,
        },
    ))
}

pub(crate) struct ObservationReceiptIdEvidenceHashes<'a> {
    observation_id_hash: &'a str,
    event_kind_hash: &'a str,
    observation_hash_hash: &'a str,
    target_hash: &'a str,
    graph_slice_id_hash: &'a str,
    graph_content_hash_hash: &'a str,
    process_node_id_hash: &'a str,
    provider_id_hash: &'a str,
    provider_kind_hash: &'a str,
}

pub(crate) fn observation_receipt_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: ObservationReceiptIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "observation_receipt",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.observation_id_hash,
            evidence_hashes.event_kind_hash,
            evidence_hashes.observation_hash_hash,
            evidence_hashes.target_hash,
            evidence_hashes.graph_slice_id_hash,
            evidence_hashes.graph_content_hash_hash,
            evidence_hashes.process_node_id_hash,
            evidence_hashes.provider_id_hash,
            evidence_hashes.provider_kind_hash,
        ],
    )
}
