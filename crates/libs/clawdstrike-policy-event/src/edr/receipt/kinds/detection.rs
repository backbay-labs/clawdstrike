use super::super::*;

pub(crate) fn require_detection_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection observation id is required"))?;
    let finding_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection finding id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection rule id is required"))?;
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("detection title is required"))?;
    let severity = decision
        .severity
        .as_ref()
        .ok_or_else(|| anyhow!("detection severity is required"))?;
    let confidence = decision
        .confidence
        .ok_or_else(|| anyhow!("detection confidence is required"))?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection graph slice id is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("detection graph content hash is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection process node id is required"))?;
    require_detection_graph_reference(
        graph,
        observation_id,
        graph_slice_id,
        graph_content_hash,
        process_node_id,
    )?;

    require_evidence_value_hash(
        evidence,
        "detectionFindingId",
        finding_id,
        "detection finding id evidence",
    )?;
    let expected_finding_id = detection_finding_id_from_signed_fields(rule_id, observation_id);
    if finding_id != expected_finding_id {
        return Err(anyhow!(
            "detection finding id must match signed rule and observation"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "detectionObservationId",
        observation_id,
        "detection observation id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionRuleId",
        rule_id,
        "detection rule id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionTitle",
        title,
        "detection title evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionSeverity",
        detection_severity_label(severity),
        "detection severity evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionConfidence",
        confidence.to_string(),
        "detection confidence evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionGraphSliceId",
        graph_slice_id,
        "detection graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionContentHash",
        graph_content_hash,
        "detection graph content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionProcessNodeId",
        process_node_id,
        "detection process node evidence",
    )
}

pub(crate) fn require_detection_graph_reference(
    graph: &EndpointGraphReference,
    observation_id: &str,
    graph_slice_id: &str,
    graph_content_hash: &str,
    process_node_id: &str,
) -> Result<()> {
    if !graph
        .node_ids
        .iter()
        .any(|node_id| node_id == process_node_id)
    {
        return Err(anyhow!(
            "detection process node reference must be included in graph node ids"
        ));
    }

    let expected_graph_slice_id = stable_id(
        "graph_slice",
        [observation_id, process_node_id, graph_content_hash],
    );
    if graph_slice_id != expected_graph_slice_id {
        return Err(anyhow!(
            "detection graph slice reference must match observation, process, and graph content hash"
        ));
    }
    Ok(())
}

pub(crate) fn detection_severity_label(severity: &DetectionSeverity) -> &'static str {
    match severity {
        DetectionSeverity::Info => "info",
        DetectionSeverity::Low => "low",
        DetectionSeverity::Medium => "medium",
        DetectionSeverity::High => "high",
        DetectionSeverity::Critical => "critical",
    }
}

pub(crate) fn detection_finding_id_from_signed_fields(
    rule_id: &str,
    observation_id: &str,
) -> String {
    stable_id("finding", [rule_id, observation_id])
}
