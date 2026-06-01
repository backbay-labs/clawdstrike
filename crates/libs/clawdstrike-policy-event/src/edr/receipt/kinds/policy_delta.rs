use super::super::*;

pub(crate) fn require_policy_delta_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    graph_slice_id: Option<&str>,
    root_node_id: Option<&str>,
) -> Result<()> {
    let policy_delta_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta rule id is required"))?;
    let graph_slice_id =
        graph_slice_id.ok_or_else(|| anyhow!("policy delta graph slice id is required"))?;
    let root_node_id =
        root_node_id.ok_or_else(|| anyhow!("policy delta root node id is required"))?;
    let operation = policy_delta_operation_from_title(decision)?;
    require_evidence_value_hash(
        evidence,
        "operation",
        operation,
        "policy delta operation evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "policyDeltaId",
        policy_delta_id,
        "policy delta id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "stagedDetectionId",
        "policy delta staged detection evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "stage", "policy delta stage evidence")?;
    require_policy_delta_stage_action_evidence(evidence, &decision.action)?;
    require_nonempty_hashed_evidence(
        evidence,
        "generatedAt",
        "policy delta generated-at evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactHash",
        "policy delta artifact hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "simulationId", "policy delta simulation evidence")?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "policy delta graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "policy delta root node evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "sourceAffectedIdentityContext",
        "policy delta source affected identity context evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "sourceAffectedToolContext",
        "policy delta source affected tool context evidence",
    )?;
    let expected_policy_delta_id = policy_delta_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        rule_id,
        &decision.action,
    )?;
    if policy_delta_id != expected_policy_delta_id {
        return Err(anyhow!(
            "policy delta id must match signed endpoint, rule, action, staged source, generation time, simulation, and graph evidence"
        ));
    }
    require_policy_delta_operation_evidence(evidence, operation, policy)?;
    Ok(())
}

pub(crate) fn require_policy_delta_stage_action_evidence(
    evidence: &[EndpointReceiptEvidence],
    action: &EndpointDecisionAction,
) -> Result<()> {
    let stage_hash = evidence_value_hash(evidence, "stage", "policy delta stage evidence")?;
    let Some(stage) = policy_delta_stage_from_hash(stage_hash) else {
        return Err(anyhow!(
            "policy delta stage evidence must be observe, audit, warn, limited_block, or full_block"
        ));
    };
    if matches!(stage, "limited_block" | "full_block")
        && !policy_delta_receipt_enforcement_action_supported(action)
    {
        return Err(anyhow!(
            "policy delta enforcement stage requires a rollback-capable policy action"
        ));
    }
    Ok(())
}

pub(crate) fn policy_delta_stage_from_hash(stage_hash: &str) -> Option<&'static str> {
    ["observe", "audit", "warn", "limited_block", "full_block"]
        .into_iter()
        .find(|stage| {
            let expected_hash = sha256(stage.as_bytes()).to_hex_prefixed();
            hex_strings_match(expected_hash.as_str(), stage_hash)
        })
}

pub(crate) fn policy_delta_receipt_enforcement_action_supported(
    action: &EndpointDecisionAction,
) -> bool {
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

pub(crate) fn policy_delta_operation_from_title(decision: &EndpointDecisionRecord) -> Result<&str> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta operation title is required"))?;
    let Some(operation) = title.strip_prefix("Endpoint staged policy delta ") else {
        return Err(anyhow!("policy delta operation title is invalid"));
    };
    match operation {
        "generated" | "prepared" | "applied" => Ok(operation),
        _ => Err(anyhow!("policy delta operation title is invalid")),
    }
}

pub(crate) fn require_policy_delta_operation_evidence(
    evidence: &[EndpointReceiptEvidence],
    operation: &str,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let has_previous_policy_hash = evidence.iter().any(|item| item.key == "previousPolicyHash");
    let has_new_policy_hash = evidence.iter().any(|item| item.key == "newPolicyHash");
    let has_backup_path = evidence.iter().any(|item| item.key == "backupPath");

    match operation {
        "generated" => {
            if has_previous_policy_hash || has_new_policy_hash || has_backup_path {
                return Err(anyhow!(
                    "policy delta generated receipt must not include apply evidence"
                ));
            }
        }
        "prepared" | "applied" => {
            require_nonempty_hashed_evidence(
                evidence,
                "previousPolicyHash",
                "policy delta applied previous policy evidence",
            )?;
            require_evidence_value_hash(
                evidence,
                "newPolicyHash",
                policy.policy_hash.as_str(),
                "policy delta applied new policy evidence",
            )?;
            require_nonempty_hashed_evidence(
                evidence,
                "backupPath",
                "policy delta applied backup evidence",
            )?;
        }
        _ => unreachable!("policy delta operation already validated"),
    }

    Ok(())
}

pub(crate) fn policy_delta_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    rule_id: &str,
    action: &EndpointDecisionAction,
) -> Result<String> {
    Ok(stable_id(
        "policy_delta",
        [
            endpoint_id,
            rule_id,
            action.as_str(),
            evidence_value_hash(
                evidence,
                "stagedDetectionId",
                "policy delta staged detection evidence",
            )?,
            evidence_value_hash(evidence, "stage", "policy delta stage evidence")?,
            evidence_value_hash(
                evidence,
                "generatedAt",
                "policy delta generated-at evidence",
            )?,
            evidence_value_hash(evidence, "simulationId", "policy delta simulation evidence")?,
            evidence_value_hash(
                evidence,
                "graphSliceId",
                "policy delta graph slice evidence",
            )?,
            evidence_value_hash(evidence, "rootNodeId", "policy delta root node evidence")?,
            evidence_value_hash(
                evidence,
                "sourceAffectedIdentityContext",
                "policy delta source affected identity context evidence",
            )?,
            evidence_value_hash(
                evidence,
                "sourceAffectedToolContext",
                "policy delta source affected tool context evidence",
            )?,
        ],
    ))
}

pub(crate) fn require_policy_delta_graph_reference(graph: &EndpointGraphReference) -> Result<()> {
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta root node id is required"))?;
    if !graph.node_ids.iter().any(|node_id| node_id == root_node_id) {
        return Err(anyhow!(
            "policy delta root node reference must be included in graph node ids"
        ));
    }
    Ok(())
}
