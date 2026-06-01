use super::super::*;

pub(crate) struct PolicyDecisionIdFields<'a> {
    pub(crate) endpoint_id: &'a str,
    pub(crate) policy_hash: &'a str,
    pub(crate) policy_epoch: u64,
    pub(crate) actor_hash: &'a str,
    pub(crate) actor_session_id: &'a str,
    pub(crate) action_type: &'a str,
    pub(crate) target: &'a str,
    pub(crate) allowed: bool,
    pub(crate) guard: &'a str,
}

pub(crate) fn policy_decision_id_from_fields(fields: PolicyDecisionIdFields<'_>) -> String {
    let policy_epoch = fields.policy_epoch.to_string();
    let policy_epoch_evidence_hash = sha256(policy_epoch.as_bytes()).to_hex_prefixed();
    let actor_hash_evidence_hash = sha256(fields.actor_hash.as_bytes()).to_hex_prefixed();
    let actor_session_id_evidence_hash =
        sha256(fields.actor_session_id.as_bytes()).to_hex_prefixed();
    let target_evidence_hash = sha256(fields.target.as_bytes()).to_hex_prefixed();
    let guard_evidence_hash = sha256(fields.guard.as_bytes()).to_hex_prefixed();
    policy_decision_id_from_evidence_hashes(PolicyDecisionIdEvidenceHashes {
        endpoint_id: fields.endpoint_id,
        policy_hash: fields.policy_hash,
        policy_epoch_evidence_hash: policy_epoch_evidence_hash.as_str(),
        actor_hash_evidence_hash: actor_hash_evidence_hash.as_str(),
        actor_session_id_evidence_hash: actor_session_id_evidence_hash.as_str(),
        action_type: fields.action_type,
        target_evidence_hash: target_evidence_hash.as_str(),
        allowed: fields.allowed,
        guard_evidence_hash: guard_evidence_hash.as_str(),
    })
}

pub(crate) fn policy_decision_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    allowed: bool,
) -> Result<String> {
    let policy_epoch_evidence_hash = evidence_value_hash(
        evidence,
        "policyEpoch",
        "policy decision policy epoch evidence",
    )?;
    let actor_hash_evidence_hash =
        evidence_value_hash(evidence, "actorHash", "policy decision actor hash evidence")?;
    let actor_session_id_evidence_hash = evidence_value_hash(
        evidence,
        "actorSessionId",
        "policy decision actor session evidence",
    )?;
    let target_evidence_hash =
        evidence_value_hash(evidence, "target", "policy decision target evidence")?;
    let guard_evidence_hash =
        evidence_value_hash(evidence, "guard", "policy decision guard evidence")?;
    Ok(policy_decision_id_from_evidence_hashes(
        PolicyDecisionIdEvidenceHashes {
            endpoint_id,
            policy_hash,
            policy_epoch_evidence_hash,
            actor_hash_evidence_hash,
            actor_session_id_evidence_hash,
            action_type,
            target_evidence_hash,
            allowed,
            guard_evidence_hash,
        },
    ))
}

pub(crate) struct PolicyDecisionIdEvidenceHashes<'a> {
    endpoint_id: &'a str,
    policy_hash: &'a str,
    policy_epoch_evidence_hash: &'a str,
    actor_hash_evidence_hash: &'a str,
    actor_session_id_evidence_hash: &'a str,
    action_type: &'a str,
    target_evidence_hash: &'a str,
    allowed: bool,
    guard_evidence_hash: &'a str,
}

pub(crate) fn policy_decision_id_from_evidence_hashes(
    fields: PolicyDecisionIdEvidenceHashes<'_>,
) -> String {
    let allowed_text = fields.allowed.to_string();
    stable_id(
        "policy_decision",
        [
            fields.endpoint_id,
            fields.policy_hash,
            fields.policy_epoch_evidence_hash,
            fields.actor_hash_evidence_hash,
            fields.actor_session_id_evidence_hash,
            fields.action_type,
            fields.target_evidence_hash,
            allowed_text.as_str(),
            fields.guard_evidence_hash,
        ],
    )
}

pub(crate) fn require_policy_decision_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision observation id is required"))?;
    let signed_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision rule id is required"))?;
    let action_type = rule_id
        .strip_prefix("endpoint.policy_decision.")
        .ok_or_else(|| anyhow!("policy decision rule id must include action type"))?;
    require_nonempty(action_type, "policy decision action type")?;
    require_evidence_value_hash(
        evidence,
        "actionType",
        action_type,
        "policy decision action type evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "target", "policy decision target evidence")?;
    let actor_hash = endpoint_decision_actor_content_hash(actor);
    require_evidence_value_hash(
        evidence,
        "actorHash",
        actor_hash.as_str(),
        "policy decision actor hash evidence",
    )?;
    let actor_session_id = policy_decision_actor_session_value(actor);
    require_evidence_value_hash(
        evidence,
        "actorSessionId",
        actor_session_id.as_str(),
        "policy decision actor session evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "policyEpoch",
        policy.policy_epoch.to_string(),
        "policy decision policy epoch evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "observationId",
        observation_id,
        "policy decision observation id evidence",
    )?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision graph slice id is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision graph content hash is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision process node id is required"))?;
    require_detection_graph_reference(
        graph,
        observation_id,
        graph_slice_id,
        graph_content_hash,
        process_node_id,
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "policy decision graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        graph_content_hash,
        "policy decision graph content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "processNodeId",
        process_node_id,
        "policy decision process node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "allowed",
        decision.passed.to_string(),
        "policy decision allowed evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "guard", "policy decision guard evidence")?;
    let expected_decision_id = policy_decision_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
        action_type,
        decision.passed,
    )?;
    if signed_id != expected_decision_id {
        return Err(anyhow!(
            "policy decision id must match signed endpoint, policy, policy epoch, actor hash, actor session, action, target, allowed, and guard evidence"
        ));
    }
    if evidence.iter().any(|item| item.key == "severity") {
        require_nonempty_hashed_evidence(
            evidence,
            "severity",
            "policy decision severity evidence",
        )?;
    }
    if evidence.iter().any(|item| item.key == "message") {
        require_nonempty_hashed_evidence(evidence, "message", "policy decision message evidence")?;
    }
    if evidence.iter().any(|item| item.key == "details") {
        require_nonempty_hashed_evidence(evidence, "details", "policy decision details evidence")?;
    }
    Ok(())
}

pub(crate) fn policy_decision_actor_session_value(actor: &EndpointDecisionActor) -> String {
    actor
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("none")
        .to_string()
}
