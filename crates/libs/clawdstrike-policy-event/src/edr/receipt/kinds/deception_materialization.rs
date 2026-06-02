use super::super::*;

pub(crate) struct DeceptionMaterializationIdValues<'a> {
    pub(crate) plan_root: &'a str,
    pub(crate) plan_hash: &'a str,
    pub(crate) report_hash: &'a str,
    pub(crate) artifact_count: &'a str,
    pub(crate) created_count: &'a str,
    pub(crate) skipped_count: &'a str,
    pub(crate) registered_artifact_count: &'a str,
    pub(crate) artifact_ids: &'a str,
}

pub(crate) struct DeceptionMaterializationIdEvidenceHashes<'a> {
    plan_root_evidence_hash: &'a str,
    plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    artifact_count_evidence_hash: &'a str,
    created_count_evidence_hash: &'a str,
    skipped_count_evidence_hash: &'a str,
    registered_artifact_count_evidence_hash: &'a str,
    artifact_ids_evidence_hash: &'a str,
}

pub(crate) fn deception_materialization_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionMaterializationIdValues<'_>,
) -> String {
    let plan_root_evidence_hash = sha256(values.plan_root.as_bytes()).to_hex_prefixed();
    let plan_hash_evidence_hash = sha256(values.plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let artifact_count_evidence_hash = sha256(values.artifact_count.as_bytes()).to_hex_prefixed();
    let created_count_evidence_hash = sha256(values.created_count.as_bytes()).to_hex_prefixed();
    let skipped_count_evidence_hash = sha256(values.skipped_count.as_bytes()).to_hex_prefixed();
    let registered_artifact_count_evidence_hash =
        sha256(values.registered_artifact_count.as_bytes()).to_hex_prefixed();
    let artifact_ids_evidence_hash = sha256(values.artifact_ids.as_bytes()).to_hex_prefixed();
    deception_materialization_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionMaterializationIdEvidenceHashes {
            plan_root_evidence_hash: plan_root_evidence_hash.as_str(),
            plan_hash_evidence_hash: plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            artifact_count_evidence_hash: artifact_count_evidence_hash.as_str(),
            created_count_evidence_hash: created_count_evidence_hash.as_str(),
            skipped_count_evidence_hash: skipped_count_evidence_hash.as_str(),
            registered_artifact_count_evidence_hash: registered_artifact_count_evidence_hash
                .as_str(),
            artifact_ids_evidence_hash: artifact_ids_evidence_hash.as_str(),
        },
    )
}

pub(crate) fn deception_materialization_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanRoot",
        "deception materialization plan root evidence",
    )?;
    let plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanHash",
        "deception materialization plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "materializationReportHash",
        "deception materialization report hash evidence",
    )?;
    let artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "artifactCount",
        "deception materialization artifact count evidence",
    )?;
    let created_count_evidence_hash = evidence_value_hash(
        evidence,
        "createdCount",
        "deception materialization created count evidence",
    )?;
    let skipped_count_evidence_hash = evidence_value_hash(
        evidence,
        "skippedCount",
        "deception materialization skipped count evidence",
    )?;
    let registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "registeredArtifactCount",
        "deception materialization registered artifact count evidence",
    )?;
    let artifact_ids_evidence_hash = evidence_value_hash(
        evidence,
        "artifactIds",
        "deception materialization artifact ids evidence",
    )?;
    Ok(deception_materialization_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionMaterializationIdEvidenceHashes {
            plan_root_evidence_hash,
            plan_hash_evidence_hash,
            report_hash_evidence_hash,
            artifact_count_evidence_hash,
            created_count_evidence_hash,
            skipped_count_evidence_hash,
            registered_artifact_count_evidence_hash,
            artifact_ids_evidence_hash,
        },
    ))
}

pub(crate) fn deception_materialization_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionMaterializationIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_materialization",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.plan_root_evidence_hash,
            evidence_hashes.plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.artifact_count_evidence_hash,
            evidence_hashes.created_count_evidence_hash,
            evidence_hashes.skipped_count_evidence_hash,
            evidence_hashes.registered_artifact_count_evidence_hash,
            evidence_hashes.artifact_ids_evidence_hash,
        ],
    )
}

pub(crate) fn require_deception_materialization_evidence(
    evidence: &[EndpointReceiptEvidence],
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_materialization_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception materialization endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanRoot",
        "deception materialization plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanHash",
        "deception materialization plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "materializationReportHash",
        "deception materialization report hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactCount",
        "deception materialization artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "createdCount",
        "deception materialization created count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "skippedCount",
        "deception materialization skipped count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "registeredArtifactCount",
        "deception materialization registered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactIds",
        "deception materialization artifact ids evidence",
    )?;
    let materialization_id = deception_materialization_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_materialization_id != Some(materialization_id.as_str()) {
        return Err(anyhow!(
            "deception materialization id must match signed plan root, plan, report, count, and artifact evidence"
        ));
    }
    Ok(())
}
