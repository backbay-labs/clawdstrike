use super::super::*;

pub(crate) struct DeceptionCleanupIdValues<'a> {
    pub(crate) plan_root: &'a str,
    pub(crate) plan_hash: &'a str,
    pub(crate) report_hash: &'a str,
    pub(crate) artifact_count: &'a str,
    pub(crate) dry_run: &'a str,
    pub(crate) removed_count: &'a str,
    pub(crate) would_remove_count: &'a str,
    pub(crate) missing_count: &'a str,
    pub(crate) refused_count: &'a str,
    pub(crate) deregistered_artifact_count: &'a str,
    pub(crate) remaining_registered_artifact_count: &'a str,
}

pub(crate) struct DeceptionCleanupIdEvidenceHashes<'a> {
    plan_root_evidence_hash: &'a str,
    plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    artifact_count_evidence_hash: &'a str,
    dry_run_evidence_hash: &'a str,
    removed_count_evidence_hash: &'a str,
    would_remove_count_evidence_hash: &'a str,
    missing_count_evidence_hash: &'a str,
    refused_count_evidence_hash: &'a str,
    deregistered_artifact_count_evidence_hash: &'a str,
    remaining_registered_artifact_count_evidence_hash: &'a str,
}

pub(crate) fn deception_cleanup_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionCleanupIdValues<'_>,
) -> String {
    let plan_root_evidence_hash = sha256(values.plan_root.as_bytes()).to_hex_prefixed();
    let plan_hash_evidence_hash = sha256(values.plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let artifact_count_evidence_hash = sha256(values.artifact_count.as_bytes()).to_hex_prefixed();
    let dry_run_evidence_hash = sha256(values.dry_run.as_bytes()).to_hex_prefixed();
    let removed_count_evidence_hash = sha256(values.removed_count.as_bytes()).to_hex_prefixed();
    let would_remove_count_evidence_hash =
        sha256(values.would_remove_count.as_bytes()).to_hex_prefixed();
    let missing_count_evidence_hash = sha256(values.missing_count.as_bytes()).to_hex_prefixed();
    let refused_count_evidence_hash = sha256(values.refused_count.as_bytes()).to_hex_prefixed();
    let deregistered_artifact_count_evidence_hash =
        sha256(values.deregistered_artifact_count.as_bytes()).to_hex_prefixed();
    let remaining_registered_artifact_count_evidence_hash =
        sha256(values.remaining_registered_artifact_count.as_bytes()).to_hex_prefixed();
    deception_cleanup_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionCleanupIdEvidenceHashes {
            plan_root_evidence_hash: plan_root_evidence_hash.as_str(),
            plan_hash_evidence_hash: plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            artifact_count_evidence_hash: artifact_count_evidence_hash.as_str(),
            dry_run_evidence_hash: dry_run_evidence_hash.as_str(),
            removed_count_evidence_hash: removed_count_evidence_hash.as_str(),
            would_remove_count_evidence_hash: would_remove_count_evidence_hash.as_str(),
            missing_count_evidence_hash: missing_count_evidence_hash.as_str(),
            refused_count_evidence_hash: refused_count_evidence_hash.as_str(),
            deregistered_artifact_count_evidence_hash: deregistered_artifact_count_evidence_hash
                .as_str(),
            remaining_registered_artifact_count_evidence_hash:
                remaining_registered_artifact_count_evidence_hash.as_str(),
        },
    )
}

pub(crate) fn deception_cleanup_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanRoot",
        "deception cleanup plan root evidence",
    )?;
    let plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanHash",
        "deception cleanup plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupReportHash",
        "deception cleanup report hash evidence",
    )?;
    let artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "artifactCount",
        "deception cleanup artifact count evidence",
    )?;
    let dry_run_evidence_hash =
        evidence_value_hash(evidence, "dryRun", "deception cleanup dry-run evidence")?;
    let removed_count_evidence_hash = evidence_value_hash(
        evidence,
        "removedCount",
        "deception cleanup removed count evidence",
    )?;
    let would_remove_count_evidence_hash = evidence_value_hash(
        evidence,
        "wouldRemoveCount",
        "deception cleanup would-remove count evidence",
    )?;
    let missing_count_evidence_hash = evidence_value_hash(
        evidence,
        "missingCount",
        "deception cleanup missing count evidence",
    )?;
    let refused_count_evidence_hash = evidence_value_hash(
        evidence,
        "refusedCount",
        "deception cleanup refused count evidence",
    )?;
    let deregistered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "deregisteredArtifactCount",
        "deception cleanup deregistered artifact count evidence",
    )?;
    let remaining_registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception cleanup remaining registered artifact count evidence",
    )?;
    Ok(deception_cleanup_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionCleanupIdEvidenceHashes {
            plan_root_evidence_hash,
            plan_hash_evidence_hash,
            report_hash_evidence_hash,
            artifact_count_evidence_hash,
            dry_run_evidence_hash,
            removed_count_evidence_hash,
            would_remove_count_evidence_hash,
            missing_count_evidence_hash,
            refused_count_evidence_hash,
            deregistered_artifact_count_evidence_hash,
            remaining_registered_artifact_count_evidence_hash,
        },
    ))
}

pub(crate) fn deception_cleanup_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionCleanupIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_cleanup",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.plan_root_evidence_hash,
            evidence_hashes.plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.artifact_count_evidence_hash,
            evidence_hashes.dry_run_evidence_hash,
            evidence_hashes.removed_count_evidence_hash,
            evidence_hashes.would_remove_count_evidence_hash,
            evidence_hashes.missing_count_evidence_hash,
            evidence_hashes.refused_count_evidence_hash,
            evidence_hashes.deregistered_artifact_count_evidence_hash,
            evidence_hashes.remaining_registered_artifact_count_evidence_hash,
        ],
    )
}

pub(crate) fn require_deception_cleanup_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_cleanup_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception cleanup endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanRoot",
        "deception cleanup plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanHash",
        "deception cleanup plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupReportHash",
        "deception cleanup report hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactCount",
        "deception cleanup artifact count evidence",
    )?;
    let dry_run = deception_cleanup_dry_run_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "dryRun",
        dry_run.to_string(),
        "deception cleanup dry-run evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "removedCount",
        "deception cleanup removed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "wouldRemoveCount",
        "deception cleanup would-remove count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "missingCount",
        "deception cleanup missing count evidence",
    )?;
    let refused_count = evidence
        .iter()
        .find(|item| item.key == "refusedCount")
        .ok_or_else(|| anyhow!("deception cleanup refused count evidence is required"))?;
    require_evidence_hash_not_empty(refused_count, "deception cleanup refused count evidence")?;
    let zero_refused_hash = sha256(b"0").to_hex_prefixed();
    let refused_count_is_zero = hex_strings_match(
        zero_refused_hash.as_str(),
        refused_count.value_hash.as_str(),
    );
    if decision.passed != refused_count_is_zero {
        return Err(anyhow!(
            "deception cleanup refused count evidence hash must match signed pass state"
        ));
    }
    require_nonempty_hashed_evidence(
        evidence,
        "deregisteredArtifactCount",
        "deception cleanup deregistered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception cleanup remaining registered artifact count evidence",
    )?;
    let cleanup_id = deception_cleanup_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_cleanup_id != Some(cleanup_id.as_str()) {
        return Err(anyhow!(
            "deception cleanup id must match signed plan root, plan, report, mode, count, and registry evidence"
        ));
    }
    Ok(())
}

pub(crate) fn deception_cleanup_dry_run_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("deception cleanup title is required"))?;
    match title {
        "Endpoint deception cleanup dry run planned" => Ok(true),
        "Endpoint deception cleanup executed" => Ok(false),
        _ => Err(anyhow!("deception cleanup title is invalid")),
    }
}
