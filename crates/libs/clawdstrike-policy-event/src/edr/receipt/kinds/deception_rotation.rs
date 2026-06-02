use super::super::*;

pub(crate) struct DeceptionRotationIdValues<'a> {
    pub(crate) old_plan_root: &'a str,
    pub(crate) new_plan_root: &'a str,
    pub(crate) old_plan_hash: &'a str,
    pub(crate) new_plan_hash: &'a str,
    pub(crate) report_hash: &'a str,
    pub(crate) dry_run: &'a str,
    pub(crate) cleanup_removed_count: &'a str,
    pub(crate) cleanup_would_remove_count: &'a str,
    pub(crate) cleanup_missing_count: &'a str,
    pub(crate) cleanup_refused_count: &'a str,
    pub(crate) materialization_created_count: &'a str,
    pub(crate) materialization_skipped_count: &'a str,
    pub(crate) deregistered_artifact_count: &'a str,
    pub(crate) registered_artifact_count: &'a str,
    pub(crate) remaining_registered_artifact_count: &'a str,
}

pub(crate) struct DeceptionRotationIdEvidenceHashes<'a> {
    old_plan_root_evidence_hash: &'a str,
    new_plan_root_evidence_hash: &'a str,
    old_plan_hash_evidence_hash: &'a str,
    new_plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    dry_run_evidence_hash: &'a str,
    cleanup_removed_count_evidence_hash: &'a str,
    cleanup_would_remove_count_evidence_hash: &'a str,
    cleanup_missing_count_evidence_hash: &'a str,
    cleanup_refused_count_evidence_hash: &'a str,
    materialization_created_count_evidence_hash: &'a str,
    materialization_skipped_count_evidence_hash: &'a str,
    deregistered_artifact_count_evidence_hash: &'a str,
    registered_artifact_count_evidence_hash: &'a str,
    remaining_registered_artifact_count_evidence_hash: &'a str,
}

pub(crate) fn deception_rotation_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionRotationIdValues<'_>,
) -> String {
    let old_plan_root_evidence_hash = sha256(values.old_plan_root.as_bytes()).to_hex_prefixed();
    let new_plan_root_evidence_hash = sha256(values.new_plan_root.as_bytes()).to_hex_prefixed();
    let old_plan_hash_evidence_hash = sha256(values.old_plan_hash.as_bytes()).to_hex_prefixed();
    let new_plan_hash_evidence_hash = sha256(values.new_plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let dry_run_evidence_hash = sha256(values.dry_run.as_bytes()).to_hex_prefixed();
    let cleanup_removed_count_evidence_hash =
        sha256(values.cleanup_removed_count.as_bytes()).to_hex_prefixed();
    let cleanup_would_remove_count_evidence_hash =
        sha256(values.cleanup_would_remove_count.as_bytes()).to_hex_prefixed();
    let cleanup_missing_count_evidence_hash =
        sha256(values.cleanup_missing_count.as_bytes()).to_hex_prefixed();
    let cleanup_refused_count_evidence_hash =
        sha256(values.cleanup_refused_count.as_bytes()).to_hex_prefixed();
    let materialization_created_count_evidence_hash =
        sha256(values.materialization_created_count.as_bytes()).to_hex_prefixed();
    let materialization_skipped_count_evidence_hash =
        sha256(values.materialization_skipped_count.as_bytes()).to_hex_prefixed();
    let deregistered_artifact_count_evidence_hash =
        sha256(values.deregistered_artifact_count.as_bytes()).to_hex_prefixed();
    let registered_artifact_count_evidence_hash =
        sha256(values.registered_artifact_count.as_bytes()).to_hex_prefixed();
    let remaining_registered_artifact_count_evidence_hash =
        sha256(values.remaining_registered_artifact_count.as_bytes()).to_hex_prefixed();
    deception_rotation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionRotationIdEvidenceHashes {
            old_plan_root_evidence_hash: old_plan_root_evidence_hash.as_str(),
            new_plan_root_evidence_hash: new_plan_root_evidence_hash.as_str(),
            old_plan_hash_evidence_hash: old_plan_hash_evidence_hash.as_str(),
            new_plan_hash_evidence_hash: new_plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            dry_run_evidence_hash: dry_run_evidence_hash.as_str(),
            cleanup_removed_count_evidence_hash: cleanup_removed_count_evidence_hash.as_str(),
            cleanup_would_remove_count_evidence_hash: cleanup_would_remove_count_evidence_hash
                .as_str(),
            cleanup_missing_count_evidence_hash: cleanup_missing_count_evidence_hash.as_str(),
            cleanup_refused_count_evidence_hash: cleanup_refused_count_evidence_hash.as_str(),
            materialization_created_count_evidence_hash:
                materialization_created_count_evidence_hash.as_str(),
            materialization_skipped_count_evidence_hash:
                materialization_skipped_count_evidence_hash.as_str(),
            deregistered_artifact_count_evidence_hash: deregistered_artifact_count_evidence_hash
                .as_str(),
            registered_artifact_count_evidence_hash: registered_artifact_count_evidence_hash
                .as_str(),
            remaining_registered_artifact_count_evidence_hash:
                remaining_registered_artifact_count_evidence_hash.as_str(),
        },
    )
}

pub(crate) fn deception_rotation_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let old_plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "oldDeceptionPlanRoot",
        "deception rotation old plan root evidence",
    )?;
    let new_plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "newDeceptionPlanRoot",
        "deception rotation new plan root evidence",
    )?;
    let old_plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "oldDeceptionPlanHash",
        "deception rotation old plan hash evidence",
    )?;
    let new_plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "newDeceptionPlanHash",
        "deception rotation new plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "rotationReportHash",
        "deception rotation report hash evidence",
    )?;
    let dry_run_evidence_hash =
        evidence_value_hash(evidence, "dryRun", "deception rotation dry-run evidence")?;
    let cleanup_removed_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupRemovedCount",
        "deception rotation cleanup removed count evidence",
    )?;
    let cleanup_would_remove_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupWouldRemoveCount",
        "deception rotation cleanup would-remove count evidence",
    )?;
    let cleanup_missing_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupMissingCount",
        "deception rotation cleanup missing count evidence",
    )?;
    let cleanup_refused_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupRefusedCount",
        "deception rotation cleanup refused count evidence",
    )?;
    let materialization_created_count_evidence_hash = evidence_value_hash(
        evidence,
        "materializationCreatedCount",
        "deception rotation materialization created count evidence",
    )?;
    let materialization_skipped_count_evidence_hash = evidence_value_hash(
        evidence,
        "materializationSkippedCount",
        "deception rotation materialization skipped count evidence",
    )?;
    let deregistered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "deregisteredArtifactCount",
        "deception rotation deregistered artifact count evidence",
    )?;
    let registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "registeredArtifactCount",
        "deception rotation registered artifact count evidence",
    )?;
    let remaining_registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception rotation remaining registered artifact count evidence",
    )?;
    Ok(deception_rotation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionRotationIdEvidenceHashes {
            old_plan_root_evidence_hash,
            new_plan_root_evidence_hash,
            old_plan_hash_evidence_hash,
            new_plan_hash_evidence_hash,
            report_hash_evidence_hash,
            dry_run_evidence_hash,
            cleanup_removed_count_evidence_hash,
            cleanup_would_remove_count_evidence_hash,
            cleanup_missing_count_evidence_hash,
            cleanup_refused_count_evidence_hash,
            materialization_created_count_evidence_hash,
            materialization_skipped_count_evidence_hash,
            deregistered_artifact_count_evidence_hash,
            registered_artifact_count_evidence_hash,
            remaining_registered_artifact_count_evidence_hash,
        },
    ))
}

pub(crate) fn deception_rotation_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionRotationIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_rotation",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.old_plan_root_evidence_hash,
            evidence_hashes.new_plan_root_evidence_hash,
            evidence_hashes.old_plan_hash_evidence_hash,
            evidence_hashes.new_plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.dry_run_evidence_hash,
            evidence_hashes.cleanup_removed_count_evidence_hash,
            evidence_hashes.cleanup_would_remove_count_evidence_hash,
            evidence_hashes.cleanup_missing_count_evidence_hash,
            evidence_hashes.cleanup_refused_count_evidence_hash,
            evidence_hashes.materialization_created_count_evidence_hash,
            evidence_hashes.materialization_skipped_count_evidence_hash,
            evidence_hashes.deregistered_artifact_count_evidence_hash,
            evidence_hashes.registered_artifact_count_evidence_hash,
            evidence_hashes.remaining_registered_artifact_count_evidence_hash,
        ],
    )
}

pub(crate) fn require_deception_rotation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_rotation_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception rotation endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "oldDeceptionPlanRoot",
        "deception rotation old plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "newDeceptionPlanRoot",
        "deception rotation new plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "oldDeceptionPlanHash",
        "deception rotation old plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "newDeceptionPlanHash",
        "deception rotation new plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "rotationReportHash",
        "deception rotation report hash evidence",
    )?;
    let dry_run = deception_rotation_dry_run_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "dryRun",
        dry_run.to_string(),
        "deception rotation dry-run evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupRemovedCount",
        "deception rotation cleanup removed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupWouldRemoveCount",
        "deception rotation cleanup would-remove count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupMissingCount",
        "deception rotation cleanup missing count evidence",
    )?;
    let refused_count = evidence
        .iter()
        .find(|item| item.key == "cleanupRefusedCount")
        .ok_or_else(|| anyhow!("deception rotation cleanup refused count evidence is required"))?;
    require_evidence_hash_not_empty(
        refused_count,
        "deception rotation cleanup refused count evidence",
    )?;
    let zero_refused_hash = sha256(b"0").to_hex_prefixed();
    let refused_count_is_zero = hex_strings_match(
        zero_refused_hash.as_str(),
        refused_count.value_hash.as_str(),
    );
    if decision.passed != refused_count_is_zero {
        return Err(anyhow!(
            "deception rotation cleanup refused count evidence hash must match signed pass state"
        ));
    }
    require_nonempty_hashed_evidence(
        evidence,
        "materializationCreatedCount",
        "deception rotation materialization created count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "materializationSkippedCount",
        "deception rotation materialization skipped count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deregisteredArtifactCount",
        "deception rotation deregistered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "registeredArtifactCount",
        "deception rotation registered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception rotation remaining registered artifact count evidence",
    )?;
    let rotation_id = deception_rotation_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_rotation_id != Some(rotation_id.as_str()) {
        return Err(anyhow!(
            "deception rotation id must match signed plan root, plan, report, mode, count, and registry evidence"
        ));
    }
    Ok(())
}

pub(crate) fn deception_rotation_dry_run_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("deception rotation title is required"))?;
    match title {
        "Endpoint deception rotation dry run planned" => Ok(true),
        "Endpoint deception rotation executed" => Ok(false),
        _ => Err(anyhow!("deception rotation title is invalid")),
    }
}
