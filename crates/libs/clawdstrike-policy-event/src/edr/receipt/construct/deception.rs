use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_deception_materialization(
        input: EndpointDeceptionMaterializationReceiptInput<'_>,
    ) -> Self {
        let plan_value = serde_json::to_value(input.plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let plan_root = input.plan.root.display().to_string();
        let plan_hash = sha256(plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let artifact_count = input.plan.artifacts.len().to_string();
        let created_count = input.report.created.len().to_string();
        let skipped_count = input.report.skipped.len().to_string();
        let registered_artifact_count = input.registered_artifact_count.to_string();
        let mut artifact_ids = input
            .plan
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<Vec<_>>();
        artifact_ids.sort_unstable();
        let artifact_ids = artifact_ids.join(",");
        let materialization_id = deception_materialization_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionMaterializationIdValues {
                plan_root: plan_root.as_str(),
                plan_hash: plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                artifact_count: artifact_count.as_str(),
                created_count: created_count.as_str(),
                skipped_count: skipped_count.as_str(),
                registered_artifact_count: registered_artifact_count.as_str(),
                artifact_ids: artifact_ids.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionMaterialization,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(materialization_id),
                rule_id: Some("endpoint.deception.materialization".to_string()),
                title: Some("Endpoint deception materialized".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", plan_root),
                EndpointReceiptEvidence::hashed("deceptionPlanHash", &plan_hash),
                EndpointReceiptEvidence::hashed("materializationReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("artifactCount", artifact_count),
                EndpointReceiptEvidence::hashed("createdCount", created_count),
                EndpointReceiptEvidence::hashed("skippedCount", skipped_count),
                EndpointReceiptEvidence::hashed(
                    "registeredArtifactCount",
                    registered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed("artifactIds", artifact_ids),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_cleanup(input: EndpointDeceptionCleanupReceiptInput<'_>) -> Self {
        let plan_value = serde_json::to_value(input.plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let plan_root = input.plan.root.display().to_string();
        let plan_hash = sha256(plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let artifact_count = input.plan.artifacts.len().to_string();
        let dry_run = input.report.dry_run.to_string();
        let removed_count = input.report.removed.len().to_string();
        let would_remove_count = input.report.would_remove.len().to_string();
        let missing_count = input.report.missing.len().to_string();
        let refused_count = input.report.refused.len().to_string();
        let deregistered_artifact_count = input.deregistered_artifact_count.to_string();
        let remaining_registered_artifact_count =
            input.remaining_registered_artifact_count.to_string();
        let cleanup_id = deception_cleanup_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionCleanupIdValues {
                plan_root: plan_root.as_str(),
                plan_hash: plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                artifact_count: artifact_count.as_str(),
                dry_run: dry_run.as_str(),
                removed_count: removed_count.as_str(),
                would_remove_count: would_remove_count.as_str(),
                missing_count: missing_count.as_str(),
                refused_count: refused_count.as_str(),
                deregistered_artifact_count: deregistered_artifact_count.as_str(),
                remaining_registered_artifact_count: remaining_registered_artifact_count.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionCleanup,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(cleanup_id),
                rule_id: Some("endpoint.deception.cleanup".to_string()),
                title: Some(if input.report.dry_run {
                    "Endpoint deception cleanup dry run planned".to_string()
                } else {
                    "Endpoint deception cleanup executed".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: refused_count == "0",
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", plan_root),
                EndpointReceiptEvidence::hashed("deceptionPlanHash", &plan_hash),
                EndpointReceiptEvidence::hashed("cleanupReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("artifactCount", artifact_count),
                EndpointReceiptEvidence::hashed("dryRun", dry_run),
                EndpointReceiptEvidence::hashed("removedCount", removed_count),
                EndpointReceiptEvidence::hashed("wouldRemoveCount", would_remove_count),
                EndpointReceiptEvidence::hashed("missingCount", missing_count),
                EndpointReceiptEvidence::hashed("refusedCount", refused_count),
                EndpointReceiptEvidence::hashed(
                    "deregisteredArtifactCount",
                    deregistered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "remainingRegisteredArtifactCount",
                    remaining_registered_artifact_count,
                ),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_rotation(input: EndpointDeceptionRotationReceiptInput<'_>) -> Self {
        let old_plan_value = serde_json::to_value(input.old_plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.old_plan.endpoint_id.clone());
        let new_plan_value = serde_json::to_value(input.new_plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.new_plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let old_plan_root = input.old_plan.root.display().to_string();
        let new_plan_root = input.new_plan.root.display().to_string();
        let old_plan_hash = sha256(old_plan_value.as_bytes()).to_hex_prefixed();
        let new_plan_hash = sha256(new_plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let dry_run = input.report.dry_run.to_string();
        let cleanup_removed_count = input.report.cleanup.removed.len().to_string();
        let cleanup_would_remove_count = input.report.cleanup.would_remove.len().to_string();
        let cleanup_missing_count = input.report.cleanup.missing.len().to_string();
        let cleanup_refused_count = input.report.cleanup.refused.len().to_string();
        let materialization_created_count = input
            .report
            .materialization
            .as_ref()
            .map_or(0, |report| report.created.len())
            .to_string();
        let materialization_skipped_count = input
            .report
            .materialization
            .as_ref()
            .map_or(0, |report| report.skipped.len())
            .to_string();
        let deregistered_artifact_count = input.report.deregistered_artifact_count.to_string();
        let registered_artifact_count = input.report.registered_artifact_count.to_string();
        let remaining_registered_artifact_count =
            input.report.remaining_registered_artifact_count.to_string();
        let rotation_id = deception_rotation_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionRotationIdValues {
                old_plan_root: old_plan_root.as_str(),
                new_plan_root: new_plan_root.as_str(),
                old_plan_hash: old_plan_hash.as_str(),
                new_plan_hash: new_plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                dry_run: dry_run.as_str(),
                cleanup_removed_count: cleanup_removed_count.as_str(),
                cleanup_would_remove_count: cleanup_would_remove_count.as_str(),
                cleanup_missing_count: cleanup_missing_count.as_str(),
                cleanup_refused_count: cleanup_refused_count.as_str(),
                materialization_created_count: materialization_created_count.as_str(),
                materialization_skipped_count: materialization_skipped_count.as_str(),
                deregistered_artifact_count: deregistered_artifact_count.as_str(),
                registered_artifact_count: registered_artifact_count.as_str(),
                remaining_registered_artifact_count: remaining_registered_artifact_count.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionRotation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(rotation_id),
                rule_id: Some("endpoint.deception.rotation".to_string()),
                title: Some(if input.report.dry_run {
                    "Endpoint deception rotation dry run planned".to_string()
                } else {
                    "Endpoint deception rotation executed".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: cleanup_refused_count == "0",
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("oldDeceptionPlanRoot", old_plan_root),
                EndpointReceiptEvidence::hashed("newDeceptionPlanRoot", new_plan_root),
                EndpointReceiptEvidence::hashed("oldDeceptionPlanHash", &old_plan_hash),
                EndpointReceiptEvidence::hashed("newDeceptionPlanHash", &new_plan_hash),
                EndpointReceiptEvidence::hashed("rotationReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("dryRun", dry_run),
                EndpointReceiptEvidence::hashed("cleanupRemovedCount", cleanup_removed_count),
                EndpointReceiptEvidence::hashed(
                    "cleanupWouldRemoveCount",
                    cleanup_would_remove_count,
                ),
                EndpointReceiptEvidence::hashed("cleanupMissingCount", cleanup_missing_count),
                EndpointReceiptEvidence::hashed("cleanupRefusedCount", cleanup_refused_count),
                EndpointReceiptEvidence::hashed(
                    "materializationCreatedCount",
                    materialization_created_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "materializationSkippedCount",
                    materialization_skipped_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "deregisteredArtifactCount",
                    deregistered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "registeredArtifactCount",
                    registered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "remainingRegisteredArtifactCount",
                    remaining_registered_artifact_count,
                ),
            ],
        }
    }
}
