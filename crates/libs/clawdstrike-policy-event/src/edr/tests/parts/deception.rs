#[test]
fn deception_plan_materializes_without_overwriting_and_detects_access() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");

    let first = plan.materialize().unwrap();
    let second = plan.materialize().unwrap();

    assert_eq!(first.created.len(), plan.artifacts.len());
    assert_eq!(second.skipped.len(), plan.artifacts.len());

    let artifact = plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == HoneyArtifactKind::SshPrivateKey)
        .unwrap();
    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: artifact.absolute_path(&root).display().to_string(),
        source_url: None,
        content_preview: None,
    });

    let findings = guard.evaluate(&event);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn deception_and_detection_metadata_deserialization_rejects_unknown_fields() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let artifact = plan.artifacts[0].clone();
    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
    let materialization_report = DeceptionMaterializationReport {
        created: plan
            .artifacts
            .iter()
            .map(|artifact| artifact.absolute_path(&root).display().to_string())
            .collect(),
        skipped: Vec::new(),
    };
    let cleanup_report = DeceptionCleanupReport {
        dry_run: false,
        removed: materialization_report.created.clone(),
        would_remove: Vec::new(),
        missing: Vec::new(),
        refused: Vec::new(),
    };
    let rotation_report = DeceptionRotationReport {
        dry_run: false,
        cleanup: cleanup_report.clone(),
        materialization: Some(materialization_report.clone()),
        deregistered_artifact_count: plan.artifacts.len(),
        registered_artifact_count: plan.artifacts.len(),
        remaining_registered_artifact_count: plan.artifacts.len(),
    };
    let detection = DetectionFinding {
        finding_id: "finding:test".to_string(),
        rule_id: "deception.honey_artifact_touched".to_string(),
        title: "Honey artifact touched".to_string(),
        severity: DetectionSeverity::High,
        confidence: 0.99,
        description: "A honey artifact was accessed".to_string(),
        observation_id: "obs:test".to_string(),
        timestamp: Utc::now(),
        evidence: vec![DetectionEvidence {
            key: "artifactId".to_string(),
            value: artifact.artifact_id.clone(),
        }],
        mitre_attack: vec!["T1552".to_string()],
        tags: vec!["deception".to_string()],
        remediation: "Review causal graph".to_string(),
    };

    assert_unknown_field_rejected::<SupplyChainRuntimeGuard>(
        serde_json::to_value(&guard).unwrap(),
        "shadowHoneyArtifacts",
    );
    assert_unknown_field_rejected::<HoneyArtifact>(
        serde_json::to_value(&artifact).unwrap(),
        "shadowMarker",
    );
    assert_unknown_field_rejected::<DeceptionPlan>(
        serde_json::to_value(&plan).unwrap(),
        "shadowRoot",
    );
    assert_unknown_field_rejected::<DeceptionMaterializationReport>(
        serde_json::to_value(&materialization_report).unwrap(),
        "shadowCreated",
    );
    assert_unknown_field_rejected::<DeceptionCleanupReport>(
        serde_json::to_value(&cleanup_report).unwrap(),
        "shadowRemoved",
    );
    assert_unknown_field_rejected::<DeceptionRotationReport>(
        serde_json::to_value(&rotation_report).unwrap(),
        "shadowRotation",
    );
    assert_unknown_field_rejected::<DetectionEvidence>(
        serde_json::to_value(&detection.evidence[0]).unwrap(),
        "shadowEvidenceValue",
    );
    assert_unknown_field_rejected::<DetectionFinding>(
        serde_json::to_value(&detection).unwrap(),
        "shadowFinding",
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn deception_plan_detects_honey_hostname_network_flow() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let artifact = plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == HoneyArtifactKind::InternalHostname)
        .unwrap();
    let honey_host = artifact.internal_hostname().unwrap().to_string();
    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
    let event = observation(EndpointEvent::NetworkFlow {
        host: honey_host.clone(),
        port: 443,
        protocol: Some("https".to_string()),
        url: Some(format!("https://{honey_host}/admin")),
    });

    let findings = guard.evaluate(&event);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "matchType" && item.value == "network_destination"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn deception_plan_detects_honey_hostname_dns_lookup() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let artifact = plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == HoneyArtifactKind::InternalHostname)
        .unwrap();
    let honey_host = artifact.internal_hostname().unwrap().to_string();
    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
    let event = observation(EndpointEvent::DnsLookup {
        query: honey_host.clone(),
        record_type: Some("A".to_string()),
        answers: vec!["10.10.10.10".to_string()],
        resolver: Some("10.0.0.53".to_string()),
        status: Some("noerror".to_string()),
    });

    let findings = guard.evaluate(&event);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "matchType" && item.value == "dns_query"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn deception_plan_detects_browser_cookie_honey_value() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let artifact = plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == HoneyArtifactKind::BrowserCookieJar)
        .unwrap();
    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
    let event = observation(EndpointEvent::CredentialAccess {
        kind: CredentialKind::BrowserCookie,
        path: None,
        name: Some(format!("intranet.invalid/session={}", artifact.marker)),
    });

    let findings = guard.evaluate(&event);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "matchType" && item.value == "browser_cookie"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_deception_materialization_receipt_binds_plan_and_report() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let report = DeceptionMaterializationReport {
        created: plan
            .artifacts
            .iter()
            .map(|artifact| artifact.absolute_path(&root).display().to_string())
            .collect(),
        skipped: Vec::new(),
    };
    let keypair = hush_core::Keypair::from_seed(&[44u8; 32]);
    let mut receipt = EndpointDecisionReceipt::for_deception_materialization(
        EndpointDeceptionMaterializationReceiptInput {
            local_sequence: 44,
            endpoint_id: "endpoint-a",
            signer_identity: "local-edr:endpoint-a",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            plan: &plan,
            report: &report,
            registered_artifact_count: plan.artifacts.len(),
        },
    );
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::DeceptionMaterialization
    );
    assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
    assert!(receipt.decision.passed);
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "deceptionPlanHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "materializationReportHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "registeredArtifactCount"));

    let mut relabeled_plan_root = receipt.clone();
    if let Some(plan_root_evidence) = relabeled_plan_root
        .evidence
        .iter_mut()
        .find(|item| item.key == "deceptionPlanRoot")
    {
        *plan_root_evidence =
            EndpointReceiptEvidence::hashed("deceptionPlanRoot", "/tmp/other-plan-root");
    }
    assert!(relabeled_plan_root
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception materialization id"));

    let mut relabeled_artifact_ids = receipt.clone();
    if let Some(artifact_ids_evidence) = relabeled_artifact_ids
        .evidence
        .iter_mut()
        .find(|item| item.key == "artifactIds")
    {
        *artifact_ids_evidence = EndpointReceiptEvidence::hashed("artifactIds", "honey:other");
    }
    assert!(relabeled_artifact_ids
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception materialization id"));

    let mut mismatched_endpoint = receipt.clone();
    if let Some(endpoint_evidence) = mismatched_endpoint
        .evidence
        .iter_mut()
        .find(|item| item.key == "endpointId")
    {
        *endpoint_evidence = EndpointReceiptEvidence::hashed("endpointId", "endpoint-other");
    }
    assert!(mismatched_endpoint
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception materialization endpoint evidence hash"));

    let mut missing_artifact_count = receipt.clone();
    missing_artifact_count
        .evidence
        .retain(|item| item.key != "artifactCount");
    assert!(missing_artifact_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception materialization artifact count evidence"));

    let mut relabeled_materialization_id = receipt.clone();
    relabeled_materialization_id.decision.finding_id =
        Some("deception_materialization:other".to_string());
    assert!(relabeled_materialization_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception materialization id"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_deception_cleanup_receipt_binds_plan_and_report() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let report = DeceptionCleanupReport {
        dry_run: false,
        removed: plan
            .artifacts
            .iter()
            .map(|artifact| artifact.absolute_path(&root).display().to_string())
            .collect(),
        would_remove: Vec::new(),
        missing: Vec::new(),
        refused: Vec::new(),
    };
    let keypair = hush_core::Keypair::from_seed(&[45u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_deception_cleanup(EndpointDeceptionCleanupReceiptInput {
            local_sequence: 45,
            endpoint_id: "endpoint-a",
            signer_identity: "local-edr:endpoint-a",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            plan: &plan,
            report: &report,
            deregistered_artifact_count: plan.artifacts.len(),
            remaining_registered_artifact_count: 0,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::DeceptionCleanup
    );
    assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
    assert!(receipt.decision.passed);
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "deceptionPlanHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "cleanupReportHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "removedCount"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "deregisteredArtifactCount"));

    let mut relabeled_plan_root = receipt.clone();
    if let Some(plan_root_evidence) = relabeled_plan_root
        .evidence
        .iter_mut()
        .find(|item| item.key == "deceptionPlanRoot")
    {
        *plan_root_evidence =
            EndpointReceiptEvidence::hashed("deceptionPlanRoot", "/tmp/other-plan-root");
    }
    assert!(relabeled_plan_root
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup id"));

    let mut mismatched_dry_run = receipt.clone();
    if let Some(dry_run_evidence) = mismatched_dry_run
        .evidence
        .iter_mut()
        .find(|item| item.key == "dryRun")
    {
        *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "true");
    }
    assert!(mismatched_dry_run
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup dry-run evidence hash"));

    let mut mismatched_endpoint = receipt.clone();
    if let Some(endpoint_evidence) = mismatched_endpoint
        .evidence
        .iter_mut()
        .find(|item| item.key == "endpointId")
    {
        *endpoint_evidence = EndpointReceiptEvidence::hashed("endpointId", "endpoint-other");
    }
    assert!(mismatched_endpoint
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup endpoint evidence hash"));

    let mut missing_cleanup_report = receipt.clone();
    missing_cleanup_report
        .evidence
        .retain(|item| item.key != "cleanupReportHash");
    assert!(missing_cleanup_report
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup report hash evidence"));

    let mut inconsistent_refused_count = receipt.clone();
    if let Some(refused_count) = inconsistent_refused_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "refusedCount")
    {
        *refused_count = EndpointReceiptEvidence::hashed("refusedCount", "1");
    }
    assert!(inconsistent_refused_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup refused count evidence hash"));

    let mut relabeled_removed_count = receipt.clone();
    if let Some(removed_count) = relabeled_removed_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "removedCount")
    {
        *removed_count = EndpointReceiptEvidence::hashed("removedCount", "0");
    }
    assert!(relabeled_removed_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup id"));

    let mut relabeled_cleanup_id = receipt.clone();
    relabeled_cleanup_id.decision.finding_id = Some("deception_cleanup:other".to_string());
    assert!(relabeled_cleanup_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception cleanup id"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_deception_rotation_receipt_binds_old_and_new_plans() {
    let root = temp_root();
    let old_plan = DeceptionPlan::standard(&root, "endpoint-a-old");
    let new_plan = DeceptionPlan::standard(&root, "endpoint-a-new");
    let report = DeceptionRotationReport {
        dry_run: false,
        cleanup: DeceptionCleanupReport {
            dry_run: false,
            removed: old_plan
                .artifacts
                .iter()
                .map(|artifact| artifact.absolute_path(&root).display().to_string())
                .collect(),
            would_remove: Vec::new(),
            missing: Vec::new(),
            refused: Vec::new(),
        },
        materialization: Some(DeceptionMaterializationReport {
            created: new_plan
                .artifacts
                .iter()
                .map(|artifact| artifact.absolute_path(&root).display().to_string())
                .collect(),
            skipped: Vec::new(),
        }),
        deregistered_artifact_count: old_plan.artifacts.len(),
        registered_artifact_count: new_plan.artifacts.len(),
        remaining_registered_artifact_count: new_plan.artifacts.len(),
    };
    let keypair = hush_core::Keypair::from_seed(&[46u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_deception_rotation(EndpointDeceptionRotationReceiptInput {
            local_sequence: 46,
            endpoint_id: "endpoint-a",
            signer_identity: "local-edr:endpoint-a",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            old_plan: &old_plan,
            new_plan: &new_plan,
            report: &report,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::DeceptionRotation
    );
    assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
    assert!(receipt.decision.passed);
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "oldDeceptionPlanHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "newDeceptionPlanHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "rotationReportHash"));

    let mut relabeled_old_plan_root = receipt.clone();
    if let Some(plan_root_evidence) = relabeled_old_plan_root
        .evidence
        .iter_mut()
        .find(|item| item.key == "oldDeceptionPlanRoot")
    {
        *plan_root_evidence =
            EndpointReceiptEvidence::hashed("oldDeceptionPlanRoot", "/tmp/other-old-plan");
    }
    assert!(relabeled_old_plan_root
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation id"));

    let mut mismatched_dry_run = receipt.clone();
    if let Some(dry_run_evidence) = mismatched_dry_run
        .evidence
        .iter_mut()
        .find(|item| item.key == "dryRun")
    {
        *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "true");
    }
    assert!(mismatched_dry_run
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation dry-run evidence hash"));

    let mut mismatched_endpoint = receipt.clone();
    if let Some(endpoint_evidence) = mismatched_endpoint
        .evidence
        .iter_mut()
        .find(|item| item.key == "endpointId")
    {
        *endpoint_evidence = EndpointReceiptEvidence::hashed("endpointId", "endpoint-other");
    }
    assert!(mismatched_endpoint
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation endpoint evidence hash"));

    let mut missing_rotation_report = receipt.clone();
    missing_rotation_report
        .evidence
        .retain(|item| item.key != "rotationReportHash");
    assert!(missing_rotation_report
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation report hash evidence"));

    let mut inconsistent_refused_count = receipt.clone();
    if let Some(refused_count) = inconsistent_refused_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "cleanupRefusedCount")
    {
        *refused_count = EndpointReceiptEvidence::hashed("cleanupRefusedCount", "1");
    }
    assert!(inconsistent_refused_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation cleanup refused count evidence hash"));

    let mut relabeled_cleanup_removed_count = receipt.clone();
    if let Some(removed_count) = relabeled_cleanup_removed_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "cleanupRemovedCount")
    {
        *removed_count = EndpointReceiptEvidence::hashed("cleanupRemovedCount", "0");
    }
    assert!(relabeled_cleanup_removed_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation id"));

    let mut relabeled_rotation_id = receipt.clone();
    relabeled_rotation_id.decision.finding_id = Some("deception_rotation:other".to_string());
    assert!(relabeled_rotation_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("deception rotation id"));

    let _ = fs::remove_dir_all(root);
}

