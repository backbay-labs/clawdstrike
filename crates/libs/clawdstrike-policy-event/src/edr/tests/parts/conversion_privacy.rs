#[test]
fn endpoint_runtime_identity_deserialization_rejects_unknown_fields() {
    let signing = CodeSignatureStatus {
        trust: SignatureTrust::Signed,
        team_id: Some("TEAMID1234".to_string()),
        signing_id: Some("com.example.tool".to_string()),
        cdhash: Some("actual-cdhash".to_string()),
        expected_cdhash: Some("expected-cdhash".to_string()),
        notarized: Some(true),
    };

    assert_unknown_field_rejected::<CodeSignatureStatus>(
        serde_json::to_value(&signing).unwrap(),
        "shadowCdhash",
    );

    let process = EndpointProcess {
        pid: Some(42),
        ppid: Some(7),
        process_guid: Some("proc-guid-42".to_string()),
        parent_process_guid: Some("proc-guid-7".to_string()),
        image: Some("/usr/local/bin/developer-tool".to_string()),
        command_line: Some("developer-tool build".to_string()),
        cwd: Some("/repo".to_string()),
        signing,
    };

    assert_unknown_field_rejected::<EndpointProcess>(
        serde_json::to_value(&process).unwrap(),
        "shadowProcessGuid",
    );

    let mut process_with_unknown_signing = serde_json::to_value(&process).unwrap();
    process_with_unknown_signing["signing"]["shadowCdhash"] =
        serde_json::Value::String("must not be ignored".to_string());
    let err = serde_json::from_value::<EndpointProcess>(process_with_unknown_signing)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowCdhash"),
        "expected unknown nested signing field to be rejected, got {err}"
    );
}

#[test]
fn endpoint_observation_and_causal_graph_deserialization_reject_unknown_fields() {
    let observation = observation(EndpointEvent::NetworkFlow {
        host: "egress.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://egress.example.invalid/upload".to_string()),
    });

    assert_unknown_field_rejected::<EndpointObservation>(
        serde_json::to_value(&observation).unwrap(),
        "shadowObservationId",
    );

    let mut recorder = CausalGraphRecorder::new();
    recorder.record_observation(&observation);
    let graph = recorder.into_graph();

    assert_unknown_field_rejected::<CausalGraph>(
        serde_json::to_value(&graph).unwrap(),
        "shadowNodeCount",
    );
    let node = graph
        .nodes
        .values()
        .next()
        .unwrap_or_else(|| panic!("expected graph node for strict serde regression"));
    assert_unknown_field_rejected::<CausalNode>(serde_json::to_value(node).unwrap(), "shadowLabel");
    let edge = graph
        .edges
        .first()
        .unwrap_or_else(|| panic!("expected graph edge for strict serde regression"));
    assert_unknown_field_rejected::<CausalEdge>(
        serde_json::to_value(edge).unwrap(),
        "shadowObservationId",
    );
}

#[test]
fn endpoint_receipt_evidence_deserialization_requires_redaction_class() {
    let missing_redaction_class = serde_json::json!({
        "key": "policyHash",
        "valueHash": sha256(b"policy@1").to_hex_prefixed()
    });
    let err = serde_json::from_value::<EndpointReceiptEvidence>(missing_redaction_class)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("redactionClass"),
        "expected missing redactionClass to be rejected, got {err}"
    );

    let explicit_redaction_class = serde_json::json!({
        "key": "policyHash",
        "valueHash": sha256(b"policy@1").to_hex_prefixed(),
        "redactionClass": "hash_only"
    });
    let evidence = serde_json::from_value::<EndpointReceiptEvidence>(explicit_redaction_class)
        .unwrap_or_else(|err| panic!("explicit redaction class should deserialize: {err}"));
    assert_eq!(
        evidence.redaction_class,
        EndpointEvidenceRedactionClass::HashOnly
    );
    assert!(evidence.raw_value.is_none());

    let unknown_evidence_field = serde_json::json!({
        "key": "policyHash",
        "valueHash": sha256(b"policy@1").to_hex_prefixed(),
        "redactionClass": "hash_only",
        "rawSecret": "must not be ignored"
    });
    let err = serde_json::from_value::<EndpointReceiptEvidence>(unknown_evidence_field)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("rawSecret"),
        "expected unknown evidence field to be rejected, got {err}"
    );
}

#[test]
fn telemetry_privacy_report_hashes_features_and_suppresses_raw_artifacts_by_default() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/Work/customer-secret.txt".to_string(),
        source_url: Some("https://intranet.example/download?token=secret".to_string()),
        content_preview: Some("raw customer token material".to_string()),
    });

    let report = EndpointTelemetryPrivacyReport::from_observations(
        &[event],
        EndpointTelemetryPrivacyMode::HashesFeatures,
    );

    assert_eq!(report.observation_count, 1);
    assert!(!report.raw_artifact_upload_permitted);
    assert!(report.hash_only_count > 0);
    assert!(report.raw_suppressed_count > 0);
    assert!(report.observations[0].projections.iter().any(|projection| {
        projection.field_path == "event.fileAccess.path"
            && projection.redaction_class == EndpointEvidenceRedactionClass::HashOnly
            && projection.raw_value.is_none()
            && projection
                .value_hash
                .as_deref()
                .is_some_and(|hash| hash.starts_with("0x"))
    }));
    assert!(report.observations[0].projections.iter().any(|projection| {
        projection.field_path == "event.fileAccess.contentPreview"
            && projection.redaction_class == EndpointEvidenceRedactionClass::LocalOnly
            && projection.raw_value.is_none()
    }));
}

#[test]
fn telemetry_privacy_report_deserialization_rejects_unknown_fields() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/Work/customer-secret.txt".to_string(),
        source_url: Some("https://intranet.example/download?token=secret".to_string()),
        content_preview: Some("raw customer token material".to_string()),
    });
    let report = EndpointTelemetryPrivacyReport::from_observations(
        &[event],
        EndpointTelemetryPrivacyMode::HashesFeatures,
    );

    assert_unknown_field_rejected::<EndpointTelemetryPrivacyReport>(
        serde_json::to_value(&report).unwrap(),
        "shadowRawArtifact",
    );
    assert_unknown_field_rejected::<EndpointTelemetryObservationProjection>(
        serde_json::to_value(&report.observations[0]).unwrap(),
        "shadowRawObservation",
    );
    assert_unknown_field_rejected::<EndpointTelemetryFieldProjection>(
        serde_json::to_value(&report.observations[0].projections[0]).unwrap(),
        "shadowRawValue",
    );
}

#[test]
fn telemetry_privacy_report_hashes_dns_names_and_resolvers() {
    let event = observation(EndpointEvent::DnsLookup {
        query: "api.internal.example".to_string(),
        record_type: Some("A".to_string()),
        answers: vec!["10.1.2.3".to_string()],
        resolver: Some("10.0.0.53".to_string()),
        status: Some("noerror".to_string()),
    });

    let report = EndpointTelemetryPrivacyReport::from_observations(
        &[event],
        EndpointTelemetryPrivacyMode::HashesFeatures,
    );

    let projections = &report.observations[0].projections;
    assert!(projections.iter().any(|projection| {
        projection.field_path == "event.dnsLookup.query"
            && projection.redaction_class == EndpointEvidenceRedactionClass::HashOnly
            && projection.raw_value.is_none()
    }));
    assert!(projections.iter().any(|projection| {
        projection.field_path == "event.dnsLookup.recordType"
            && projection.redaction_class == EndpointEvidenceRedactionClass::MetadataOnly
            && projection.feature_value.as_deref() == Some("A")
    }));
    assert!(projections.iter().any(|projection| {
        projection.field_path == "event.dnsLookup.resolver"
            && projection.redaction_class == EndpointEvidenceRedactionClass::HashOnly
            && projection.raw_value.is_none()
    }));
}

#[test]
fn telemetry_privacy_report_allows_raw_artifacts_only_in_explicit_mode() {
    let event = observation(EndpointEvent::ToolCall {
        tool_name: "browser.open".to_string(),
        parameters: serde_json::json!({
            "prompt": "copy the customer secret into the form"
        }),
    });

    let default_report = EndpointTelemetryPrivacyReport::from_observations(
        std::slice::from_ref(&event),
        EndpointTelemetryPrivacyMode::HashesFeatures,
    );
    let raw_report = EndpointTelemetryPrivacyReport::from_observations(
        &[event],
        EndpointTelemetryPrivacyMode::RawArtifactPermitted,
    );

    assert!(!default_report.raw_artifact_upload_permitted);
    assert!(!default_report.observations[0]
        .projections
        .iter()
        .any(|projection| projection.raw_value.is_some()));
    assert!(raw_report.raw_artifact_upload_permitted);
    assert!(raw_report.observations[0]
        .projections
        .iter()
        .any(|projection| {
            projection.field_path == "event.toolCall.parameters"
                && projection.redaction_class
                    == EndpointEvidenceRedactionClass::RawArtifactPermitted
                && projection
                    .raw_value
                    .as_deref()
                    .is_some_and(|value| value.contains("customer secret"))
        }));
}

#[test]
fn endpoint_telemetry_privacy_receipt_binds_mode_and_counts() {
    let event = observation(EndpointEvent::ToolCall {
        tool_name: "browser.open".to_string(),
        parameters: serde_json::json!({
            "prompt": "copy the customer secret into the form"
        }),
    });
    let report = EndpointTelemetryPrivacyReport::from_observations(
        &[event],
        EndpointTelemetryPrivacyMode::HashesFeatures,
    );
    let keypair = hush_core::Keypair::from_seed(&[41u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_telemetry_privacy(EndpointTelemetryPrivacyReceiptInput {
            local_sequence: 41,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            report: &report,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::PrivacyReport
    );
    assert_eq!(
        receipt.decision.finding_id.as_deref(),
        Some(report.report_id.as_str())
    );
    assert_eq!(
        receipt.decision.rule_id.as_deref(),
        Some("endpoint.telemetry_privacy")
    );
    assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "privacyMode"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "projectionContentHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "rawSuppressedCount"));
    assert!(receipt.evidence.iter().all(|item| item.raw_value.is_none()));

    let mut leaked_hash_only_receipt = receipt.clone();
    leaked_hash_only_receipt.evidence[0].raw_value =
        Some("raw customer secret material".to_string());
    assert!(leaked_hash_only_receipt
        .validate()
        .unwrap_err()
        .to_string()
        .contains("raw evidence"));

    let mut mismatched_report_id = receipt.clone();
    if let Some(report_id_evidence) = mismatched_report_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "privacyReportId")
    {
        *report_id_evidence =
            EndpointReceiptEvidence::hashed("privacyReportId", "telemetry_privacy_report:other");
    }
    assert!(mismatched_report_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("privacy report id evidence hash"));

    let mut relabeled_report_id = receipt.clone();
    relabeled_report_id.decision.finding_id = Some("telemetry_privacy_report:other".to_string());
    if let Some(report_id_evidence) = relabeled_report_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "privacyReportId")
    {
        *report_id_evidence =
            EndpointReceiptEvidence::hashed("privacyReportId", "telemetry_privacy_report:other");
    }
    assert!(relabeled_report_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("privacy report id"));

    let mut missing_raw_suppressed_count = receipt.clone();
    missing_raw_suppressed_count
        .evidence
        .retain(|item| item.key != "rawSuppressedCount");
    assert!(missing_raw_suppressed_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("privacy report raw suppressed count evidence"));

    let mut missing_projection_content_hash = receipt.clone();
    missing_projection_content_hash
        .evidence
        .retain(|item| item.key != "projectionContentHash");
    assert!(missing_projection_content_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("privacy report projection content hash evidence"));

    let mut mismatched_raw_receipt = receipt;
    mismatched_raw_receipt.evidence[0].redaction_class =
        EndpointEvidenceRedactionClass::RawArtifactPermitted;
    mismatched_raw_receipt.evidence[0].raw_value =
        Some("different raw customer secret material".to_string());
    assert!(mismatched_raw_receipt
        .validate()
        .unwrap_err()
        .to_string()
        .contains("raw evidence hash"));
}

#[test]
fn endpoint_telemetry_privacy_receipt_binds_raw_artifact_approval() {
    let event = observation(EndpointEvent::ToolCall {
        tool_name: "browser.open".to_string(),
        parameters: serde_json::json!({
            "prompt": "copy the customer secret into the form"
        }),
    });
    let reason_hash = sha256(b"incident ir-41 live collection approved").to_hex_prefixed();
    let report = EndpointTelemetryPrivacyReport::from_observations_with_raw_artifact_approval(
        &[event],
        EndpointTelemetryPrivacyMode::RawArtifactPermitted,
        Some("approval-ir-41"),
        Some(reason_hash.as_str()),
    );
    let receipt =
        EndpointDecisionReceipt::for_telemetry_privacy(EndpointTelemetryPrivacyReceiptInput {
            local_sequence: 42,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            report: &report,
        });

    receipt
        .validate()
        .expect("raw privacy receipt should validate");
    assert_eq!(
        report.raw_artifact_approval_id.as_deref(),
        Some("approval-ir-41")
    );
    assert_eq!(
        report.raw_artifact_approval_reason_hash.as_deref(),
        Some(reason_hash.as_str())
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "rawArtifactApprovalId"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "rawArtifactApprovalReasonHash"));

    let mut missing_approval = receipt.clone();
    missing_approval
        .evidence
        .retain(|item| item.key != "rawArtifactApprovalId");
    assert!(missing_approval
        .validate()
        .unwrap_err()
        .to_string()
        .contains("privacy report raw artifact approval id evidence"));

    let mut mismatched_approval = receipt;
    if let Some(approval) = mismatched_approval
        .evidence
        .iter_mut()
        .find(|item| item.key == "rawArtifactApprovalId")
    {
        *approval = EndpointReceiptEvidence::hashed("rawArtifactApprovalId", "approval-other");
    }
    assert!(mismatched_approval
        .validate()
        .unwrap_err()
        .to_string()
        .contains("privacy report id"));
}

#[test]
fn policy_event_converts_to_endpoint_observation() {
    let event = PolicyEvent {
        event_id: "policy-1".to_string(),
        event_type: PolicyEventType::NetworkEgress,
        timestamp: Utc::now(),
        session_id: Some("session".to_string()),
        data: PolicyEventData::Network(NetworkEventData {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://api.example.com/v1".to_string()),
        }),
        metadata: Some(serde_json::json!({
            "endpointId": "endpoint-policy-1",
            "principalId": "principal-policy-1",
            "endpointAgentId": "agent-policy-1",
            "workload_identity": "spiffe://example.test/workload/policy-1",
            "approval_id": "approval-policy-1",
            "process": {
                "pid": 9,
                "image": "/usr/bin/python3",
                "commandLine": "python3 script.py"
            }
        })),
        context: Some(serde_json::json!({
            "endpoint_id": "endpoint-context-should-not-win",
            "principalId": "principal-context-should-not-win"
        })),
    };

    let observation = EndpointObservation::from_policy_event(&event);

    assert_eq!(observation.observation_id, "policy-1");
    assert_eq!(observation.host_id.as_deref(), Some("endpoint-policy-1"));
    assert_eq!(observation.user_id.as_deref(), Some("principal-policy-1"));
    assert_eq!(observation.process.pid, Some(9));
    match &observation.event {
        EndpointEvent::NetworkFlow { host, port, .. } => {
            assert_eq!(host, "api.example.com");
            assert_eq!(*port, 443);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    let actor = EndpointDecisionActor::from_observation("endpoint-policy-1", &observation);
    assert_eq!(actor.agent_id.as_deref(), Some("agent-policy-1"));
    assert_eq!(
        actor.workload_id.as_deref(),
        Some("spiffe://example.test/workload/policy-1")
    );
    assert_eq!(actor.approval_id.as_deref(), Some("approval-policy-1"));

    let mut recorder = CausalGraphRecorder::new();
    let touched_nodes = recorder.record_observation(&observation);
    let process_node = recorder
        .graph()
        .nodes
        .get(&touched_nodes[0])
        .unwrap_or_else(|| panic!("missing process node"));
    assert_eq!(process_node.attributes["agentId"], "agent-policy-1");
    assert_eq!(
        process_node.attributes["workloadId"],
        "spiffe://example.test/workload/policy-1"
    );
    assert_eq!(process_node.attributes["approvalId"], "approval-policy-1");
}

#[test]
fn policy_event_context_identity_converts_to_endpoint_observation() {
    let event = PolicyEvent {
        event_id: "policy-context-1".to_string(),
        event_type: PolicyEventType::ToolCall,
        timestamp: Utc::now(),
        session_id: None,
        data: PolicyEventData::Tool(ToolEventData {
            tool_name: "mcp__filesystem__read_file".to_string(),
            parameters: serde_json::json!({ "path": "/repo/.env" }),
        }),
        metadata: Some(serde_json::json!({
            "process": {
                "pid": 11,
                "image": "/usr/bin/node",
                "commandLine": "node mcp-server.js"
            }
        })),
        context: Some(serde_json::json!({
            "endpoint_id": "endpoint-context-1",
            "identity": {
                "id": "principal-context-1"
            },
            "session": {
                "session_id": "session-context-1"
            },
            "metadata": {
                "runtimeAgentId": "runtime-agent-context-1",
                "spiffeId": "spiffe://example.test/workload/context-1",
                "approvalRequestId": "approval-context-1",
                "policyEpoch": 42,
                "policyVersion": "policy-context-v1"
            }
        })),
    };

    let observation = EndpointObservation::from_policy_event(&event);

    assert_eq!(observation.host_id.as_deref(), Some("endpoint-context-1"));
    assert_eq!(observation.user_id.as_deref(), Some("principal-context-1"));
    assert_eq!(observation.session_id.as_deref(), Some("session-context-1"));
    assert!(!observation.metadata.contains_key("context"));
    assert_eq!(observation.metadata["policyEpoch"], serde_json::json!(42));
    assert_eq!(
        observation.metadata["policyVersion"],
        serde_json::json!("policy-context-v1")
    );

    let actor = EndpointDecisionActor::from_observation("endpoint-context-1", &observation);
    assert_eq!(actor.agent_id.as_deref(), Some("runtime-agent-context-1"));
    assert_eq!(
        actor.workload_id.as_deref(),
        Some("spiffe://example.test/workload/context-1")
    );
    assert_eq!(actor.approval_id.as_deref(), Some("approval-context-1"));

    let mut recorder = CausalGraphRecorder::new();
    let touched_nodes = recorder.record_observation(&observation);
    let process_node = recorder
        .graph()
        .nodes
        .get(&touched_nodes[0])
        .unwrap_or_else(|| panic!("missing process node"));
    assert_eq!(
        process_node.attributes["agentId"],
        "runtime-agent-context-1"
    );
    assert_eq!(
        process_node.attributes["workloadId"],
        "spiffe://example.test/workload/context-1"
    );
    assert_eq!(process_node.attributes["approvalId"], "approval-context-1");
}

#[test]
fn endpoint_observation_projects_to_policy_event() {
    let observation = EndpointObservation {
        observation_id: "history-network-1".to_string(),
        timestamp: Utc::now(),
        host_id: Some("host-1".to_string()),
        session_id: Some("session-1".to_string()),
        process: EndpointProcess {
            pid: Some(42),
            image: Some("/usr/bin/curl".to_string()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::NetworkFlow {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://api.example.com/v1".to_string()),
        },
        ..EndpointObservation::default()
    };

    let event = observation.to_policy_event_projection();

    event
        .validate()
        .unwrap_or_else(|err| panic!("projected policy event should validate: {err}"));
    assert_eq!(event.event_id, "history-network-1");
    assert_eq!(event.event_type, PolicyEventType::NetworkEgress);
    assert_eq!(event.session_id.as_deref(), Some("session-1"));
    match event.data {
        PolicyEventData::Network(network) => {
            assert_eq!(network.host, "api.example.com");
            assert_eq!(network.port, 443);
            assert_eq!(network.protocol.as_deref(), Some("tcp"));
        }
        other => panic!("unexpected projected data: {other:?}"),
    }
    let metadata = event
        .metadata
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_else(|| panic!("projected event should carry endpoint metadata"));
    assert_eq!(metadata["hostId"], "host-1");
    assert_eq!(metadata["endpointObservationId"], "history-network-1");
    assert_eq!(metadata["endpointEventKind"], "network_flow");
}

#[test]
fn dns_lookup_projects_to_custom_policy_event_and_round_trips() {
    let observation = EndpointObservation {
        observation_id: "history-dns-1".to_string(),
        timestamp: Utc::now(),
        host_id: Some("host-1".to_string()),
        session_id: Some("session-1".to_string()),
        process: EndpointProcess {
            pid: Some(42),
            image: Some("/usr/bin/dig".to_string()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::DnsLookup {
            query: "api.internal.example".to_string(),
            record_type: Some("AAAA".to_string()),
            answers: vec!["2001:db8::10".to_string()],
            resolver: Some("fd00::53".to_string()),
            status: Some("noerror".to_string()),
        },
        ..EndpointObservation::default()
    };

    let event = observation.to_policy_event_projection();

    event
        .validate()
        .unwrap_or_else(|err| panic!("projected DNS policy event should validate: {err}"));
    assert_eq!(event.event_id, "history-dns-1");
    assert_eq!(event.event_type, PolicyEventType::Custom);
    let PolicyEventData::Custom(custom) = &event.data else {
        panic!("unexpected projected data: {:?}", event.data);
    };
    assert_eq!(custom.custom_type, "endpoint.dns_lookup");
    assert_eq!(custom.extra["endpointEvent"]["type"], "dns_lookup");
    assert_eq!(
        custom.extra["endpointEvent"]["query"],
        "api.internal.example"
    );

    let round_trip = EndpointObservation::from_policy_event(&event);
    match &round_trip.event {
        EndpointEvent::DnsLookup {
            query,
            record_type,
            answers,
            resolver,
            status,
        } => {
            assert_eq!(query, "api.internal.example");
            assert_eq!(record_type.as_deref(), Some("AAAA"));
            assert_eq!(answers, &vec!["2001:db8::10".to_string()]);
            assert_eq!(resolver.as_deref(), Some("fd00::53"));
            assert_eq!(status.as_deref(), Some("noerror"));
        }
        other => panic!("unexpected round-trip event: {other:?}"),
    }
}

#[test]
fn browser_download_projection_preserves_artifact_proof_fields() {
    let content_hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let observation = EndpointObservation {
        observation_id: "history-browser-download-1".to_string(),
        timestamp: Utc::now(),
        host_id: Some("host-1".to_string()),
        session_id: Some("session-1".to_string()),
        process: EndpointProcess {
            pid: Some(42),
            image: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::BrowserDownload {
            browser: "chrome".to_string(),
            path: "/Users/alice/Downloads/tool.pkg".to_string(),
            source_url: Some("https://downloads.example.invalid/tool.pkg".to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(8192),
        },
        ..EndpointObservation::default()
    };

    let event = observation.to_policy_event_projection();

    event
        .validate()
        .unwrap_or_else(|err| panic!("projected browser download should validate: {err}"));
    let PolicyEventData::Custom(custom) = &event.data else {
        panic!("unexpected projected data: {:?}", event.data);
    };
    assert_eq!(custom.custom_type, "endpoint.browser_download");
    assert_eq!(custom.extra["endpointEvent"]["content_hash"], content_hash);
    assert_eq!(custom.extra["endpointEvent"]["byte_count"], 8192);

    let round_trip = EndpointObservation::from_policy_event(&event);
    match &round_trip.event {
        EndpointEvent::BrowserDownload {
            browser,
            path,
            source_url,
            content_hash: observed_hash,
            byte_count,
        } => {
            assert_eq!(browser, "chrome");
            assert_eq!(path, "/Users/alice/Downloads/tool.pkg");
            assert_eq!(
                source_url.as_deref(),
                Some("https://downloads.example.invalid/tool.pkg")
            );
            assert_eq!(observed_hash.as_deref(), Some(content_hash));
            assert_eq!(*byte_count, Some(8192));
        }
        other => panic!("unexpected round-trip event: {other:?}"),
    }

    let mut recorder = CausalGraphRecorder::new();
    recorder.record_observation(&round_trip);
    let download_node = recorder
        .graph()
        .nodes
        .values()
        .find(|node| node.kind == CausalNodeKind::BrowserDownload)
        .unwrap_or_else(|| panic!("missing browser download node"));
    assert_eq!(download_node.attributes["contentHash"], content_hash);
    assert_eq!(download_node.attributes["byteCount"], 8192);

    let report = EndpointTelemetryPrivacyReport::from_observations(
        &[round_trip],
        EndpointTelemetryPrivacyMode::HashesFeatures,
    );
    let projections = &report.observations[0].projections;
    assert!(projections.iter().any(|projection| {
        projection.field_path == "event.browserDownload.contentHash"
            && projection.redaction_class == EndpointEvidenceRedactionClass::MetadataOnly
            && projection.feature_value.as_deref() == Some(content_hash)
    }));
    assert!(projections.iter().any(|projection| {
        projection.field_path == "event.browserDownload.byteCount"
            && projection.redaction_class == EndpointEvidenceRedactionClass::MetadataOnly
            && projection.feature_value.as_deref() == Some("8192")
    }));
}

#[test]
fn policy_event_secret_scope_maps_to_typed_credential_detection() {
    let event = PolicyEvent {
        event_id: "policy-secret-1".to_string(),
        event_type: PolicyEventType::SecretAccess,
        timestamp: Utc::now(),
        session_id: Some("session".to_string()),
        data: PolicyEventData::Secret(crate::event::SecretEventData {
            secret_name: "NPM_TOKEN".to_string(),
            scope: "npm_registry".to_string(),
        }),
        metadata: Some(serde_json::json!({
            "process": {
                "pid": 9,
                "image": "/usr/bin/node",
                "commandLine": "node install.js"
            }
        })),
        context: None,
    };

    let observation = EndpointObservation::from_policy_event(&event);

    match &observation.event {
        EndpointEvent::CredentialAccess { kind, name, .. } => {
            assert_eq!(kind, &CredentialKind::PackageRegistryToken);
            assert_eq!(name.as_deref(), Some("NPM_TOKEN"));
        }
        other => panic!("unexpected event: {other:?}"),
    }

    let findings = SupplyChainRuntimeGuard::new().evaluate(&observation);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "supply_chain.developer_secret_access");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| { item.key == "credentialKind" && item.value == "package_registry_token" }));
}
