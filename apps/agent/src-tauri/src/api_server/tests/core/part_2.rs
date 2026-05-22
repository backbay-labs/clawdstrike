    #[test]
    fn endpoint_receipt_index_rebuilds_on_family_metadata_mismatch() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[91u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-receipt-index-1",
                signer_identity: "test-edr-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "receipt-index-test".to_string(),
                    policy_hash: sha256(b"receipt-index-test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                reason: "receipt index metadata validation",
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let signed = receipt
            .sign_with(&keypair)
            .unwrap_or_else(|e| panic!("failed to sign receipt index test receipt: {e}"));
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| panic!("failed to append receipt index test receipt: {e}"));

        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        let mut records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].family.as_deref(), Some("sensor_state"));
        records[0].family = Some("response_execution".to_string());
        let mut tampered_index = String::new();
        for record in &records {
            tampered_index.push_str(
                &serde_json::to_string(record)
                    .unwrap_or_else(|e| panic!("failed to encode tampered receipt index: {e}")),
            );
            tampered_index.push('\n');
        }
        std::fs::write(&receipt_index_path, tampered_index)
            .unwrap_or_else(|e| panic!("failed to write tampered receipt index: {e}"));

        let receipts = read_recent_indexed_endpoint_receipts(
            &receipt_path,
            10,
            EdrReceiptFilter {
                family: Some("response_execution"),
                ..EdrReceiptFilter::default()
            },
        )
        .unwrap_or_else(|e| panic!("failed to read indexed receipts: {e}"))
        .unwrap_or_else(|| panic!("missing indexed receipt lookup result"));

        assert!(receipts.is_empty());
        let rebuilt_records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index: {e}"));
        assert_eq!(rebuilt_records.len(), 1);
        assert_eq!(rebuilt_records[0].family.as_deref(), Some("sensor_state"));

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(receipt_index_path);
    }

    #[test]
    fn endpoint_receipt_index_rebuilds_before_filtering_stale_false_negative() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[97u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-receipt-index-false-negative",
                signer_identity: "test-edr-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "receipt-index-false-negative-test".to_string(),
                    policy_hash: sha256(b"receipt-index-false-negative-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                reason: "receipt index false-negative validation",
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let signed = receipt.sign_with(&keypair).unwrap_or_else(|e| {
            panic!("failed to sign receipt index false-negative test receipt: {e}")
        });
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| {
                panic!("failed to append receipt index false-negative test receipt: {e}")
            });

        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        let mut records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert_eq!(records[0].family.as_deref(), Some("sensor_state"));
        records[0].family = Some("response_execution".to_string());
        let tampered_index = records
            .iter()
            .map(|record| {
                serde_json::to_string(record)
                    .unwrap_or_else(|e| panic!("failed to encode tampered receipt index: {e}"))
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&receipt_index_path, tampered_index)
            .unwrap_or_else(|e| panic!("failed to write tampered receipt index: {e}"));

        let receipts = read_recent_indexed_endpoint_receipts(
            &receipt_path,
            10,
            EdrReceiptFilter {
                family: Some("sensor_state"),
                ..EdrReceiptFilter::default()
            },
        )
        .unwrap_or_else(|e| panic!("failed to read indexed receipts: {e}"))
        .unwrap_or_else(|| panic!("missing indexed receipt lookup result"));

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipt_family(&receipts[0]), Some("sensor_state"));
        let rebuilt_records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index: {e}"));
        assert_eq!(rebuilt_records.len(), 1);
        assert_eq!(rebuilt_records[0].family.as_deref(), Some("sensor_state"));

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(receipt_index_path);
    }

    #[test]
    fn endpoint_receipt_index_rebuilds_on_unknown_sidecar_field() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[95u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-receipt-index-unknown-field-1",
                signer_identity: "test-edr-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "receipt-index-unknown-field-test".to_string(),
                    policy_hash: sha256(b"receipt-index-unknown-field-test-policy")
                        .to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                reason: "receipt index unknown field validation",
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let signed = receipt
            .sign_with(&keypair)
            .unwrap_or_else(|e| panic!("failed to sign receipt index unknown-field receipt: {e}"));
        let expected_receipt_id = signed.receipt.receipt_id.clone();
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| {
                panic!("failed to append receipt index unknown-field receipt: {e}")
            });

        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        let records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert_eq!(records.len(), 1);
        let mut unknown_index_record = serde_json::to_value(&records[0])
            .unwrap_or_else(|e| panic!("failed to encode receipt index record: {e}"));
        unknown_index_record["shadowReceiptFamily"] =
            serde_json::Value::String("must not be ignored".to_string());
        write_jsonl_value(&receipt_index_path, &unknown_index_record);
        assert_anyhow_error_mentions_unknown_field(
            read_endpoint_receipt_index(&receipt_index_path).unwrap_err(),
            "shadowReceiptFamily",
        );

        let receipts = read_recent_indexed_endpoint_receipts(
            &receipt_path,
            10,
            EdrReceiptFilter {
                family: Some("sensor_state"),
                ..EdrReceiptFilter::default()
            },
        )
        .unwrap_or_else(|e| panic!("failed to read indexed receipts after corrupt index: {e}"))
        .unwrap_or_else(|| panic!("missing indexed receipt lookup result"));

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].receipt.receipt_id.as_deref(),
            expected_receipt_id.as_deref()
        );
        let rebuilt_records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index: {e}"));
        assert_eq!(rebuilt_records.len(), 1);
        assert_eq!(rebuilt_records[0].family.as_deref(), Some("sensor_state"));
        let rebuilt_index = std::fs::read_to_string(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index contents: {e}"));
        assert!(!rebuilt_index.contains("shadowReceiptFamily"));

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(receipt_index_path);
    }

    #[test]
    fn latest_required_receipt_rejects_invalid_signature() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[92u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let (execution, graph) = test_collect_evidence_execution(
            "proc-invalid-proof-receipt-1",
            "invalid-proof-receipt.example.invalid",
            600,
            "collect proof receipt signature validation evidence",
        );
        let plan = EndpointResponsePlan {
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: execution.reason.clone(),
            created_at: execution.started_at,
            expires_at: execution.expires_at(),
            node_count: execution.evidence_bundle.node_count,
            edge_count: execution.evidence_bundle.edge_count,
        };
        let mut receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-invalid-proof-receipt-1",
                signer_identity: "test-edr-signer",
                actor: EndpointDecisionActor {
                    user_id: Some("operator:test".to_string()),
                    ..EndpointDecisionActor::default()
                },
                policy: EndpointPolicySnapshot {
                    policy_version: "proof-receipt-signature-test".to_string(),
                    policy_hash: sha256(b"proof-receipt-signature-test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                graph: &graph,
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let mut signed = receipt
            .sign_with(&keypair)
            .unwrap_or_else(|e| panic!("failed to sign proof receipt test receipt: {e}"));
        signed.receipt.timestamp = "2099-01-01T00:00:00Z".to_string();
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| panic!("failed to append invalid proof receipt: {e}"));

        let result = latest_required_receipt(
            &ledger,
            "response_request",
            execution.action_id.as_str(),
            "response request receipt",
        );

        match result {
            Ok(_) => panic!("invalid receipt signature was accepted"),
            Err((status, message)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(message.contains("signature"));
            }
        }

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[test]
    fn latest_required_receipt_rejects_untrusted_signer() {
        let receipt_path = test_receipt_path();
        let trusted_keypair = Keypair::from_seed(&[93u8; 32]);
        let trusted_signer_public_key = trusted_keypair.public_key().to_hex();
        let untrusted_keypair = Keypair::from_seed(&[94u8; 32]);
        let untrusted_signer_public_key = untrusted_keypair.public_key().to_hex();
        let (execution, graph) = test_collect_evidence_execution(
            "proc-untrusted-proof-receipt-1",
            "untrusted-proof-receipt.example.invalid",
            600,
            "collect proof receipt signer trust evidence",
        );
        let plan = EndpointResponsePlan {
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: execution.reason.clone(),
            created_at: execution.started_at,
            expires_at: execution.expires_at(),
            node_count: execution.evidence_bundle.node_count,
            edge_count: execution.evidence_bundle.edge_count,
        };
        let mut receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-untrusted-proof-receipt-1",
                signer_identity: "test-edr-signer",
                actor: EndpointDecisionActor {
                    user_id: Some("operator:test".to_string()),
                    ..EndpointDecisionActor::default()
                },
                policy: EndpointPolicySnapshot {
                    policy_version: "proof-receipt-signer-test".to_string(),
                    policy_hash: sha256(b"proof-receipt-signer-test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                graph: &graph,
            });
        receipt.signer.signer_public_key = Some(untrusted_signer_public_key);
        let signed = receipt
            .sign_with(&untrusted_keypair)
            .unwrap_or_else(|e| panic!("failed to sign untrusted proof receipt: {e}"));
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair: trusted_keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key: trusted_signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| panic!("failed to append untrusted proof receipt: {e}"));

        let result = latest_required_receipt(
            &ledger,
            "response_request",
            execution.action_id.as_str(),
            "response request receipt",
        );

        match result {
            Ok(_) => panic!("untrusted receipt signer was accepted"),
            Err((status, message)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(message.contains("signer"));
            }
        }

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    fn test_flight_recorder_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-flight-recorder-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_honey_registry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-honey-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_evidence_bundle_dir() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-bundles-{}-{counter}",
            std::process::id()
        ))
    }

    fn test_stored_graph_slice_bundle(
        process_guid: &str,
        host: &str,
        reason: &str,
        age_seconds: i64,
    ) -> (EndpointEvidenceBundleReference, CausalGraph) {
        let observation = EndpointObservation {
            observation_id: format!("bundle-maintenance-{process_guid}"),
            process: EndpointProcess {
                process_guid: Some(process_guid.to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: host.to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some(format!("https://{host}/upload")),
            },
            ..EndpointObservation::default()
        };
        let root_node_id = observation.process.stable_node_id();
        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let graph = recorder.into_graph();
        let mut bundle =
            evidence_bundle_for_graph_slice(&root_node_id, "causal_subgraph", Some(reason), &graph)
                .unwrap_or_else(|err| panic!("failed to create test graph-slice bundle: {err}"));
        bundle.created_at = chrono::Utc::now() - chrono::Duration::seconds(age_seconds);
        (bundle, graph)
    }

    fn test_response_execution_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-response-executions-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_response_acknowledgement_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-response-acknowledgements-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_control_ack_postback_retry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-control-ack-postback-retries-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_control_archive_upload_retry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-control-archive-upload-retries-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_control_receipt_upload_retry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-control-receipt-upload-retries-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_fleet_hunt_event_outbox_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-fleet-hunt-event-outbox-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_fleet_hunt_event_outbox_entry(
        outbox_id: &str,
        event_id: &str,
        raw_ref: &str,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
    ) -> EndpointFleetHuntEventOutboxEntry {
        let now = chrono::Utc::now();
        EndpointFleetHuntEventOutboxEntry {
            outbox_id: outbox_id.to_string(),
            event_id: event_id.to_string(),
            raw_ref: raw_ref.to_string(),
            event: serde_json::json!({
                "eventId": event_id,
                "source": "receipt",
                "kind": "detection_fired",
                "tenantId": "4b83d8d0-7b6d-4a3b-8cc4-0aa83d1f3b41",
                "agentId": "endpoint-agent-archive-1",
                "evidence": {
                    "rawRef": raw_ref,
                    "schemaName": "clawdstrike.edr.evidence_bundle_archive.v1"
                },
                "target": {
                    "kind": "evidence_bundle",
                    "id": "bundle-outbox-test"
                },
                "attributes": {
                    "archiveHash": "0x0123456789abcdef",
                    "verification": {
                        "verified": true
                    }
                }
            }),
            attempt_count: 1,
            next_attempt_at,
            last_attempt_at: None,
            last_error_hash: None,
            created_at: now,
            updated_at: now,
        }
    }

    struct TestFleetHuntPublisher {
        agent_id: String,
        published: Mutex<Vec<serde_json::Value>>,
        failures_remaining: Mutex<usize>,
    }

    impl TestFleetHuntPublisher {
        fn new(agent_id: &str) -> Self {
            Self {
                agent_id: agent_id.to_string(),
                published: Mutex::new(Vec::new()),
                failures_remaining: Mutex::new(0),
            }
        }

        async fn published_events(&self) -> Vec<serde_json::Value> {
            self.published.lock().await.clone()
        }
    }

    impl FleetHuntEventPublisher for TestFleetHuntPublisher {
        fn agent_id(&self) -> &str {
            &self.agent_id
        }

        fn publish_hunt_event<'a>(
            &'a self,
            event_json: &'a [u8],
        ) -> FleetHuntEventPublishFuture<'a> {
            Box::pin(async move {
                let mut failures_remaining = self.failures_remaining.lock().await;
                if *failures_remaining > 0 {
                    *failures_remaining -= 1;
                    return Err(anyhow::anyhow!("injected fleet hunt event publish failure"));
                }
                drop(failures_remaining);

                let event = serde_json::from_slice(event_json)
                    .with_context(|| "decode published fleet hunt event")?;
                self.published.lock().await.push(event);
                Ok(())
            })
        }
    }

    #[derive(Clone, Default)]
    struct MockControlApiArchiveState {
        requests: Arc<Mutex<Vec<MockControlApiArchiveRequest>>>,
        failures_remaining: Arc<Mutex<usize>>,
    }

    #[derive(Clone, Debug)]
    struct MockControlApiArchiveRequest {
        api_key: Option<String>,
        body: serde_json::Value,
    }

    async fn mock_control_api_record_endpoint_archive(
        State(state): State<MockControlApiArchiveState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        state
            .requests
            .lock()
            .await
            .push(MockControlApiArchiveRequest {
                api_key: headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                body: body.clone(),
            });
        let mut failures_remaining = state.failures_remaining.lock().await;
        if *failures_remaining > 0 {
            *failures_remaining -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "retained": false })),
            )
                .into_response();
        }
        Json(serde_json::json!({
            "archiveId": body["archiveId"].clone(),
            "archiveHash": body["archiveHash"].clone(),
            "rawRef": body["rawRef"].clone(),
            "bundleId": body["bundleId"].clone(),
            "retained": true
        }))
        .into_response()
    }

    async fn spawn_mock_control_api_archive() -> (
        String,
        MockControlApiArchiveState,
        tokio::task::JoinHandle<()>,
    ) {
        let state = MockControlApiArchiveState::default();
        let app = Router::new()
            .route(
                "/api/v1/hunt/evidence-bundle-archives",
                post(mock_control_api_record_endpoint_archive),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock Control API archive endpoint: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| {
                panic!("failed to read mock Control API archive endpoint port: {e}")
            })
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock Control API archive endpoint failed: {e}"));
        });
        (format!("http://127.0.0.1:{port}"), state, handle)
    }

    #[derive(Clone, Default)]
    struct MockControlApiReceiptState {
        requests: Arc<Mutex<Vec<MockControlApiReceiptRequest>>>,
        failures_remaining: Arc<Mutex<usize>>,
    }

    #[derive(Clone, Debug)]
    struct MockControlApiReceiptRequest {
        api_key: Option<String>,
        body: serde_json::Value,
    }

    async fn mock_control_api_store_receipts(
        State(state): State<MockControlApiReceiptState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        state
            .requests
            .lock()
            .await
            .push(MockControlApiReceiptRequest {
                api_key: headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                body: body.clone(),
            });
        let mut failures_remaining = state.failures_remaining.lock().await;
        if *failures_remaining > 0 {
            *failures_remaining -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "stored": [], "count": 0 })),
            )
                .into_response();
        }
        drop(failures_remaining);
        let receipts = body
            .get("receipts")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let stored: Vec<_> = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| {
                serde_json::json!({
                    "id": format!("00000000-0000-4000-8000-{index:012}"),
                    "timestamp": receipt["timestamp"].clone(),
                    "verdict": receipt["verdict"].clone(),
                    "guard": receipt["guard"].clone(),
                    "policy_name": receipt["policy_name"].clone(),
                    "signature": receipt["signature"].clone(),
                    "public_key": receipt["public_key"].clone(),
                })
            })
            .collect();
        Json(serde_json::json!({
            "stored": stored,
            "count": receipts.len()
        }))
        .into_response()
    }

    async fn spawn_mock_control_api_receipts() -> (
        String,
        MockControlApiReceiptState,
        tokio::task::JoinHandle<()>,
    ) {
        let state = MockControlApiReceiptState::default();
        let app = Router::new()
            .route(
                "/api/v1/receipts/batch",
                post(mock_control_api_store_receipts),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock Control API receipt endpoint: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| {
                panic!("failed to read mock Control API receipt endpoint port: {e}")
            })
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock Control API receipt endpoint failed: {e}"));
        });
        (format!("http://127.0.0.1:{port}"), state, handle)
    }

    #[test]
    fn endpoint_fleet_hunt_event_outbox_tracks_retry_state() {
        let path = test_fleet_hunt_event_outbox_path();
        let now = chrono::Utc::now();
        let due = test_fleet_hunt_event_outbox_entry(
            "0xfleet-due",
            "event-due",
            "endpoint-evidence-bundle-archive:due:0xaaa",
            now - chrono::Duration::seconds(1),
        );
        let future = test_fleet_hunt_event_outbox_entry(
            "0xfleet-future",
            "event-future",
            "endpoint-evidence-bundle-archive:future:0xbbb",
            now + chrono::Duration::seconds(300),
        );
        let mut outbox = EndpointFleetHuntEventOutbox::open(&path)
            .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}"));

        outbox
            .append(due)
            .unwrap_or_else(|err| panic!("failed to append due outbox event: {err}"));
        outbox
            .append(future)
            .unwrap_or_else(|err| panic!("failed to append future outbox event: {err}"));

        assert_eq!(outbox.path(), Some(path.as_path()));
        assert_eq!(outbox.pending_count(), 2);
        assert_eq!(outbox.due(now, 10, false).len(), 1);
        assert_eq!(outbox.due(now, 10, true).len(), 2);

        let error_hash = sha256(b"nats disconnected").to_hex_prefixed();
        let updated = outbox
            .mark_failed("0xfleet-due", now, Some(error_hash.clone()))
            .unwrap_or_else(|err| panic!("failed to mark outbox event failed: {err}"))
            .unwrap_or_else(|| panic!("missing failed outbox event"));
        assert_eq!(updated.attempt_count, 2);
        assert_eq!(updated.last_attempt_at, Some(now));
        assert_eq!(
            updated.last_error_hash.as_deref(),
            Some(error_hash.as_str())
        );
        assert!(updated.next_attempt_at > now);

        let delivered = outbox
            .mark_delivered("0xfleet-future")
            .unwrap_or_else(|err| panic!("failed to mark outbox event delivered: {err}"))
            .unwrap_or_else(|| panic!("missing delivered outbox event"));
        assert_eq!(delivered.event_id, "event-future");
        assert_eq!(outbox.pending_count(), 1);

        let persisted = read_fleet_hunt_event_outbox(&path)
            .unwrap_or_else(|err| panic!("failed to read persisted fleet hunt outbox: {err}"));
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].outbox_id, "0xfleet-due");
        assert_eq!(persisted[0].attempt_count, 2);
        assert_eq!(
            persisted[0].last_error_hash.as_deref(),
            Some(error_hash.as_str())
        );

        let mut shadow_outbox_entry = serde_json::to_value(&persisted[0])
            .unwrap_or_else(|err| panic!("failed to encode fleet hunt outbox entry: {err}"));
        shadow_outbox_entry
            .as_object_mut()
            .unwrap_or_else(|| panic!("fleet hunt outbox entry was not a JSON object"))
            .insert(
                "shadowOutboxId".to_string(),
                serde_json::json!("0xshadow-outbox"),
            );
        assert_unknown_field_rejected::<EndpointFleetHuntEventOutboxEntry>(
            shadow_outbox_entry.clone(),
            "shadowOutboxId",
        );
        let shadow_outbox_path = test_fleet_hunt_event_outbox_path();
        write_jsonl_value(
            &shadow_outbox_path,
            &serde_json::json!([shadow_outbox_entry]),
        );
        let err = match read_fleet_hunt_event_outbox(&shadow_outbox_path) {
            Ok(_) => panic!("expected shadow outbox entry rejection"),
            Err(err) => err,
        };
        assert_anyhow_error_mentions_unknown_field(err, "shadowOutboxId");
        let _ = std::fs::remove_file(shadow_outbox_path);
    }

    #[tokio::test]
    async fn fleet_hunt_event_retry_requires_nats_without_dropping_queue() {
        let mut state = test_state();
        let outbox_path = test_fleet_hunt_event_outbox_path();
        state.edr_fleet_hunt_event_outbox = Arc::new(Mutex::new(
            EndpointFleetHuntEventOutbox::open(&outbox_path)
                .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}")),
        ));
        {
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-retry-no-nats",
                    "event-retry-no-nats",
                    "endpoint-evidence-bundle-archive:no-nats:0xccc",
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to append fleet hunt event outbox entry: {err}")
                });
        }
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .with_state(Arc::new(state));
        let body = serde_json::json!({
            "force": true,
            "limit": 5
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/fleet-hunt-events/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|err| panic!("failed to build fleet hunt retry request: {err}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|err| panic!("fleet hunt retry request failed: {err}"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|err| panic!("failed to read fleet hunt retry response: {err}"));
        let body = std::str::from_utf8(&bytes)
            .unwrap_or_else(|err| panic!("fleet hunt retry response was not utf8: {err}"));
        assert!(body.contains("NATS is not connected"));

        let persisted = read_fleet_hunt_event_outbox(&outbox_path).unwrap_or_else(|err| {
            panic!("failed to read fleet hunt outbox after failed retry: {err}")
        });
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].outbox_id, "0xfleet-retry-no-nats");
        assert_eq!(persisted[0].attempt_count, 1);
        assert_eq!(persisted[0].last_error_hash, None);
    }

    #[tokio::test]
    async fn fleet_hunt_event_retry_drains_due_queue_with_publisher() {
        let publisher = Arc::new(TestFleetHuntPublisher::new("endpoint-agent-archive-1"));
        let mut state = test_state();
        let outbox_path = test_fleet_hunt_event_outbox_path();
        state.fleet_hunt_publisher = Some(publisher.clone());
        state.edr_fleet_hunt_event_outbox = Arc::new(Mutex::new(
            EndpointFleetHuntEventOutbox::open(&outbox_path)
                .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}")),
        ));
        {
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            let now = chrono::Utc::now();
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-retry-due",
                    "event-retry-due",
                    "endpoint-evidence-bundle-archive:due:0xddd",
                    now - chrono::Duration::seconds(1),
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to append due fleet hunt outbox entry: {err}")
                });
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-retry-future",
                    "event-retry-future",
                    "endpoint-evidence-bundle-archive:future:0xeee",
                    now + chrono::Duration::seconds(300),
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to append future fleet hunt outbox entry: {err}")
                });
        }
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .with_state(Arc::new(state));
        let body = serde_json::json!({
            "force": false,
            "limit": 5
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/fleet-hunt-events/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|err| panic!("failed to build fleet hunt drain request: {err}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|err| panic!("fleet hunt drain request failed: {err}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|err| panic!("failed to read fleet hunt drain response: {err}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("failed to decode fleet hunt drain response: {err}"));
        assert_eq!(payload["attempted"], 1);
        assert_eq!(payload["delivered"], 1);
        assert_eq!(payload["failed"], 0);
        assert_eq!(payload["skipped"], 1);
        assert_eq!(payload["pending"], 1);
        assert_eq!(payload["attempts"][0]["outboxId"], "0xfleet-retry-due");

        let published = publisher.published_events().await;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0]["eventId"], "event-retry-due");
        let persisted = read_fleet_hunt_event_outbox(&outbox_path)
            .unwrap_or_else(|err| panic!("failed to read fleet hunt outbox after drain: {err}"));
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].outbox_id, "0xfleet-retry-future");
    }

    #[tokio::test]
    async fn fleet_sync_loop_drains_due_fleet_hunt_outbox_on_startup() {
        let publisher = Arc::new(TestFleetHuntPublisher::new("endpoint-agent-archive-1"));
        let mut state = test_state();
        state.fleet_hunt_publisher = Some(publisher.clone());
        state.edr_fleet_hunt_event_outbox =
            Arc::new(Mutex::new(EndpointFleetHuntEventOutbox::transient()));
        {
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-sync-due",
                    "event-sync-due",
                    "endpoint-evidence-bundle-archive:sync:0xfff",
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                ))
                .unwrap_or_else(|err| panic!("failed to append sync outbox entry: {err}"));
        }
        let state = Arc::new(state);
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        let sync_state = state.clone();
        let sync_task = tokio::spawn(async move {
            fleet_agent_secret_touch_sync_loop(sync_state, &mut shutdown_rx).await;
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state
                    .edr_fleet_hunt_event_outbox
                    .lock()
                    .await
                    .pending_count()
                    == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for fleet hunt outbox startup drain"));

        let published = publisher.published_events().await;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0]["eventId"], "event-sync-due");
        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), sync_task)
            .await
            .unwrap_or_else(|_| panic!("fleet sync loop did not shut down"))
            .unwrap_or_else(|err| panic!("fleet sync loop task failed: {err}"));
    }

    fn test_staged_detection_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-staged-detections-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_policy_delta_dir() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-policy-deltas-{}-{counter}",
            std::process::id()
        ))
    }

    fn test_network_extension_egress_policy_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-ne-egress-policy-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_quarantine_dir() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-quarantine-{}-{counter}",
            std::process::id()
        ))
    }

    #[test]
    fn endpoint_policy_snapshot_prefers_explicit_policy_epoch() {
        let policy_path = test_policy_path();
        std::fs::write(
            &policy_path,
            "version: explicit-epoch\npolicy:\n  epoch: 4242\n",
        )
        .unwrap_or_else(|err| panic!("failed to write explicit epoch policy: {err}"));
        let settings = Settings {
            policy_path: policy_path.clone(),
            ..Settings::default()
        };

        let snapshot = endpoint_policy_snapshot_from_settings(&settings)
            .unwrap_or_else(|err| panic!("failed to build policy snapshot: {err}"));
        assert_eq!(snapshot.policy_version, "explicit-epoch");
        assert_eq!(snapshot.policy_epoch, 4242);

        let _ = std::fs::remove_file(policy_path);
    }

    #[test]
    fn endpoint_policy_snapshot_accepts_bundle_policy_epoch_string() {
        let policy_path = test_policy_path();
        std::fs::write(
            &policy_path,
            "version: bundle-epoch\nbundle:\n  policyEpoch: \"5150\"\n",
        )
        .unwrap_or_else(|err| panic!("failed to write bundle epoch policy: {err}"));
        let settings = Settings {
            policy_path: policy_path.clone(),
            ..Settings::default()
        };

        let snapshot = endpoint_policy_snapshot_from_settings(&settings)
            .unwrap_or_else(|err| panic!("failed to build policy snapshot: {err}"));
        assert_eq!(snapshot.policy_version, "bundle-epoch");
        assert_eq!(snapshot.policy_epoch, 5150);

        let _ = std::fs::remove_file(policy_path);
    }

    #[test]
    fn proposed_policy_snapshot_requires_explicit_policy_epoch() {
        let err =
            endpoint_policy_snapshot_from_memory_policy_bytes(b"version: no-epoch\n").unwrap_err();
        assert!(
            err.to_string().contains("policy_epoch"),
            "unexpected proposed policy snapshot error: {err}"
        );
        let snapshot = endpoint_policy_snapshot_from_memory_policy_bytes(
            b"version: proposed-epoch\npolicy_epoch: 6161\n",
        )
        .unwrap_or_else(|err| panic!("failed to build proposed policy snapshot: {err}"));
        assert_eq!(snapshot.policy_version, "proposed-epoch");
        assert_eq!(snapshot.policy_epoch, 6161);
    }

    fn read_json_file(path: &FsPath) -> serde_json::Value {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read JSON file {}: {err}", path.display()));
        serde_json::from_str(&contents)
            .unwrap_or_else(|err| panic!("failed to decode JSON file {}: {err}", path.display()))
    }

    #[test]
    fn endpoint_egress_restriction_artifacts_reject_unknown_fields() {
        let now = chrono::Utc::now();
        let restriction = EndpointEgressRestriction {
            restriction_id: "restriction-strict-egress".to_string(),
            execution_id: "execution-strict-egress".to_string(),
            action_id: "action-strict-egress".to_string(),
            graph_slice_id: "graph-strict-egress".to_string(),
            rollback_ref: "rollback-strict-egress".to_string(),
            target: "strict-egress.example.invalid:443".to_string(),
            target_hash: sha256(b"strict-egress.example.invalid:443").to_hex_prefixed(),
            active: true,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(10),
            updated_at: now,
        };

        let mut restriction_value = serde_json::to_value(&restriction)
            .unwrap_or_else(|err| panic!("failed to encode egress restriction: {err}"));
        restriction_value["shadowActive"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EndpointEgressRestriction>(
            restriction_value.clone(),
            "shadowActive",
        );

        let ledger_path = std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-egress-restrictions-{}-{}.jsonl",
            std::process::id(),
            TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        write_jsonl_value(&ledger_path, &restriction_value);
        assert_anyhow_error_mentions_unknown_field(
            read_egress_restriction_ledger(&ledger_path).unwrap_err(),
            "shadowActive",
        );

        let snapshot = NetworkExtensionEgressPolicySnapshot {
            schema_version: EDR_NETWORK_EXTENSION_EGRESS_POLICY_SCHEMA_VERSION,
            generated_at: now,
            restrictions: vec![restriction],
        };
        let mut snapshot_value = serde_json::to_value(&snapshot)
            .unwrap_or_else(|err| panic!("failed to encode egress snapshot: {err}"));
        snapshot_value["shadowProviderState"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<NetworkExtensionEgressPolicySnapshot>(
            snapshot_value,
            "shadowProviderState",
        );

        let mut nested_snapshot_value = serde_json::to_value(&snapshot)
            .unwrap_or_else(|err| panic!("failed to encode nested egress snapshot: {err}"));
        nested_snapshot_value["restrictions"][0]["shadowTarget"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<NetworkExtensionEgressPolicySnapshot>(
            nested_snapshot_value,
            "shadowTarget",
        );

        let _ = std::fs::remove_file(ledger_path);
    }

    #[tokio::test]
    async fn network_extension_policy_sync_requests_provider_reload() {
        let state = Arc::new(test_state());
        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<crate::macos::host::MacosNetworkExtensionReloadRequest>(1);
        state
            .macos_host
            .install_network_extension_reload_channel(reload_tx)
            .await;

        let now = chrono::Utc::now();
        {
            let mut ledger = state.edr_egress_restriction_ledger.lock().await;
            ledger
                .append(&[EndpointEgressRestriction {
                    restriction_id: "restriction-sync-reload".to_string(),
                    execution_id: "execution-sync-reload".to_string(),
                    action_id: "action-sync-reload".to_string(),
                    graph_slice_id: "graph-sync-reload".to_string(),
                    rollback_ref: "rollback-sync-reload".to_string(),
                    target: "sync-reload.example.invalid:443".to_string(),
                    target_hash: sha256(b"sync-reload.example.invalid:443").to_hex_prefixed(),
                    active: true,
                    created_at: now,
                    expires_at: now + chrono::Duration::minutes(10),
                    updated_at: now,
                }])
                .unwrap_or_else(|err| panic!("failed to append sync reload restriction: {err}"));
        }

        let sync_state = state.clone();
        let sync_task = tokio::spawn(async move {
            sync_edr_network_extension_egress_policy(&sync_state, now).await
        });

        let request = reload_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("missing NetworkExtension reload request"));
        assert_eq!(
            request.policy_snapshot_path,
            *state.edr_network_extension_egress_policy_path
        );
        assert_eq!(request.generation, now.timestamp_millis() as u64);
        assert_eq!(
            request.timeout_duration,
            Duration::from_millis(EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS)
        );
        request
            .reply_tx
            .send(Ok(crate::macos::host::MacosNetworkExtensionReloadResult {
                requested: true,
                saved: true,
                request_id: "test-sync-reload".to_string(),
                policy_snapshot_path: state
                    .edr_network_extension_egress_policy_path
                    .display()
                    .to_string(),
                generation: now.timestamp_millis() as u64,
            }))
            .unwrap_or_else(|_| panic!("failed to send NetworkExtension reload response"));

        sync_task
            .await
            .unwrap_or_else(|err| panic!("sync task panicked: {err}"))
            .unwrap_or_else(|err| panic!("sync failed: {err:?}"));

        let snapshot = read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            snapshot["restrictions"][0]["target"],
            "sync-reload.example.invalid:443"
        );
    }

    fn test_collect_evidence_execution(
        process_guid: &str,
        host: &str,
        ttl_seconds: u64,
        reason: &str,
    ) -> (EndpointResponseExecutionReport, CausalGraph) {
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some(process_guid.to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: host.to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some(format!("https://{host}/upload")),
            },
            ..EndpointObservation::default()
        };
        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let root_node_id = observation.process.stable_node_id();
        let subgraph = recorder
            .graph()
            .causal_subgraph_from(&root_node_id, 3)
            .unwrap_or_else(|| panic!("missing test response execution subgraph"));
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &root_node_id,
            &subgraph,
            ttl_seconds,
            reason,
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to build collect evidence report: {err}"));
        (execution, subgraph)
    }

    #[test]
    fn policy_version_cache_marks_refresh_in_flight_once_per_interval() {
        let mut cache = PolicyVersionCache::default();
        let now = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(now));
        assert!(!cache.mark_refresh_started_if_due(now));
    }

    #[test]
    fn policy_version_cache_finish_refresh_updates_value_and_clears_in_flight() {
        let mut cache = PolicyVersionCache::default();
        let started = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(started));
        assert!(cache.refresh_in_flight);
        assert_eq!(cache.refresh_started_at, Some(started));

        cache.finish_refresh(Some("42".to_string()), started);
        assert_eq!(cache.value.as_deref(), Some("42"));
        assert!(!cache.refresh_in_flight);
        assert!(cache.refresh_started_at.is_none());
    }

    #[test]
    fn policy_version_cache_recovers_when_refresh_task_stalls() {
        let mut cache = PolicyVersionCache::default();
        let started = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(started));
        assert!(!cache.mark_refresh_started_if_due(started + POLICY_VERSION_CACHE_REFRESH_INTERVAL));

        let after_timeout =
            started + POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT + Duration::from_millis(1);
        assert!(cache.mark_refresh_started_if_due(after_timeout));
        assert!(cache.refresh_in_flight);
    }

    #[test]
    fn macos_host_health_status_is_pending_for_unknown_state() {
        assert_eq!(
            macos_host_health_status(&CombinedSystemExtensionStatus::default()),
            "pending"
        );
    }

    #[test]
    fn macos_host_health_status_is_degraded_for_blocked_or_missing_extensions() {
        let blocked = CombinedSystemExtensionStatus {
            approval: SystemExtensionApproval::ApprovalBlocked,
            ..CombinedSystemExtensionStatus::default()
        };
        assert_eq!(macos_host_health_status(&blocked), "degraded");

        let not_installed = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::NotInstalled,
            ..CombinedSystemExtensionStatus::default()
        };
        assert_eq!(macos_host_health_status(&not_installed), "degraded");
    }

    #[test]
    fn macos_host_health_status_is_pending_for_inactive_extensions() {
        let inactive = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus::inactive(),
            network_extension: crate::macos::status::ProviderStatus::inactive(),
            ..CombinedSystemExtensionStatus::default()
        };
        assert_eq!(macos_host_health_status(&inactive), "pending");
    }

    #[test]
    fn macos_host_health_status_is_ok_for_fully_active_extensions() {
        let active = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            network_extension: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        assert_eq!(macos_host_health_status(&active), "ok");
    }

    #[test]
    fn endpoint_sensor_state_marks_unknown_macos_providers_degraded() {
        let sensor_state =
            endpoint_sensor_state_from_macos_host(&CombinedSystemExtensionStatus::default());
        let endpoint_security = sensor_state
            .providers
            .iter()
            .find(|provider| provider.provider_id == "macos.endpoint_security")
            .unwrap_or_else(|| panic!("missing endpoint security provider state"));

        assert!(!endpoint_security.installed);
        assert!(!endpoint_security.active);
        assert!(!endpoint_security.healthy);
        assert!(endpoint_security.degraded);
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"provider runtime unknown".to_string()));
    }

    #[test]
    fn endpoint_sensor_state_marks_loss_deadline_and_fda_evidence_degraded() {
        let mut counters = BTreeMap::new();
        counters.insert("dropped_event_count".to_string(), 2);
        counters.insert("deadline_miss_count".to_string(), 1);
        let status = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                counters,
                evidence_paths: vec![crate::macos::status::EvidenceArtifact {
                    kind: "missing_full_disk_access".to_string(),
                    path: "/tmp/clawdstrike/missing-fda.json".to_string(),
                    detail: "EndpointSecurity lacks Full Disk Access".to_string(),
                }],
                ..crate::macos::status::ProviderStatus::unknown()
            },
            network_extension: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        let sensor_state = endpoint_sensor_state_from_macos_host(&status);
        let endpoint_security = sensor_state
            .providers
            .iter()
            .find(|provider| provider.provider_id == "macos.endpoint_security")
            .unwrap_or_else(|| panic!("missing endpoint security provider state"));

        assert!(endpoint_security.installed);
        assert!(endpoint_security.active);
        assert!(!endpoint_security.healthy);
        assert!(endpoint_security.degraded);
        assert_eq!(endpoint_security.dropped_event_count, 2);
        assert_eq!(endpoint_security.deadline_miss_count, 1);
        assert_eq!(endpoint_security.full_disk_access, Some(false));
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"provider dropped enforcement events".to_string()));
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"provider authorization deadline misses".to_string()));
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"missing_full_disk_access".to_string()));
    }

    #[test]
    fn endpoint_sensor_state_redacts_secret_like_provider_degradation_reasons() {
        let status = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "runtime failure ghs_1234567890abcdef1234".to_string(),
                },
                last_error: Some("last provider error xoxb-1234567890abcdef1234567890".to_string()),
                provider_state: Some(crate::macos::status::ProviderAttestationState {
                    provider: "endpoint_security".to_string(),
                    installed: true,
                    approval_status: crate::macos::status::ProviderApprovalStatus::Approved,
                    active: true,
                    healthy: false,
                    availability: crate::macos::status::ProviderAvailability::Degraded,
                    degraded_reasons: vec![
                        "attestation leaked sk-abcdefghijklmnopqrstuvwxyz".to_string()
                    ],
                    last_healthy_timestamp: None,
                }),
                ..crate::macos::status::ProviderStatus::unknown()
            },
            network_extension: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        let sensor_state = endpoint_sensor_state_from_macos_host(&status);
        let endpoint_security = sensor_state
            .providers
            .iter()
            .find(|provider| provider.provider_id == "macos.endpoint_security")
            .unwrap_or_else(|| panic!("missing endpoint security provider state"));
        let reasons = endpoint_security.degradation_reasons.join("\n");

        assert!(endpoint_security.degraded);
        assert!(reasons.contains("[REDACTED]"));
        assert!(!reasons.contains("ghs_1234567890abcdef1234"));
        assert!(!reasons.contains("xoxb-1234567890abcdef1234567890"));
        assert!(!reasons.contains("sk-abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn agent_health_status_preserves_non_macos_ok_fallback() {
        let status = CombinedSystemExtensionStatus::default();
        if cfg!(target_os = "macos") {
            assert_eq!(agent_health_status(&status), "pending");
        } else {
            assert_eq!(agent_health_status(&status), "ok");
        }
    }

    #[test]
    fn auth_accepts_bearer_token() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer test-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn auth_rejects_missing_headers() {
        let state = test_state();
        let headers = HeaderMap::new();
        let result = require_auth(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn auth_rejects_invalid_tokens() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer wrong-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn auth_accepts_cookie_token_without_authorization_header() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={}", AGENT_AUTH_COOKIE_NAME, current_auth_token(&state))
                .parse()
                .unwrap_or_else(|_| panic!("failed to build cookie header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn auth_allows_cookie_fallback_when_authorization_is_invalid() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer wrong-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );
        headers.insert(
            COOKIE,
            format!("{}={}", AGENT_AUTH_COOKIE_NAME, current_auth_token(&state))
                .parse()
                .unwrap_or_else(|_| panic!("failed to build cookie header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn local_host_header_accepts_ipv6_loopback_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "[::1]:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        assert!(is_local_host_header(&headers));
    }

    #[test]
    fn local_host_header_rejects_public_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "example.com:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        assert!(!is_local_host_header(&headers));
    }

    #[test]
    fn local_host_header_rejects_missing_header() {
        let headers = HeaderMap::new();
        assert!(!is_local_host_header(&headers));
    }

    #[test]
    fn map_openclaw_error_classifies_dns_resolution_failure_as_bad_request() {
        let err = anyhow::anyhow!("failed to resolve gateway host bad.example:443");
        let (status, message) = map_openclaw_error(err);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("failed to resolve gateway host"));
    }

    #[test]
    fn request_is_secure_uri_accepts_https_scheme_without_proxy_header() {
        let headers = HeaderMap::new();
        let uri = "https://localhost/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse https uri for secure check"));
        assert!(request_is_secure_uri(&headers, &uri));
    }

    #[test]
    fn request_is_secure_uri_rejects_forwarded_proto_for_non_local_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "example.com:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        headers.insert(
            "x-forwarded-proto",
            "https"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build x-forwarded-proto header")),
        );
        let uri = "/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse relative uri for secure check"));
        assert!(!request_is_secure_uri(&headers, &uri));
    }

    #[test]
    fn request_is_secure_uri_accepts_forwarded_proto_for_local_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "127.0.0.1:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        headers.insert(
            "x-forwarded-proto",
            "https"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build x-forwarded-proto header")),
        );
        let uri = "/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse relative uri for secure check"));
        assert!(request_is_secure_uri(&headers, &uri));
    }

    #[tokio::test]
    async fn ui_routes_require_auth_and_bootstrap_with_one_time_code() {
        let state = Arc::new(test_state());
        let ui_router = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state.clone(), attach_ui_auth_cookie),
        );
        let app = Router::new()
            .route("/api/v1/ui/bootstrap/start", post(start_ui_bootstrap))
            .route("/ui/bootstrap", post(ui_bootstrap_verify))
            .nest("/ui", ui_router)
            .with_state(Arc::clone(&state));

        let unauth_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui")
            .header("host", "127.0.0.1:9878")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unauth request: {e}"));
        let unauth_resp = app
            .clone()
            .oneshot(unauth_req)
            .await
            .unwrap_or_else(|e| panic!("unauth request failed: {e}"));
        assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);
        assert!(unauth_resp.headers().get(SET_COOKIE).is_none());

        let deprecated_query_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui?agent_token=test-token")
            .header("host", "127.0.0.1:9878")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build deprecated query request: {e}"));
        let deprecated_query_resp = app
            .clone()
            .oneshot(deprecated_query_req)
            .await
            .unwrap_or_else(|e| panic!("deprecated query request failed: {e}"));
        assert_eq!(deprecated_query_resp.status(), StatusCode::BAD_REQUEST);

        let start_req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/ui/bootstrap/start")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"next_path":"/ui/settings/siem"}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build bootstrap start request: {e}"));
        let start_resp = app
            .clone()
            .oneshot(start_req)
            .await
            .unwrap_or_else(|e| panic!("bootstrap start request failed: {e}"));
        assert_eq!(start_resp.status(), StatusCode::OK);
        let start_bytes = axum::body::to_bytes(start_resp.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read bootstrap start body: {e}"));
        let payload: UiBootstrapStartResponse = serde_json::from_slice(&start_bytes)
            .unwrap_or_else(|e| panic!("failed to decode bootstrap start payload: {e}"));

        let verify_body = format!(
            "session_id={}&user_code={}",
            payload.session_id, payload.user_code
        );
        let verify_req = axum::http::Request::builder()
            .method("POST")
            .uri("/ui/bootstrap")
            .header("host", "127.0.0.1:9878")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(verify_body))
            .unwrap_or_else(|e| panic!("failed to build bootstrap verify request: {e}"));
        let bootstrap_resp = app
            .clone()
            .oneshot(verify_req)
            .await
            .unwrap_or_else(|e| panic!("bootstrap verify request failed: {e}"));
        assert_eq!(bootstrap_resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            bootstrap_resp
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/ui/settings/siem")
        );
        assert!(bootstrap_resp.headers().get(SET_COOKIE).is_some());

        let cookie_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui")
            .header("host", "127.0.0.1:9878")
            .header(COOKIE, format!("{AGENT_AUTH_COOKIE_NAME}=test-token"))
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cookie request: {e}"));
        let cookie_resp = app
            .oneshot(cookie_req)
            .await
            .unwrap_or_else(|e| panic!("cookie request failed: {e}"));
        assert_eq!(cookie_resp.status(), StatusCode::OK);
    }

    #[test]
    fn approval_submission_limiter_enforces_burst_limit() {
        let mut limiter = ApprovalSubmissionLimiter::default();
        let now = Instant::now();
        for _ in 0..APPROVAL_RATE_LIMIT_BURST {
            assert!(limiter.allow_now(now).is_ok());
        }
        assert!(limiter.allow_now(now).is_err());
    }

    #[tokio::test]
    async fn agent_health_route_requires_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/health", get(agent_health))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/health")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let resp = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_health_route_reports_pending_host_state() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/health", get(agent_health))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/health")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let resp = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|e| panic!("failed to decode response body: {e}"));
        let expected_status = if cfg!(target_os = "macos") {
            "pending"
        } else {
            "ok"
        };
        assert_eq!(payload["status"], expected_status);
        assert_eq!(payload["macos_host"]["install_state"], "unknown");
        assert_eq!(payload["macos_host"]["approval"], "unknown");
        assert_eq!(
            payload["macos_host"]["endpoint_security"]["runtime"]["state"],
            "unknown"
        );
        assert_eq!(
            payload["macos_host"]["network_extension"]["runtime"]["state"],
            "unknown"
        );
    }

