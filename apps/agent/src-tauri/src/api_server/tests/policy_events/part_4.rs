    #[tokio::test]
    async fn agent_edr_flight_recorder_compaction_rejects_unbounded_request() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/flight-recorder/compact",
                post(agent_edr_flight_recorder_compact),
            )
            .with_state(Arc::new(test_state()));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/flight-recorder/compact")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap_or_else(|e| panic!("failed to build unbounded graph compaction: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unbounded graph compaction failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn agent_edr_causal_subgraph_returns_persisted_process_effects() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/causal-subgraph",
                post(agent_edr_causal_subgraph),
            )
            .with_state(state);
        let identity_metadata = BTreeMap::from([
            ("agentId".to_string(), serde_json::json!("agent-subgraph-1")),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-subgraph-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-subgraph-1"),
            ),
            (
                "toolCallId".to_string(),
                serde_json::json!("tool-call-subgraph-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "subgraph-tool-1".to_string(),
                host_id: Some("host-subgraph-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-subgraph-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-subgraph-1".to_string()),
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
                observation_id: "subgraph-network-1".to_string(),
                host_id: Some("host-subgraph-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-subgraph-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-subgraph-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "api.example.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://api.example.invalid/upload".to_string()),
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
            "process": {
                "processGuid": "proc-subgraph-1"
            },
            "maxDepth": 3
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-subgraph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build subgraph request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("subgraph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read subgraph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode subgraph response: {e}"));

        assert!(payload["node_count"].as_u64().unwrap_or_default() >= 2);
        assert!(payload["edge_count"].as_u64().unwrap_or_default() >= 1);
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing graph nodes"))
            .values()
            .any(|node| node["label"] == "api.example.invalid:443"));
        assert_eq!(payload["affected_identity_count"].as_u64(), Some(6));
        assert_eq!(payload["affected_tool_count"].as_u64(), Some(1));
        assert_eq!(
            payload["affected_identities"]["hosts"][0]["id"],
            "host-subgraph-1"
        );
        assert_eq!(payload["affected_identities"]["users"][0]["id"], "alice");
        assert_eq!(
            payload["affected_identities"]["sessions"][0]["id"],
            "session-subgraph-1"
        );
        assert_eq!(
            payload["affected_identities"]["agents"][0]["id"],
            "agent-subgraph-1"
        );
        assert_eq!(
            payload["affected_identities"]["workloads"][0]["id"],
            "workload-subgraph-1"
        );
        assert_eq!(
            payload["affected_identities"]["approvals"][0]["id"],
            "approval-subgraph-1"
        );
        assert_eq!(payload["affected_tools"][0]["toolName"], "mcp.shell");

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode graph slice receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing graph slice endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing graph slice receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse graph slice receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "graph_slice");
        assert_eq!(
            endpoint_decision["decision"]["findingId"],
            endpoint_decision["graph"]["graphSliceId"]
        );
        assert_eq!(
            endpoint_decision["graph"]["processNodeId"],
            payload["root_node_id"]
        );
    }

    #[tokio::test]
    async fn agent_edr_causal_context_returns_upstream_cause_and_downstream_effects() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open durable flight recorder: {e}")),
        ));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/causal-subgraph",
                post(agent_edr_causal_subgraph),
            )
            .route(
                "/api/v1/agent/edr/causal-context",
                post(agent_edr_causal_context),
            )
            .with_state(state);
        let identity_metadata = BTreeMap::from([
            ("agentId".to_string(), serde_json::json!("agent-context-1")),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-context-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-context-1"),
            ),
            (
                "toolCallId".to_string(),
                serde_json::json!("tool-call-context-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "context-tool-1".to_string(),
                host_id: Some("host-context-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("context-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-context-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.browser".to_string(),
                    parameters: serde_json::json!({
                        "url": "https://evil.example/collect"
                    }),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                session_id: Some("context-session-1".to_string()),
                host_id: Some("host-context-1".to_string()),
                user_id: Some("alice".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-context-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::PackageRegistryToken,
                    path: Some("/Users/alice/.npmrc".to_string()),
                    name: Some("npm-token".to_string()),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "context-network-1".to_string(),
                session_id: Some("context-session-1".to_string()),
                host_id: Some("host-context-1".to_string()),
                user_id: Some("alice".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-context-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "evil.example".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://evil.example/collect".to_string()),
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
            "process": {
                "processGuid": "proc-context-1"
            },
            "maxDepth": 4
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-subgraph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build subgraph request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("subgraph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read subgraph response: {e}"));
        let subgraph_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode subgraph response: {e}"));
        let network_node_id = subgraph_payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing graph nodes"))
            .iter()
            .find_map(|(node_id, node)| {
                (node["label"] == "evil.example:443").then(|| node_id.clone())
            })
            .unwrap_or_else(|| panic!("missing network node"));

        let body = serde_json::json!({
            "rootNodeId": network_node_id,
            "upstreamDepth": 3,
            "downstreamDepth": 1
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-context")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build causal context request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("causal context request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read causal context response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode causal context response: {e}"));

        assert_eq!(
            payload["contextExpansionStrategy"],
            "durable_graph_edge_sidecar_adjacency"
        );
        assert!(payload["edgeIndexPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing causal context edge index path"))
            .ends_with(".graph-edge-index.jsonl"));
        assert!(payload["graph"]["edges"]
            .as_array()
            .unwrap_or_else(|| panic!("missing context edges"))
            .iter()
            .any(|edge| edge["kind"] == "temporal_next"));
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing context nodes"))
            .values()
            .any(|node| node["label"] == "/Users/alice/.npmrc"));
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing context nodes"))
            .values()
            .any(|node| node["kind"] == "process"));
        assert_eq!(payload["affected_identity_count"].as_u64(), Some(6));
        assert_eq!(payload["affected_tool_count"].as_u64(), Some(1));
        assert_eq!(
            payload["affected_identities"]["hosts"][0]["id"],
            "host-context-1"
        );
        assert_eq!(payload["affected_identities"]["users"][0]["id"], "alice");
        assert_eq!(
            payload["affected_identities"]["sessions"][0]["id"],
            "context-session-1"
        );
        assert_eq!(
            payload["affected_identities"]["agents"][0]["id"],
            "agent-context-1"
        );
        assert_eq!(
            payload["affected_identities"]["workloads"][0]["id"],
            "workload-context-1"
        );
        assert_eq!(
            payload["affected_identities"]["approvals"][0]["id"],
            "approval-context-1"
        );
        assert_eq!(payload["affected_tools"][0]["toolName"], "mcp.browser");

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode causal context receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing causal context endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing causal context receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse causal context receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "graph_slice");
        assert_eq!(
            endpoint_decision["graph"]["processNodeId"],
            payload["root_node_id"]
        );

        let _ = std::fs::remove_file(&flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_graph_search_returns_signed_context_for_session_network_query() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-tool-1".to_string(),
                host_id: Some("host-graph-search-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("graph-search-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-1".to_string()),
                    image: Some("/usr/local/bin/node".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp__browser__open".to_string(),
                    parameters: serde_json::json!({
                        "url": "https://api.graph-search.invalid/upload"
                    }),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-graph-search-1"),
                    ),
                    (
                        "workloadIdentity".to_string(),
                        serde_json::json!("workload-graph-search-1"),
                    ),
                    (
                        "approvalId".to_string(),
                        serde_json::json!("approval-graph-search-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-graph-search-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-search-network-1".to_string(),
                host_id: Some("host-graph-search-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("graph-search-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-1".to_string()),
                    image: Some("/usr/local/bin/node".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "api.graph-search.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://api.graph-search.invalid/upload".to_string()),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-graph-search-1"),
                    ),
                    (
                        "workloadIdentity".to_string(),
                        serde_json::json!("workload-graph-search-1"),
                    ),
                    (
                        "approvalId".to_string(),
                        serde_json::json!("approval-graph-search-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-graph-search-1"),
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
            .unwrap_or_else(|e| panic!("failed to build graph-search findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-search findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "network",
            "labelContains": "api.graph-search.invalid",
            "sessionId": "graph-search-session-1",
            "upstreamDepth": 3,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(payload["totalMatchCount"], 1);
        assert_eq!(payload["queryPlan"]["indexed"], true);
        assert_eq!(payload["queryPlan"]["strategy"], "indexed_prefilter");
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing graph-search indexed keys"))
            .iter()
            .any(|key| key == "nodeKind"));
        assert!(
            payload["queryPlan"]["scannedNodeCount"]
                .as_u64()
                .unwrap_or_default()
                <= payload["queryPlan"]["candidateCount"]
                    .as_u64()
                    .unwrap_or_default()
        );
        let first_match = &payload["matches"][0];
        assert_eq!(first_match["rootKind"], "network");
        assert_eq!(first_match["rootLabel"], "api.graph-search.invalid:443");
        assert_eq!(first_match["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(first_match["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            first_match["affectedIdentities"]["hosts"][0]["id"],
            "host-graph-search-1"
        );
        assert_eq!(first_match["affectedIdentities"]["users"][0]["id"], "alice");
        assert_eq!(
            first_match["affectedIdentities"]["sessions"][0]["id"],
            "graph-search-session-1"
        );
        assert_eq!(
            first_match["affectedIdentities"]["agents"][0]["id"],
            "agent-graph-search-1"
        );
        assert_eq!(
            first_match["affectedIdentities"]["workloads"][0]["id"],
            "workload-graph-search-1"
        );
        assert_eq!(
            first_match["affectedIdentities"]["approvals"][0]["id"],
            "approval-graph-search-1"
        );
        assert_eq!(
            first_match["affectedTools"][0]["toolName"],
            "mcp__browser__open"
        );
        let graph_nodes = first_match["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing graph-search nodes"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "process"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "tool"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "network"));

        let signed: SignedReceipt = serde_json::from_value(first_match["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode graph-search receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing graph-search endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing graph-search receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse graph-search public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "graph_slice");
        assert_eq!(
            endpoint_decision["decision"]["ruleId"],
            "endpoint.graph_slice.graph_search"
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing graph-search receipt evidence"))
            .iter()
            .any(|item| item["key"] == "sliceKind"));
    }

    #[tokio::test]
    async fn agent_edr_graph_search_uses_durable_graph_sidecar_for_node_kind_prefilter() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open durable flight recorder: {e}")),
        ));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let observations = vec![EndpointObservation {
            observation_id: "graph-search-sidecar-network-1".to_string(),
            process: EndpointProcess {
                process_guid: Some("proc-graph-search-sidecar-1".to_string()),
                image: Some("/usr/local/bin/codex".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "durable.graph-search.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://durable.graph-search.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        }];
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
            .unwrap_or_else(|e| {
                panic!("failed to build durable graph-search findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable graph-search findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "network",
            "labelContains": "durable.graph-search.invalid",
            "upstreamDepth": 1,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build durable graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read durable graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode durable graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(
            payload["queryPlan"]["strategy"],
            "durable_graph_sidecar_prefilter"
        );
        assert_eq!(payload["queryPlan"]["indexSource"], "durable_graph_sidecar");
        assert!(payload["queryPlan"]["indexPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing durable graph-search index path"))
            .ends_with(".graph-index.jsonl"));
        assert_eq!(
            payload["queryPlan"]["edgeIndexSource"],
            "durable_graph_edge_sidecar"
        );
        assert!(payload["queryPlan"]["edgeIndexPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing durable graph-search edge index path"))
            .ends_with(".graph-edge-index.jsonl"));
        assert!(
            payload["queryPlan"]["edgeIndexCount"]
                .as_u64()
                .unwrap_or_default()
                >= 1
        );
        assert_eq!(
            payload["queryPlan"]["contextExpansionStrategy"],
            "durable_graph_edge_sidecar_adjacency"
        );
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing durable graph-search indexed keys"))
            .iter()
            .any(|key| key == "nodeKind"));
        assert_eq!(payload["queryPlan"]["candidateCount"], 1);

        let _ = std::fs::remove_file(&flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_graph_search_uses_durable_graph_sidecar_for_exact_path_prefilter() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open durable flight recorder: {e}")),
        ));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-sidecar-path-ssh-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-path-1".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::SshKey,
                    path: Some("/Users/alice/.ssh/id_rsa".to_string()),
                    name: Some("ssh-private-key".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-search-sidecar-path-aws-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-path-2".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build durable path findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable path findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "path": "/Users/alice/.ssh/id_rsa",
            "upstreamDepth": 1,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build durable path graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable path graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read durable path graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode durable path graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(
            payload["queryPlan"]["strategy"],
            "durable_graph_sidecar_prefilter"
        );
        assert_eq!(payload["queryPlan"]["indexSource"], "durable_graph_sidecar");
        assert!(payload["queryPlan"]["indexPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing durable path graph-search index path"))
            .ends_with(".graph-index.jsonl"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing durable path graph-search indexed keys"))
            .iter()
            .any(|key| key == "path"));
        assert_eq!(payload["queryPlan"]["candidateCount"], 1);
        assert_eq!(payload["queryPlan"]["scannedNodeCount"], 1);
        assert_eq!(payload["matches"][0]["rootKind"], "credential");
        assert_eq!(
            payload["matches"][0]["rootLabel"],
            "/Users/alice/.ssh/id_rsa"
        );

        let _ = std::fs::remove_file(&flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_graph_search_uses_durable_graph_sidecar_for_path_prefix_prefilter() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open durable flight recorder: {e}")),
        ));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-sidecar-prefix-ssh-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-prefix-1".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::SshKey,
                    path: Some("/Users/alice/.ssh/id_rsa".to_string()),
                    name: Some("ssh-private-key".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-search-sidecar-prefix-aws-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-prefix-2".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
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
            .unwrap_or_else(|e| {
                panic!("failed to build durable path-prefix findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable path-prefix findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "pathPrefix": "/Users/alice/.ssh/",
            "upstreamDepth": 1,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build durable path-prefix graph-search request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable path-prefix graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read durable path-prefix graph-search response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode durable path-prefix response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(
            payload["queryPlan"]["strategy"],
            "durable_graph_sidecar_prefilter"
        );
        assert_eq!(payload["queryPlan"]["indexSource"], "durable_graph_sidecar");
        assert!(payload["queryPlan"]["indexPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing durable path-prefix graph-search index path"))
            .ends_with(".graph-index.jsonl"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing durable path-prefix graph-search indexed keys"))
            .iter()
            .any(|key| key == "pathPrefix"));
        assert_eq!(payload["queryPlan"]["candidateCount"], 1);
        assert_eq!(payload["queryPlan"]["scannedNodeCount"], 1);
        assert_eq!(payload["matches"][0]["rootKind"], "credential");
        assert_eq!(
            payload["matches"][0]["rootLabel"],
            "/Users/alice/.ssh/id_rsa"
        );

        let _ = std::fs::remove_file(&flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_graph_search_uses_durable_graph_sidecar_for_path_pattern_prefilter() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open durable flight recorder: {e}")),
        ));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-sidecar-pattern-ssh-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-pattern-1".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::SshKey,
                    path: Some("/Users/alice/.ssh/id_rsa".to_string()),
                    name: Some("ssh-private-key".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-search-sidecar-pattern-known-hosts-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-pattern-2".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::ApiToken,
                    path: Some("/Users/alice/.ssh/known_hosts".to_string()),
                    name: Some("known-hosts".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-search-sidecar-pattern-aws-1".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-sidecar-pattern-3".to_string()),
                    image: Some("/usr/local/bin/codex".to_string()),
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
            .unwrap_or_else(|e| {
                panic!("failed to build durable path-pattern findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable path-pattern findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "pathPattern": "/Users/alice/.ssh/id_*",
            "upstreamDepth": 1,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build durable path-pattern graph-search request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("durable path-pattern graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read durable path-pattern graph-search response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode durable path-pattern response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(
            payload["queryPlan"]["strategy"],
            "durable_graph_sidecar_prefilter"
        );
        assert_eq!(payload["queryPlan"]["indexSource"], "durable_graph_sidecar");
        assert!(payload["queryPlan"]["indexPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing durable path-pattern graph-search index path"))
            .ends_with(".graph-index.jsonl"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing durable path-pattern graph-search indexed keys"))
            .iter()
            .any(|key| key == "pathPattern"));
        assert_eq!(payload["queryPlan"]["candidateCount"], 1);
        assert_eq!(payload["queryPlan"]["scannedNodeCount"], 1);
        assert_eq!(payload["matches"][0]["rootKind"], "credential");
        assert_eq!(
            payload["matches"][0]["rootLabel"],
            "/Users/alice/.ssh/id_rsa"
        );

        let _ = std::fs::remove_file(&flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_graph_search_filters_credentials_by_agent_and_attribute() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "agentId".to_string(),
            serde_json::Value::String("agent:codex".to_string()),
        );
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-agent-tool-1".to_string(),
                session_id: Some("graph-search-agent-session-1".to_string()),
                metadata: metadata.clone(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-agent-1".to_string()),
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
                observation_id: "graph-search-agent-credential-1".to_string(),
                session_id: Some("graph-search-agent-session-1".to_string()),
                metadata,
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-agent-1".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build credential graph-search findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("credential graph-search findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "credential",
            "attributeKey": "credentialKind",
            "attributeValue": "cloud_credential",
            "agentId": "agent:codex",
            "upstreamDepth": 3,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build credential graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("credential graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read credential graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode credential graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(payload["queryPlan"]["indexed"], true);
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing credential graph-search indexed keys"))
            .iter()
            .any(|key| key == "attribute:credentialKind"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing credential graph-search indexed keys"))
            .iter()
            .any(|key| key == "agentId"));
        let first_match = &payload["matches"][0];
        assert_eq!(first_match["rootKind"], "credential");
        assert_eq!(first_match["rootLabel"], "/Users/alice/.aws/credentials");
        let graph_nodes = first_match["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing credential graph-search nodes"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "tool"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "credential"));
    }

    #[tokio::test]
    async fn agent_edr_graph_search_filters_by_tool_call_identity() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "mcp_tool",
                    "id": "graph-search-tool-call-activity-1",
                    "hostId": "host-tool-call-search-1",
                    "userId": "user-tool-call-search-1",
                    "sessionId": "session-tool-call-search-1",
                    "agentId": "agent:codex",
                    "workloadId": "mcp-server",
                    "approvalId": "approval-tool-call-search-1",
                    "toolCallId": "tool-call-search-1",
                    "toolName": "mcp__filesystem__read_file",
                    "parameters": {
                        "path": "/repo/.env"
                    },
                    "process": {
                        "processGuid": "proc-tool-call-search-1",
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
            .unwrap_or_else(|e| panic!("failed to build tool-call developer activity: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("tool-call developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "tool",
            "attributeKey": "toolCallId",
            "attributeValue": "tool-call-search-1",
            "upstreamDepth": 3,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build tool-call graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("tool-call graph-search failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read tool-call graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode tool-call graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(payload["queryPlan"]["indexed"], true);
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing tool-call graph-search indexed keys"))
            .iter()
            .any(|key| key == "nodeKind"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing tool-call graph-search indexed keys"))
            .iter()
            .any(|key| key == "attribute:toolCallId"));
        assert_eq!(payload["matches"][0]["rootKind"], "tool");
        let graph_nodes = payload["matches"][0]["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing tool-call graph-search nodes"));
        assert!(graph_nodes.values().any(|node| {
            node["kind"] == "tool" && node["attributes"]["toolCallId"] == "tool-call-search-1"
        }));
        assert!(graph_nodes.values().any(|node| {
            node["kind"] == "process" && node["attributes"]["toolCallId"] == "tool-call-search-1"
        }));
    }

    #[tokio::test]
    async fn agent_edr_graph_search_filters_by_tool_name() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);

        let body = serde_json::json!({
            "activities": [
                {
                    "kind": "mcp_tool",
                    "id": "graph-search-tool-name-read-1",
                    "sessionId": "session-tool-name-search-1",
                    "agentId": "agent:codex",
                    "toolName": "mcp__filesystem__read_file",
                    "parameters": {
                        "path": "/repo/.env"
                    },
                    "process": {
                        "processGuid": "proc-tool-name-search-1",
                        "image": "/usr/bin/python3"
                    }
                },
                {
                    "kind": "mcp_tool",
                    "id": "graph-search-tool-name-browser-1",
                    "sessionId": "session-tool-name-search-1",
                    "agentId": "agent:codex",
                    "toolName": "mcp__browser__open_url",
                    "parameters": {
                        "url": "https://docs.example.invalid"
                    },
                    "process": {
                        "processGuid": "proc-tool-name-search-1",
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
            .unwrap_or_else(|e| panic!("failed to build tool-name developer activity: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("tool-name developer activity failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "tool",
            "toolName": "mcp__filesystem__read_file",
            "upstreamDepth": 3,
            "downstreamDepth": 1,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build tool-name graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("tool-name graph-search failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read tool-name graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode tool-name graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(payload["queryPlan"]["indexed"], true);
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing tool-name graph-search indexed keys"))
            .iter()
            .any(|key| key == "nodeKind"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing tool-name graph-search indexed keys"))
            .iter()
            .any(|key| key == "toolName"));
        assert_eq!(payload["matches"][0]["rootKind"], "tool");
        assert_eq!(
            payload["matches"][0]["rootLabel"],
            "mcp__filesystem__read_file"
        );
    }

    #[tokio::test]
    async fn agent_edr_graph_search_filters_by_host_identity() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(state);
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-host-a-network-1".to_string(),
                host_id: Some("endpoint-host-a".to_string()),
                user_id: Some("alice@example.com".to_string()),
                session_id: Some("graph-search-host-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-host-a".to_string()),
                    image: Some("/usr/local/bin/node".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "api.host-search.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://api.host-search.invalid/upload".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-search-host-b-network-1".to_string(),
                host_id: Some("endpoint-host-b".to_string()),
                user_id: Some("alice@example.com".to_string()),
                session_id: Some("graph-search-host-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-host-b".to_string()),
                    image: Some("/usr/local/bin/node".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "api.host-search.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://api.host-search.invalid/upload".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build host graph-search findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("host graph-search findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "host",
            "hostId": "endpoint-host-a",
            "downstreamDepth": 3,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build host graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("host graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read host graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode host graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(payload["queryPlan"]["indexed"], true);
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing host graph-search indexed keys"))
            .iter()
            .any(|key| key == "nodeKind"));
        assert!(payload["queryPlan"]["indexedKeys"]
            .as_array()
            .unwrap_or_else(|| panic!("missing host graph-search indexed keys"))
            .iter()
            .any(|key| key == "hostId"));
        assert_eq!(payload["matches"][0]["rootKind"], "host");
        assert_eq!(payload["matches"][0]["rootLabel"], "endpoint-host-a");
    }

    #[tokio::test]
    async fn agent_edr_graph_search_can_start_from_agent_identity_node() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
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
        metadata.insert(
            "approvalId".to_string(),
            serde_json::Value::String("approval-graph-agent-1".to_string()),
        );
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-search-agent-root-tool-1".to_string(),
                host_id: Some("host-agent-root-1".to_string()),
                user_id: Some("user-agent-root-1".to_string()),
                session_id: Some("graph-search-agent-root-session-1".to_string()),
                metadata: metadata.clone(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-agent-root-1".to_string()),
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
                observation_id: "graph-search-agent-root-credential-1".to_string(),
                host_id: Some("host-agent-root-1".to_string()),
                user_id: Some("user-agent-root-1".to_string()),
                session_id: Some("graph-search-agent-root-session-1".to_string()),
                metadata,
                process: EndpointProcess {
                    process_guid: Some("proc-graph-search-agent-root-1".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build agent-root graph findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("agent-root graph findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "nodeKind": "agent",
            "labelContains": "agent:codex",
            "downstreamDepth": 3,
            "limit": 10
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build agent-root graph-search request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("agent-root graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read agent-root graph-search response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode agent-root graph-search response: {e}"));

        assert_eq!(payload["matchCount"], 1);
        assert_eq!(payload["matches"][0]["rootKind"], "agent");
        assert_eq!(payload["matches"][0]["rootLabel"], "agent:codex");
        let graph_nodes = payload["matches"][0]["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing agent-root graph nodes"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "process"));
        assert!(graph_nodes.values().any(|node| node["kind"] == "tool"));
        assert!(graph_nodes
            .values()
            .any(|node| node["kind"] == "credential"));
        assert!(payload["matches"][0]["graph"]["edges"]
            .as_array()
            .unwrap_or_else(|| panic!("missing agent-root graph edges"))
            .iter()
            .any(|edge| edge["kind"] == "used_agent"));
    }

    #[tokio::test]
    async fn agent_edr_graph_search_rejects_unbounded_query() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .with_state(Arc::new(test_state()));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-search")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap_or_else(|e| panic!("failed to build unbounded graph-search request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unbounded graph-search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unbounded graph-search response: {e}"));
        let body = std::str::from_utf8(&bytes)
            .unwrap_or_else(|e| panic!("unbounded graph-search response is not utf8: {e}"));
        assert!(body.contains("at least one graph search filter must be provided"));
    }

    #[tokio::test]
    async fn agent_edr_graph_slice_export_stores_retrievable_bundle_and_receipt() {
        let bundle_dir = test_evidence_bundle_dir();
        let receipt_path = test_receipt_path();
        let fleet_outbox_path = test_fleet_hunt_event_outbox_path();
        let keypair = Keypair::from_seed(&[67u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_evidence_bundle_store = Arc::new(Mutex::new(
            EndpointEvidenceBundleStore::open(&bundle_dir)
                .unwrap_or_else(|err| panic!("failed to open graph-slice export store: {err}")),
        ));
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-graph-slice-archive-signer".to_string(),
            signer_public_key,
        }));
        state.edr_fleet_hunt_event_outbox = Arc::new(Mutex::new(
            EndpointFleetHuntEventOutbox::open(&fleet_outbox_path)
                .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}")),
        ));
        {
            let mut settings = state.settings.write().await;
            settings.nats.tenant_id = Some("4b83d8d0-7b6d-4a3b-8cc4-0aa83d1f3b41".to_string());
            settings.nats.agent_id = Some("endpoint-agent-archive-1".to_string());
        }
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
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
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish",
                post(agent_edr_evidence_bundle_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/archive/verify",
                post(agent_edr_evidence_bundle_archive_verify),
            )
            .with_state(Arc::new(state));
        let identity_metadata = BTreeMap::from([
            (
                "agentId".to_string(),
                serde_json::json!("agent-graph-slice-export-1"),
            ),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-graph-slice-export-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-graph-slice-export-1"),
            ),
            (
                "toolCallId".to_string(),
                serde_json::json!("tool-call-graph-slice-export-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "graph-slice-export-tool-1".to_string(),
                host_id: Some("host-graph-slice-export-1".to_string()),
                user_id: Some("exporter".to_string()),
                session_id: Some("graph-slice-export-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-slice-export-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.export".to_string(),
                    parameters: serde_json::json!({
                        "target": "export-bundle.example.invalid"
                    }),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-slice-export-network-1".to_string(),
                host_id: Some("host-graph-slice-export-1".to_string()),
                user_id: Some("exporter".to_string()),
                session_id: Some("graph-slice-export-session-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-slice-export-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "export-bundle.example.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://export-bundle.example.invalid/upload".to_string()),
                },
                metadata: identity_metadata,
                ..EndpointObservation::default()
            },
        ];
        let export_root_node_id = observations[0].process.stable_node_id();
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
            .unwrap_or_else(|e| panic!("failed to build graph-slice export findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-slice export findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "process": {
                "processGuid": "proc-graph-slice-export-1"
            },
            "sliceKind": "causal_subgraph",
            "maxDepth": 3,
            "reason": "operator export for incident review"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/graph-slices/export")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build graph-slice export request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-slice export request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph-slice export response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode graph-slice export response: {e}"));

        assert_eq!(payload["sliceKind"], "causal_subgraph");
        assert!(payload["nodeCount"].as_u64().unwrap_or_default() >= 2);
        assert_eq!(payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            payload["affectedIdentities"]["hosts"][0]["id"],
            "host-graph-slice-export-1"
        );
        assert_eq!(payload["affectedIdentities"]["users"][0]["id"], "exporter");
        assert_eq!(
            payload["affectedIdentities"]["sessions"][0]["id"],
            "graph-slice-export-session-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["agents"][0]["id"],
            "agent-graph-slice-export-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-graph-slice-export-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-graph-slice-export-1"
        );
        assert_eq!(payload["affectedTools"][0]["toolName"], "mcp.export");
        assert_eq!(
            payload["bundle"]["graphSliceId"],
            payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["graph"]["graphSliceId"]
        );
        assert_eq!(
            payload["artifact"]["bundleId"],
            payload["bundle"]["bundleId"]
        );
        let artifact_path = payload["artifact"]["path"]
            .as_str()
            .unwrap_or_else(|| panic!("missing graph-slice export artifact path"));
        assert!(
            std::path::Path::new(artifact_path).exists(),
            "graph-slice export artifact was not persisted"
        );
        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode graph-slice export receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing graph-slice export endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing graph-slice export receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse graph-slice export public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "graph_slice");
        assert_eq!(
            endpoint_decision["decision"]["ruleId"],
            "endpoint.graph_slice.causal_subgraph"
        );

        let bundle_id = payload["bundle"]["bundleId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing exported graph-slice bundle id"));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/api/v1/agent/edr/evidence-bundles/{bundle_id}"))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build graph-slice bundle fetch: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-slice bundle fetch failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph-slice bundle response: {e}"));
        let bundle_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode graph-slice bundle response: {e}"));
        assert_eq!(bundle_payload["bundle"]["bundleId"], bundle_id);
        assert_eq!(
            bundle_payload["bundle"]["contentHash"],
            payload["bundle"]["contentHash"]
        );
        assert!(bundle_payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing graph-slice bundle nodes"))
            .values()
            .any(|node| node["label"] == "export-bundle.example.invalid:443"));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build graph-slice bundle archive request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-slice bundle archive request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph-slice bundle archive response: {e}"));
        let archive_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode graph-slice bundle archive response: {e}")
            });
        assert_eq!(archive_payload["archive"]["bundle"]["bundleId"], bundle_id);
        assert_eq!(
            archive_payload["archive"]["bundle"]["contentHash"],
            payload["bundle"]["contentHash"]
        );
        assert!(archive_payload["archiveHash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"));
        assert_eq!(archive_payload["verification"]["verified"], true);
        assert_eq!(
            archive_payload["verification"]["graphContentHash"],
            payload["bundle"]["contentHash"]
        );
        assert_eq!(archive_payload["verification"]["contentHashMatches"], true);
        assert_eq!(
            archive_payload["verification"]["artifactMatchesBundle"],
            true
        );
        assert_eq!(
            archive_payload["verification"]["artifactByteCountMatches"],
            true
        );
        assert_eq!(archive_payload["verification"]["graphCountsMatch"], true);
        assert_eq!(
            archive_payload["verification"]["receiptSignaturesValid"],
            true
        );
        assert_eq!(
            archive_payload["verification"]["requiredReceiptFamiliesPresent"],
            true
        );
        assert_eq!(
            archive_payload["verification"]["receiptsBindGraphSlice"],
            true
        );
        assert_eq!(
            archive_payload["verification"]["receiptsBindContentHash"],
            true
        );
        assert_eq!(archive_payload["verification"]["receiptFailureCount"], 0);
        assert!(archive_payload["archiveId"]
            .as_str()
            .unwrap_or_default()
            .starts_with("evidence_bundle_archive-"));
        assert_eq!(archive_payload["receiptCount"], 1);
        assert_eq!(
            archive_payload["archive"]["receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "graph_slice"
        );
        assert_eq!(
            archive_payload["archive"]["receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["graph"]["graphSliceId"],
            payload["bundle"]["graphSliceId"]
        );
        assert!(
            archive_payload["archive"]["receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing graph-slice archive receipt evidence"))
                .iter()
                .any(|item| item["key"] == "contentHash")
        );
        assert!(archive_payload["archive"]["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing graph-slice archive nodes"))
            .values()
            .any(|node| node["label"] == "export-bundle.example.invalid:443"));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(archive_payload.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build graph-slice bundle archive verifier request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("graph-slice bundle archive verifier request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read graph-slice bundle archive verifier response: {e}")
            });
        let verify_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode graph-slice bundle archive verifier response: {e}")
            });
        assert_eq!(verify_payload["verified"], true);
        assert_eq!(
            verify_payload["archiveHash"],
            archive_payload["archiveHash"]
        );
        assert_eq!(verify_payload["archiveHashMatches"], true);
        assert_eq!(
            verify_payload["expectedArchiveId"],
            archive_payload["archiveId"]
        );
        assert_eq!(verify_payload["archiveIdMatches"], true);
        assert_eq!(verify_payload["receiptCountMatches"], true);
        assert_eq!(verify_payload["verificationMatches"], true);
        assert_eq!(verify_payload["generatedAtCoversReceipts"], true);
        assert!(verify_payload["newestReceiptTimestamp"]
            .as_str()
            .is_some_and(|timestamp| timestamp.ends_with('Z')));
        assert_eq!(verify_payload["verification"]["verified"], true);
        assert_eq!(
            verify_payload["verification"]["receiptsBindContentHash"],
            true
        );
        assert_eq!(verify_payload["verification"]["receiptsBindBundleId"], true);
        assert_eq!(verify_payload["verification"]["receiptsBindActor"], true);
        assert_eq!(verify_payload["verification"]["receiptsBindPolicy"], true);
        assert_eq!(
            verify_payload["verification"]["receiptsBindSensorState"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["receiptsBindEndpointDecision"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["receiptsBindEndpointIdentity"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["receiptEndpointIds"]
                .as_array()
                .unwrap_or_else(|| panic!("missing graph-slice endpoint identity list"))
                .len(),
            1
        );
        assert_eq!(verify_payload["verification"]["receiptsBindRootNode"], true);
        assert_eq!(
            verify_payload["verification"]["receiptRootNodeIds"]
                .as_array()
                .unwrap_or_else(|| panic!("missing graph-slice root-node list"))
                .len(),
            1
        );
        assert_eq!(
            verify_payload["verification"]["receiptSignersConsistent"],
            true
        );
        assert_eq!(verify_payload["verification"]["receiptIdsUnique"], true);
        assert!(verify_payload["verification"]["presentReceiptFamilies"]
            .as_array()
            .unwrap_or_else(|| panic!("missing present receipt-family list"))
            .iter()
            .any(|family| family == "graph_slice"));
        assert_eq!(
            verify_payload["verification"]["receiptFamilyCounts"]["graph_slice"],
            1
        );
        assert_eq!(
            verify_payload["verification"]["receiptFamilyCardinalityValid"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["requiredReceiptFamilies"],
            serde_json::json!(["graph_slice"])
        );
        assert_eq!(
            verify_payload["verification"]["missingRequiredReceiptFamilies"],
            serde_json::json!([])
        );
        assert_eq!(
            verify_payload["verification"]["receiptLocalSequencesPresent"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["receiptLocalSequencesUnique"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["receiptLocalSequences"],
            serde_json::json!([3])
        );
        assert_eq!(
            verify_payload["verification"]["receiptTimestampsParse"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["receiptChronologyConsistent"],
            true
        );
        assert_eq!(
            verify_payload["verification"]["graphContentHash"],
            payload["bundle"]["contentHash"]
        );
        assert_eq!(verify_payload["verification"]["receiptFailureCount"], 0);

        let archive_receipt_signer_public_key = archive_payload["archive"]["receipts"][0]
            ["receipt"]["metadata"]["endpointDecision"]["signer"]["signerPublicKey"]
            .as_str()
            .unwrap_or_else(|| panic!("missing archive receipt signer public key"));
        let mut trusted_signer_payload = archive_payload.clone();
        trusted_signer_payload["trustedSignerPublicKey"] =
            Value::String(archive_receipt_signer_public_key.to_string());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(trusted_signer_payload.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build trusted-signer archive verifier request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("trusted-signer archive verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read trusted-signer verifier response: {e}"));
        let trusted_signer_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode trusted-signer verifier response: {e}"));
        assert_eq!(trusted_signer_verify_payload["verified"], true);
        assert_eq!(
            trusted_signer_verify_payload["trustedSignerPublicKey"],
            archive_receipt_signer_public_key
        );
        assert_eq!(trusted_signer_verify_payload["signerTrustMatches"], true);

        let mut wrong_trusted_signer_payload = archive_payload.clone();
        wrong_trusted_signer_payload["trustedSignerPublicKey"] =
            Value::String(Keypair::from_seed(&[71u8; 32]).public_key().to_hex());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                wrong_trusted_signer_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build wrong trusted-signer archive verifier request: {e}")
            });
        let response = app.clone().oneshot(req).await.unwrap_or_else(|e| {
            panic!("wrong trusted-signer archive verifier request failed: {e}")
        });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read wrong trusted-signer verifier response: {e}")
            });
        let wrong_trusted_signer_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode wrong trusted-signer verifier response: {e}")
            });
        assert_eq!(wrong_trusted_signer_verify_payload["verified"], false);
        assert_eq!(
            wrong_trusted_signer_verify_payload["verification"]["verified"],
            true
        );
        assert_eq!(
            wrong_trusted_signer_verify_payload["signerTrustMatches"],
            false
        );

        let mut empty_trusted_signer_payload = archive_payload.clone();
        empty_trusted_signer_payload["trustedSignerPublicKey"] = Value::String("   ".to_string());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                empty_trusted_signer_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build empty trusted-signer archive verifier request: {e}")
            });
        let response = app.clone().oneshot(req).await.unwrap_or_else(|e| {
            panic!("empty trusted-signer archive verifier request failed: {e}")
        });
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut malformed_trusted_signer_payload = archive_payload.clone();
        malformed_trusted_signer_payload["trustedSignerPublicKey"] =
            Value::String("not-a-public-key".to_string());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                malformed_trusted_signer_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build malformed trusted-signer archive verifier request: {e}")
            });
        let response = app.clone().oneshot(req).await.unwrap_or_else(|e| {
            panic!("malformed trusted-signer archive verifier request failed: {e}")
        });
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut stale_generated_at_payload = archive_payload.clone();
        stale_generated_at_payload["generatedAt"] =
            Value::String("1970-01-01T00:00:00Z".to_string());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                stale_generated_at_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build stale generatedAt archive verifier request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("stale generatedAt archive verifier request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read stale generatedAt verifier response: {e}"));
        let stale_generated_at_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode stale generatedAt verifier response: {e}")
            });
        assert_eq!(
            stale_generated_at_verify_payload["archiveHashMatches"],
            true
        );
        assert_eq!(
            stale_generated_at_verify_payload["verification"]["verified"],
            true
        );
        assert_eq!(
            stale_generated_at_verify_payload["generatedAtCoversReceipts"],
            false
        );
        assert_eq!(stale_generated_at_verify_payload["verified"], false);

        let mut wrong_archive_id_payload = archive_payload.clone();
        wrong_archive_id_payload["archiveId"] =
            serde_json::Value::String("evidence_bundle_archive:wrong".to_string());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(wrong_archive_id_payload.to_string()))
            .unwrap_or_else(|e| panic!("failed to build wrong-archive-id verifier request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("wrong-archive-id verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read wrong-archive-id verifier response: {e}"));
        let wrong_archive_id_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode wrong-archive-id verifier response: {e}"));
        assert_eq!(wrong_archive_id_verify_payload["archiveHashMatches"], true);
        assert_eq!(
            wrong_archive_id_verify_payload["verification"]["verified"],
            true
        );
        assert_eq!(wrong_archive_id_verify_payload["archiveIdMatches"], false);
        assert_eq!(wrong_archive_id_verify_payload["receiptCountMatches"], true);
        assert_eq!(wrong_archive_id_verify_payload["verified"], false);

        let mut wrong_receipt_count_payload = archive_payload.clone();
        wrong_receipt_count_payload["receiptCount"] = serde_json::Value::from(0);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                wrong_receipt_count_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build wrong-receipt-count verifier request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("wrong-receipt-count verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read wrong-receipt-count verifier response: {e}")
            });
        let wrong_receipt_count_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode wrong-receipt-count verifier response: {e}")
            });
        assert_eq!(wrong_receipt_count_verify_payload["archiveIdMatches"], true);
        assert_eq!(
            wrong_receipt_count_verify_payload["receiptCountMatches"],
            false
        );
        assert_eq!(
            wrong_receipt_count_verify_payload["verificationMatches"],
            true
        );
        assert_eq!(wrong_receipt_count_verify_payload["verified"], false);

        let mut wrong_verification_payload = archive_payload.clone();
        wrong_verification_payload["verification"]["verified"] = serde_json::Value::Bool(false);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                wrong_verification_payload.to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build wrong-verification verifier request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("wrong-verification verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read wrong-verification verifier response: {e}"));
        let wrong_verification_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode wrong-verification verifier response: {e}")
            });
        assert_eq!(
            wrong_verification_verify_payload["archiveHashMatches"],
            true
        );
        assert_eq!(wrong_verification_verify_payload["archiveIdMatches"], true);
        assert_eq!(
            wrong_verification_verify_payload["receiptCountMatches"],
            true
        );
        assert_eq!(
            wrong_verification_verify_payload["verificationMatches"],
            false
        );
        assert_eq!(
            wrong_verification_verify_payload["verification"]["verified"],
            true
        );
        assert_eq!(wrong_verification_verify_payload["verified"], false);
        let archive: EdrEvidenceBundleArchive =
            serde_json::from_value(archive_payload["archive"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode archive payload for fleet event: {e}")
            });
        let archive_verification = evidence_bundle_archive_verification(&archive)
            .unwrap_or_else(|e| panic!("failed to verify archive for fleet event: {e}"));
        let mut duplicate_receipt_archive = archive.clone();
        duplicate_receipt_archive
            .receipts
            .push(duplicate_receipt_archive.receipts[0].clone());
        let duplicate_receipt_verification =
            evidence_bundle_archive_verification(&duplicate_receipt_archive)
                .unwrap_or_else(|e| panic!("failed to verify duplicate-receipt archive: {e}"));
        assert_eq!(duplicate_receipt_verification.verified, false);
        assert_eq!(duplicate_receipt_verification.receipt_ids_unique, false);
        assert_eq!(
            duplicate_receipt_verification.receipt_local_sequences_present,
            true
        );
        assert_eq!(
            duplicate_receipt_verification.receipt_local_sequences_unique,
            false
        );
        assert_eq!(
            duplicate_receipt_verification.receipt_signatures_valid,
            true
        );
        assert_eq!(
            duplicate_receipt_verification.receipt_signers_consistent,
            true
        );
        assert_eq!(
            duplicate_receipt_verification.receipt_family_cardinality_valid,
            false
        );
        assert!(
            duplicate_receipt_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.starts_with("duplicate_receipt_id:")),
            "missing duplicate receipt-id failure: {:?}",
            duplicate_receipt_verification.receipt_failures
        );
        assert!(
            duplicate_receipt_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.starts_with("duplicate_receipt_local_sequence:")),
            "missing duplicate local-sequence failure: {:?}",
            duplicate_receipt_verification.receipt_failures
        );
        assert!(
            duplicate_receipt_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "duplicate_receipt_family:graph_slice:2"),
            "missing duplicate receipt-family failure: {:?}",
            duplicate_receipt_verification.receipt_failures
        );
        let mut invalid_timestamp_archive = archive.clone();
        invalid_timestamp_archive.receipts[0].receipt.timestamp = "not-a-timestamp".to_string();
        let invalid_timestamp_verification =
            evidence_bundle_archive_verification(&invalid_timestamp_archive)
                .unwrap_or_else(|e| panic!("failed to verify invalid-timestamp archive: {e}"));
        assert_eq!(invalid_timestamp_verification.verified, false);
        assert_eq!(
            invalid_timestamp_verification.receipt_timestamps_parse,
            false
        );
        assert_eq!(
            invalid_timestamp_verification.receipt_chronology_consistent,
            false
        );
        assert!(
            invalid_timestamp_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":invalid_receipt_timestamp")),
            "missing invalid timestamp failure: {:?}",
            invalid_timestamp_verification.receipt_failures
        );
        let mut endpoint_decision_drift_archive = archive.clone();
        let endpoint_decision_value = endpoint_decision_drift_archive.receipts[0]
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .cloned()
            .unwrap_or_else(|| panic!("missing endpoint decision metadata for drift receipt"));
        let receipt_id = endpoint_decision_drift_archive.receipts[0]
            .receipt
            .receipt_id
            .clone()
            .unwrap_or_else(|| panic!("missing receipt id for endpoint-decision drift receipt"));
        let drift_receipt = hush_core::Receipt::new(
            sha256(b"wrong endpoint decision metadata"),
            hush_core::Verdict::pass(),
        )
        .with_id(receipt_id)
        .with_metadata(serde_json::json!({
            "endpointDecision": endpoint_decision_value
        }));
        let drift_receipt =
            SignedReceipt::sign_with(drift_receipt, &Keypair::from_seed(&[67u8; 32]))
                .unwrap_or_else(|e| panic!("failed to sign endpoint-decision drift receipt: {e}"));
        endpoint_decision_drift_archive.receipts[0] = drift_receipt;
        let endpoint_decision_drift_verification = evidence_bundle_archive_verification(
            &endpoint_decision_drift_archive,
        )
        .unwrap_or_else(|e| panic!("failed to verify endpoint-decision drift archive: {e}"));
        assert_eq!(endpoint_decision_drift_verification.verified, false);
        assert_eq!(
            endpoint_decision_drift_verification.receipt_signatures_valid,
            true
        );
        assert_eq!(
            endpoint_decision_drift_verification.receipts_bind_endpoint_decision,
            false
        );
        assert!(
            endpoint_decision_drift_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains("endpoint_decision_binding_invalid")),
            "missing endpoint decision binding failure: {:?}",
            endpoint_decision_drift_verification.receipt_failures
        );
        let mut wrong_graph_slice_count_archive = archive.clone();
        let wrong_graph_slice_count_hash = sha256(b"0").to_hex_prefixed();
        let graph_slice_metadata = wrong_graph_slice_count_archive.receipts[0]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing graph-slice endpointDecision metadata"));
        let graph_slice_evidence = graph_slice_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing graph-slice receipt evidence"));
        let graph_slice_node_count_evidence = graph_slice_evidence
            .iter_mut()
            .find(|item| item.get("key").and_then(Value::as_str) == Some("nodeCount"))
            .unwrap_or_else(|| panic!("missing graph-slice nodeCount evidence"));
        graph_slice_node_count_evidence["valueHash"] = Value::String(wrong_graph_slice_count_hash);
        let wrong_graph_slice_count_verification = evidence_bundle_archive_verification(
            &wrong_graph_slice_count_archive,
        )
        .unwrap_or_else(|e| panic!("failed to verify wrong graph-slice count archive: {e}"));
        assert_eq!(wrong_graph_slice_count_verification.verified, false);
        assert_eq!(
            wrong_graph_slice_count_verification.receipt_signatures_valid,
            false
        );
        assert_eq!(
            wrong_graph_slice_count_verification.graph_counts_match,
            false
        );
        assert_eq!(
            wrong_graph_slice_count_verification.receipts_bind_graph_slice,
            true
        );
        assert_eq!(
            wrong_graph_slice_count_verification.receipts_bind_content_hash,
            true
        );
        assert!(
            wrong_graph_slice_count_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":node_count_mismatch:")),
            "missing graph-slice node-count mismatch failure: {:?}",
            wrong_graph_slice_count_verification.receipt_failures
        );
        assert!(
            wrong_graph_slice_count_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":signature_invalid")),
            "missing signature failure for tampered graph-slice receipt: {:?}",
            wrong_graph_slice_count_verification.receipt_failures
        );
        let mut unknown_contract_archive = archive.clone();
        unknown_contract_archive.bundle.bundle_id = "custom_bundle:graph-slice-export".to_string();
        unknown_contract_archive.artifact.bundle_id =
            unknown_contract_archive.bundle.bundle_id.clone();
        let unknown_contract_verification =
            evidence_bundle_archive_verification(&unknown_contract_archive)
                .unwrap_or_else(|e| panic!("failed to verify unknown-contract archive: {e}"));
        assert_eq!(unknown_contract_verification.verified, false);
        assert_eq!(
            unknown_contract_verification.required_receipt_families_present,
            false
        );
        assert!(unknown_contract_verification
            .required_receipt_families
            .is_empty());
        assert!(unknown_contract_verification
            .missing_required_receipt_families
            .is_empty());
        assert_eq!(unknown_contract_verification.receipt_families_valid, true);
        assert!(
            unknown_contract_verification
                .receipt_failures
                .iter()
                .any(|failure| failure
                    == "unknown_required_family_contract:custom_bundle:graph-slice-export"),
            "missing unknown required-family contract failure: {:?}",
            unknown_contract_verification.receipt_failures
        );
        let archive_id = archive_payload["archiveId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing archive id for fleet event"));
        let archive_hash = archive_payload["archiveHash"]
            .as_str()
            .unwrap_or_else(|| panic!("missing archive hash for fleet event"));
        let fleet_event = fleet_hunt_event_for_evidence_bundle_archive(
            archive_id,
            archive_hash,
            &archive,
            &archive_verification,
            "4b83d8d0-7b6d-4a3b-8cc4-0aa83d1f3b41",
            "endpoint-agent-archive-1",
        );
        assert_eq!(
            fleet_event["eventId"],
            format!("evidence-bundle-archive:endpoint-agent-archive-1:{archive_id}")
        );
        assert_eq!(fleet_event["source"], "receipt");
        assert_eq!(fleet_event["kind"], "detection_fired");
        assert_eq!(
            fleet_event["evidence"]["rawRef"],
            format!("endpoint-evidence-bundle-archive:{archive_id}:{archive_hash}")
        );
        assert_eq!(
            fleet_event["evidence"]["schemaName"],
            "clawdstrike.edr.evidence_bundle_archive.v1"
        );
        assert_eq!(fleet_event["target"]["kind"], "evidence_bundle");
        assert_eq!(fleet_event["target"]["id"], bundle_id);
        assert_eq!(fleet_event["attributes"]["archiveHash"], archive_hash);
        assert_eq!(fleet_event["attributes"]["verification"]["verified"], true);
        assert_eq!(
            fleet_event["attributes"]["graphNodeCount"],
            archive.bundle.node_count
        );
        assert_eq!(
            fleet_event["attributes"]["graphEdgeCount"],
            archive.bundle.edge_count
        );
        assert!(fleet_event["attributes"]["receiptHashes"]
            .as_array()
            .unwrap_or_else(|| panic!("missing fleet archive receipt hashes"))
            .iter()
            .all(|hash: &serde_json::Value| hash
                .as_str()
                .is_some_and(|value| value.starts_with("0x"))));
        let attributes = fleet_event["attributes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing fleet archive attributes"));
        assert!(
            !attributes.contains_key("archive"),
            "fleet event must not inline raw archive payload"
        );
        assert!(
            !attributes.contains_key("graph"),
            "fleet event must not inline raw graph"
        );
        assert!(
            !attributes.contains_key("receipts"),
            "fleet event must not inline raw receipt bodies"
        );

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build graph-slice bundle fleet publish request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph-slice bundle fleet publish request failed: {e}"));
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read fleet publish queued response: {e}"));
        let queued_publish_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode fleet publish queued response: {e}"));
        assert_eq!(queued_publish_payload["published"], false);
        assert_eq!(queued_publish_payload["queued"], true);
        assert!(queued_publish_payload["outboxId"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"));

        let queued_events = read_fleet_hunt_event_outbox(&fleet_outbox_path)
            .unwrap_or_else(|e| panic!("failed to read fleet hunt event outbox: {e}"));
        assert_eq!(queued_events.len(), 1);
        assert_eq!(queued_events[0].event_id, fleet_event["eventId"]);
        assert_eq!(queued_events[0].raw_ref, fleet_event["evidence"]["rawRef"]);
        assert_eq!(
            queued_events[0].event["attributes"]["archiveHash"],
            archive_hash
        );
        let queued_attributes = queued_events[0].event["attributes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing queued archive attributes"));
        assert!(
            !queued_attributes.contains_key("archive"),
            "queued fleet event must not inline raw archive payload"
        );
        assert!(
            !queued_attributes.contains_key("graph"),
            "queued fleet event must not inline raw graph"
        );
        assert!(
            !queued_attributes.contains_key("receipts"),
            "queued fleet event must not inline raw receipt bodies"
        );

        let mut wrong_bundle = archive.bundle.clone();
        wrong_bundle.bundle_id = "evidence_bundle:wrong-archive-bundle".to_string();
        let wrong_bundle_keypair = Keypair::from_seed(&[69u8; 32]);
        let mut wrong_bundle_decision = EndpointDecisionReceipt::for_evidence_bundle_manifest(
            EndpointEvidenceBundleManifestReceiptInput {
                local_sequence: 69,
                endpoint_id: "endpoint-agent-archive-1",
                signer_identity: "test-edr-graph-slice-archive-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-edr".to_string(),
                    policy_hash: sha256(b"test-edr").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                root_node_id: export_root_node_id.as_str(),
                bundle: &wrong_bundle,
                graph: &archive.graph,
            },
        );
        wrong_bundle_decision.signer.signer_public_key =
            Some(wrong_bundle_keypair.public_key().to_hex());
        let wrong_bundle_receipt = wrong_bundle_decision
            .sign_with(&wrong_bundle_keypair)
            .unwrap_or_else(|e| panic!("failed to sign wrong-bundle archive receipt: {e}"));
        let mut wrong_bundle_archive_payload = archive_payload.clone();
        wrong_bundle_archive_payload["archive"]["receipts"] =
            serde_json::json!([wrong_bundle_receipt]);
        let wrong_bundle_archive_hash = canonical_json_hash(
            &wrong_bundle_archive_payload["archive"],
            "wrong-bundle evidence bundle archive",
        )
        .unwrap_or_else(|e| panic!("failed to hash wrong-bundle archive: {e}"));
        wrong_bundle_archive_payload["archiveHash"] =
            serde_json::Value::String(wrong_bundle_archive_hash);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                wrong_bundle_archive_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build wrong-bundle archive verifier request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("wrong-bundle archive verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read wrong-bundle verifier response: {e}"));
        let wrong_bundle_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode wrong-bundle verifier response: {e}"));
        assert_eq!(wrong_bundle_verify_payload["archiveHashMatches"], true);
        assert_eq!(wrong_bundle_verify_payload["verified"], false);
        assert_eq!(
            wrong_bundle_verify_payload["verification"]["receiptsBindBundleId"],
            false
        );
        assert_eq!(
            wrong_bundle_verify_payload["verification"]["receiptsBindGraphSlice"],
            true
        );
        assert_eq!(
            wrong_bundle_verify_payload["verification"]["requiredReceiptFamiliesPresent"],
            false
        );
        assert_eq!(
            wrong_bundle_verify_payload["verification"]["receiptsBindContentHash"],
            true
        );
        assert!(
            wrong_bundle_verify_payload["verification"]["receiptFailures"]
                .as_array()
                .unwrap_or_else(|| panic!("missing wrong-bundle receipt failures"))
                .iter()
                .any(|failure| failure.as_str().is_some_and(|failure| {
                    failure.contains("manifest_finding_id_mismatch")
                        || failure.contains("evidence_bundle_id_mismatch")
                }))
        );

        let wrong_family_root = bundle_dir.join("wrong-family-deception");
        let wrong_family_plan =
            DeceptionPlan::standard(&wrong_family_root, "endpoint-agent-archive-1");
        let wrong_family_cleanup = DeceptionCleanupReport {
            dry_run: true,
            removed: Vec::new(),
            would_remove: wrong_family_plan
                .artifacts
                .iter()
                .map(|artifact| {
                    artifact
                        .absolute_path(&wrong_family_root)
                        .display()
                        .to_string()
                })
                .collect(),
            missing: Vec::new(),
            refused: Vec::new(),
        };
        let wrong_family_keypair = Keypair::from_seed(&[68u8; 32]);
        let mut wrong_family_decision =
            EndpointDecisionReceipt::for_deception_cleanup(EndpointDeceptionCleanupReceiptInput {
                local_sequence: 67,
                endpoint_id: "endpoint-agent-archive-1",
                signer_identity: "test-edr-graph-slice-archive-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-edr".to_string(),
                    policy_hash: sha256(b"test-edr").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &wrong_family_plan,
                report: &wrong_family_cleanup,
                deregistered_artifact_count: 0,
                remaining_registered_artifact_count: wrong_family_plan.artifacts.len(),
            });
        wrong_family_decision.signer.signer_public_key =
            Some(wrong_family_keypair.public_key().to_hex());
        let wrong_family_receipt = wrong_family_decision
            .sign_with(&wrong_family_keypair)
            .unwrap_or_else(|e| panic!("failed to sign wrong-family archive receipt: {e}"));
        let mut wrong_family_archive_payload = archive_payload.clone();
        wrong_family_archive_payload["archive"]["receipts"] =
            serde_json::json!([wrong_family_receipt]);
        let wrong_family_archive_hash = canonical_json_hash(
            &wrong_family_archive_payload["archive"],
            "wrong-family evidence bundle archive",
        )
        .unwrap_or_else(|e| panic!("failed to hash wrong-family archive: {e}"));
        wrong_family_archive_payload["archiveHash"] =
            serde_json::Value::String(wrong_family_archive_hash);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                wrong_family_archive_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build wrong-family archive verifier request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("wrong-family archive verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read wrong-family verifier response: {e}"));
        let wrong_family_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode wrong-family verifier response: {e}"));
        assert_eq!(wrong_family_verify_payload["archiveHashMatches"], true);
        assert_eq!(wrong_family_verify_payload["verified"], false);
        assert_eq!(
            wrong_family_verify_payload["verification"]["receiptFamiliesValid"],
            false
        );
        assert_eq!(
            wrong_family_verify_payload["verification"]["requiredReceiptFamiliesPresent"],
            false
        );
        assert!(
            wrong_family_verify_payload["verification"]["receiptFailures"]
                .as_array()
                .unwrap_or_else(|| panic!("missing wrong-family receipt failures"))
                .iter()
                .any(|failure| failure
                    .as_str()
                    .is_some_and(|failure| failure.contains("unexpected_receipt_family")))
        );

        let mut mismatched_artifact_archive_payload = archive_payload.clone();
        mismatched_artifact_archive_payload["archive"]["artifact"]["contentHash"] =
            serde_json::Value::String(sha256(b"tampered artifact hash").to_hex_prefixed());
        let mismatched_artifact_archive_hash = canonical_json_hash(
            &mismatched_artifact_archive_payload["archive"],
            "mismatched artifact evidence bundle archive",
        )
        .unwrap_or_else(|e| panic!("failed to hash mismatched artifact archive: {e}"));
        mismatched_artifact_archive_payload["archiveHash"] =
            serde_json::Value::String(mismatched_artifact_archive_hash);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                mismatched_artifact_archive_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build mismatched artifact archive verifier request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("mismatched artifact archive verifier request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read mismatched artifact verifier response: {e}")
            });
        let mismatched_artifact_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode mismatched artifact verifier response: {e}")
            });
        assert_eq!(
            mismatched_artifact_verify_payload["archiveHashMatches"],
            true
        );
        assert_eq!(mismatched_artifact_verify_payload["verified"], false);
        assert_eq!(
            mismatched_artifact_verify_payload["verification"]["artifactMatchesBundle"],
            false
        );
        assert!(
            mismatched_artifact_verify_payload["verification"]["receiptFailures"]
                .as_array()
                .unwrap_or_else(|| panic!("missing mismatched artifact failures"))
                .iter()
                .any(|failure| failure
                    .as_str()
                    .is_some_and(|failure| failure.contains("artifact_content_hash_mismatch")))
        );

        let mut mismatched_artifact_byte_count_archive_payload = archive_payload.clone();
        mismatched_artifact_byte_count_archive_payload["archive"]["artifact"]["byteCount"] =
            serde_json::Value::from(0);
        let mismatched_artifact_byte_count_archive_hash = canonical_json_hash(
            &mismatched_artifact_byte_count_archive_payload["archive"],
            "mismatched artifact byte count evidence bundle archive",
        )
        .unwrap_or_else(|e| panic!("failed to hash mismatched artifact byte count archive: {e}"));
        mismatched_artifact_byte_count_archive_payload["archiveHash"] =
            serde_json::Value::String(mismatched_artifact_byte_count_archive_hash);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                mismatched_artifact_byte_count_archive_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!(
                    "failed to build mismatched artifact byte count archive verifier request: {e}"
                )
            });
        let response = app.clone().oneshot(req).await.unwrap_or_else(|e| {
            panic!("mismatched artifact byte count archive verifier request failed: {e}")
        });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read mismatched artifact byte count verifier response: {e}")
            });
        let mismatched_artifact_byte_count_verify_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode mismatched artifact byte count verifier response: {e}")
            });
        assert_eq!(
            mismatched_artifact_byte_count_verify_payload["archiveHashMatches"],
            true
        );
        assert_eq!(
            mismatched_artifact_byte_count_verify_payload["verified"],
            false
        );
        assert_eq!(
            mismatched_artifact_byte_count_verify_payload["verification"]
                ["artifactByteCountMatches"],
            false
        );
        assert_eq!(
            mismatched_artifact_byte_count_verify_payload["verification"]["graphCountsMatch"],
            true
        );
        assert!(
            mismatched_artifact_byte_count_verify_payload["verification"]["receiptFailures"]
                .as_array()
                .unwrap_or_else(|| panic!("missing mismatched artifact byte count failures"))
                .iter()
                .any(|failure| failure
                    .as_str()
                    .is_some_and(|failure| failure.contains("artifact_byte_count_mismatch")))
        );

        let mut mismatched_count_archive_payload = archive_payload.clone();
        mismatched_count_archive_payload["archive"]["bundle"]["nodeCount"] =
            serde_json::Value::from(0);
        let mismatched_count_archive_hash = canonical_json_hash(
            &mismatched_count_archive_payload["archive"],
            "mismatched count evidence bundle archive",
        )
        .unwrap_or_else(|e| panic!("failed to hash mismatched count archive: {e}"));
        mismatched_count_archive_payload["archiveHash"] =
            serde_json::Value::String(mismatched_count_archive_hash);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/evidence-bundles/archive/verify")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                mismatched_count_archive_payload.to_string(),
            ))
            .unwrap_or_else(|e| {
                panic!("failed to build mismatched count archive verifier request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("mismatched count archive verifier request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read mismatched count verifier response: {e}"));
        let mismatched_count_verify_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode mismatched count verifier response: {e}"));
        assert_eq!(mismatched_count_verify_payload["archiveHashMatches"], true);
        assert_eq!(mismatched_count_verify_payload["verified"], false);
        assert_eq!(
            mismatched_count_verify_payload["verification"]["graphCountsMatch"],
            false
        );
        assert!(
            mismatched_count_verify_payload["verification"]["receiptFailures"]
                .as_array()
                .unwrap_or_else(|| panic!("missing mismatched count failures"))
                .iter()
                .any(|failure| failure
                    .as_str()
                    .is_some_and(|failure| failure.contains("bundle_node_count_mismatch")))
        );

        let _ = std::fs::remove_dir_all(bundle_dir);
        let _ = std::fs::remove_file(receipt_path);
        let _ = std::fs::remove_file(fleet_outbox_path);
    }

